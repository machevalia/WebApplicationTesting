#!/usr/bin/env python3
"""
regexss_dom_scanner.py

Scan response bodies (HTML/JS) for potentially vulnerable regular expressions that manipulate
HTML attributes in ways that can lead to REGEXSS (regex-driven XSS) issues.

Features:
- Fetch URL(s) or read local file(s)/stdin
- Extract inline <script> and external JS (robust HTML parser)
- Flag risky replace/replaceAll, split/join, new RegExp, and replacer functions with empty-ish returns
- Heuristics: attribute-token gating, greedy token detection, dotAll awareness, sink proximity scoring
- Severity scoring and multi-line context output with caret
- Output formats: text, json, jsonl, sarif; min severity filtering; fail-on-high
- Concurrency for fetching externals and response size caps
- Additionally scan using patterns from XSS/wordlists/regexss-vulnerable-regex-patterns.txt

Reference: Stealthcopter — REGEXSS: How .* Turned Into over $6k in Bounties
https://sec.stealthcopter.com/regexss/#
"""

import argparse
import json
import os
import re
import sys
from html import unescape
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse
from urllib.request import urlopen, Request
from concurrent.futures import ThreadPoolExecutor, as_completed


RISKY_REPLACE_REGEX_LITERAL = re.compile(
    r"\.(?:replace|replaceAll)\s*\(\s*/((?:[^/\\]|\\.)+)/([a-z]*)\s*,\s*([^)]+?)\)",
    re.IGNORECASE | re.DOTALL,
)

RISKY_REPLACE_NEW_REGEXP = re.compile(
    r"\.replace\s*\(\s*new\s+RegExp\s*\(\s*([\'\"])(.*?)\1\s*,\s*([\'\"])([a-z]*)\3\s*\)\s*,\s*([^)]+?)\)",
    re.IGNORECASE | re.DOTALL,
)

RISKY_SPLIT_JOIN = re.compile(
    r"\.split\s*\(\s*/((?:[^/\\]|\\.)+)/([a-z]*)\s*\)\s*\.join\s*\(\s*([^)]+?)\)",
    re.IGNORECASE | re.DOTALL,
)

RISKY_REPLACER_FN = re.compile(
    r"\.replace\s*\(\s*/((?:[^/\\]|\\.)+)/([a-z]*)\s*,\s*(?:function\s*\([^)]*\)\s*\{[^}]*\}|\(.*?\)\s*=>\s*\{?[^}]*\}? )\)",
    re.IGNORECASE | re.DOTALL,
)

RISKY_NEWREGEXP_ANY = re.compile(
    r"new\s+RegExp\s*\(\s*((?:\s|\+|\"(?:\\.|[^\"])*\"|'(?:\\.|[^'])*')+)\s*(?:,\s*([\'\"])\s*([a-z]*)\s*\2)?\)",
    re.IGNORECASE | re.DOTALL,
)

# Indicators within a regex pattern that suggest attribute-targeting with greedy matching
ATTR_EQ_QUOTE = re.compile(r"=\s*[\'\"]")
ATTR_TOKENS = re.compile(r"\b(?:href|src|data-[\w-]+|itemprop|title|alt|id|class|style|on\w+)\b", re.IGNORECASE)
GREEDY_TOKENS = [
    re.compile(r"\.\*[\?\+]?"),                 # .*, .*?, .*+
    re.compile(r"\[\^['\"]\]\*[\?\+]?"),     # [^'\"]*, [^'\"]*?, [^'\"]*+
    re.compile(r"\[\^>\]\*[\?\+]?"),          # [^>]* etc.
    re.compile(r"\[\\s\\S\]\*[\?\+]?"),     # [\s\S]* variants
]

SINK_ASSIGN = re.compile(r"\b(innerHTML|outerHTML|insertAdjacentHTML|write)\s*=", re.IGNORECASE)
SINK_SETTER = re.compile(r"\.(?:innerHTML|outerHTML|insertAdjacentHTML)\s*\(", re.IGNORECASE)


MAX_BYTES = 3_000_000

def http_get(url: str, timeout: int = 15) -> str:
    req = Request(url, headers={"User-Agent": "regexss-dom-scanner/1.1", "Accept-Encoding": "gzip, deflate"})
    with urlopen(req, timeout=timeout) as resp:
        data = resp.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise RuntimeError("response too large")
        charset = resp.headers.get_content_charset() or "utf-8"
        return data.decode(charset, errors="replace")


class ScriptExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.inline = []
        self.externals = []
        self._buf = []
        self._in_script = False
        self._in_script_has_src = False

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "script":
            self._in_script = True
            src = dict(attrs).get("src")
            self._in_script_has_src = bool(src)
            if src:
                self.externals.append(src)

    def handle_endtag(self, tag):
        if tag.lower() == "script":
            if self._in_script and not self._in_script_has_src:
                self.inline.append(unescape(''.join(self._buf)))
            self._buf, self._in_script, self._in_script_has_src = [], False, False

    def handle_data(self, data):
        if self._in_script and not self._in_script_has_src:
            self._buf.append(data)

def extract_scripts(html: str, base_url: str | None = None):
    p = ScriptExtractor()
    p.feed(html)
    externals = [urljoin(base_url, s) if base_url else s for s in p.externals]
    return p.inline, externals

def scan_html_for_regex_surgery_indicators(html: str, source: str) -> list[dict]:
    findings: list[dict] = []
    # Simple heuristics: attributes without values, on* promoted, quote imbalance per tag
    for m in re.finditer(r"<([a-zA-Z][a-zA-Z0-9:-]*)\b([^>]*)>", html):
        tag = m.group(1)
        attrs = m.group(2)
        if re.search(r"\bon\w+\s*=\s*[^'\"\s][^\s>]*", attrs):
            findings.append({"type": "html-indicator", "location": source, "line": None, "regex": "on*-attr-unquoted", "snippet": f"<{tag}{attrs[:80]}...>", "severity": "low", "reason": "inline event attr without quotes may be promoted by regex surgery"})
        if re.search(r"\b\w+\s*=\s*(?=[\s>])", attrs):
            findings.append({"type": "html-indicator", "location": source, "line": None, "regex": "attr-without-value", "snippet": f"<{tag}{attrs[:80]}...>", "severity": "low", "reason": "attribute without value suggests broken removal"})
        if attrs.count('"') % 2 == 1 or attrs.count("'") % 2 == 1:
            findings.append({"type": "html-indicator", "location": source, "line": None, "regex": "quote-imbalance", "snippet": f"<{tag}{attrs[:80]}...>", "severity": "low", "reason": "odd quote count suggests regex broke quoting"})
    return findings


def load_wordlist_patterns(default_path: str | None) -> list[re.Pattern]:
    patterns: list[re.Pattern] = []
    if not default_path or not os.path.exists(default_path):
        return patterns
    try:
        with open(default_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    patterns.append(re.compile(line, re.IGNORECASE | re.DOTALL))
                except re.error:
                    # Skip invalid patterns in the list
                    pass
    except Exception:
        pass
    return patterns


def has_dotall(flags: str) -> bool:
    return 's' in (flags or '')

def looks_attribute_and_greedy(regex_source: str, flags: str = "") -> bool:
    if not ATTR_EQ_QUOTE.search(regex_source):
        return False
    if not ATTR_TOKENS.search(regex_source):
        return False
    for g in GREEDY_TOKENS:
        if g.search(regex_source):
            return True
    return False

def replacement_classification(repl_expr: str) -> str:
    expr = repl_expr.strip()
    if expr in ("''", '""', '``'):
        return 'empty'
    if expr in ('" "', "' '") or re.fullmatch(r"\(\s*\)\s*=>\s*(['\"])\1", expr):
        return 'emptyish'
    if re.search(r"\$\d+", expr):
        return 'backref'
    if re.search(r"return\s+(['\"])\1", expr):
        return 'emptyish'
    return 'other'

def compute_severity(regex_src: str, flags: str, replacement_kind: str, flow_to_sink: bool) -> tuple[str, int, str]:
    score = 1
    reasons = []
    if has_dotall(flags) or re.search(r"\[\\s\\S\]", regex_src):
        score += 2
        reasons.append('dotAll or [\\s\\S]*')
    if re.search(r"\bon\w+\b|\bhref\b|\bsrc\b", regex_src, re.IGNORECASE):
        score += 1
        reasons.append('targets sensitive attributes')
    if replacement_kind in ('empty', 'emptyish', 'backref'):
        score += 1
        reasons.append(f'replacement={replacement_kind}')
    if flow_to_sink:
        score += 1
        reasons.append('near HTML sink')
    if not any(g.search(regex_src) for g in GREEDY_TOKENS):
        score -= 1
        reasons.append('no greedy token detected')
    severity = 'low'
    if score >= 4:
        severity = 'high'
    elif score >= 2:
        severity = 'medium'
    return severity, score, ', '.join(reasons)


def _context_with_caret(content: str, start: int, width: int = 120, radius: int = 2):
    line_no = content.count("\n", 0, start) + 1
    line_start = content.rfind("\n", 0, start) + 1
    col_no = start - line_start + 1
    lines = content.splitlines()
    i = line_no - 1
    lo, hi = max(0, i - radius), min(len(lines), i + radius + 1)
    block = []
    for idx in range(lo, hi):
        prefix = ">" if idx == i else " "
        block.append(f"{prefix} {idx+1:>5}: {lines[idx][:width]}")
    block.append(f"          {' '*(col_no-1)}^")
    return "\n".join(block), line_no, col_no

def likely_flows_to_sink(js: str, m: re.Match) -> bool:
    start = m.end()
    next_chunk = js[start:start + 2000]
    return bool(SINK_ASSIGN.search(next_chunk) or SINK_SETTER.search(next_chunk))

def scan_js(content: str, source: str, wordlist_res: list[re.Pattern]) -> list[dict]:
    findings: list[dict] = []

    # Pattern A: .replace or .replaceAll with regex literal
    for m in RISKY_REPLACE_REGEX_LITERAL.finditer(content):
        pattern_src = m.group(1)
        flags = m.group(2) or ''
        repl = m.group(3) or ''
        if looks_attribute_and_greedy(pattern_src, flags):
            flow = likely_flows_to_sink(content, m)
            rkind = replacement_classification(repl)
            severity, score, reason = compute_severity(pattern_src, flags, rkind, flow)
            findings.append(_make_finding("replace-regex-literal", source, content, m, pattern_src, flags, rkind, severity, reason))

    # Pattern B: .replace(new RegExp("...","flags"), ...)
    for m in RISKY_REPLACE_NEW_REGEXP.finditer(content):
        pattern_src = m.group(2)
        flags = m.group(4) or ''
        repl = m.group(5) or ''
        if looks_attribute_and_greedy(pattern_src, flags):
            flow = likely_flows_to_sink(content, m)
            rkind = replacement_classification(repl)
            severity, score, reason = compute_severity(pattern_src, flags, rkind, flow)
            findings.append(_make_finding("replace-new-RegExp", source, content, m, pattern_src, flags, rkind, severity, reason))

    # Pattern C: split(regex).join(replacement)
    for m in RISKY_SPLIT_JOIN.finditer(content):
        pattern_src = m.group(1)
        flags = m.group(2) or ''
        repl = m.group(3) or ''
        if looks_attribute_and_greedy(pattern_src, flags):
            flow = likely_flows_to_sink(content, m)
            rkind = replacement_classification(repl)
            severity, score, reason = compute_severity(pattern_src, flags, rkind, flow)
            findings.append(_make_finding("split-join", source, content, m, pattern_src, flags, rkind, severity, reason))

    # Pattern D: replacer function forms
    for m in RISKY_REPLACER_FN.finditer(content):
        pattern_src = m.group(1)
        flags = m.group(2) or ''
        # Heuristic: treat as emptyish if function body returns ''
        span = content[m.start():m.end()]
        repl_kind = 'emptyish' if re.search(r"return\s+(['\"])\1|=>\s*(['\"])\2", span) else 'other'
        if looks_attribute_and_greedy(pattern_src, flags):
            flow = likely_flows_to_sink(content, m)
            severity, score, reason = compute_severity(pattern_src, flags, repl_kind, flow)
            findings.append(_make_finding("replace-replacer-fn", source, content, m, pattern_src, flags, repl_kind, severity, reason))

    # Pattern E: dynamic new RegExp with concatenated strings
    for m in RISKY_NEWREGEXP_ANY.finditer(content):
        arg = m.group(1)
        flags = m.group(3) or ''
        parts = re.findall(r"\"(?:\\.|[^\"])*\"|'(?:\\.|[^'])*'", arg)
        combined = ''.join(p[1:-1] for p in parts)
        if combined and looks_attribute_and_greedy(combined, flags):
            flow = likely_flows_to_sink(content, m)
            rkind = 'other'
            severity, score, reason = compute_severity(combined, flags, rkind, flow)
            findings.append(_make_finding("new-RegExp-dynamic", source, content, m, combined, flags, rkind, severity, reason))

    # Pattern F: Wordlist patterns anywhere in JS
    for rx in wordlist_res:
        for m in rx.finditer(content):
            findings.append(_make_finding("wordlist-hit", source, content, m, m.group(0), '', 'other', 'low', 'wordlist pattern'))

    return findings


def _make_finding(kind: str, source: str, content: str, match: re.Match, regex_src: str, flags: str = '', replacement_kind: str = 'other', severity: str = 'low', reason: str = '') -> dict:
    start = match.start()
    line_no = content.count("\n", 0, start) + 1
    line_start = content.rfind("\n", 0, start) + 1
    line_end = content.find("\n", start)
    if line_end == -1:
        line_end = len(content)
    line = content[line_start:line_end]
    snippet = line.strip()
    ctx, ln, col = _context_with_caret(content, start)
    return {
        "type": kind,
        "location": source,
        "line": line_no,
        "column": col,
        "regex": regex_src[:500],
        "flags": flags,
        "replacement_kind": replacement_kind,
        "severity": severity,
        "reason": reason,
        "snippet": snippet[:500],
        "context": ctx,
    }


def collect_from_target(target: str, timeout: int, max_scripts: int, wordlist_res: list[re.Pattern], same_origin: bool) -> list[dict]:
    findings: list[dict] = []
    if target.startswith("http://") or target.startswith("https://"):
        html = http_get(target, timeout)
        inline, externals = extract_scripts(html, base_url=target)
        # HTML indicators
        findings.extend(scan_html_for_regex_surgery_indicators(html, target))

        # Inline
        for idx, js in enumerate(inline[:max_scripts]):
            findings.extend(scan_js(js, f"{target}#inline:{idx}", wordlist_res))

        # External
        if same_origin:
            base_netloc = urlparse(target).netloc
            externals = [s for s in externals if urlparse(s).netloc == base_netloc]
        to_fetch = externals[:max_scripts - len(inline)]
        with ThreadPoolExecutor(max_workers=8) as ex:
            futs = {ex.submit(http_get, src, timeout): src for src in to_fetch}
            for fut in as_completed(futs):
                src = futs[fut]
                try:
                    js = fut.result()
                    findings.extend(scan_js(js, src, wordlist_res))
                except Exception as e:
                    findings.append({
                        "type": "fetch-error",
                        "location": src,
                        "error": str(e),
                    })
    else:
        # Local file
        try:
            with open(target, "r", encoding="utf-8", errors="replace") as f:
                data = f.read()
        except Exception as e:
            return [{"type": "read-error", "location": target, "error": str(e)}]

        # If HTML, extract scripts; else treat entire file as JS
        if "<script" in data.lower():
            inline, externals = extract_scripts(data, base_url=None)
            for idx, js in enumerate(inline[:max_scripts]):
                findings.extend(scan_js(js, f"{target}#inline:{idx}", wordlist_res))
            findings.extend(scan_html_for_regex_surgery_indicators(data, target))
        else:
            findings.extend(scan_js(data, target, wordlist_res))

    return findings


def main():
    parser = argparse.ArgumentParser(description="Scan HTML/JS for regex-based XSS risks (REGEXSS)")
    parser.add_argument("targets", nargs="*", help="URLs or file paths. Use '-' to read HTML/JS from stdin.")
    parser.add_argument("--patterns", dest="patterns", help="Path to additional regex patterns wordlist.")
    parser.add_argument("--timeout", dest="timeout", type=int, default=15, help="HTTP timeout seconds (default 15)")
    parser.add_argument("--max-scripts", dest="max_scripts", type=int, default=100, help="Max scripts to analyze per page (default 100)")
    parser.add_argument("--output", dest="output", choices=["text", "json", "jsonl", "sarif"], default="text", help="Output format")
    parser.add_argument("--same-origin", action="store_true", help="Only fetch scripts from the page's origin")
    parser.add_argument("--max-bytes", dest="max_bytes", type=int, default=MAX_BYTES, help="Response size cap in bytes")
    parser.add_argument("--min-severity", dest="min_sev", choices=["low","medium","high"], default="low", help="Minimum severity to report")
    parser.add_argument("--fail-on-high", action="store_true", help="Exit non-zero if any high-severity finding")
    args = parser.parse_args()

    # Default wordlist path adjacent to this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_wordlist = os.path.normpath(os.path.join(script_dir, "..", "wordlists", "regexss-vulnerable-regex-patterns.txt"))
    wordlist_path = args.patterns or default_wordlist
    wordlist_res = load_wordlist_patterns(wordlist_path)

    all_findings: list[dict] = []

    if not args.targets or args.targets == ["-"]:
        data = sys.stdin.read()
        src = "stdin"
        # Treat as HTML if it looks like it; else JS
        if "<script" in data.lower():
            inline, _ = extract_scripts(data)
            for idx, js in enumerate(inline):
                all_findings.extend(scan_js(js, f"{src}#inline:{idx}", wordlist_res))
            all_findings.extend(scan_html_for_regex_surgery_indicators(data, src))
        else:
            all_findings.extend(scan_js(data, src, wordlist_res))
    else:
        for t in args.targets:
            try:
                all_findings.extend(collect_from_target(t, args.timeout, args.max_scripts, wordlist_res, args.same_origin))
            except Exception as e:
                all_findings.append({"type": "target-error", "location": t, "error": str(e)})

    # De-dupe by (type, location, regex)
    dedup = {}
    for f in all_findings:
        key = (f.get('type'), f.get('location'), f.get('regex'))
        dedup[key] = f
    findings = list(dedup.values())

    # Filter by min severity
    sev_rank = {"low": 1, "medium": 2, "high": 3}
    min_rank = sev_rank.get(args.min_sev, 1)
    findings = [f for f in findings if sev_rank.get(f.get('severity','low'),1) >= min_rank or f.get('type','').endswith('error') or f.get('type') == 'html-indicator']

    if args.output == "json":
        print(json.dumps({"findings": findings}, indent=2))
    elif args.output == "jsonl":
        for f in findings:
            print(json.dumps(f))
    elif args.output == "sarif":
        sarif = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "regexss-dom-scanner", "version": "1.1"}},
                "results": [
                    {
                        "ruleId": f.get('type', 'regexss'),
                        "level": {"low": "note", "medium": "warning", "high": "error"}.get(f.get('severity','low'), 'note'),
                        "message": {"text": (f"{f.get('reason','')} regex={f.get('regex','')}").strip()},
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {"uri": f.get('location','')},
                                "region": {"startLine": f.get('line') or 1, "startColumn": f.get('column') or 1}
                            }
                        }]
                    }
                    for f in findings if not f.get('type','').endswith('error')
                ]
            }]
        }
        print(json.dumps(sarif, indent=2))
    else:
        if not findings:
            print("No suspicious patterns found.")
            return
        for f in findings:
            if f.get("type", "").endswith("error"):
                print(f"[ERROR] {f.get('location')}: {f.get('error')}")
                continue
            print(f"[{f['severity'].upper()}][{f['type']}] {f['location']}:{f.get('line','?')}:{f.get('column','?')}")
            print(f"  reason: {f.get('reason','')}")
            print(f"  regex : {f['regex']}")
            if f.get('flags'):
                print(f"  flags : {f['flags']}")
            print(f"  repl  : {f.get('replacement_kind','')}")
            print(f"{f.get('context','').rstrip()}")

    if args.fail_on_high and any(f.get('severity') == 'high' for f in findings):
        sys.exit(2)


if __name__ == "__main__":
    main()


