### REGEXSS Hunt Methodology — Regex-driven XSS via greedy replacements

Purpose: A focused workflow to detect and exploit XSS caused by overly-greedy regular expressions that manipulate HTML strings post-sanitization ("REGEXSS"). Based on patterns described by Stealthcopter’s write-up [REGEXSS: How .* Turned Into over $6k in Bounties](https://sec.stealthcopter.com/regexss/#).

---

## 1) Recognition — Where this bug class appears
- Post-sanitization HTML munging using regex (PHP `preg_replace`, JS `String.replace`, etc.).
- Attribute-stripping or value-normalization implemented with patterns like `attribute=".*?"`, `itemprop\="(.*?)"`, `data-...\s*=\s*['"].*?['"]`.
- Mixed-quote handling not normalized (single and double quotes allowed in attributes).
- Frontend filters, legacy CMS plugins, older template code, or ad-hoc sanitizers.

Signals to look for in JS/HTML responses or source:
- `.replace(/.../, '')` or `.replace(/.../g, '')` where the regex includes `=\s*["']` and a greedy token like `.*`, `.*?`, `[^"']*`.
- Regex literals that reference attribute names: `itemprop`, `data-`, `href`, `src`, `attribute`.
- PHP: `preg_replace('/.../', '', $content)` with the same greedy attribute patterns.

See also `XSS/wordlists/regexss-vulnerable-regex-patterns.txt` and the scanner `XSS/tools/regexss_dom_scanner.py`.

---

## 2) Preconditions for exploitability
- Regex runs after sanitizer output (so it can break structure created by a safe parser).
- Mixed quotes permitted in attributes (no normalization to a single quote style).
- Output is subsequently inserted into DOM or rendered as HTML.

Explicitly verify sinks
- Client sinks: `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, attribute setters (e.g., `el.setAttribute(...)`), inline event attributes, `href=javascript:`.
- Server-side rendering: ensure the transformed HTML is used in a template or returned as HTML, not only logged or returned as plain text.
- If output is text-only (`textContent`, JSON, logs), XSS is not achievable without a later HTML insertion.

Risk escalators
- The regex removes entire attribute/value ranges instead of replacing a narrowly scoped token.
- The target context allows promotion of text into attributes (attribute injection) or event handler attributes.

---

## 3) Exploitation patterns
Use inputs that cause the regex to start or end its match in unexpected positions.

- Start shift (begin match inside previous attribute’s value):
  - Before: `<a href="attribute=" title="javascript:alert(1)">test</a>`
  - After removal of `attribute=".*?"`: `<a href="javascript:alert(1)">test</a>`

- End shift (extend match using mixed quotes):
  - Before: `<a title='attribute="' href="new title' onfocus=alert(1) x='y'">t</a>`
  - After: attribute boundaries move; text is promoted into attributes including event handlers.

- Cross-element/content spanning (riskier but possible):
  - Before: `<img src='attribute="">"x' onerror="alert(1)">`
  - After: value collapses, `onerror` remains as an active attribute.

Ready-made payload ideas are in:
- `XSS/wordlists/regexss-attribute-shift-start.txt`
- `XSS/wordlists/regexss-attribute-shift-end.txt`
- `XSS/wordlists/regexss-cross-element-payloads.txt`

---

## 4) Practical test workflow
1. Discover candidates
   - Grep/scan responses and JS bundles using the scanner for patterns in `replace(/.../, '')` that include `="` or `='` with `.*?` or `[^"']*`.
2. Verify ordering (critical)
   - Confirm the regex manipulation occurs after any sanitizer/normalizer (DOMPurify/KSES/etc.). If sanitizer runs after, it may strip promoted attributes.
3. Craft payloads
   - Start with attribute-shift-start payloads; escalate to mixed-quote end-shift; try cross-element if needed.
4. Observe DOM and events
   - Check for promoted attributes (`onfocus`, `onerror`, `tabindex=1`) and trigger via focus/click or load.
5. Prove impact safely
   - Use non-destructive payloads (e.g., `alert(1)` or OAST ping via harmless fetch) respecting scope.

6. Consider templating/escaping paths
   - Template engines (Mustache/Handlebars/Blade/Jinja) may auto-escape by default. Test raw/unescaped contexts (triple-mustache, `|safe`, etc.).
7. Encoding/normalization variants
   - Try `%22`, `&#34;`, `&quot;` to influence regex start positions; verify browser vs server behavior differences.

---

## 5) Common vulnerable regex shapes (red flags)
- `/<attr>\s*=\s*".*?"/` or `/<attr>\s*=\s*'.*?'/`
- `/data-[A-Za-z0-9_-]+\s*=\s*["'][^"']*["']/`
- `/itemprop\=\"(.*?)\"/` (real case)
- Any attribute-targeting pattern combined with a global removal replacement to `''`.

Note: Lazy `.*?` is still dangerous in HTML contexts; it can span unintended boundaries.

---

## 5.1) Practical detection cheats (ripgrep)
Search code/bundles for suspicious replacements:
```
rg --hidden --no-ignore -n "replace\(/\s*[^)]*=\s*['\"]"         # JS .replace(...="... or ...='...
rg --hidden --no-ignore -n "replace\(/\s*[^)]*\.\*\?"            # JS lazy quantifier in replace
rg --hidden --no-ignore -n "preg_replace\(\s*['\"].*=[^']*['\"]" # PHP preg_replace removing attributes
rg --hidden --no-ignore -n "preg_replace\([^\)]*(\"|')\.\*(\?|) (\\1)"  # heuristic greedy removal
```
Search responses (built assets):
```
rg -n "replace\(/[^\)]*=['\"][\s\S]*?\1" dist/*.js
```

---

## 6) False-negative/positive considerations
- If quotes are normalized (e.g., DOMPurify converts single → double), some mixed-quote payloads fail.
- Some replacements may run on plain text, not HTML. Validate execution path to HTML sinks.
- Greedy tokens that are further constrained (e.g., anchored to tag boundaries) may be safe; test to confirm.
 - False positive: regex matches exist but only affect logs/plain text.
 - False negative: patterns constrained with `[^>]*` or tag-anchored boundaries can be low risk; still test.

---

## 7) Remediation guidance
- Do not use regex to modify HTML structure. Use an HTML parser (e.g., `DOMParser`, `DOMDocument`, `WP_HTML_Tag_Processor`).
- If replacement is unavoidable, reduce scope: match exact attribute names and values, avoid `.*`/`[^"']*`, and operate only on parsed nodes.
- Normalize quotes before any string ops to reduce mixed-quote abuse pathways.

Snippets you can drop-in
```php
// PHP/PCRE — match quoted value without crossing quotes
$re = '/\\battr\\s*=\\s*([\'\"])' + "[^'\"]*" + '\\1/i';
$content = preg_replace($re, '', $content);

// Conservative href removal (URL charset)
$re = '/\\bhref\\s*=\\s*([\'\"])' + "[A-Za-z0-9\\-._~:\\/?#\\[\\]@!$&'()*+,;=%]*" + '\\1/i';

// JS — remove only well-formed quoted attribute values
content = content.replace(/\\battr\\s*=\\s*(['\"])' + "[^'\"]*" + '\\1/gi, '');
```

---

## 8) Reporting template (key details)
- Location of regex and execution path; proof it runs post-sanitization.
- Minimal payload and resulting HTML/DOM diff.
- Impact narrative and user interaction required (if any).
- Clear fix: switch to parser-based attribute removal; include code references.
 - Include sinks: identify whether content reaches `innerHTML`/SSR/inline attrs; if not, note as non-exploitable.
 - Recommend CSP as defense-in-depth and parser-based sanitization (DOMPurify/DOMDocument/Tag Processor).

References
- Stealthcopter — REGEXSS article: [link](https://sec.stealthcopter.com/regexss/#)

