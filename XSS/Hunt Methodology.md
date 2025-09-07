### XSS Hunt Methodology

Use only with explicit authorization. This gives a fast, systematic path to find and exploit XSS with your existing wordlists.

Key wordlists in this repo
- `XSS/wordlists/tags-probe.txt` — minimal tag probes (e.g., `<tag =1>`) to map blacklist behavior.
- `XSS/wordlists/js-autoexec.txt` — auto/indirect-exec vectors (onerror/onload/srcdoc/javascript:/meta refresh).
- `XSS/wordlists/custom-tags-only.txt` — payloads for environments where only custom tags pass.
- `XSS/wordlists/svg-restricted-events.txt` — SVG vectors incl. SMIL onbegin/onend/onrepeat and interaction fallbacks.
- `XSS/wordlists/typo-attrs.txt` — common typo/case variants for naive blacklist bypass.
- `XSS/wordlists/payloads.txt` — `prompt/alert/confirm/print` function list.
- `XSS/wordlists/tags-events-payloads-core.txt` — compact, high-signal combinations for quick sweeps.

---

## Decision tree: question-driven XSS hunting

1) Where does your input land in the final DOM?
- HTML text node → try tag/attribute injection. Use `tags-probe.txt`, then `js-autoexec.txt` or `tags-events-payloads-core.txt`.
- Attribute value (e.g., `href`, `src`, `title`) → use `attribute-breakouts.txt`; if it’s a URL attribute, also try `javascript-url-payloads.txt`.
- Event handler code (e.g., `onclick="…"`) → use `attribute-breakouts.txt` (handler breakouts) or `js-string-breakouts.txt` if quotes are escaped.
- Inside a JavaScript string/template → use `js-string-breakouts.txt` or `template-literal-injection.txt`.
- Inside JSON that is `eval()`/`Function()`’d → use `json-breakouts.txt`.
- SVG-only or SVG-allowed contexts → try `svg-restricted-events.txt` first; then pointer/focus fallbacks.

2) How is it transformed/encoded?
- `<`/`>` encoded but quotes intact → attribute/URL payloads still viable; use `attribute-breakouts.txt`, `javascript-url-payloads.txt`.
- Single quotes escaped but backslash not → use backslash-cancel trick in `js-string-breakouts.txt`.
- Angle brackets and double quotes encoded, single quotes escaped → prefer backslash-cancel or non-angle vectors (e.g., template literal, event handler breakouts).
- Everything Unicode-escaped except `${}` and backticks → use `template-literal-injection.txt`.

3) Is this DOM-based? Which source and sink?
- Sources: `location.search/hash`, `document.cookie`, `postMessage`, XHR/fetch response.
- Sinks: `innerHTML`, `document.write`, jQuery `.html()/.attr()`, `eval/new Function`, `setTimeout(string)`.
- Use the browser DevTools/DOM Invader to identify the exact sink. Map sink to list as per step 1.

4) Is there CSP?
- If inline scripts/handlers blocked: prefer SVG SMIL `onbegin` timing, `javascript:` URLs (if allowed), or sandboxed `iframe srcdoc` if permitted by CSP. Avoid `<script>` PoCs.

5) Can you trigger without user interaction?
- Prefer auto-exec: `onerror`, `onload`, `meta refresh`, `iframe srcdoc`. See `js-autoexec.txt` and `iframe-srcdoc.txt`.
- If not, use focus/pointer events. Add `tabindex` and rely on fragment focus (`#id`) when feasible. See `custom-tags-only.txt` and `tags-events-payloads-core.txt`.

6) Special cases to check early
- Canonical link tag: attribute injection on `<link rel=canonical>` (use `canonical-link-attr.txt`).
- AngularJS 1.x expressions reflected: use `angularjs-expressions.txt`.
- URL attributes (`href/src`): try `javascript-url-payloads.txt` and case/whitespace variants.

7) Confirm execution cleanly
- Prefer OAST callbacks over visual alerts where possible. See detection tips in `wordlists/README.md`.

---

## 1) Recon and context mapping
- Enumerate all sinks: query params, POST fields, JSON, headers, cookies, path segments, fragment.
- Reflect vs store: check immediate reflection (Reflected XSS) and persistent surfaces (Stored XSS).
- DOM sinks: review client-side code for `innerHTML`, `document.write`, jQuery/html(), template rendering, URL fragment usage.
- Determine rendering context where payload lands:
  - HTML body, attribute, URL, script block, CSS, or within JS strings.
- Check headers and CSP: note `Content-Security-Policy`, `X-XSS-Protection`, caching, and MIME type quirks.

## 2) Tag blacklist mapping
- Run `tags-probe.txt` and observe:
  - Which tags are dropped vs preserved vs encoded (`&lt;`/`&#x3c;`).
  - Whether void/obsolete tags pass (e.g., `<marquee>`, `<blink>`, `<svg>`, custom tags like `<xss>`).
- If built-ins blocked but custom allowed, pivot to `custom-tags-only.txt`.

## 3) Auto-exec vectors first
- Try `js-autoexec.txt`:
  - `onerror`/`onload` on media (`<img>`, `<video>`, `<audio>`), `iframe srcdoc`, `meta refresh`, `javascript:` URLs.
  - Prefer these before interaction-required payloads.
- If SVG allowed, immediately test `svg-restricted-events.txt` (SMIL `onbegin` often survives filters).

## 4) Constrain by allowed events
- From responses/DOM, infer which event attributes survive.
- Filter your attempts to only those events:
  - Mouse/pointer: `onclick`, `onmouseover`, `onpointer*`.
  - Focus/keyboard: `onfocus(in/out)`, `onkeydown/up` with `tabindex`.
  - SVG/SMIL: `onbegin`, `onend`, `onrepeat`, event-based `begin="target.click"`, or `begin="indefinite"` + `beginElement()` from an allowed event.

## 5) Interaction strategies
- Use Burp’s embedded browser (or an external browser) to interact with rendered candidates:
  - Hover, click, focus, scroll, keypress.
  - Add `tabindex=1` to focusable nodes to enable focus/keyboard events.
- For custom-tags-only: the fragment + `tabindex` trick: `<xss id=x tabindex=1 onfocus=...>#x`.

## 6) Confirming success
- OAST/Collaborator: replace visual PoC with network callback where viable:
  - Example: `onerror=new Image().src='https://<id>.oastify.com/'`.
- Burp Intruder Grep - Match/Extract:
  - Match: `(?i)on(error|load|begin|click|mouseover)\s*=`, `(?i)javascript:\s*`, `srcdoc="<script>`.
  - Extract: capture ~40-80 chars around your insertion to see if encoded/rewritten.
- Response diffs: sort by length/code to spot blocking or sanitizer behavior.

## 7) SVG specifics (high ROI)
- Auto/indirect: `<svg onload=...>`, `<image onerror=...>`, SMIL `onbegin` with `begin="0s"` or event-based.
- Minimal working variants included (your success case):
  - `"><svg><animatetransform onbegin=alert(1)>`
  - URL-encoded: `%22%3E%3Csvg%3E%3Canimatetransform%20onbegin=alert(1)%3E`
- If `onload` filtered, rely on SMIL timing:
  - Immediate: `<animate begin="0s" dur="0.001s" onbegin=...>`
  - Event-driven: `begin="indefinite"` + `beginElement()` invoked via allowed event (e.g., `onclick`).
  - Event-based timing: `begin="target.click"`.

## 8) WAF and filter evasion
- Case/spacing: `ONERROR`, `onError`, `onerror =` with varied whitespace.
- Attribute splitting and HTML entity encoding where applicable.
- Use `typo-attrs.txt` for naive blacklist slips (e.g., `oonload`).
- Mutation XSS: malformed markup that the parser “repairs”.
- CSP-aware payloads: avoid inline JS if nonce/hash is required; pivot to allowed vectors (e.g., `onbegin`).

## 9) Workflow quickstart (practical)
- Step 1: `tags-probe.txt` → learn which tags survive.
- Step 2: If SVG allowed, run `svg-restricted-events.txt` first; else `js-autoexec.txt`.
- Step 3: Narrow to surviving events; use `tags-events-payloads-core.txt` to sweep with `onclick/onmouseover/onfocus`.
- Step 4: For custom-tags-only, use `custom-tags-only.txt` + fragment focus.
- Step 5: Confirm with OAST and render/interaction; iterate encodings.

## 10) Reporting/mitigation reminders
- Recommend proper output encoding by context, safe DOM APIs (`textContent`, attribute setters), and templating auto-escape.
- Enforce strict CSP (nonces/hashes; disallow `unsafe-inline`), and avoid dangerous sinks (`innerHTML`, `document.write`).
- Server-side validation blocks obvious payloads but must not replace output encoding.

References
- PortSwigger XSS cheat sheet: https://portswigger.net/web-security/cross-site-scripting/cheat-sheet

## 11) Canonical link (<link rel="canonical">) XSS

Nature: If user-controlled input is reflected into the `href` of `<link rel="canonical">` without proper encoding, attribute injection can create interactive handlers. Although head elements are not visible, `accesskey` can be used to trigger events.

Identify
- View-source or DOM and locate `<link rel="canonical" href="...">`.
- Append a unique marker to a param and confirm it reflects inside `href`.

Exploit (interaction required)
- Inject attribute break and handlers into `href` value. Example URL param (raw):
  - `'?q='accesskey='x'onclick='alert(1)`
- Resulting DOM (conceptual):
  - `<link rel="canonical" href="..." accesskey="x" onclick="alert(1)">`
- Trigger with the browser’s accesskey shortcut (e.g., Alt+Shift+X on Windows, Ctrl+Alt+X on macOS in some browsers).

Detection with Intruder Grep
- Grep - Match (case-insensitive):
  - `(?i)<link[^>]+rel=["']?canonical["']?`
  - `(?i)href=`, `(?i)accesskey=`, `(?i)on(click|focus|keydown)=`
- Grep - Extract around the canonical tag to verify attribute injection and encoding.

Notes
- Success typically requires attribute context break or unquoted attributes in `href` reflection.
- CSP may still block inline handlers; prefer events that the environment allows (e.g., `onclick`).
- Some browsers/versions may not honor `accesskey` on `link`; test across targets.

Mitigation
- Strict output encoding for attribute values (`href`).
- Disallow injecting additional attributes; sanitize/whitelist URL structure for canonical.
- Enforce CSP nonces/hashes and avoid inline event handlers.

## 12) DOM eval(JSON) breakout (string-to-code escapes)

Pattern
- Client fetches JSON, then builds code strings and uses `eval()` or `Function()` to parse/assign, e.g.:
  - `eval('var data = ' + RESPONSE_TEXT)`
- Your input lands inside the JSON (e.g., a string field), so you must break out of a quoted string and neutralize the remainder.

How to hunt
- Use DOM Invader or instrument the page to detect sinks like `eval`, `new Function`, `setTimeout(string)`.
- Inspect JS for concatenation of untrusted `responseText` into an eval’d string.
- Confirm reflection shape of the JSON: `{ "searchTerm": "<INPUT>", "results": [...] }`.

Probing and crafting
- Goal: terminate the surrounding string, inject code, and comment or structurally end the code so the rest doesn’t error.
- Common successful patterns:
  - `\"-alert(1)}//`  (breaks out of JSON string, closes object, comments rest)
  - `\";alert(1);//`
  - `\"));alert(1);//`
  - `\"-confirm(1)}//`
- Technique rationale:
  - Backslash escapes the current context so the following quote is consumed.
  - Insert a terminator `-` or `);` or `}` per surrounding syntax.
  - End with `//` (or `/*`) to comment the remainder.

Verification
- Reproduce the exact eval input with developer tools (override XHR/fetch, or log `RESPONSE_TEXT`).
- Ensure the transformed program is valid JS after your injection.

Mitigation (for reports)
- Never `eval()` server responses; use `JSON.parse()`.
- Avoid string-based code construction; prefer data flow with safe APIs.

## 13) JS quote/backslash escaping pitfalls (breaking out of JS strings)

Symptom
- Your single quote `'` gets backslash-escaped (becomes `\'`) preventing breakout, but literal backslashes `\` are not escaped.
- Typical with code like: `var searchTerms = '<INPUT>'; document.write('<img src="...'+encodeURIComponent(searchTerms)+'">');`

Hunting steps
- Identify quote type wrapping your reflection (`'...'` vs `"..."`).
- Probe how characters are handled by sending:
  - `test'X` → if you see `\'`, quotes are escaped
  - `test\X` → if you see `\X` unchanged, backslash survives
- If quotes are escaped but backslash is not, use a backslash to cancel the escaping and terminate the string.

Breakout patterns
- Single-quoted contexts:
  - `\'-alert(1)//`
  - `\');alert(1);//`
  - `\')) ;alert(1);//`
- Double-quoted contexts:
  - `\"-alert(1)//`
  - `\");alert(1);//`
- Rationale: the leading backslash neutralizes the escape, the following quote terminates the JS string, your code executes, and `//` comments out the remainder.

Encoding notes
- URL-encode backslash as needed: `%5C` → payload example: `%5C'-alert(1)//`
- Ensure only one backslash reaches the JS sink after any decoding layers.
- If additional HTML/attribute encoding is applied later, pivot to DOM-only sinks or alternate contexts.

Verification
- Use the browser DevTools to copy the constructed program or set breakpoints to inspect the exact JS after your input is inserted.
- Confirm the transformed code is syntactically valid with your terminators and trailing comment.
