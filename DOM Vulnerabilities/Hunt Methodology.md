### DOM Vulnerabilities Hunt Methodology

Use only with explicit authorization. This flow maps untrusted sources → dangerous sinks and common sanitizer/clobbering bypasses.

---

## Decision tree: question-driven DOM hunting

1) Identify sources
- URL parts: `location.search/hash/pathname/href`, `document.URL`, `referrer`.
- Storage/cookies: `document.cookie`, `localStorage`, `sessionStorage`.
- Messaging: `postMessage` (`message` event), `BroadcastChannel`.
- Programmatic: `history.pushState/replaceState`, `window.name`.

2) Locate sinks
- HTML insertion: `innerHTML/outerHTML/insertAdjacentHTML/document.write`.
- URL/navigation: `location.href/assign/replace`, `open()`.
- Attribute setters: `setAttribute('href/src', ...)`, template literals in attributes.
- JS eval: `eval/new Function/setTimeout(string)/setInterval(string)`.

3) Data flow and guards
- Is data parsed (JSON.parse), sanitized (DOMPurify/HTMLJanitor), or validated (origin checks)?
- Any regex filters? Are they substring/naive checks?

4) Choose attack path
- Web messages → inject HTML or `javascript:` URL via postMessage; test origin validation.
- JSON.parse path → craft JSON to load `javascript:` or HTML payloads consumed by sinks.
- Cookie/storage → store payload and trigger read on next render.
- DOM clobbering → create elements with conflicting `id/name` to override globals/objects.
- Sanitizer bypass → exploit attribute/property clobbering to keep event handlers.

5) Confirm execution
- Prefer `print()` or OAST beacons; use iframes to drive focus/hash navigation when needed.

---

## Quick payload mapping

- postMessage → `<iframe src="TARGET" onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')">`
- postMessage + navigation → `postMessage('javascript:print()//http:','*')`
- JSON.parse message → `postMessage(JSON.stringify({type:'load-channel',url:'javascript:print()'}),'*')`
- Cookie-seeded XSS → navigate in iframe to set cookie payload, then back to home to read and render.
- DOM clobbering → `<a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=print()//">`
- HTMLJanitor attr-clobber bypass → `<form id=x tabindex=0 onfocus=print()><input id=attributes>` + `#x` focus.

---

## Reporting/mitigation

- Validate message origins and data shape; avoid `'*'` unless necessary.
- Use safe DOM APIs: `textContent`, attribute setters for URLs with strict allowlists.
- Avoid string-based eval; avoid writing to `innerHTML` with untrusted data.
- Harden sanitizers and avoid relying on DOM globals; disable implicit element globals.


