Encounter Cliff Notes

- postMessage → JS URL redirect
  - Page forwarded `e.data` to `location.href` if it contained `http/https`. Posted `javascript:print()//http:` from iframe to execute.

- postMessage → innerHTML sink
  - `innerHTML = e.data` in ads container. Posted an `<img onerror=print()>` from iframe.

- postMessage + JSON.parse → iframe URL
  - Message accepted `{url: ...}`. Sent `javascript:print()` via JSON to load into created iframe.

- DOM open redirect
  - Link’s onclick parsed `url=` from `location`. Added `&url=https://attacker` and used Back to Blog to navigate off-site.

- Cookie-to-DOM XSS (lastViewedProduct)
  - App built HTML from a cookie URL. Forced cookie to include `<script>print()</script>` by visiting product URL that sets cookie, then navigated to home where it rendered.

- DOM clobbering to load attacker script
  - Comments allowed HTML; clobbered `window.defaultAvatar` with anchors so avatar URL became `cid:" onerror=alert(1)//`, triggering on next render.

- Attribute clobbering to bypass HTML filters
  - Sanitizer allowed `<form>` and `<input>`. Used `<input id=attributes>` to break attribute stripping on a focused form with `onfocus=print()` triggered via `#x` anchor.


