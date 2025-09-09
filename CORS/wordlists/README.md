### CORS Wordlists and Tools

Use these with `CORS/Hunt Methodology.md`. Start with `origins.txt` to probe ACAO/ACAC behavior, then use PoCs for exploitation.

Lists
- origins.txt: common, tricky, and bypass-style Origin values.
- preflight.txt: method/header permutations for OPTIONS preflights.

PoCs (see `../pocs/`)
- xhr_with_credentials.html: credentialed XHR read + exfil template.
- null_origin_iframe.html: sandbox data URL PoC to force Origin null.
- fetch_reflection_test.html: in-browser tester for reflected ACAO.
- websocket_cors_poc.html: attempts cross-origin WebSocket; logs/exfil messages if Origin not validated.

Script
- `../tools/cors_probe.sh`: curl-based iterator over origins; prints ACAO/ACAC/ACAM/ACAH.

