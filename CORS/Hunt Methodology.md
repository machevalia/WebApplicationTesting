### CORS Hunt Methodology

Use only with explicit authorization. This flow helps you detect and exploit risky CORS configurations that enable cross-origin reads with credentials.

---

## Decision tree: question-driven CORS hunting

1) Is CORS in play for the target resource?
- Inspect responses for: `Access-Control-Allow-Origin` (ACAO), `Access-Control-Allow-Credentials` (ACAC), `Access-Control-Allow-Headers/Methods`.
- Review JS for cross-origin XHR/fetch to sensitive paths (account details, API keys).

2) What origins are allowed?
- Static allowlist? Wildcard `*`? Reflected origin (server copies `Origin` value)? `null` accepted? Insecure scheme (http) for a https site? Subdomain wildcards?

3) Are credentials allowed?
- If `Access-Control-Allow-Credentials: true` with reflected/permissive origin → high risk of cross-origin reads with cookies.
- Note: `ACAC: true` must not be used with `ACAO: *` (browsers block); check for server bugs attempting both.

4) Preflight behavior
- Which methods/headers are allowed in `Access-Control-Allow-Methods/Headers`? Overly broad can widen attack surface.
- Reflective handling of `Access-Control-Request-Headers` can indicate poor validation.

5) Choose validation path
- Origin reflection: send varied `Origin` values (see `wordlists/origins.txt`); confirm ACAO echoes attacker origin and ACAC is true.
- `null` origin: deliver PoC from a sandboxed iframe/data URL to force `Origin: null`.
- Insecure protocol: attempt `http://` origin on a `https://` target; test subdomain permutations.
- Subdomain/regex bypasses: try `trusted.com.attacker.com`, `attacker.com/trusted.com`.

6) Confirm exploitability
- Run credentialed XHR from attacker origin with `withCredentials=true`; read sensitive body and exfiltrate.
- Verify preflight passes when custom headers/methods are needed.

---

## Quick checks and patterns

- Reflection: ACAO equals request Origin for arbitrary `Origin` values.
- `null` accepted: ACAO set to `null`; use `<iframe sandbox="allow-scripts" srcdoc=...>` to force null.
- Credentials: ACAC is `true`; confirm cookies are required to access data.
- Overly permissive methods/headers in preflight responses.

---

## PoC mapping (see `CORS/pocs/`)

- `xhr_with_credentials.html`: basic credentialed XHR read + exfil.
- `null_origin_iframe.html`: sandboxed iframe PoC to force `Origin: null` and read.
- `fetch_reflection_test.html`: dynamic origin reflection tester.

---

## Reporting/mitigation

- Do not reflect arbitrary `Origin`. Maintain a strict allowlist of exact origins.
- Never combine `ACAC: true` with wildcard ACAO. Prefer tokens or server-side sessionless APIs for cross-origin usage.
- Restrict allowed methods/headers; explicitly enumerate only what’s needed.
- For `null` origin, deny unless a valid use-case is required.


