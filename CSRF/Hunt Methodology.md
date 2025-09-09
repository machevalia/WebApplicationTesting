### CSRF Hunt Methodology

Use only with explicit authorization. This is a question-driven flow to identify, validate, and exploit CSRF reliably, including modern SameSite interactions and weak header-based protections.

---

## Decision tree: question-driven CSRF hunting

1) Is the action state-changing and user-authenticated?
- Targets: profile/email/password changes, funds transfer, role/ACL changes, delete/disable, address/2FA, OAuth flows.
- If read-only or anonymous, CSRF impact may be limited.

2) How is the action invoked?
- HTTP method: GET, POST, PUT, DELETE, PATCH.
- Content type accepted: `application/x-www-form-urlencoded`, `multipart/form-data`, `text/plain` (preflight-safe) vs `application/json` (requires custom header → typically not CSRF-able unless CORS misconfig/JSONP).
- Supports method overrides like `_method=POST` on GET?

3) What auth and cookie settings apply?
- Is a session cookie required? Inspect `Set-Cookie`; note `SameSite` attribute values: Strict, Lax, None; Secure; HttpOnly.
- Any CSRF token in form or response (hidden field, header, meta)? Is it required on server?

4) What defenses are present and how are they validated?
- Token presence only? Token tied to user session/account? Token bound to a separate cookie (double-submit)?
- Origin/Referer validation? Is it strict (scheme+host match), presence-only, or broken substring match?
- Custom header checks (e.g., `X-Requested-With`) or JSON-only APIs (preflight)?

5) Choose validation path
- No visible defenses → attempt simple form or top-level GET navigation PoC.
- Token present → try: omit; reuse; stale; other user’s token; double-submit mismatch; token tied to wrong cookie.
- SameSite=Lax → leverage top-level GET navigation; method-override to POST if supported.
- SameSite=Strict → identify in-app client-side redirects or sibling-domain flows; or target flows that do not require cookies.
- Header-based defenses → strip or rewrite Referer via `<meta name="referrer">` or force unsafe-url with query padding; verify Origin handling.
- Cookie seeding via CRLF injection in reflected header endpoints to control CSRF helper cookies.
- OAuth login refresh → induce user interaction, open login in a popup, then submit CSRF after refresh.
- WebSockets (CSWSH) → if cookies sent and no Origin check, establish socket and perform actions or exfiltrate messages.

6) Confirm exploitability and impact
- Execute with auto-submit PoC; verify state change on victim account.
- Rate/UX considerations: add minimal interaction if required (click).
- Prefer OAST beacons for silent confirmation if UI feedback is absent.

---

## Validation steps and quick checks

- Token presence test: remove CSRF token; does the request still succeed?
- Token reuse test: replay same token; does it work multiple times?
- Cross-user token test: take token from user A, submit as user B; does it work?
- Double-submit consistency: does server only check equality of header/cookie, without tying to session? Try setting both to arbitrary identical value.
- Origin/Referer checks:
  - Remove Referer via `<meta name="referrer" content="no-referrer">`.
  - Force full Referer via `<meta name="referrer" content="unsafe-url">` and append target URL in current page query.
  - Test malformed or sibling hostnames if substring checks are used.
- SameSite behavior:
  - Lax allows cookies on top-level GET navigation; craft GET-based CSRF or GET + `_method=POST`.
  - Strict blocks cross-site cookies in subresources and navigations; look for app-induced redirects that re-originate on the first-party domain.
- Content types:
  - Prefer `application/x-www-form-urlencoded`, `multipart/form-data`, `text/plain` for preflight-free cross-site POSTs.
  - JSON APIs typically require custom headers, blocking CSRF unless CORS is misconfigured.
- Cookie seeding (CRLF): if any reflected header endpoints (e.g., search) exist, inject `Set-Cookie:` lines to seed helper cookies (e.g., csrfKey/duplicate CSRF), then submit the CSRF form.

---

## PoC selection guide (map to files under `CSRF/pocs/`)

- Basic POST form auto-submit → `post_autosubmit.html`
- Basic GET (top-level) → `get_top_nav.html`
- Script SRC GET (for sites tolerating GET without CSRF) → `script_src_get.html`
- Method override (`_method=POST`) → `method_override_get.html`
- Referer stripping (presence required) → `referrer_no_referrer.html`
- Referer broken validation (substring) → `referrer_unsafe_url.html`
- Cookie seed then submit (CRLF) → `cookie_seed_then_submit.html`
- OAuth refresh then submit (requires click) → `oauth_click_then_submit.html`
- WebSocket exfil (CSWSH) → `websocket_csrf_exfil.html`

---

## Reporting/mitigation reminders

- Require per-request CSRF tokens tied to user session and rotated.
- Verify Origin and/or Referer strictly (full scheme+host) on state-changing requests.
- Enforce `SameSite=Strict` for session cookies where feasible; consider `Lax` tradeoffs.
- Reject method overrides for sensitive endpoints; restrict to same-origin.
- Avoid accepting `text/plain`/`multipart/form-data` for JSON-only APIs; require custom headers and enforce CORS.
- Prevent CRLF/header injection; sanitize reflected headers; set robust response headers.
- For WebSockets, validate Origin and require explicit CSRF token or reauth handshake.


