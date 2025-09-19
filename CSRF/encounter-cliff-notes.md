Encounter Cliff Notes

- No CSRF defenses
  - Auto-submitting form changed victim email.

- Token validated only on POST
  - Changed request to GET with params; no token needed. Delivered via script tag.

- Token required to be present (but not validated)
  - Omitting token server-side still accepted. Sent form without token.

- Token not bound to session
  - Reused my valid token in victim’s request. Delivered via CSRF form.

- Token tied to separate cookie (csrfKey) → overwrite via cookie injection
  - Search reflected into `Set-Cookie`. Injected newline to set `csrfKey` for victim, then submitted CSRF with matching value.

- Double-submit cookie implementation broken
  - Overwrote `csrf` cookie via search cookie injection so cookie == form value. Submitted change.

- SameSite=Lax bypass via method override
  - Top-level GET navigation allowed with `_method=POST`. Used auto-submitting GET form with hidden `_method`.

- SameSite=Strict bypass via client-side redirect
  - Abuse redirect script to navigate into sensitive path with GET params that change email.

- SameSite=Strict bypass via sibling domain (CSWSH + XSS)
  - Opened WS to victim origin to receive chat data, then used XSS on sibling CMS domain to capture cookies/session flow and pivot.

- SameSite=Lax bypass via cookie refresh (OAuth)
  - Forced user interaction to open social-login, refresh session, then submitted CSRF shortly after.

- Referer required but only when present
  - Stripped Referer using meta policy. POST succeeded.

- Broken Referer validation (substring match)
  - Set policy to send full URL and added victim URL as query on attacker page so Referer contained expected substring.


