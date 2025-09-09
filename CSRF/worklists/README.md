### CSRF Wordlists and PoCs

Use these lists with the decision tree in `CSRF/Hunt Methodology.md`. Pair checklists with the matching PoC templates under `CSRF/pocs/`.

Lists
- checklist.txt: end-to-end questions to triage and validate CSRF.
- headers.txt: Origin/Referer/SameSite investigation aids and meta-referrer directives.
- same-site-bypasses.txt: techniques for Lax/Strict scenarios.

PoC templates (see `../pocs/`)
- post_autosubmit.html: classic POST form auto-submission.
- get_top_nav.html: top-level GET navigation.
- script_src_get.html: script-src GET trigger.
- method_override_get.html: GET with `_method=POST`.
- referrer_no_referrer.html: remove Referer header.
- referrer_unsafe_url.html: force full Referer with query padding.
- cookie_seed_then_submit.html: CRLF cookie seed + submit.
- oauth_click_then_submit.html: user click triggers OAuth refresh then submit.
- websocket_csrf_exfil.html: CSWSH exfil skeleton.

Notes
- Replace placeholders like TARGET_ORIGIN, PATH, and PARAMETERS per target.
- For cookie seeding, confirm a vulnerable reflected header sink first.

