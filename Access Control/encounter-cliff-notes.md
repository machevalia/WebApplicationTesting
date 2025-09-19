Encounter Cliff Notes

- User role change via account update
  - Saw `roleid` in profile update response. Added `roleid=2` when updating email. Account became admin.

- IDOR on username
  - Changed target identifier to victim’s username in the request. Their API key and data returned.

- Username mismatch leaks data
  - Supplying another user in the URL showed their page briefly before a redirect. Captured data on the way out.

- URL-based control bypass via upstream header
  - Discovered `X-Original-URL` is honored. Set it to `/admin` while requesting `/`. Admin panel functions worked with normal query params.

- Method-based access controls are weak
  - Admin actions accept GET with action params (e.g., `action=upgrade`). Hitting the endpoint directly applies the change.

- Multi-step action missing server-side checks
  - Process could be replayed by adding `confirmed=true` with the right username. No session tie-in on confirmation.

- Referer-based access control
  - Server only checked that Referer contained `/admin`. Sending requests with that Referer and correct params allowed admin actions.


