Encounter Cliff Notes

- Basic SSRF to localhost
  - Stock checker accepted URL. Targeted `127.0.0.1` to reach admin, navigated internal links to delete user.

- Blind SSRF via header
  - No obvious URL param; Referrer header triggered server-side requests. Confirmed with collaborator.

- Blacklist bypass
  - `127.0.0.1` blocked; used `127.1`. Blocklist on path keyword `admin` bypassed via double-URL-encoding: `%2561dmin`.

- SSRF via open redirect
  - Found open redirect endpoint. Pointed stock checker to it with `path=http://internal/admin/delete?username=carlos` to pivot to internal host.


