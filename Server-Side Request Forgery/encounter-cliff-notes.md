Encounter Cliff Notes

- Basic SSRF to localhost
  - Stock checker accepted URL. Targeted `127.0.0.1` to reach admin, navigated internal links to delete user.

- Blind SSRF via header
  - No obvious URL param; Referrer header triggered server-side requests. Confirmed with collaborator.

- Blacklist bypass
  - `127.0.0.1` blocked; used `127.1`. Blocklist on path keyword `admin` bypassed via double-URL-encoding: `%2561dmin`.

- SSRF via open redirect
  - Found open redirect endpoint. Pointed stock checker to it with `path=http://internal/admin/` to pivot to internal host.

- SSRF via open redirect when localhost isn't available 
  - Make sure to scan the network internally - try 192.168.x.x 10.x for other hosts that may be more responsive to requests. E.g. `path=http://192.168.0.1:8080/admin/`


