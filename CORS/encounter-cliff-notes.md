Encounter Cliff Notes

- ACAO reflects Origin
  - `/accountDetails` responded with `Access-Control-Allow-Origin: <origin>`. From attacker origin, used XHR with `withCredentials=true` to read and exfiltrate API key.

- Trusted null origin
  - Server allowed `Origin: null`. Used sandboxed iframe `srcdoc` to force null origin and XHR’d sensitive endpoint with credentials, then beaconed out.

- Trusted insecure protocols + XSS delivery
  - Origin check trusted `http://` subdomains. Found reflected XSS on stock subdomain; injected CORS-stealing XHR payload there and delivered to victim to read main site API with creds.


