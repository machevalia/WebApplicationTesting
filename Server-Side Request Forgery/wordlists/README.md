### SSRF Wordlists

Use these lists to probe SSRF sinks. Replace placeholders like internal-server and {domain} as needed.

Files
- internal-services.txt: localhost and internal network service targets and common ports.
- cloud-metadata.txt: AWS/GCP/Azure metadata endpoints (with required headers where applicable).
- protocol-smuggling.txt: file:// and gopher:// examples.
- url-bypasses.txt: encodings, IPv4/IPv6 representations, domain tricks.
- redirects.txt: attacker-controlled redirect patterns.
 - headers.txt: headers to probe as SSRF sinks; includes GCP metadata header.
 - blind-oob.txt: collaborator/OOB endpoints for blind SSRF.
 - admin-paths.txt: common internal admin endpoints to append.

Notes
- For GCP metadata, include header `Metadata-Flavor: Google` when required.
- Use the target’s HTTP client behavior to your advantage (redirects, DNS rebind, protocol downgrades).
 - Some filters block keywords like `admin`; try double-encoding characters (e.g., `%2561dmin`).

