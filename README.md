### Universal Web Application Hunt Methodology

Purpose: A question-driven, end-to-end workflow from first touch to exploitation and reporting. It integrates your per-vuln methodologies (XSS, SQLi, DOM, CSRF, CORS, XXE, SSTI, SSRF, Path Traversal, Command Injection) and ensures coverage.

---

## Phase 0 — Scoping and setup
- What’s in scope (hosts, APIs, mobile, third-party callbacks)?
- Allowed traffic types (auth, egress, destructive tests)?
- Credentials/roles available? Test accounts? OAST domain?

Artifacts to prepare: Burp project, Collaborator domain, wordlists from this repo, browser with extensions (DOM Invader), headless tools (param miner, content discovery), notes template.

---

## Phase 1 — External recon and mapping
- What endpoints exist? Crawl and dirbust: web root, `/api`, `/static`, backups, admin panels.
- What technologies? Fingerprint server/framework, CSP, cookies, headers.
- What inputs exist? Params, JSON bodies, forms, file uploads, cookies, headers, path segments, fragments.
- What roles/flows? Login, forgot password, OAuth flows, admin panels, webhooks.

Deliverable: Endpoint map with request prototypes and suspected sinks.

---

## Phase 2 — Parameter and header discovery
- Hidden parameters: Use Param Miner; brute candidate names based on frameworks.
- Header sinks: Try `X-Forwarded-Host`, `X-Original-URL`, `Referer` (SSRF/CSRF bypass), `Origin` (CORS), `Content-Type` switches.
- Cookies: Track values that reflect into DOM/HTML or server logic.

Deliverable: Parameter/header inventory and likely trust boundaries.

---

## Phase 3 — Client-side code review (DOM analysis)
- What sources feed the DOM? `location.*`, `postMessage`, storage, cookies.
- What sinks? `innerHTML`, `document.write`, attribute setters, `eval/new Function`, navigation.
- Are sanitizers used (DOMPurify/HTMLJanitor) and how can they be bypassed (attr clobbering, focus)?
- Any web messaging without origin checks? JSON.parse on attacker-controlled data?

Reference: `DOM Vulnerabilities/Hunt Methodology.md` and PoCs.

---

## Phase 4 — Server-side input testing (by context)

Ask for each endpoint/input:
- Is the response content or behavior influenced by my input? If yes, what context?
- Is data reflected raw (Reflected XSS), processed in templates (SSTI), concatenated into SQL (SQLi), used in filesystem paths (Traversal), executed by shell (CMDi), fetched server-side (SSRF), parsed as XML (XXE), or protected by CSRF/CORS?

Then follow the relevant methodology:
- XSS: See `XSS/Hunt Methodology.md` and wordlists.
  - For exploit-server delivery of final payloads (redirect/navigation pages), see `XSS/wordlists/exploit-delivery.txt` for ready-made templates with placeholders.
- REGEXSS (Regex-based XSS): See `XSS/REGEXSS Hunt Methodology.md`, `XSS/Regex XSS Cheatsheet.md`, and the new wordlists under `XSS/wordlists/regexss-*.txt`. A helper scanner lives at `XSS/tools/regexss_dom_scanner.py`.
- DOM: See `DOM Vulnerabilities/Hunt Methodology.md`.
- SQLi: See `SQL Injections/DBMS Hunt Methodology.md`.
- CSRF: See `CSRF/Hunt Methodology.md` and PoCs.
- CORS: See `CORS/Hunt Methodology.md` and PoCs.
- XXE: See `XXE/Hunt Methodology.md`.
- SSTI: Use `SSTI/wordlists/*` by engine.
- SSRF: See `Server-Side Request Forgery/Hunt Methodology.md` and wordlists.
- Path Traversal: See `Path Traversal/Hunt Methodology.md`.
- Command Injection: See `Command Injections/Hunt Methodology.md` and wordlists.

---

## Phase 5 — Auth, session, and access control
- Roles and privilege: Horizontal/vertical access checks; IDORs.
- Session handling: Cookie flags (HttpOnly, Secure, SameSite); session fixation; logout/rotation.
- CSRF protections: Tokens, origin/referrer validation, SameSite behaviors.

Reference: `CSRF/Hunt Methodology.md` and your encounters.

---

## Phase 6 — Egress, integrations, and supply chain
- SSRF egress: Can the app make requests to internal nets/metadata? (Use SSRF lists.)
- Webhooks and importers: URL filters, redirects, protocol smuggling.
- Third-party SDKs/widgets: CORS, token leaks, postMessage.

---

## Phase 7 — Chaining and escalation
- Can SSRF reach an admin panel that is path-traversable or vulnerable to SSTI?
- Can traversal expose config that enables SQLi or XXE endpoints?
- Can DOM clobbering enable XSS that steals CSRF tokens to change state?

Document chains with prerequisites and impact.

---

## Phase 8 — Validation, safety, and OAST
- Prefer safe proofs (delays, OAST pings) before destructive actions.
- Keep payloads minimal; respect scope; use temp files for any write tests.

---

## Phase 9 — Reporting and remediation
- For each issue: affected endpoints, payloads, conditions, impact, likelihood, and clear remediation tied to the relevant methodology.
- Include headers, CSP, and config improvements; suggest allowlists, canonicalization, prepared statements, safe APIs, strict origins.

---

## Quick checklists

Discovery
- Crawl + dirbust + API discovery
- Param Miner + hidden headers
- JS review for sources/sinks + secrets

Context tests (per input)
- Reflection → XSS/SSTI
- DB errors/timing → SQLi
- File reads/errors → Traversal
- Shell behavior/timing → CMDi
- Network egress/DNS hits → SSRF
- XML parsing/OOB → XXE
- Cross-origin headers → CORS
- State changes without token → CSRF

Tie-back: Use wordlists/PoCs under each folder for focused payloads and escalation paths.

---

## Encounter Cliff Notes

For each vulnerability area, see `encounter-cliff-notes.md` inside the corresponding folder for plain-language “how I found and exploited it” summaries distilled from your Encounters:
- `Access Control/encounter-cliff-notes.md`
- `Authentication/encounter-cliff-notes.md`
- `Business Logic Vulnerabilities/encounter-cliff-notes.md`
- `Clickjacking/encounter-cliff-notes.md`
- `Command Injections/encounter-cliff-notes.md`
- `CORS/encounter-cliff-notes.md`
- `CSRF/encounter-cliff-notes.md`
- `Deserialization/encounter-cliff-notes.md`
- `DOM Vulnerabilities/encounter-cliff-notes.md`
- `File Upload Vulnerabilities/encounter-cliff-notes.md`
- `Information Disclosure/encounter-cliff-notes.md`
- `Path Traversal/encounter-cliff-notes.md`
- `Request Smuggling/encounter-cliff-notes.md`
- `Server-Side Request Forgery/encounter-cliff-notes.md`
- `SQL Injections/encounter-cliff-notes.md`
- `SSTI/encounter-cliff-notes.md`
- `XXE/encounter-cliff-notes.md`

