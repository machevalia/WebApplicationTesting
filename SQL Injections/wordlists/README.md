### SQLi Wordlists

Purpose: Quick, targeted payload sets for detection, enumeration, and exploitation across SQLi techniques and DBMSs. Pair with `SQL Injections/DBMS Hunt Methodology.md` decision tree.

Lists
- detection-basic.txt: minimal breakers, boolean toggles, timing toggles (cross-DBMS variants).
- union-setup.txt: ORDER BY probes, NULL enumerations, printable-column tests.
- error-based.txt: type-cast, XML/arith errors per DBMS.
- blind-boolean.txt: length/ASCII probes with binary-search patterns per DBMS.
- blind-time.txt: conditional sleep payloads per DBMS.
- oob-dns.txt: DNS/HTTP exfil primitives per DBMS (use carefully).
- schema-enum.txt: information_schema/all_* queries per DBMS.
- dbms-fingerprint.txt: comment styles, concat variants, version/sleep primitives.
- unified_sqli_wordlist.txt: Intruder-ready consolidated list (Encounters + common payloads).

Context-to-list mapping
- Unknown behavior → detection-basic.txt, dbms-fingerprint.txt
- Reflected results → union-setup.txt → schema-enum.txt
- Verbose DB errors → error-based.txt
- Silent behavior → blind-boolean.txt or blind-time.txt
- OOB permitted → oob-dns.txt (after confirming safe to test)

Usage tips
- Always mirror quoting/parentheses and terminate with correct comment syntax for the DBMS.
- Prefer `NULL` for UNION type-compat.
- On Oracle, add `FROM dual` where needed.

Unified list (Intruder-ready)
- No labels or blank lines; one payload per line.
- URL-encoded variants included where helpful.
- Placeholders for quick replace in Burp Intruder:
  - `{table_name}`, `{column}`, `{column1}`, `{column2}`
  - `{where}` (e.g., username='administrator')
  - `{n}` numeric threshold; `{pos}` index; `{mid}` ASCII midpoint; `{ch}` character
  - `{expr}` inline SQL expression (e.g., SELECT password FROM users WHERE ...)
  - `{domain}` collaborator/controlled domain; `{collab}` collaborator host
  - `{json_field}`, `{key}`, `{regex}`, `{marker}`

Recommended flow
1) Fingerprint DBMS using dbms-fingerprint.txt.
2) Detect boolean/time behavior via detection-basic.txt.
3) If blind, use blind-boolean.txt or blind-time.txt; otherwise union-setup.txt → schema-enum.txt.
4) Switch to unified_sqli_wordlist.txt when you want breadth and Intruder-ready payloads in one place.

