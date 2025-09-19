Encounter Cliff Notes

- Basic traversal
  - Used `../../..` sequences in `filename` to fetch `/etc/passwd`.

- Absolute path allowed
  - Provided `/etc/passwd` directly (or `C:\Windows\win.ini` on Windows) to read file.

- Non-recursive strip bypass
  - Filter removed single `../`. Used `....//` repeated to reach target.

- Double-URL-decode bypass
  - Sent `%252e%252e%252f...` so server decoded twice, restoring `../`.

- Start-of-path validation bypass
  - Prefixed with expected base then traversed back: `/var/www/images/../../../etc/passwd`.

- Null byte extension bypass
  - Required `.jpg`. Appended `%00.jpg` after target path to satisfy extension check.


