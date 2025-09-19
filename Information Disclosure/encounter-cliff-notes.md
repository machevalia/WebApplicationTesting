Encounter Cliff Notes

- Error message leaks
  - Added `'` to parameter and read stack/version details to identify tech/version.

- Debug page exposed
  - Comment hinted `phpinfo.php`. Visited it and pulled secret key from output.

- Backup files accessible
  - Discovered `/backup`. Downloaded backup and found DB password.

- Auth bypass via IP header
  - TRACE revealed `X-Custom-IP-Authorization`. Setting `127.0.0.1` granted admin. Deleted user via admin panel.

- Version control history leak
  - Fetched `.git`, inspected history to recover credentials in previous commit config.


