Encounter Cliff Notes

- Username enumeration via responses
  - Login errors differed for bad user vs bad password. Used Intruder to find valid username, then password.

- 2FA bypass (split endpoints)
  - Primary login set a valid session at `/login`. Skipped `/login2` and browsed to `my-account` directly.

- Reusable password reset token
  - Reset flow accepted target username and reused token. Submitted token with `username=carlos` to set new password.

- Subtle copy change leaks valid user
  - One error lacked a period for valid users. Bruteforced password for that account.

- Timing-based enumeration with IP rotation
  - Response time slower for valid users. Bypassed lockout by rotating `X-Forwarded-For`. Found user, then password.

- Broken 2FA validation (bruteforceable)
  - Could brute the 2FA code at `/login2` within validity window after obtaining username/password.


