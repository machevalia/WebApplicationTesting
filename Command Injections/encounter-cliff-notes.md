Encounter Cliff Notes

- Simple OS command injection
  - Stock checker param was shell-concatenated. Appended `;whoami` to `productId` and saw execution in response.

- Blind with time delay
  - No output. Injected in feedback form email with `$(sleep 10)` and measured delay.

- Blind with output redirection
  - Wrote command output to web-readable path: `$(whoami >> /var/www/images/whoami.txt)`, then fetched the file.

- Blind with OOB interaction
  - Used collaborator DNS payloads without URL-encoding and added request delay. Observed callbacks to confirm execution.

- Blind with OOB exfiltration
  - Sent payloads that appended data to collaborator domain in DNS/HTTP to exfiltrate values.


