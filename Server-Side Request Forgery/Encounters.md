# Encounters

# Basic SSRF against the local server
Get to localhost and delete carlos. 
## Observations
- Stock check function uses URL
- 127.0.0.1 works to get page and includes logged in admin panel.
- Navigating through the links until I find the delete user option 

# Blind SSRF with out-of-band detection
- Only one param for product ID I can find. It may be a header or something else though so I am running param miner. 
- The referrer header works - it requests http/dns lookups when that is changed. 


# SSRF with blacklist-based input filter
Delete carlos
- 127.0.0.1 doesn't work. 
- 127.1 does work but /admin doesn't. Thought it was the backslashes but they're trying to block admin by blacklisting a. Double URL encoding it worked.  
```
stockApi=http%3A%2F%2F127.1/%2561dmin/delete?username=carlos
```

# SSRF with filter bypass via open redirection vulnerability
- Open redirect - 
```
GET /product/nextProduct?currentProductId=2&path=fwfgoz78yfewz8kcded4mf0l6cc30uvik.oastify.com HTTP/2
```
- Delete user carlos using this path:
```
stockApi=/product/nextProduct?path=http://192.168.0.12:8080/admin/delete?username=carlos
```

