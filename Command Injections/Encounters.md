# Encounters

# OS command injection, simple case
whoami
## Observations
- Stock checker
- Threw a single quote into the productId parameter and it threw an error of unterminated string. 
- appended ```;whoami``` and get the error with the username prepended to the error. 
Request:
```
productId=7;whoami&storeId=1
```
Response:
```
/home/peter-guYDc6/stockreport.sh: line 5: $2: unbound variable
whoami: extra operand '1'
Try 'whoami --help' for more information.
```

# Blind OS command injection with time delays
Sleep the response for 10 seconds. 
## Observations
- there is a feedback form. 
- Tried session token, URL params, and now form fields. 
- Found that ```$(sleep 10)``` does the trick in the email field. 

# Blind OS command injection with output redirection
Output whoami to /var/www/images/
## Observations
- Same feedback form.
- Just need to write to a file. 
```
t$(whoami+>>+/var/www/images/whoami.txt)
```
- Then get the results from images?filename=whoami.txt

# Blind OS command injection with out-of-band interaction
Get OOB interaction
## Observations
- Initially, does not seem to be the feedback form again. 
- Turns out I was messing up the payloads - I needed to avoid URL encoding them in Intruder and also re-order my payloads with DNS lookups because they need time to parse so I moved them higher in the list and also add a 2 second delay between requests to give Intruder plenty of runtime for the OOB DNS look ups to finish. 
- Multiple of my OOB payloads worked. I added the right marker in the list {domain} so I could add a collaborate match & replace rule in Intruder for easy collabs. 

# Blind OS command injection with out-of-band data exfiltration
Submit user's name. 
## Observations
- Just ran my custom payload list with no URL encoding, match and replace on {domain}, and a 200ms delay. 

