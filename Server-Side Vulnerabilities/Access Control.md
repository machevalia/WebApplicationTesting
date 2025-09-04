# Unprotected functionality
In some cases, sensitive functionality is concealed by giving it a less predictable URL. This is an example of so-called "security by obscurity". However, hiding sensitive functionality does not provide effective access control because users might discover the obfuscated URL in a number of ways.

Imagine an application that hosts administrative functions at the following URL:

https://insecure-website.com/administrator-panel-yb556
This might not be directly guessable by an attacker. However, the application might still leak the URL to users. The URL might be disclosed in JavaScript that constructs the user interface based on the user's role:

<script>
	var isAdmin = false;
	if (isAdmin) {
		...
		var adminPanelTag = document.createElement('a');
		adminPanelTag.setAttribute('href', 'https://insecure-website.com/administrator-panel-yb556');
		adminPanelTag.innerText = 'Admin panel';
		...
	}
</script>
This script adds a link to the user's UI if they are an admin user. However, the script containing the URL is visible to all users regardless of their role.

## Challenge
Delete users carlos from the Shop. 

In body of home page:

<script>
var isAdmin = false;
if (isAdmin) {
   var topLinksTag = document.getElementsByClassName("top-links")[0];
   var adminPanelTag = document.createElement('a');
   adminPanelTag.setAttribute('href', '/admin-2x1lau');
   adminPanelTag.innerText = 'Admin panel';
   topLinksTag.append(adminPanelTag);
   var pTag = document.createElement('p');
   pTag.innerText = '|';
   topLinksTag.appendChild(pTag);
}
</script>

# Parameter-based access control methods
Some applications determine the user's access rights or role at login, and then store this information in a user-controllable location. This could be:

- A hidden field.
- A cookie.
- A preset query string parameter.
The application makes access control decisions based on the submitted value. For example:

https://insecure-website.com/login/home.jsp?admin=true
https://insecure-website.com/login/home.jsp?role=1

This approach is insecure because a user can modify the value and access functionality they're not authorized to, such as administrative functions.

## Challenge
In shop, delete user Carlos by getting admin panel access. 
Logged in as wiener:peter and found that there is a cookie set "Admin:false". Changed to true and reloaded page to access the Admin Panel. 

# Horizontal privilege escalation
Horizontal privilege escalation occurs if a user is able to gain access to resources belonging to another user, instead of their own resources of that type. For example, if an employee can access the records of other employees as well as their own, then this is horizontal privilege escalation.

Horizontal privilege escalation attacks may use similar types of exploit methods to vertical privilege escalation. For example, a user might access their own account page using the following URL:

https://insecure-website.com/myaccount?id=123
If an attacker modifies the id parameter value to that of another user, they might gain access to another user's account page, and the associated data and functions.

Note
This is an example of an insecure direct object reference (IDOR) vulnerability. This type of vulnerability arises where user-controller parameter values are used to access resources or functions directly.

In some applications, the exploitable parameter does not have a predictable value. For example, instead of an incrementing number, an application might use globally unique identifiers (GUIDs) to identify users. This may prevent an attacker from guessing or predicting another user's identifier. However, the GUIDs belonging to other users might be disclosed elsewhere in the application where users are referenced, such as user messages or reviews.

## Challenge
In Blog, find the GUID of Carlos and then access his account by logging into your own and changing the ID parameter's value to his GUID.

# Horizontal to vertical privilege escalation
Often, a horizontal privilege escalation attack can be turned into a vertical privilege escalation, by compromising a more privileged user. For example, a horizontal escalation might allow an attacker to reset or capture the password belonging to another user. If the attacker targets an administrative user and compromises their account, then they can gain administrative access and so perform vertical privilege escalation.

An attacker might be able to gain access to another user's account page using the parameter tampering technique already described for horizontal privilege escalation:

https://insecure-website.com/myaccount?id=456

If the target user is an application administrator, then the attacker will gain access to an administrative account page. This page might disclose the administrator's password or provide a means of changing it, or might provide direct access to privileged functionality.

## Challenge
In Shop, log into your own account, change the user ID param to administrator to find the masked password is pre-filled in the password change field. Copy and then log into Admin to delete carlos. 

