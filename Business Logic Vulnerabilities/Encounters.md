# Encounters

# Auth Bypass via encryption oracle
## Observations
- Stay logged in capability in the login page which sets a token. 
- Token is URL encoded
- Attempting to post with an invalid email address results in an error message that reflects the user input. 
-- The notification input is a reflection of the decoded notification cookie value which matches the format of the stay-logged-in cookie. 
-- Copying and pasting my stay-logged-in cookie value into the notification value decrypts the value of my stay-logged-in cookie. We should then be able to provide an arbitrary value to the email address input and get a valid cookie value from notification that can be used in the stay-logged-in value. 
```
administrator:<timestamp>
```
- Send this through and get an encrypted cookie but it is prepended with a text string for the notification.
-- The notification string is 23 characters long. I unencoded it and tried to remove that string but messed up and confirmed that we're looking for multiples of 16 with a server error that attempted to decrypt what I provided confirming a likely oracle padding attack. 
-- In reality it wasn't 23 characters that I needed to delete it was 32 because what I needed to do was resubmit the comment with the token value but prepend 9 characters to bring the padding at the beginning to 32 characters to make the token value a multiple of 16. Once I did that we're in business. Re-encode that value and submit it as my stay-logged-in value without the session token and we're in as Administrator. 

- References:
https://medium.com/@masjadaan/oracle-padding-attack-a61369993c86

