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

# Use a low-level logic flaw to purchase an item for less than its normal price. 
- There is a mathematical logicflaw on the back-end that has a recrusive number issue where if enough jackets are added to the cart eventually the numbers rotate through a negative number set and the entire possible positive number set. 
- The price has exceeded the maximum value permitted for an integer in the back-end programming language (2,147,483,647). As a result, the value has looped back around to the minimum possible value (-2,147,483,648).
- Have to find the number of jackets that ends up causing the value to be within out $100 credit. Numerically, it could be somewhere around 370
-- Did this with a value of 99 items in the cart in intruder with a null payload. 
- Doing this we can get it to $115 but we can't get within 0-100 so what I can do is add enough to get into a negative space and then add another item for a positive value. 

# Insufficient workflow validation
- Can purchase a small item with funds to get the confirmation parameter set to true which is what validates the purchase, not the actual funds in your account. 

# Auth bypass via flawed logic in role selection. 
- Upon logging in users are allowed to select role, via discovery there is an /admin panel. 
- Cannot set yourself to admin via a hidden role so instead, drop the request to find that we can default to admin if you don't select a low-level role. 

# Weak password change functionality with flawed validation
- The application allows users to specify a user during password change and does not validate the username is tied to the session token and doesn't validate that the currentpassword param is provided.





