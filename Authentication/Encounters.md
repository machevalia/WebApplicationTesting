# Encounters

# Username enum via different responses
Find a valid username and password. 
## Observations
- Login page tells you if the username is invalid or if the password is wrong. 
- Using intruder cluster bomb with follow redirects we can find the valid username and password. 
- While the attack is running we can see 'an' is the right user because her response size is different it can be seen in the response that it says "incorrect password". 
- Now I could have done snipers and just done users first then passwords which would have probably been a bit more efficient. 
- an:amanda. 

# 2FA Bypass
Get access to Carlos' account.
## Observations
- There are two login prompts login and login2. Login is the username and password which actually authenticates you and sets a session token. login2 validates your 2fa code but doesn't change any session information. 
- You can simply login (login not login2) and then navigate manually to my-account. 

# Password reset logic is broken
Get access to carlo's account.
## Observations
- Password reset uses username in the form to reset password and the reset token can be reused. 
- Simply change to carlos and reset his password:
```
temp-forgot-password-token=e0kss16k5qur6w5z72ssmu1q14sg3ehj&username=carlos&new-password-1=peter&new-password-2=peter
```

# Username enumeration via subtly different responses
Get acccess an account. 
## Observations
- Nothing unusual after a first round of intruder with the username list provided. 
- Grep extract the error finds that the username 'argentina' doesn't have a period at the end of the warning. 
- Set up a sniper attack again with the password list and follow redirects with cookie processing and found 'daniel' is the password. 

# Username enumeration based on timing. 
## Observations
- Did a straight sniper attack - found that certain users take almost 2 seconds for a response whereas most are a little over a second. 
- You can get locked for too many password attempts. 
- Param miner identified x-forwarded-for header so we may be able to bypass that by simply providing a rotating list of IPs. 
- Added the x-forwarded-for header, lengthened the password to increase potential processing time and redid the users. (Pitchfork)
- This resulted in a very long (4 second) response for 'application'.
- Reran to target the password and found 'taylor'. 

