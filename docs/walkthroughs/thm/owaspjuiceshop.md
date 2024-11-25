---
title: OWASP Juice Shop
desc: >-
  THM: This room uses the Juice Shop vulnerable web application to learn how to
  identify and exploit common web application vulnerabilities.
---
## Introduction

This room looks at [OWASP's Top 10 Vulnerabilities](https://owasp.org/www-project-top-ten/) in web applications. The intent of this room is not to cover every topic but the following topics will be covered.
  - Injection
  - Broken Authentication
  - Sensitive Data Exposure
  - Broken Access Control
  - Cross-Site Scripting (XSS)

## Task 1 - Open for Business!
Nothing specific to do in this task other than starting the machine and ensuring Burp Suite is properly configured.

## Task 2 - Let's Go on an Adventure!
Before getting into vulnerabilities in the web application, let's have a look around the application. This is called walking through the application which is a form of reconnaissance. 

#### Question 1:
The reviews on the product cards show user emails. The admin email address (`admin@juice-sh.op`)can be found by checking the review section on the Apple Juice (1000ml) product card.

![Admin Email](../../assets/images/thm/owaspjuiceshop/01%20-%20Admin%20Email.png)

#### Question 2:
The search parameter (`q`) can be found by clicking on the magnifying glass to expand the search bar and searching some text.

![Search Parameter](../../assets/images/thm/owaspjuiceshop/02%20-%20Search%20Parameter.png)

#### Question 3:
To find the show referenced by Jim, we need to look at the review he left for the Green Smoothie product.

![Jim's Show Reference](../../assets/images/thm/owaspjuiceshop/03%20-%20Jim%20Show%20Reference.png)

Replicator is a reference to Star Trek.

## Task 3 - Inject the Juice
This task will be focusing on injecting vulnerabilities in the the web application. Injection vulnerabilities are extremely dangerous and can lead to downtime and/or loss of data. 

First step to injection is identifying injection points within the web application. Most injection points will typically return some sort of an error. Although there are many types of injection attacks, the following are the most common.
  - **SQL Injection** - SQL injection attacks requires an attacker to enter a malicious or malformed SQL query to either tamper with or retrieve data from a database. SQL injection can also be used to log into accounts if inputs are not properly sanitized and parameterized queries are not used.
  - **Command Injection** - Command injection occurs when an a web application takes input or user-controlled data and runs them as a system command. An attacker may tamper with this data to execute their own system commands. This can be seen in applications that perform misconfigured ping tests.
  - **Email Injection** - Email injection is a security vulnerability that allows malicious users to send email messages without prior authorization by the email server. These occur when the attacker adds extra data to fields which are not interpreted by the server correctly.

The exercises in this task will utilize SQL injection techniques.

#### Question 1: Log into the administrator account!
To begin, let's enable Intercept in Burp Suite and ensure that our browser is configured with the correct proxy. Capture the request made by the login page with random data in the email and password field.

![Burp Intercept - Account Login](../../assets/images/thm/owaspjuiceshop/04%20-%20Account%20Login%20Burp%20Intercept.png)

Let's modify the email data with the malicious SQL query: `' or 1=1;--`

Let's assume the backend SQL query looks like something like the following:

```sql
SELECT * FROM users WHERE username = '$username' AND password = '$password';
```
The malicious entry will result in a modified query as follows:

```sql
SELECT * FROM users WHERE username = '' OR 1=1;-- AND password = '$password';
```
Since the statement `1=1` is always true, the whole statement becomes true. Note that the password portion of the query is commented out due to `--` which is denotes comment in several SQL syntaxes. As a result, the authentication check is bypassed and the server logs us into `user id 0`, which happens to be the administrator account.

This query is always true and if proper measures are not taken in the backend will allow us to bypass authentication completely.

![Account Login Bypass](../../assets/images/thm/owaspjuiceshop/05%20-%20Account%20Login%20Bypass.png)

Forward the request in Burp Suite to exploit the vulnerability.

![Successful Admin Account Login](../../assets/images/thm/owaspjuiceshop/06%20-%20Admin%20Account%20Login%20Success.png)

![Admin Login](../../assets/images/thm/owaspjuiceshop/07%20-%20Admin%20Login.png)

Retrieved Flag: `32a5e0f21372bcc1000a6088b93b458e41f0e02a`

#### Question 2: Log into the Bender Account
In this challenge, we are asked to log into Bender's account. To facilitate this, we are provided with Bender's email address: `bender@juice-sh.op`

We can achieve this by following the similar technique as the previous challenge but instead using the payload `' or 1=1;--` which logs us into admin's account (User ID 0), we will instead use the payload `bender@juice-sh.op';--`. Since we know that email address exists, we do not need to provide an always true condition since our payload will result in a true condition regardless. Because we know that the login form is susceptible to SQLi form the previous challenge, our payload will allow us to bypass authentication check for Bender's account and log us in.

![Bender's Login Form Payload](../../assets/images/thm/owaspjuiceshop/08%20-%20Bender%20Login%20Form.png)

![Bender's Flag](../../assets/images/thm/owaspjuiceshop/09%20-%20Bender%20Flag.png)

![Successful Login in Bender's Account](../../assets/images/thm/owaspjuiceshop/10%20-%20Bender%20Account%20Login%20Success.png)

Retrieved Flag: `fb364762a3c102b2db932069c0e6b78e738d4066`

## Task 4 - Who Broke My Lock?!
In this task, we will be exploiting authentication through the following flaws:
  - Weak passwords in high privileged accounts
  - Forgotten password pages

#### Question 1 - Bruteforce the Administrator Account's Password!
In the previous task, we logged into the administrator account without knowing the password. In this challenge, we are asked to determine the administrator account's password. Let's brute-force the password. We can accomplish this by using the Intrude feature of Burp Suite.

With the browser configured with Burp proxy, let's capture a login request for the administrator account using Burp Suite Intercept.

![Admin Login Intercept](../../assets/images/thm/owaspjuiceshop/11%20-%20Admin%20Brute-Force%20Intercept.png)

Right-click and send to Intruder. Clear all payload markers and delete the data in the password field. Add two payload makers in the password data field as indicated below.

![Admin Brute-Force Intruder](../../assets/images/thm/owaspjuiceshop/12%20-%20Admin%20Brute-Force%20Intruder.png)

Under the `Payloads` tab, ensure that `Simple List` is selected as a payload type. Under the `Payload Options` load the `best1050.txt` list from Seclists (located at: /usr/share/seclists/Passwords/Common-Credentials/best1050.txt).

When ready, click `Start attack` to begin brute-forcing the password. Failed attempts at the login will return a `401 Unauthorized` status while a successful request will return a `200 OK` status.

![Admin Password Brute-Forced](../../assets/images/thm/owaspjuiceshop/13%20-%20Admin%20Brute-Force%20Password.png)

Credentials Found: `admin@juice-sh.op:admin123`

Let's use the above credentials to log into the administrator's account.

![Admin Password Login](../../assets/images/thm/owaspjuiceshop/14%20-%20Admin%20Brute-Force%20Login.png)

![Admin Password Login Flag](../../assets/images/thm/owaspjuiceshop/15%20-%20Admin%20Brute-Force%20Flag.png)

![Admin Password Login Successful](../../assets/images/thm/owaspjuiceshop/16%20-%20Admin%20Brute-Force%20Login%20Success.png)

Retrieved Flag: `c2110d06dc6f81c67cd8099ff0ba601241f1ac0e`

#### Question 2 - Reset Jim's Password!
In this challenge, we will be exploiting the password reset mechanism present in many web applications. This method of exploitation often requires Social Engineering and OSINT to fool the application into thinking that an attacker is the legitimate user requesting a password reset.

Let's click on the `Forgot your password?` link on the Login form. Entering Jim's email into the Email field yields a Security Question: `Your eldest siblings middle name?`

From Task 2, we determined that Jim has an affinity to Star Trek. This might be a good start. In the original Star Trek series, the James Tiberius Kirk, played by William Shatner, was often called Jim by his crew members. Searching for Captain Kirk's family tree reveals that he had an older brother named `George Samuel Kirk`. 

Let's use `Samuel` as the answer to the security question and `pass123` as the new password.

![Jim's Password Reset Attempt](../../assets/images/thm/owaspjuiceshop/17%20-%20Jim%20Password%20Reset%20Attempt.png)

![Jim's Password Reset Successful](../../assets/images/thm/owaspjuiceshop/18%20-%20Jim%20Password%20Reset%20Success.png)

![Jim's Password Reset Flag](../../assets/images/thm/owaspjuiceshop/19%20-%20Jim%20Password%20Reset%20Flag.png)

Retrieved Flag: `094fbc9b48e525150ba97d05b942bbf114987257`

## Task 5 - AH! Don't Look!
Developers must ensure that their web application stores and transmits data safely and securely. If data protection is not applied consistently across the web application, it can make sensitive resources accessible to the public leading to sensitive data exposure.

#### Access the Confidential Document
Under the `About Us` section of the web application, we notice that the developer has linked a file containing the company's terms and conditions (`http://$MACHINE_IP/ftp/legal.md`).

Playing around with the URL, we notice that the developer has violated the principle of least privilege or deny by default. As a result, we are able to bypass access control checks by modifying the URL to gain unauthorized access to sensitive information.

We can view the contents of the `ftp` directory by navigating to `http://$MACHINE_IP/ftp`.

![Unauthorized Access](../../assets/images/thm/owaspjuiceshop/20%20-%20Unauthorized%20Access.png)

Let's download the the `acquisitions.md` document and navigate back to the homepage to retrieve the flag.

![Unauthorized Access Flag](../../assets/images/thm/owaspjuiceshop/21%20-%20Unauthorized%20Access%20Flag.png)

Retrieved Flag: `edf9281222395a1c5fee9b89e32175f1ccf50c5b`

#### Question 2 - Log into MC SafeSearch's Account!
In this challenge, we are asked to log into MC SafeSearch's account. We are provided a link to a video and are told that the the password is mentioned somewhere in the video. We are provided the email address: `mc.safesearch@juice-shop.op`

Video Link: `https://www.youtube.com/watch?v=v59CX2DiX0Y&t=116s`

In one of the verses, MC SafeSearch states that his password is the name of his dog `Mr. Noodles` with some of the vowels replaced with zeroes. The most probable password then is `Mr. N00dles`.

Let's try and login with credentials: `mc.safesearch@juice-sh.op:Mr. N00dles`

![MC SafeSearch Login Attempt](../../assets/images/thm/owaspjuiceshop/22%20-%20MC%20SafeSearch%20Login.png)

![MC SafeSearch Flag](../../assets/images/thm/owaspjuiceshop/23%20-%20MC%20SafeSearch%20Flag.png)

Retrieved Flag: `66bdcffad9e698fd534003fbb3cc7e2b7b55d7f0`

#### Question 3 - Download the Backup File!
In this challenge, we are asked to download the `package.json.bak` file. However, when attempting to download the file, we get a `403 Error: Only .md and .pdf files are allowed!`.

![Restricted File Download Error](../../assets/images/thm/owaspjuiceshop/24%20-%20Restricted%20Download%20Error.png)

We can bypass this restriction by using a character bypass technique called [Poison Null Byte](https://www.thehacker.recipes/web/inputs/null-byte-injection) (see also [Embedding Null Code](https://owasp.org/www-community/attacks/Embedding_Null_Code)). Poison Null Byte bypass relies on injecting a null byte character (`%00`, `\00`) to bypass file access restrictions. The Null Byte is actually a NULL terminator which when placed in a string at a certain byte tells the server to terminate at that point thereby nulling the rest of the string.

Note that when injecting a Null Byte into a URL, the Null Byte will need to be encoded into a URL encoded format (`%00 = %2500`, `\00 = %5C00`).

Let's modify the URL string as follows: `http://$Machine_IP/ftp/package.json.bak%2500.pdf`

When the modified request is passed to the server, the server will terminate the string before the injected Null Byte and ignore everything afterwards; thus allowing us to bypass the file extension filter and download the desired file.

![Restricted File Download Success](../../assets/images/thm/owaspjuiceshop/25%20-%20Restricted%20Download%20Success.png)

![Restricted File Download Flag](../../assets/images/thm/owaspjuiceshop/26%20-%20Restriced%20Download%20Flag.png)

Retrieved Flag: `bfc1e6b4a16579e85e06fee4c36ff8c02fb13795`

## Task 6 - Who's Flying This Thing?
Modern web applications allow for multiple users to have access to different pages through access control. When Broken Access Control vulnerabilities are found, they are typically categorized in one of the two following types:
  - **Horizontal Privilege Escalation** - Occurs when a user can perform an action or access data from another user with the same level of permissions.
  - **Vertical Privilege Escalation** - Occurs when a user can perform an action or access data of another user with a higher level of permissions.

![Broken Access Control Overview](../../assets/images/thm/owaspjuiceshop/27%20-%20Broken%20Access%20Control.png)

#### Question 1 - Access the Administrator Page!
In this challenge, we are tasked to find the administrator page for the Juice Shop. We can try using Feroxbuster or Gobuster however the challenge hints that the path to the administrator page is somewhere in the source.

Let's open up debugger and look at all the sources the page is loading. Looking through `main-es2015.js` and searching for the term `admin` we find what looks to be a path to an admin portal.

![Admin Page Search](../../assets/images/thm/owaspjuiceshop/28%20-%20Admin%20Page.png)

Trying to access the page at `http://Machine_IP/#/administration` we receive a `403 Forbidden` error before being redirected back to the main page. It is possible that the page is only accessible to individuals with appropriate permissions. Let's try accessing the page when logged in as the administrator.

Use the admin credentials found previously (`admin@juice-sh.op:admin123`) to log in. Access the admin portal via the link above once logged in to solve the challenge.

![Admin Page URL](../../assets/images/thm/owaspjuiceshop/29%20-%20Admin%20Page%20URL.png)

![Admin Page Flag](../../assets/images/thm/owaspjuiceshop/30%20-%20Admin%20Page%20Flag.png)

Retrieved Flag: `946a799363226a24822008503f5d1324536629a0`

#### Question 2 - View Another User's Shopping Basket!
In this challenge, we are tasked with viewing another user's basket while not signed in as the target user.

Open Burp Suite and configure the web browser to Burp Proxy. Enable Intercept and while logged in as another user (for example as the administrator from the previous challenge) click on the `Your Basket` and capture the request (you may need to forward a few requests until you see the following request).

![View Another Basket Request](../../assets/images/thm/owaspjuiceshop/31%20-%20View%20Another%20Basket%20Request.png)

Looks like the application makes a GET request to retrieve a user's basket. We can modify the request as shown below to view another user's basket.

![View Another Basket Request Modified](../../assets/images/thm/owaspjuiceshop/32%20-%20View%20Another%20Basket%20Request%20Modify.png)

Forward the modified request to solve the challenge.

![View Another User's Basket](../../assets/images/thm/owaspjuiceshop/33%20-%20View%20Another%20Basket.png)

![View Another User's Basket Flag](../../assets/images/thm/owaspjuiceshop/34%20-%20View%20Another%20Basket%20Flag.png)

Retrieved Flag: `41b997a36cc33fbe4f0ba018474e19ae5ce52121`

#### Question 3 - Remove All 5-Star Reviews!
In this challenge, we are asked to remove all 5-Star reviews left by the users of the Juice Shop. To do this, we need to revisit the `administration` page and click on the bin icon next to the reviews to remove them.

![Delete Reviews](../../assets/images/thm/owaspjuiceshop/35%20-%20Delete%20Reviews.png)

![Delete Reviews Flag](../../assets/images/thm/owaspjuiceshop/36%20-%20Delete%20Reviews%20Flag.png)

Retrieved Flag: `50c97bcce0b895e446d61c83a21df371ac2266ef`

## Task 7 - Where Did That Come From?
In this task, we will be looking at Cross-site scripting (or XSS). XSS vulnerability allows an attacker to run javascript in web applications. Other than SQLi, XSS vulnerabilities are some of the most common bugs with web applications.

There are three major types of XSS attacks:

  - **DOM (Special)** - DOM XSS (Document Object Model-based Cross-site Scripting) uses the HTML environment to execute malicious javascript. These type of attacks commonly use the `<script></script> HTML tags.
  - **Persistent (Server-side)** - Persistent XSS is javascript that is run when the server loads the page containing it. These can occur when the server does not sanitize the user data when it is uploaded to a page. These are commonly found on blog posts and message boards.
  - **Reflected (Client-side)** - Reflected XSS is javascript that is run on the client-side end of the web application. These are most commonly found when the server doesn't sanitize search data.

#### Question 1 - Perform a DOM XSS!
In this challenge, we are asked to perform a DOM XSS attack. As per the requirements, we will be using iframe element with javascript alert tag: 

```html
<iframe src="javascript:alert(`XSS`)">
```

Note that the iframe being used is a common HTML element found in many web applications though there are other variants which also produce the same result. This type of XSS is also called Cross-Frame Scripting (XFS) and is one of the most common forms of detecting XSS within web applications. Web applications that allow the user to modify the iframe or other DOM elements will most likely be vulnerable to XSS.

![DOM XSS Payload](../../assets/images/thm/owaspjuiceshop/38%20-%20DOM%20XSS%20Payload.png)

![DOM XSS](../../assets/images/thm/owaspjuiceshop/37%20-%20DOM%20XSS.png)

![DOM XSS Flag](../../assets/images/thm/owaspjuiceshop/39%20-%20DOM%20XSS%20Flag.png)

Retrieved Flag: `9aaf4bbea5c30d00a1f5bbcfce4db6d4b0efe0bf`

#### Question 2 - Perform a Persistent XSS!
In this challenge, we are asked to perform a Persistent XSS attack. To do this, we are first asked to log into the admin account and navigate to the `Last Login IP` page for this attack. THis page logs the last login IP address. To continue, we will need to use Burp Suite.

Let's capture a logout request so that our IP address can<> be logged. Open the Inspector panel and expand the Request Headers section. Add the following new header: 

```html
True-Client-IP:<iframe src="javascript:alert(`XSS`)">
```

When signing back into the admin account and navigating to the `Last Login IP` page, the XSS alert is displayed.

![Persistent XSS Payload](../../assets/images/thm/owaspjuiceshop/40%20-%20Persistent%20XSS.png)

![Persistent XSS Popup](../../assets/images/thm/owaspjuiceshop/41%20-%20Persistent%20XSS%20Popup.png)

![Persistent XSS Flag](../../assets/images/thm/owaspjuiceshop/42%20-%20Persistent%20XSS%20Flag.png)

Retrieved Flag: `149aa8ce13d7a4a8a931472308e269c94dc5f156`

#### Question 3 - Perform a Reflected XSS!
In this challenge, we are asked to perform a reflected XSS. To do this, let's navigate to the `Order History` page in the admin account. Here we see a *Truck* icon which when clicked-on will bring us to the track result page. On this page, we are presented with an ID paired with an order.

![Reflected XSS ID](../../assets/images/thm/owaspjuiceshop/43%20-%20Reflected%20XSS%20ID.png)

Substituting the ID `5267-cb88c5750e5e4b5f` with:

```html
<iframe src="javascript:alert(`XSS`)">
```
Submitting the request will trigger the XSS. You may need to hard refresh the page for the pop-up to occur.

![Reflected XSS](../../assets/images/thm/owaspjuiceshop/44%20-%20Reflected%20XSS.png)

![Reflected XSS Flag](../../assets/images/thm/owaspjuiceshop/45%20-%20Reflected%20XSS%20Flag.png)

Retrieved Flag: `23cefee1527bde039295b2616eeb29e1edc660a0`

## Task 8 - Exploration
Navigating to the `http://Machine_IP/#/score-board/` page we can retrieve the final flag required to complete the room. However, there are many other vulnerabilities on the web application which we can explore and attempt to exploit at this point or in the future.

![Exploration](../../assets/images/thm/owaspjuiceshop/46%20-%20Exploration.png)

Retrieved Flag: `7efd3174f9dd5baa03a7882027f2824d2f72d86e`