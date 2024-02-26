---
title: John The Ripper
desc: >-
  THM:Learn how to use John the Ripper - An extremely powerful and adaptable
  hash cracking tool.
---
## Introduction

This room covers topics related to the use of John the Ripper to bruteforce hashes. Tasks 1, 2, and 3 cover basic background information on what John the Ripper is, how to install it, and the use of wordlists in conjunction with John to permit bruteforce attacks on hashes.

Hashes related to the following tasks are stored at: `/home/siachen/CyberSec/THM/johntheripper/`

## Cracking Basic Hashes

Basic John the Ripper syntax is as follows:

```text
john [options] [path to hash file]
```
John has a built in feature which detects what type of hash it is being given and as such selects the appropriate rules and formats to crack the provided hash. This can however be unreliable as it is better to supply the format (type) of the hash John is working with. Format-specific cracking can be done using the following syntax:

```text
john --format=[hash format/type] [path to hash file]
```
Tools such as `hashid`, `hash-identifier`, or online hash identifiers can be used to identify the hash. Both of these tools come installed by default on Kali Linux.

All supported hash formats can be listed out by using the following syntax:

```text
john --list=formats
```
Note that when dealing with a standard hash type like MD5, the hash format must be prefixed with `raw-` which tells John that the hash in question is a standard hash type.

Finally, John needs to be supplied with a wordlist with which it can bruteforce the hashes with. The syntax to supply a wordlist to John is as follows:

```text
john --wordlist=[path to wordlist] [path to hash file]
```
Putting the above together, a typical syntax when using John to crack hashes is given as follows:

```text
john --format=[hash format/type] --wordlist=[path to wordlist] [path to hash file]
```
With this knowledge, we can begin cracking some basic hashes.

### Question 1 - What type of hash is in hash1.txt?

Using an online [hash identifier tool](https://hashes.com/en/tools/hash_identifier) reveals the hash to be MD5.

### Question 2 - What is the cracked value of hash1.txt?

```text
┌──(siachen㉿kali)-[~/CyberSec/THM/johntheripper/task_four_hashes]
└─$ john --format=raw-md5 --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt hash1.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 128/128 AVX 4x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
biscuit          (?)     
1g 0:00:00:00 DONE (2023-02-28 21:40) 16.66g/s 44800p/s 44800c/s 44800C/s shamrock..nugget
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed. 
```
### Question 3 - What type of hash is hash2.txt?

Using the online hash identification tool, the most probable hash type is SHA1.

### Question 4 - What is the cracked value of hash2.txt?

```text
┌──(siachen㉿kali)-[~/CyberSec/THM/johntheripper/task_four_hashes]
└─$ john --format=raw-sha1 --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt hash2.txt
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA1 [SHA1 128/128 AVX 4x])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
kangeroo         (?)     
1g 0:00:00:00 DONE (2023-02-28 21:43) 10.00g/s 1171Kp/s 1171Kc/s 1171KC/s kangeroo..kalinda
Use the "--show --format=Raw-SHA1" options to display all of the cracked passwords reliably
Session completed.
```
### Question 5 - What type of hash is hash3.txt?

Verifying with online hash identification tool reveals most probable hash type is SHA256.

### Question 6 - What is the cracked value of hash3.txt?

```text
┌──(siachen㉿kali)-[~/CyberSec/THM/johntheripper/task_four_hashes]
└─$ john --format=raw-sha256 --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt hash3.txt
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA256 [SHA256 128/128 AVX 4x])
Warning: poor OpenMP scalability for this hash type, consider --fork=4
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
microphone       (?)     
1g 0:00:00:00 DONE (2023-02-28 21:48) 16.66g/s 1638Kp/s 1638Kc/s 1638KC/s rozalia..Dominic1
Use the "--show --format=Raw-SHA256" options to display all of the cracked passwords reliably
Session completed. 
```
### Question 7 - What type of hash is hash4.txt?

Using the online hash identification tool, the most likely hash type is Whirlpool.

### Question 8 - What is the cracked value of hash4.txt?

```text
┌──(siachen㉿kali)-[~/CyberSec/THM/johntheripper/task_four_hashes]
└─$ john --format=whirlpool --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt hash4.txt
Using default input encoding: UTF-8
Loaded 1 password hash (whirlpool [WHIRLPOOL 32/64])
Warning: poor OpenMP scalability for this hash type, consider --fork=4
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
colossal         (?)     
1g 0:00:00:00 DONE (2023-02-28 21:57) 2.000g/s 1359Kp/s 1359Kc/s 1359KC/s davist..chata1994
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```
## Cracking Windows Authentication Hashes
Windows authentication hashes are hashed versions of passwords that are stored by the operating system in a local Security Account Manager (SAM) database located in the Window's registry. In order to obtain these hashes, a user must be a privileged user on the Windows machine.

*NThash* is the hash format that modern Windows OS machines use to store user and service passwords. These hashes are commonly referred to as "NTLM" which references the previous version of Windows formats for hashing passwords known as "LM" and hench "NT/LM" or "NTLM".

NTLM hashes can be obtained by dumping the SAM database on a Windows machine but using a tool like *Mimikatz* or from the Active Directory Database: `NTDS.dit`. With these hashes, an attacker may not need to crack the hash to continue privilege escalation as it is often possible to conduct a "pass the hash" attack instead.

Let's look at cracking an example NTLM hash.

### Question 1 - What do we need to set the "format" flag to, in order to crack this?

In John, we need to set the hash format to NT.

### Question 2 - What is the cracked value of this password?

```text
┌──(siachen㉿kali)-[~/CyberSec/THM/johntheripper/task_five_hashes]
└─$ john --format=nt --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt ntlm.txt
Using default input encoding: UTF-8
Loaded 1 password hash (NT [MD4 128/128 AVX 4x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
mushroom         (?)     
1g 0:00:00:00 DONE (2023-02-28 22:10) 20.00g/s 61440p/s 61440c/s 61440C/s lance..dangerous
Use the "--show --format=NT" options to display all of the cracked passwords reliably
Session completed. 
```
## Cracking /etc/shadow Hashes
The `/etc/shadow` file is where Linux machines store their password hashes. The file also stores additional information such as the date of the last password change and password expiration information. The `/etc/shadow` file contains one entry per line for each user or user account on the system and is usually only accessible by the root user.

In order to crack `/etc/shadow` passwords, the file must be combined with the `/etc/passwd` file in order for John to understand the data it's being give. To do this, a tool called `unshadow` which is built into the John suite can be used. The syntax is as follows:

```text
unshadow [path to /etc/passwd] [path to /etc/shadow] > [output file]
```
Note that when using `unshadow`, one can either use the entire `/etc/passwd` and `/etc/shadow` file or use only the relevant line from each.

The output from `unshadow` can then be fed into John. Although a hash format doesn't need to be specified, it is good practice to provide the appropriate hash format of `--format=sha512crypt`.

Let's look at a practical example.

### Question 1 - What is the root password?

We don't need to use `unshadow` to combine the `/etc/passwd` file with `/etc/shadow` as the the hash file provided by the challenge has already done this step for us. All we need to do is crack the hash with John.

```text
┌──(siachen㉿kali)-[~/CyberSec/THM/johntheripper/task_six_hashes]
└─$ john --format=sha512crypt --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt etchashes.txt
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 128/128 AVX 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
1234             (root)     
1g 0:00:00:00 DONE (2023-02-28 22:25) 1.639g/s 2098p/s 2098c/s 2098C/s kucing..poohbear1
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
## Single Crack Mode
In the Single Crack Mode, John uses only the information provided in the username to try and work out possible passwords heuristically by slightly changing the letters and numbers contained within the username.

John uses a technique called word mangling thereby building it's own dictionary based on the information that it has been fed. By using a set of rules called "mangling rules" which define how it can mutate the word it started with, John is able to build a wordlist based off of relevant factors for the target it is trying to crack.

Single Crack Mode can be used with the following syntax:

```text
john --single --format=[hash format/type] [path to hash file]
```
Note that when using Single Crack Mode, the file format being provided to John needs to be modified by prepending the hash with the username that the hash belongs to. For example given a hash `1efee03cdcb96d90ad48ccc7b8666033` and a username `mike`, the file will need to be modified as `mike:1efee03cdcb96d90ad48ccc7b8666033`.

Let's put this into practice.

### Question 1 - What is Joker's password?

Let's start by modifying our hash file to include the username as required by the Single Crack Mode.

```text
┌──(siachen㉿kali)-[~/CyberSec/THM/johntheripper/task_seven_hashes]
└─$ cat hash7.txt
joker:7bf6d9bb82bed1302f331fc6b816aada
```
With the file modified, we can now use John in Single Crack Mode to crack the hash.

```text
┌──(siachen㉿kali)-[~/CyberSec/THM/johntheripper/task_seven_hashes]
└─$ john --single --format=raw-md5 hash7.txt                                                                     
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 128/128 AVX 4x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
Warning: Only 2 candidates buffered for the current salt, minimum 12 needed for performance.
Jok3r            (joker)     
1g 0:00:00:00 DONE (2023-02-28 22:38) 16.66g/s 3250p/s 3250c/s 3250C/s j0ker..J0k3r
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed. 
```
## Custom Rules
John allows users to create a custom set of rules to use with the Single Crack Mode which John can then use to dynamically create passwords. This is particularly useful when more information is known about the password structure of the target.

Custom rules are defined in the `john.conf` file typically located at `/etc/john/john.conf`.

For more information on custom rules and associated modifiers, ready through the [wiki](https://www.openwall.com/john/doc/RULES.shtml).

The syntax to use custom rules is a follows:

```text
john --wordlist=[path to wordlist] --rule=[name of rule] [path to hash file]
```
## Cracking Password Protected Zip Files
John can be used to crack the password on password protected zip files. To do this, `zip2john` is used to convert the zip file into a hash format that John understands. The hash is then used with John and a wordlist to extract the password.

The syntax for using `zip2john` is as follows:

```text
zip2john [options] [zip file] > [output hash file]
```
Let's look at a practical example.

### Question 1 - What is the password for the secure.zip file?

```text
┌──(siachen㉿kali)-[~/CyberSec/THM/johntheripper/task_nine_hashes]
└─$ zip2john secure.zip > ziphash.txt
ver 1.0 efh 5455 efh 7875 secure.zip/zippy/flag.txt PKZIP Encr: 2b chk, TS_chk, cmplen=38, decmplen=26, crc=849AB5A6 ts=B689 cs=b689 type=0
                                                                                                                   
┌──(siachen㉿kali)-[~/CyberSec/THM/johntheripper/task_nine_hashes]
└─$ cat ziphash.txt                         
secure.zip/zippy/flag.txt:$pkzip$1*2*2*0*26*1a*849ab5a6*0*48*0*26*b689*964fa5a31f8cefe8e6b3456b578d66a08489def78128450ccf07c28dfa6c197fd148f696e3a2*$/pkzip$:zippy/flag.txt:secure.zip::secure.zip
                                                                                                                   
┌──(siachen㉿kali)-[~/CyberSec/THM/johntheripper/task_nine_hashes]
└─$ john --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt ziphash.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
pass123          (secure.zip/zippy/flag.txt)     
1g 0:00:00:00 DONE (2023-03-01 13:09) 8.333g/s 68266p/s 68266c/s 68266C/s 123456..total90
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
### Question 2 - What is the contents of the flag inside the zip file?

Unzip the zip file with the above password to retrieve the flag: **THM{w3ll_d0n3_h4sh_r0y4l}**

## Cracking Password Protected RAR Archives
Similar zip files, John can be used to crack passwords on password protected RAR files. This can be accomplished using the `rar2john` tool with the following syntax:

```text
rar2john [rar file] > [output hash file]
```
The output hash file is then used with John to crack the password.

Let's look at a practical example.

### Question 1 - What is the password for the secure.rar file?

```text
┌──(siachen㉿kali)-[~/CyberSec/THM/johntheripper/task_ten_hashes]
└─$ rar2john secure.rar > rarhash.txt
                                                                                                                   
┌──(siachen㉿kali)-[~/CyberSec/THM/johntheripper/task_ten_hashes]
└─$ cat rarhash.txt
secure.rar:$rar5$16$b7b0ffc959b2bc55ffb712fc0293159b$15$4f7de6eb8d17078f4b3c0ce650de32ff$8$ebd10bb79dbfb9f8
                                                                                                                   
┌──(siachen㉿kali)-[~/CyberSec/THM/johntheripper/task_ten_hashes]
└─$ john --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt rarhash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (RAR5 [PBKDF2-SHA256 128/128 AVX 4x])
Cost 1 (iteration count) is 32768 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
password         (secure.rar)     
1g 0:00:00:00 DONE (2023-03-01 13:15) 5.263g/s 336.8p/s 336.8c/s 336.8C/s 123456..charlie
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```
### Question 2 - What is the contents of the flag inside the zip file?

Use the `unrar` tool to extract the RAR file to retrieve the flag: THM{r4r_4rch1ve5_th15_t1m3}

## Cracking SSH Keys with John
John can be used to crack the SSH private key password of id_rsa files. Unless configured otherwise, SSH authentication happens using password alone. However, once can configure a key-based authentication which allows the use of a private id_rsa key as an authentication method to login to a remote machine.

Using the the `ssh2john` tool, we can convert the private id_rsa key to a hash understood by John. The syntax is as follows:

```text
ssh2john [id_rsa private key file] > [output hash file]
```
The hash can then be used with John to crack the password on the id_rsa private key.

Let's look at a practical example.

### Question 1 - What is the SSH private key password?

```text
┌──(siachen㉿kali)-[~/CyberSec/THM/johntheripper/task_eleven_hashes]
└─$ ssh2john idrsa.id_rsa > idrsa_hash.txt
                                                                                                       
┌──(siachen㉿kali)-[~/CyberSec/THM/johntheripper/task_eleven_hashes]
└─$ john --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt idrsa_hash.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
mango            (idrsa.id_rsa)     
1g 0:00:00:00 DONE (2023-03-01 13:27) 11.11g/s 47644p/s 47644c/s 47644C/s access..mango
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
## Additional Resources

- [Hash Decrypter](https://hashes.com/en/decrypt/hash)
- [Hash Identifier](https://hashes.com/en/tools/hash_identifier)
- [Crackstation](https://crackstation.net/)