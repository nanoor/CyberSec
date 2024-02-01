---
title: Passwd/Shadow
desc: 'Exploiting Writeable /etc/passwd and /etc/shadow for privilege escalation'
---
## Introduction to /etc/passwd and /etc/shadow
`/etc/passwd` is a Linux configuration file which stores user account information such as username, user ID, and group ID in plain-text. The `/etc/passwd` file is owned by the root user and has permissions which allow it to be readable by all users on the system. Note that it may only be modified by the root user or other users with `sudo` privileges.

![File Permissions on /etc/passwd File](../../assets/images/passwd/01%20-%20passwd%20permissions.png)

In older Linux systems, password hashes were kept in the `/etc/passwd` file. This allowed any user on the system to be able to read the hashed passwords stored in the file. Modern Linux systems have moved away from this practice and utilize the `/etc/shadow` to provide  enhanced authentication mechanism by restricting access at the account level.

The `/etc/shadow` stores encrypted user passwords and is only accessible to the root user and the shadow group. This prevents unauthorized users or malicious actors from extracting user password hashes which can then be cracked using various brute-force techniques.

![File Permissions on /etc/shadow File](../../assets/images/passwd/02%20-%20shadow%20permissions.png)

## Understanding /etc/passwd File Format
Let's take a look at the contents of a `/etc/passwd` file. Note that we are not a super user but are still able to read the contents due to the world-readable permissions imposed on the `/etc/passwd` file.

![Contents of /etc/passwd](../../assets/images/passwd/03%20-%20passwd%20content.png)

The `/etc/passwd` file contains one record per line for each user account with access to the system and contains seven colon-separated fields with the following syntax:

```text
Username:Password:UID:GID:GECOS:Directory:Shell
```
The fields are defined as follows:

1. **Username**: This field contains the user's login name. The field is normally limited to a length between 1 and 32 characters and should not contain any capital letters.
2. **Password**: In older Linux systems, this field stored the encrypted password hashes for the users with access to the system. Modern Linux systems replaced the password hashes with the character `x` which indicates that the encrypted password is stored in the `/etc/shadow` file. Note that this field can be left empty (ie: blank) to indicate that the respective user does not need a password to login.
3. **User ID (UID)**: This field contains an identifier number which is used by the operating system for internal purposes. The distribution of UIDs is listed below:
   1. `UID 0` is reserved for the super user (ie: root).
   2. `UID 1-99` are traditionally reserved for predefined users (sometimes called pseudo-users). These users are administrators who do not need total root powers, but who perform some administrator tasks which require elevated privileges.
   3. `UID 100-999` are often reserved for system accounts and groups.
   4. `UID 1000+` are used for user accounts.
4. **Group ID (GID)**: This field determines the primary group of the user. Linux permits a user to be part of more than one group. Additional groups a user is part of will be defined in the system group file which is accessible using the `groups <username>` command. The distribution of GIDs is listed below:
   1. `GID 0` is reserved for the super user (ie: root).
   2. `GID 1-99` are reserved for the system and application use.
   3. `GID 100+` are allocated for the user group.
5. **GECOS**: This field is typically used to record general information about the account or its user. Information such as a user's full name, address, phone number, etc. can be stored in this field. All values stored in this field are comma-separated. GECOS is considered an optional field and therefore is not required to be filed in.
6. **Directory**: This field contains the path to the user's home directory in Linux. The value in this field is used to set the `HOME` environment variable.
7. **Shell**: This field contains the path the user's default login shell. The value in this field is used to set the `SHELL` environment variable.

Let's look at a practical example. We can break down the record for *user3* to better understand the file format based on the information provided above.

```console
user3:x:1002:1002:user3,,,:/home/user3:/bin/bash
```
The entry above contains information related to *user3*:

- The encrypted password is stored in the */etc/shadow* file as indicated by the character *x* in the password field. 
- The user belongs to *UID 1002* and *GID 1002*. 
- The only value in the GECOS field is the username *user3*. 
- The home directory for *user3* is defined as */home/user3*.
- The default login shell being */bin/bash*.

## Understanding /etc/shadow File Format
Similar to the `/etc/passwd` file, `/etc/shadow` contains one record per line for each user on the system. Each line contains nine colon-separated fields with the following syntax:

```text
Username:Password:LastPassChange:MinPassAge:MaxPassAge:WarningPeriod:InactivityPeriod:ExpirationDate:Reserved
```
The fields are defined as follows:

1. **Username**: This field contains the user's login name. This field must contain a value with a valid account name which exists on the system.
2. **Password**: This field stores the salted and hashed password for the user. The password is stored in the form `$id$salt$hashed` where `$id` represents the cryptographic algorithm used during the hashing process and can have the following values:

      1. `$1$` - MD5
      2. `$2a$` - Blowfish
      3. `$2y$` - Blowfish
      4. `$5$` - SHA-256
      5. `$6$` - SHA-512
      
      Note that this field can be empty, in which case no password is required from the user to authenticate. If the field contains the characters `*` or `!`, the user cannot use password authentication to log into the system.

3. **LastPassChange**: The value of this field represents the last time the password was changed. The value is expressed as the number of days which counts up from Jan 1, 1970 (epoch date). A zero (`0`) in this field implies that the user must change their password the next time they log in to the system. An empty field means that the password ageing feature is disabled.
4. **MinPassAge**: The value stored in this field represents the minimum number of days the user will need to wait before they are allowed to change their password again. An empty value or a value of zero (`0`) disables this feature.
5. **MaxPassAge**: The value in this field represents the number of days after which a user password change is required. An empty field disables the feature requiring maximum password age, password warning period, and password inactivity period.<br><br>Note that if the maximum password age is set below the minimum password age, the user cannot change their password.
6. **WarningPeriod**: The value in this field represents the number of days before the password expires during which the user is warned that the password must be changed. An empty  value or a value of zero (`0`) disables this feature.
7. **InactivityPeriod**: The value in this field represents the number of days after a password has expired during which the password should still be accepted. Once the expiration period and password inactivity period has elapsed, no login is possible using the current password. An empty value disables the password inactivity period.
8. **ExpirationDate**: The value in this field represents the date after which the account expires. The value is expressed as the number of days which counts up from the epoch date.<br><br>Note that the value in this field refers to *account expiration* and not *password expiration*.
9. **Reserved**: This field is reserved and unused.

With this information in mind, let's look at a practical example. 

```console
user3:$6$/X1sAdOR$uA/H.A4A2TSP.VG6InA3lzsU1xev1sPyn9qiyuwD5p5GG9JUCZo3ww25qTsjLciORvimu2Yd0jfTaCxqhHI0h/:18323:0:99999:7:::
```
The entry above contains information related to *user3*:

- The password was encrypted using SHA-512. 
- The user password was last changed on 2nd of March, 2020 (18323).
- The administrator has assigned no minimum password age.
- The password must be changed every *99999* days.
- The user will receive a warning to change the password *seven (7)* days prior to the password expiration date.
- No password inactivity period and account expiration date has been set.

## Exploiting /etc/passwd File for Privilege Escalation
The key to exploiting the `/etc/passwd` file for privilege escalation is to somehow be able to add a new user with root privileges to the file (or modify the password of an existing user like root). For this to happen as a low privileged user, we would need write permissions to the file itself or rely on other means such as abusing SUID system binaries to be able to modify the contents of file.

As noted earlier, the `/etc/passwd` file is normally globally-readable and only the super user has permissions to write to it. Permissions are defined this way to prevent low privileged users and threat-actors from being able to add or modify accounts with root privileges. Now Suppose a system administrator inadvertently marks `/etc/passwd` with global write permissions. With the file marked as globally-writeable, any user can modify the contents and give themselves root permissions.

If you remember from our discussion on the `/etc/passwd` file format, modern Linux systems do not store the encrypted password for a user in the `/etc/passwd` file. The character `x` is used instead to indicate that the encrypted password hash is stored in the `/etc/shadow` file. In order to maintain backwards compatibility with older Linux systems, however, modern Linux systems still permit users to authentication if the `/etc/passwd` file has the character `x` replaced with a password hash instead. There are multiple ways to generate password hashes, so let's have a look at a few examples below. 

#### OpenSSL
OpenSSL comes pre-installed on most Linux distributions. The `passwd` command can be used to generate a new password hash with the following syntax:

```console
openssl passwd -1 -salt [salt value] [password]
```
![OpenSSL Password Hash](../../assets/images/passwd/04%20-%20openssl%20hash.png)

#### mkpasswd
The `mkpasswd` command is an over-featured front end to the crypt(3) libc function and can be used to generate password hashes with the following syntax:

```console
mkpasswd -m [encryption algorithm] [password] -S [salt value]
```
![mkpasswd Password Hash](../../assets/images/passwd/05%20-%20mkpasswd%20hash.png)

#### Python
Python comes preinstalled on most Linux distributions. Python's crypt module can be used to generate password hashes with the following syntax:

```python
python3 -c 'import crypt; print(crypt.crypt([password], "$1$[salt value]"))'
```
![Python Password Hash](../../assets/images/passwd/06%20-%20python%20hash.png)


!!! warning
      Python's `crypt` module is deprecated and is slated to be removed in Python 3.13.

Once the password hash has been generated using one of the above methods, we simply need to either append a new user to the `/etc/passwd` file with root privileges or modify the entry for the root user by replacing the character `x` with our generated password hash. Let's see this in action.

Let's start by generating a password hash using OpenSSL.

![Generated Password Hash for PrivEsc](../../assets/images/passwd/07%20-%20passwd%20hash%20created.png)

Append the following line to the the `/etc/passwd file`:

```console
testuser:$1$testuser$61VaLhqTLFOznqUAe/Erk1:0:0:testuser:/root:/bin/bash
```
Note that with the above syntax, we are adding a new user named *testuser* with *UID = 0* and *GID = 0* (ie: root privileges). We can append the line using one of the several command line editors such as `nano` or `vi` however the most universal method would be to simply use the `echo` command. Also note that we will need to escape the `$` characters by using the `\` escape character when using the `echo` command.

![New User Added to /etc/passwd](../../assets/images/passwd/08%20-%20passwd%20new%20user%20added.png)

Now all that's left to do is to switch over to the new user using the password and an interactive shell to gain our root access.

![Root Access Gained via New User](../../assets/images/passwd/09%20-%20root%201.png)

As mentioned earlier, an alternative to adding a new user with root privileges is to simply replace the `x` character for the root user with our generated password hash. Mechanically, this works the same way.

![Modify Root Password](../../assets/images/passwd/10%20-%20passwd%20root%20hash.png)

![Escalate to Root](../../assets/images/passwd/11%20-%20root%202.png)

## Exploiting /etc/shadow File for Privilege Escalation
The `/etc/shadow` is easily exploitable for privilege escalation if misconfigured. Recall that the `/etc/shadow` file has read permissions set for the root user and the shadow group with the root user having the sole permissions to write to the file.

Let's look at an example where a system administrator has inadvertently provided global read permissions to the `/etc/shadow` file. As a result of this misconfiguration, we as a low privileged user are able to view the contents of the `/etc/shadow` file. Since the file contains the encrypted password hashes for each user with access to the system, we are able to use brute-forcing techniques to obtain user passwords. Note that this method relies on the users having weak passwords. Let's use John the Ripper to brute-force the root user's password hash.

The process of using John the Ripper to extract passwords from the `/etc/shadow` file requires two basic steps. We first have to use a utility called `unshadow` to combine the contents of `/etc/passwd` file with the contents of `/etc/shadow` file. We begin by copying the line for the root user from the `/etc/passwd` file and the `/etc/shadow` file to files `passwd.txt` and `shadow.txt` respectively.

![Shadow Contents](../../assets/images/passwd/12%20-%20shadow%20content.png)

![Local Files](../../assets/images/passwd/13%20-%20local%20files.png)

We then use the `unshadow` utility, which comes packaged with John the Ripper, to combine the contents of the two files. The syntax is as follows:

```text
unshadow [file with passwd content] [file with shadow content] > [unshadowed file name]
```
![Unshadowed file](../../assets/images/passwd/14%20-%20unshadow.png)

With the file now *unshadowed*, we can use John the Ripper to crack the root user's password hash.

![John Root Password](../../assets/images/passwd/15%20-%20john%20root%20pass.png)

We can now use these credentials to elevate to the root user.

![Root Privileges](../../assets/images/passwd/16%20-%20shadow%20read%20root%201.png)

Note that if a system administrator misconfigured the `/etc/shadow` file to be both globally-readable and writeable (or we are able to find and abuse SUID binaries owned by the root user which allows us to modify the file) the task of privilege escalation to the root user becomes trivial. Similar to how we were able to modify the `/etc/passwd` file with write permissions by replacing the `x` character with our generated password hash, we can do the same with the `/etc/shadow` file by replacing the existing password hash for the root user with our generated password hash. Once saved, we are then able to use the new root credentials to escalate our privileges.

## Conclusion
Improper file permissions can trivialise privilege escalation in Linux systems. As a system administration, one needs to be extremely careful when assigning permissions to ensure that sensitive files like `/etc/passwd` and `/etc/shadow` files are not given relaxed permissions for under privileged users. We saw how write permissions on the `/etc/passwd` file and read permissions on `/etc/shadow` file can be abused to gain super user privileges on a system. Although these misconfigured permissions are not common, it is still worth while as a penetration tester to quickly check the permissions on these files for easy an privilege escalation vector.