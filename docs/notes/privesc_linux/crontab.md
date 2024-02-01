---
title: Crontab
desc: 'Exploiting Crontab for privilege escalation'
---
## Introduction
Cron is a linux utility used for scheduling tasks to be executed at a specified time. Cron is a background process (daemon) which executes non-interactive jobs.Tasks scheduled in cron are referred to as *cron jobs*.

A cron file is a simple text file where each line represents a cron job. Cron jobs are made up of three main elements:

1. The time interval at which the task is to be executed
2. User to execute the task as
3. Command or script to execute

Cron jobs are typically stored in the `/etc/cron.*` folders or in the `/etc/crontab` file.

An example of a cron job from `/etc/crontab` is presented below.

![Example Cronjob](../../assets/images/crontab/01%20-%20example_cron_job.png)

The crontab syntax consists of seven fields:

- **Minute**: The minute of the hour the command will execute on. This value ranges between 0-59.
- **Hour**: The hour the command will execute at. This value is given in the 24 hour format and the value ranges between 0-23.
- Cron is a background process (daemon) which executes non-interactive jobs.
- **Day of Month**: The day of the month the command shall execute on. This value ranges between 1-31.
- **Month**: The month that the command shall execute in. This value ranges between 1-12 representing the months of January to December.
- **Day of the Week**: The day of the week the command shall execute on. This value ranges from 0-6 (Sunday to Saturday). Note that Sunday can take the value of either 0 or 7. Alternatively, the abbreviations sun, mon, tue, wed, thu, fri, sat can be used on supported Linux systems.
- **User**: This field denotes the user the command will execute as.
- **Command**: This field denotes the command that will be executed.

Cron jobs allow the use of operators to specify which values a user wants to enter in each field.

- **Asterisk (*)**: This operator is used to assign all possible values in a field. For example, a cron job can be made to execute every minute by assigning an asterisk to the *Minute* field.
- **Comma (,)**: This operator is used to denote a list of multiple values. For example, assigning the values 1,5 in the *Day of the Week* field will schedule the task to be executed every Monday and Friday.
- **Hyphen (-)**: This operator is used to assign a range of values. For example, assigning the value 6-9 in the *Months* field will schedule the task to be executed from June to September.
- **Separator (/)**: This operator is used to divide a value. For example, a value of \*/12 in the *Hour* field will schedule a task which executes every 12 hours.
- **Last (L)**: This operator can be used in the *Day of Month* or *Day of Week* fields. For example, a value of 1L in the *Day of Week* schedules a task that executes on the last Monday of a month.
- **Weekday (W)**: This operator is used to determine the closest weekday from a given time. For example if the 1st of a month is a Sunday, a value of 1W in the *Day of Month* field will execute the task on the following Monday.
- **Hash (#)**: This operator is used to determine the day of the week. It is followed by a number ranging from 1-5. For example, 1#2 means second Monday of the month.
- **Question Mark (?)**: This operations is used to denote "no specific value" for the *Day of Month* and *Day of Week* fields.

Cron jobs also permit the use of special strings to schedule tasks at specific time intervals without the user having to figure out the logical set of numbers to input.

- **@hourly**: The task will be executed once an hour.
- **@daily or @midnight**: The task will be executed daily at midnight.
- **@weekly**: The task will be executed once a week on Sunday.
- **@monthly**: The task will be executed once on the first day of every month.
- **@yearly**: The task will executed once a year at midnight on January 1st.
- **@reboot**: The task will execute once at startup.

Let's look at a few examples of cron jobs given the syntax above:

```text
0 0 * * 0 root /script.sh           # Execute script.sh every Sunday at midnight
0 2,14 * * * root /script.sh        # Execute script.sh twice a day at 2AM and 2PM
*/15 * * * * root /script.sh        # Execute script.sh every 15 minutes
```
## Exploiting Scheduled Tasks
There are three main ways to exploit cron jobs to gain privilege escalation in Linux systems.
1. Weak file permissions used for cron files or scripts being run by them.
2. Missing absolute path in binaries and commands which can be exploited via the *PATH* environment variable.
3. Wildcards being used when running commands (wildcard injection).

Let's look at these methods in a bit more detail.

### Exploiting Weak File Permissions
By default, Cron runs as root when executing `/etc/crontab`. Any script executed by Cron that is editable by an unprivileged user becomes a vector for privilege escalation. Let's look at an example where weak permissions on a script executed by Cron allows us to escalate our privileges to root.

We begin by looking at the contents of `/etc/crontab` in order to identify any possible targets.

![Target Crontab](../../assets/images/crontab/02%20-%20target_cron_job.png)

One of the listed cronjobs executes `/home/user3/Desktop/autoscript.sh` every minute. Let's look at the permissions for the script file in question.

![Script Permissions](../../assets/images/crontab/03%20-%20target_script_permissions.png)

Looks like the permissions on the script have been misconfigured allowing it to be editable by any user on the target machine. We can abuse this misconfiguration by adding our malicious code to the script to permit privilege escalation.

Let's open the file in *nano* to see what it does.

![Original Script](../../assets/images/crontab/04%20-%20target_script_original.png)

Here we see a simple shell script which deletes the contents of the `/tmp` folder. At this stage, we have many options on how we approach privilege escalation. For example, we can grant ourselves superuser privileges by adding the low privileged user to `/etc/sudoers`.

```text
echo "user3 ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
```
We can also add a new root user to the `/etc/passwd` using:

```text
echo "newrootuser::0:0:newrootuser:/root:/bin/bash" >> /etc/passwd
```
Alternatively, we could simply set the SUID bit on the `/bin/bash` binary to gain root privileges. Let's take this approach. With the script open in nano, we can append the following line to set the SUID bit on the `/bin/bash` binary:

```text
chmod u+s /bin/bash
```
![Set SUID](../../assets/images/crontab/05%20-%20target_script_modified.png)

Once the cronjob runs, we can see that the permissions for `/bin/bash` have been modified with the SUID bit set. From hereon, we can execute the binary with the `-p` flag which does not reset the effective user id and allows the binary to be ran as the owner.

![Bash Permissions](../../assets/images/crontab/06%20-%20suid_bit_set.png)

![PrivEsc](../../assets/images/crontab/07%20-%20privesc.png)

### Exploiting Missing Absolute Paths
The *PATH* environmental variable is a colon-delimited list of directories that tells the shell which directories to search for executable files. Say for example that you have two binaries that share the same name located in two different directories. If executed, the shell will run the file that is in the directory that comes first in the *PATH* variable. This can have security implications if the *PATH* variable has been misconfigured; thus leading to an easy privilege escalation vector.

Let's look at this in action. Looking at the contents of `/etc/crontab` we see a script named `autoscript.sh` running every minute. Note that an absolute path is not provided to the script file. Furthermore, the *PATH* variable in crontab includes `/tmp` which by default is world-writeable.

![Crontab PATH](../../assets/images/crontab/08%20-%20path_cron_job.png)

Due to the omission of an absolute path for the script and the inclusion of a globally-writeable directory in the *PATH* variable, we can simply create a script with the same name in the `/tmp` folder to get privilege escalation. This is due to the fact that when Cron goes to run the script, it will look in the `/tmp` folder first before looking elsewhere due to how the *PATH* variable has been setup in the `/etc/crontab`.

![Create Script](../../assets/images/crontab/09%20-%20path_script.png)

Here we create a simple script which sets the SUID bit on the `/bin/bash` binary. All we need to do afterwards is to mark the script as executable and wait for Cron to run the job.

![Script Permissions](../../assets/images/crontab/10%20-%20path_script_permission.png)

Once the cron job has run, we execute the `/bin/bash` binary with the `-p` flag like before to get privilege escalation.

![SUID Set](../../assets/images/crontab/11%20-%20path%20_suid_set.png)

![PATH PrivEsc](../../assets/images/crontab/12%20-%20path_privesc.png)

### Exploiting Wildcard Injection
A wildcard injection vulnerability occurs when a command uses the wildcard (*) character in an insecure way thus allowing an attacker to change the command's behaviour by injecting command flags. 

Let's explore an example where we exploit a weakness in the *tar* utility. Tar is a common Linux utility which is used to make archives of files and folders. To exploit wildcard injection in the *tar* utility, we will be using the `--checkpoint` argument which allows the utility to display a progress message every time a specified number of files have been archived. When used in conjunction with the `--checkpoint-action` argument, we can execute a binary whenever the checkpoint is condition is satisfied.

When the *tar* utility is used with a wildcard, the utility will sift through all the files in the specified directory in an effort to archive them. We can exploit this by creating two files in the specified directory with the following names:

```text
--checkpoint=1
--checkpoint-action=exec=<COMMAND_TO_EXECUTE>
```
Let's see this in action. Looking at the contents of `/etc/crontab` we see a cron job which archives all files in the `/home/user3/Documents` folder. Note the use of the wildcard (*) character in the command.

![Wildcard Crontab](../../assets/images/crontab/13%20-%20wild_cron_job.png)

Since *user3* owns the directory in question, we can write files to the directory without requiring elevated privileges. We begin by creating a simple shell script which sets the SUID bit on the `/bin/bash` binary and assign execution permissions.

![Wildcard Script](../../assets/images/crontab/14%20-%20wild_script.png)

Next we create the following two files which will server as our arguments when the *tar* utility indexes the directory. Here we want to ensure that when the checkpoint condition is satisfied, the utility executes our shell script.

```text
touch /home/user3/Documents/--checkpoint=1
touch '/home/user3/Documents/--checkpoint-action=exec=sh privesc.sh'
```
![Wildcard Files](../../assets/images/crontab/15%20-%20wild_files.png)

All we need to do now is to wait for Cron to run the job and execute the `/bin/bash` binary with the `-p` flag to get privilege escalation.

![Wildcard SUID Set](../../assets/images/crontab/16%20-%20wild_suid_set.png)

![Wildcard PrivEsc](../../assets/images/crontab/17%20-%20wild_privesc.png)

## Conclusion
Cron jobs provide a simple vector for privilege escalation in Linux systems. When automating tasks, users and system administrators need to be cautious about how they go about configuring the cron jobs by ensuring that correct permissions are assigned to any script called by the job. Additionally, absolute paths to scripts and binaries should be employed to further minimize risks of exploitation. Finally, care should be taken to prevent situations where an argument injection vector may become a viable exploitation path by limiting the use of wildcard characters.

## References
- [Crontab Generator](https://crontab-generator.org/)
- [Crontab Guru](https://crontab.guru/)
- [Argument Injection Vectors](https://sonarsource.github.io/argument-injection-vectors/)
- [GTFOArgs](https://gtfoargs.github.io/)
