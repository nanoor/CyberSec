---
title: Day 02 - Log Analysis
desc: >-
  Day 2 covers server log files are and their importance in Blue Team scenario.
  Log files typically contain historical records of events and other data from
  an application.
---
## Introduction

Log files content vary however a useful log will contain at least the following:
1. A timestamp of when an event occurred.
2. The name of the service that is generating of the log file. 
3. The actual event the service logs.

## Common Locations of Log Files

### Windows
The windows operating system features an in-built application (Event Viewer) which features historical records of events. Events are typically categorized as follows:

|Category|Description|
|:-:|:--|
|Application|Contains all events related to applications on the system (ie. when a service or application are started or stopped and why)|
|Security|Contains all events related to system's security (ie. when a user logins into a system or a failed login attempt)|
|Setup|Contains all events related to system's maintenance (ie. Windows update logs)|
|System|Contains all events related to the system itself and any changes which may have occurred (ie. external device plugged-in/removed)|

### Linux (Ubuntu/Debian)
All log files related to Ubuntu or Debian systems are stored under `/var/log`.

Some important log files are presented below:

|Category|Description|File|
|:-:|:--|:-:|
|Authentication|Contains all attempted and successful local or remote authentications|auth.log|
|Package Management|Contains all events related to package management on the system (ie. package installation/removal/updates)|dpkg.log|
|Syslog|Contains all events related to things happening in the system's background (ie. crontabs executing, services starting/stopping)|syslog|
|Kernel|Contains all events related to kernel on the system (ie. changes to the kernel, output form devices such as network equipment or USB devices)|kern.log|

## CTF Questions
The name of the important list that the attacker stole from Santa was discovered using:

```console
elfmcblue@day-2-log-analysis:~$ grep -i "wget" webserver.log 
10.10.249.191 - - [18/Nov/2022:12:28:18 +0000] "GET /ipwget HTTP/1.1" 404 437 "-"
10.10.249.191 - - [18/Nov/2022:12:28:18 +0000] "GET /wget HTTP/1.1" 404 437 "-" "
10.10.249.191 - - [18/Nov/2022:12:34:39 +0000] "GET /santaslist.txt HTTP/1.1" 200
10.10.249.191 - - [18/Nov/2022:12:35:18 +0000] "GET /gwget HTTP/1.1" 404 437 "-" 
10.10.249.191 - - [18/Nov/2022:12:35:19 +0000] "GET /wget HTTP/1.1" 404 437 "-" "
```

The final flag was discovered using:

```console
elfmcblue@day-2-log-analysis:~$ grep -r "THM{" .
./SSHD.log:THM{STOLENSANTASLIST}
```