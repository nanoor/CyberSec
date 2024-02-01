---
title: Day 04 - Scanning
desc: >-
  Day 4 covers topics related to scanning and network enumeration using tools
  like Nmap and Nikto.
---
## Introduction
The challenge of the day requires the user to login to SMB using provided credentials. The answers are located in the files (`flag.txt` and `userlist.txt`) in the `admins` share.

Target IP = 10.10.241.147 ($IP) <br>
Username = ubuntu <br>
Password = S@nta2022

```console
┌──(siachen㉿kali)-[~]
└─$ smbclient -L //$IP                     
Password for [WORKGROUP\siachen]:

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        sambashare      Disk      Samba on Ubuntu
        admins          Disk      Samba on Ubuntu
        IPC$            IPC       IPC Service (ip-10-10-241-147 server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            ----
---

        Workgroup            Master
        ---------            -------
        WORKGROUP            

┌──(siachen㉿kali)-[~]
└─$ smbclient //$IP/admins -U ubuntu        
Password for [WORKGROUP\ubuntu]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Wed Nov  9 22:44:30 2022
  ..                                  D        0  Wed Nov  9 10:43:21 2022
  flag.txt                            A       23  Wed Nov  9 10:55:58 2022
  userlist.txt                        A      111  Wed Nov  9 22:44:29 2022

                40581564 blocks of size 1024. 38196224 blocks available

smb: \> 

```