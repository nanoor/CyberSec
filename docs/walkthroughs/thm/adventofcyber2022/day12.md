---
title: Day 12 - Malware Analysis
desc: >-
  Day 12 covers topics related to fundamentals of analysing malware samples
  without relying on autmoated sandbox scanners. Principals of static and
  dynamic analysis are intoduced as well as typical malware behaviours and their
  importance in incident investigation pipeline are presented.
---
## Introduction

Malware is defined as software created to harm a computer or an entire network.

Known common behaviours of malware are as follows:

- *Network connections*: Malware establishes internal and/or external network connections. External connections all remote access or for downloading staged payloads. Internal connections allow for lateral movement (or pivoting).
- *Registry key modifications*: Malware typically uses registry keys to establish persistence. A good example is `Registry Run Keys` which allows binaries to be autmatically executed when a user logs in or the machine boots up.
- *File manipulations*: Malware tends to download or create new files needed for its successful execution.

## Dangers of Analysing Malware Samples

!!! warning
    Handling a malware sample is dangerous. Always consider precautions while analysing it.

Following are some helpful tips when handling live malware:

- Always assume that the malware samples will infect your device and as such, executing it is not always the first step in analysing it.
- Only run the malware sample in a controlled environment that prevents potential compromise of unwanted assests.
- It is always recommended to have your `sandbox` to allow for a worry-free execution of malware samples.

A `sandbox` is a controlled test environment that mimics a legitimate end-user working environment to execute malware samples and learn their behavriour. A typical sandbox also provices automated analysis at the disposal of Security Analysts to determine if a binary from a set of malware samples requires further manual investigation.

## Static and Dynamic Analysis

- *Static Analysis*: A way of analysing malware sample without executing it. This method mainly focuses on profiling the binary with its readable information (such as its properties, program flow, and strings).
- *Dynamic Analysis*: A way of analysing malware samples by executing it in a safe sandboxed environment. By doing this, you will see the malware live in action, its exact behaviour, and how it infects the environment.

## CTF Questions

Let's profile the `mysterygift` binary through static analysis. For this we will use two tools: 

- [Detect It Easy (DIE)](https://github.com/horsicq/Detect-It-Easy)
- [CAPA](https://github.com/mandiant/capa)

DIE provides information about the file, such as its architecture, significant headers, packer used, and strings. Right click on the `mysterygift` binary and select `Detect IT Easy` in the context menu to begin analysis. Upon opening the file in DIE, we notice that the the binary was packed with `UPX(3.95)`. Packing malware is a common technique used by malware developers to compress, obfuscate or encrypt the binary. Due to this, contents such as significant strings and headers will not be immediately visible to Static Analysis Tools.

Let's run CAPA. CAPA detects capabilities in executable files. May it be for the installation of a service, invocation of network connections, registry modifications and such.

```cmd
C:\Users\Administrator\Desktop\Malware Sample>capa mysterygift
loading : 100%|███████████████████████████████████████████████████████| 485/485 [00:00<00:00, 1633.69     rules/s]
matching: 100%|█████████████████████████████████████████████████████████████| 3/3 [00:02<00:00,  1.11 functions/s]
WARNING:capa:--------------------------------------------------------------------------------
WARNING:capa: This sample appears to be packed.
WARNING:capa:
WARNING:capa: Packed samples have often been obfuscated to hide their logic.
WARNING:capa: capa cannot handle obfuscation well. This means the results may be misleading or incomplete.
WARNING:capa: If possible, you should try to unpack this input file before analyzing it with capa.
WARNING:capa:
WARNING:capa: Use -v or -vv if you really want to see the capabilities identified by capa.
WARNING:capa:--------------------------------------------------------------------------------
```
Given the CAPA output, we have verified that the malware sample is packed.  we previously fround from Detect It Easy that the binary is packed by UPX.

Let's unpack the binary using UPX and re-analyse the binaries using CAPA.

```cmd
FLARE Tue 12/13/2022 10:53:06.02
C:\Users\Administrator\Desktop\Malware Sample>upx -d mysterygift
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2020
UPX 3.96w       Markus Oberhumer, Laszlo Molnar & John Reiser   Jan 23rd 2020

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
    502169 <-    227737   45.35%    win64/pe     mysterygift

Unpacked 1 file.

C:\Users\Administrator\Desktop\Malware Sample>dir
 Volume in drive C has no label.
 Volume Serial Number is 0EBE-2DEE

 Directory of C:\Users\Administrator\Desktop\Malware Sample

12/13/2022  10:56 AM    <DIR>          .
12/13/2022  10:56 AM    <DIR>          ..
11/04/2022  05:25 AM           502,169 mysterygift
12/13/2022  10:53 AM         2,016,605 mysterygift.viv
               2 File(s)      2,518,774 bytes
               2 Dir(s)  30,772,412,416 bytes free
```

With the binary unpacked, we can re-analyze the binary using CAPA. However before we can continue, we need to delete the `mysterygift.viv` cached results which forces CAPA to re-analyze the binary with accurate results.

```cmd
C:\Users\Administrator\Desktop\Malware Sample>del mysterygift.viv
```

Re-run CAPA.

```cmd
C:\Users\Administrator\Desktop\Malware Sample>capa mysterygift
loading : 100%|█████████████████████████████████████████████████████████| 485/485 [00:00<00:00, 1633.69     rules/s]
matching: 100%|███████████████████████████████████████████████████████████| 573/573 [00:16<00:00, 34.27 functions/s]
+------------------------+------------------------------------------------------------------------------------+
| md5                    | 4e0321d7347cc872a5ac8ca7220b0631                                                   |
| sha1                   | 2dfcba8c182e4ea7665c44054d46549cc7b4430a                                           |
| sha256                 | 647458e71aea13d92e944bc7b7f305c6da808c71c3d19dc255a96dd60c8800a7                   |
| path                   | mysterygift                                                                        |
+------------------------+------------------------------------------------------------------------------------+

+------------------------+------------------------------------------------------------------------------------+
| ATT&CK Tactic          | ATT&CK Technique                                                                   |
|------------------------+------------------------------------------------------------------------------------|
| DEFENSE EVASION        | Obfuscated Files or Information [T1027]                                            |
| DISCOVERY              | File and Directory Discovery [T1083]                                               |
|                        | System Information Discovery [T1082]                                               |
| EXECUTION              | Shared Modules [T1129]                                                             |
| PERSISTENCE            | Boot or Logon Autostart Execution::Registry Run Keys / Startup Folder [T1547.001]  |
+------------------------+------------------------------------------------------------------------------------+

+-----------------------------+-------------------------------------------------------------------------------+
| MBC Objective               | MBC Behavior                                                                  |
|-----------------------------+-------------------------------------------------------------------------------|
| ANTI-BEHAVIORAL ANALYSIS    | Debugger Detection::Software Breakpoints [B0001.025]                          |
| DATA                        | Check String [C0019]                                                          |
|                             | Encoding::Base64 [C0026.001]                                                  |
|                             | Non-Cryptographic Hash::MurmurHash [C0030.001]                                |
| DEFENSE EVASION             | Obfuscated Files or Information::Encoding-Standard Algorithm [E1027.m02]      |
| FILE SYSTEM                 | Read File [C0051]                                                             |
|                             | Write File [C0052]                                                            |
| MEMORY                      | Allocate Memory [C0007]                                                       |
| PROCESS                     | Terminate Process [C0018]                                                     |
+-----------------------------+-------------------------------------------------------------------------------+

+------------------------------------------------------+------------------------------------------------------+
| CAPABILITY                                           | NAMESPACE                                            |
|------------------------------------------------------+------------------------------------------------------|
| check for software breakpoints                       | anti-analysis/anti-debugging/debugger-detection      |
| compiled with Nim                                    | compiler/nim                                         |
| encode data using Base64                             | data-manipulation/encoding/base64                    |
| reference Base64 string                              | data-manipulation/encoding/base64                    |
| hash data using murmur3 (2 matches)                  | data-manipulation/hashing/murmur                     |
| contain a resource (.rsrc) section                   | executable/pe/section/rsrc                           |
| contain a thread local storage (.tls) section        | executable/pe/section/tls                            |
| query environment variable                           | host-interaction/environment-variable                |
| check if file exists                                 | host-interaction/file-system/exists                  |
| read file (3 matches)                                | host-interaction/file-system/read                    |
| write file (4 matches)                               | host-interaction/file-system/write                   |
| get thread local storage value                       | host-interaction/process                             |
| allocate RWX memory                                  | host-interaction/process/inject                      |
| terminate process                                    | host-interaction/process/terminate                   |
| parse PE header (2 matches)                          | load-code/pe                                         |
| reference startup folder                             | persistence/startup-folder                           |
+------------------------------------------------------+------------------------------------------------------+
```

With the knowledge gained from CAPA, let's begin Dynamic Malware Analysis.

Open [Process Monitor](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon). This Windows tool shows real-time registry, file system, and process/thread activity. Set the filter condition to `Process Name - is - mysterygift.exe` and press `Add` to add the filter and press `OK` to accept.

Rename the binary with the extension `.exe` and execute the binary.

ProcMon has a panel that can filter the following, as highlighted in the image below (in sequence):

- Show Registry Activity
- Show File System Activity
- Show Network Activity
- Show Process and Thread Activity
- Show Profiling Events

Focus on the first three; Registry, File System and Network.

Let's determine if any significant Registry Modifications are executed by the binary.

Unclick all filters and only choose `Show Registry Activity`. The results still give several results so let's add a filter by finding all Registry Key Creations and Modifications. 

Remove the following Operations by right-clicking an entry from the Operation column and choosing `Exclude`:

- RegOpenKey
- RegQueryValue
- RegQueryKey
- RegCloseKey

This leaves only the `RegCreateKey` as our results. In the results, only one Registry Key (Key: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`; Value: `C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\wishes.bat`) has both the `RegCreateKey` and `RegSetValue`. This key is related to a persistence technique called `Registry Run Key Modification` and is commonly used by malware developers to install a backdoor.

Let's now determine if the malware sample executes File Creations. It may indicate that the malware drops prerequisite files for its successful execution.

Select the `Show File System Activity` filter and filter on `File Write` events. This can be done by choosing `Exclude` for the following:

- CreateFile
- CreateFileMapping
- QuerySecurityFile
- QueryNameInformationFile
- QueryBasicInformationFile
- CloseFile
- ReadFile

It looks like the malware writes two files:

- C:\Users\Administrator\AppData\Local\Temp\2\test.jpg
- C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\wishes.bat

The first file is located in the user's `TEMP` directory, which is commonly used by malware to drop another file for its disposal. The other file is written in the `STARTUP` directory, also used for persistence via `Startup Folders`.

Let's confirm if the malware sample attempts to make a network connection. It may indicate that the malware communicates with external resources to download or establish remote access.

Select the `Show Network Activity` filter. We can see that the malware makes the following network connections:

- bestfestivalcompany.thm
- virustotal.com

For the final question, we can go back and analyse the unpacked binary in DIE. Use the `Strings` feature and filter on `bestfestivalcompany.thm` to get the full URL: `http://bestfestivalcompany.thm/favicon.ico`.