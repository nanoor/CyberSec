---
title: Day 11 - Memory Forensics
desc: Day 11 covers topics related to memory forensics using Volatility tool.
---
## Introduction

Memory forensics is the analysis of volatile memory (RAM) that is in use when a computer is powered on. RAM is extremely quick and is the preferred method of storing and accessing data when a software is running.

Memory forensics is an extremely important element when investigating a computer. A memory dump is a full capture of what was happening on the computer at the time. Memory dumps can be used for analysis at a later date.

### Volatility (Tool)

Volatility is an open-source memory forensics toolkit written in Python. Volatility allows us to analyse memory dumps taken from Windows, Linux and Mac OS devices and is an extremely popular tool in memory forensics. For example, Volatility allows us to:

- List all processes that were running on the device at the time of the capture
- List active and closed network connections
- Use Yara rules to search for indicators of malware
- Retrieve hashed passwords, clipboard contents, and contents of the command prompt

## CTF Questions

Begin by confirming the operating system of the device from which the memory dump was captured from.

```console
elfmcblue@aoc2022-day-11:~/volatility3$ python3 vol.py -f workstation.vmem windows.info
Volatility 3 Framework 2.4.1
Progress:  100.00PDB scanning finished                        
VariableValue

Kernel Base0xf803218a8000
DTB0x1ad000
Symbolsfile:///home/elfmcblue/volatility3/volatility3/symbols/windows/ntkrnlmp.pdb/E0093F3AEF
15D58168B753C9488A4043-1.json.xz
Is64BitTrue
IsPAEFalse
layer_name0 WindowsIntel32e
memory_layer1 FileLayer
KdVersionBlock0xf80321cd23c8
Major/Minor15.18362
MachineType34404
KeNumberProcessors4
SystemTime2022-11-23 10:15:56
NtSystemRootC:\Windows
NtProductTypeNtProductWinNt
NtMajorVersion10
NtMinorVersion0
PE MajorOperatingSystemVersion10
PE MinorOperatingSystemVersion0
PE Machine34404
PE TimeDateStampMon Apr 14 21:36:50 2104
```
The above result confirms that the memory dump is from a `Windows 10` machine.

Let's lists all of the processes that were running at the time of the memory capture.

```console
elfmcblue@aoc2022-day-11:~/volatility3$ python3 vol.py -f workstation.vmem windows.pslist          
Volatility 3 Framework 2.4.1
Progress:  100.00   PDB scanning finished
PID PPID  ImageFileName Offset(V) Threads Handles SessionId Wow64 CreateTime  ExitTime  File output

4 0 System  0xc0090b286040  141 - N/A False 2022-11-23 09:43:13.000000  N/A Disabled
104 4 Registry  0xc0090b2dd080  4 - N/A False 2022-11-23 09:43:04.000000  N/A Disabled
316 4 smss.exe  0xc0090e438400  2 - N/A False 2022-11-23 09:43:13.000000  N/A Disabled
436 428 csrss.exe 0xc0090ea65140  10  - 0 False 2022-11-23 09:43:18.000000  N/A Disabled
512 504 csrss.exe 0xc0090f35e140  12  - 1 False 2022-11-23 09:43:19.000000  N/A Disabled
536 428 wininit.exe 0xc0090f2c0080  1 - 0 False 2022-11-23 09:43:19.000000  N/A Disabled
584 504 winlogon.exe  0xc0090f383080  3 - 1 False 2022-11-23 09:43:19.000000  N/A Disabled
656 536 services.exe  0xc0090e532340  5 - 0 False 2022-11-23 09:43:20.000000  N/A Disabled
680 536 lsass.exe 0xc0090f3a5080  6 - 0 False 2022-11-23 09:43:20.000000  N/A Disabled
792 656 svchost.exe 0xc0090fa33240  12  - 0 False 2022-11-23 09:43:22.000000  N/A Disabled
820 536 fontdrvhost.ex  0xc0090f3a3140  5 - 0 False 2022-11-23 09:43:22.000000  N/A Disabled
828 584 fontdrvhost.ex  0xc0090fa39140  5 - 1 False 2022-11-23 09:43:22.000000  N/A Disabled
916 656 svchost.exe 0xc0090fad72c0  7 - 0 False 2022-11-23 09:43:23.000000  N/A Disabled
1000  584 dwm.exe 0xc0090fb0b080  13  - 1 False 2022-11-23 09:43:24.000000  N/A Disabled
380 656 svchost.exe 0xc0090fba9240  41  - 0 False 2022-11-23 09:43:25.000000  N/A Disabled
420 656 svchost.exe 0xc0090fbbf280  15  - 0 False 2022-11-23 09:43:25.000000  N/A Disabled
1116  656 svchost.exe 0xc0090fc2e2c0  16  - 0 False 2022-11-23 09:43:26.000000  N/A Disabled
1124  656 svchost.exe 0xc0090fc302c0  16  - 0 False 2022-11-23 09:43:26.000000  N/A Disabled
1204  656 svchost.exe 0xc0090fc2a080  19  - 0 False 2022-11-23 09:43:26.000000  N/A Disabled
1256  4 MemCompression  0xc0090fa35040  34  - N/A False 2022-11-23 09:43:26.000000  N/A Disabled
1292  656 svchost.exe 0xc0090fc752c0  2 - 0 False 2022-11-23 09:43:26.000000  N/A Disabled
1436  656 svchost.exe 0xc0090fdb52c0  7 - 0 False 2022-11-23 09:43:28.000000  N/A Disabled

--cropped for brevity--
```

`PID 2040` with an `Image File Name = mysterygift.exe` seems peculiar.

Let's analyze the process further.

```console
elfmcblue@aoc2022-day-11:~/volatility3$ python3 vol.py -f workstation.vmem windows.psscan --pid 2040
Volatility 3 Framework 2.4.1
Progress:  100.00   PDB scanning finished
PID PPID  ImageFileName Offset(V) Threads Handles SessionId Wow64 CreateTime  ExitTime  File output

2040  5888  mysterygift.exe  0xc0090b52e4c0  3 - 1 False 2022-11-23 10:15:19.000000  N/A Disabled
```

Let's use `windows.dumpfile` to export process `2040` for further analysis.

```console
elfmcblue@aoc2022-day-11:~/volatility3$ python3 vol.py -f workstation.vmem windows.dumpfiles --pid 2040
```

The dump of the process binary shows a total of `16` files.