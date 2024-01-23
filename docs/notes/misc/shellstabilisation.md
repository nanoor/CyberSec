---
title: Reverse Shell Stabilisation
desc: 'Technique to stabilise reverse shells during CTF'
---
The following method can be used to stabilise a simple reverse shell received from a target machine during an engagement. 

!!! warning

    This method requires Python to be installed on the target machine.

## TL;DR
1. Import `pty` and spawn bash shell.

    ```sh
    python3 -c 'import pty; pty.spawn("/bin/bash")'
    ```

2. Press ++ctrl+z++ to background the process and get back to your host machine.

3. Use `stty` to set terminal line settings and foreground back to the target machine.

    ```sh
    stty raw -echo; fg
    ```

4. Set the terminal emulator to `xterm`.

    ```sh
    $ export TERM=xterm
    ```

## Detailed Explanation
When attempting to stabilise a reverse shell from a target, we first need to ensure that the target machine has Python installed.

```sh
which python && which python3
```
Once we have established that Python is installed on the target machine, we can begin stabilising the shell by importing Python's `pty` module to spawn a bash shell. The `pty` module allows us to start another process while giving us the ability to read and write from its controlling terminal programmatically.

```python
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
In the above command, `pty.spawn` spawns the defined process `/bin/bash` and connects its controlling terminal with the current process's standard I/O.

Once our process has been spawned, we can press ++ctrl+z++ to background the process and get back to the host machine.

Using the `stty` tool, we can set the input and output line settings for the terminal interface.

```sh
stty raw -echo; fg
```
`stty raw` simply activates raw mode where characters are read one at a time (instead of reading the whole line at once). Additionally, with `stty raw` ++ctrl+c++ can't be used to end a process. This is desirable as it will stop our shell from dying in the event we use ++ctrl+c++ to terminate a process on the target machine.

The use of `-echo` disables the the echoing back of our typing. `fg` simply foregrounds our backgrounded process from earlier thus allowing us to interact with the target machine's terminal once again.

We can now set the terminal emulator to `xterm` by using the `export` command to tell the system which terminal we are using and how the text on the screen should be adapted.

```sh
export TERM=xterm
```
OR

```sh
export TERM=xterm256-color
```

!!! tip

    The following command can be used to set terminal rows and columns: 

    ```sh
    stty rows <num> columns <num>
    ```
    We can use the `stty -a` command to get the desired rows and columns information from our host machine's terminal.
