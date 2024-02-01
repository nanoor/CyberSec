---
title: Day 20 - Firmware Reverse Engineering
desc: >-
  Day 20 covers topics and techniques related to firmware reverse engineering.
  Fundamentals of extracting hidden keys from encrypted firmware and modifying
  and rebuilding a firmware are covered as well.
---
## Introduction

Firmware reverse engineering involves extracting the original code from the firmware binary file and verifying that the code does not carry out malicious or unintended functionality.

Following is a basic process followed when doing firmware reverse engineering:

1. Obtain the firmware from the vendor's website or extract it from the device.
2. The obtained/extracted firmware (typically a binary file) is first analyzed to figure out its type (bare metal or OS based).
3. Verify if the firmware is either encrypted or packed. Encrypted firmware is challenging to analyze as it usually needs a tricky workaround, such as reversing the previous non-encrypted releases of the firmware or performing hardware attacks like [Side Channel Attacks (SCA)](https://en.wikipedia.org/wiki/Side-channel_attack) to fetch the encryption keys.
4. Once the encrypted firmware is decrypted, different techniques and tools are used to perform reverse engineering based on type.

## Types of Firmware Analysis

Firmware analysis is typically conducted using two techniques, `Static Analysis` and `Dynamic Analysis`.

### Static Analysis

Static analysis involves examining the binary file contents, performing its reverse engineering, and reading the assembly instructions to understand the functionality. The following tools are commonly employed when conducting static analysis on firmwares:

- [Binwalk](https://github.com/ReFirmLabs/binwalk): A firmware extraction tool that extracts code snippets inside any binary by searching for signatures against many standard binary file formats like `zip, tar, exe, ELF`. The common objective of using this tool is to extract a file system like `Squashfs, yaffs2, Cramfs, ext*fs, jffs2`, which is embeded in the firmware binary. The file system contains all the application code that will be running on the device.
- [Firmware ModKit (FMK)](https://github.com/rampageX/firmware-mod-kit): FMK is widely used for firmware reverse engineering. It extracts the firmware using `binwalk` and outputs a directory with the firmware file system. Once the code is extracted, the desired files can be modified and the binary repacked with a single command.
- [Firmwalker](https://github.com/craigz28/firmwalker): Searches through extracted firmware file system for unique strings and directories like `etc/shadow`, `etc/passwd`, `etc/ssl`, keywords like `admin, root, password`, and vulnerable binaries like `ssh, telnet, netcat`.

### Dynamic Analysis

Dynamic analysis involves running the firmware on an actual hardware and observing its behaviour through emulation and hardware/software based debugging. One of the significant advantages of dynamic analysis is to analyze unintended network communication for identifying data exfiltration. The following tools are commonly used for dynamic analysis:

- [Qemu](https://www.qemu.org/): Qemu is a free and open-source emulator which enables working on cross-platform environments. The tool provides various ways to emulate binary firmware for different architectures like `Advanced RISC Machines (ARM)`, `Microprocessors without Interlocked Pipelined Stages (MIPS)`, and others on the host system. Qemu can help in full-system emulation or a single binary emulation of `Executable and Linkable Format (ELF)` files.
- [Gnu DeBugger (GDB)](https://www.sourceware.org/gdb/): GDB is a dynamic debugging tool for emulating a binary and inspecting its memory and registers. GDB also supports remote debugging, commonly used during firmware reversing when the target binary runs on a separate host and reversing is carried out from a different host.

## CTF Questions

### Step 1 - Verify Encryption

Let's use `binwalk` to verify whether the binary file is encrypted using a technique known as `file entropy analysis`.

```text
test@ip-10-10-204-137:~$ ls
bin  bin-unsigned  firmware-mod-kit
test@ip-10-10-204-137:~$ cd bin
test@ip-10-10-204-137:~/bin$ ls
firmwarev2.2-encrypted.gpg
test@ip-10-10-204-137:~/bin$ binwalk -E -N firmwarev2.2-encrypted.gpg 

DECIMAL       HEXADECIMAL     ENTROPY
--------------------------------------------------------------------------------
0             0x0             Rising entropy edge (0.989903)
```

In the above output, the `rising entropy` edge means that the file is probably encrypted and has increased randomness.

### Step 2 - Extracting Unencrypted Older Version

Let's extract the firmware from the older unencrypted binary using `FMK`.

```text
test@ip-10-10-204-137:~/bin-unsigned$ ls
firmwarev1.0-unsigned
test@ip-10-10-204-137:~/bin-unsigned$ extract-firmware.sh firmwarev1.0-unsigned 
Firmware Mod Kit (extract) 0.99, (c)2011-2013 Craig Heffner, Jeremy Collake

Scanning firmware...

Scan Time:     2022-12-20 17:35:07
Target File:   /home/test/bin-unsigned/firmwarev1.0-unsigned
MD5 Checksum:  b141dc2678be3a20d4214b93354fedc0
Signatures:    344

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             TP-Link firmware header, firmware version: 0.-15360.3, image ver
sion: "", product ID: 0x0, product version: 138412034, kernel load address: 0x0, kernel entry 
point: 0x80002000, kernel offset: 4063744, kernel length: 512, rootfs offset: 849104, rootfs l
ength: 1048576, bootloader offset: 2883584, bootloader length: 0
13344         0x3420          U-Boot version string, "U-Boot 1.1.4 (Apr  6 2016 - 11:12:23)"
13392         0x3450          CRC32 polynomial table, big endian
14704         0x3970          uImage header, header size: 64 bytes, header CRC: 0x5A946B00, cr
eated: 2016-04-06 03:12:24, image size: 35920 bytes, Data Address: 0x80010000, Entry Point: 0x
80010000, data CRC: 0x510235FE, OS: Linux, CPU: MIPS, image type: Firmware Image, compression 
type: lzma, image name: "u-boot image"
14768         0x39B0          LZMA compressed data, properties: 0x5D, dictionary size: 3355443
2 bytes, uncompressed size: 93944 bytes
131584        0x20200         TP-Link firmware header, firmware version: 0.0.3, image version:
 "", product ID: 0x0, product version: 138412034, kernel load address: 0x0, kernel entry point
: 0x80002000, kernel offset: 3932160, kernel length: 512, rootfs offset: 849104, rootfs length
: 1048576, bootloader offset: 2883584, bootloader length: 0
132096        0x20400         LZMA compressed data, properties: 0x5D, dictionary size: 3355443
2 bytes, uncompressed size: 2494744 bytes
1180160       0x120200        Squashfs filesystem, little endian, version 4.0, compression:lzm
a, size: 2812026 bytes, 600 inodes, blocksize: 131072 bytes, created: 2022-11-17 11:14:32

Extracting 1180160 bytes of tp-link header image at offset 0
Extracting squashfs file system at offset 1180160
3994112
3994112
0
Extracting squashfs files...
Firmware extraction successful!
Firmware parts can be found in '/home/test/bin-unsigned/fmk/*'
```

### Step 3 - Finding Encryption Keys

The original firmware is `GPG` protected (as per the narrative). We need to find a public and private key and a paraphrase to decrypt the originally signed firmware. The unencrypted firmware is extracted successfully and stored in the `fmk` folder (as per the last Step 2). Let's search for the public and private key as well as the paraphrase in the extracted firmware.

```text
test@ip-10-10-204-137:~/bin-unsigned/fmk$ grep -ir 'pgp'
rootfs/gpg/public.key:-----BEGIN PGP PUBLIC KEY BLOCK-----
rootfs/gpg/public.key:-----END PGP PUBLIC KEY BLOCK-----
rootfs/gpg/private.key:-----BEGIN PGP PRIVATE KEY BLOCK-----
rootfs/gpg/private.key:-----END PGP PRIVATE KEY BLOCK-----

test@ip-10-10-204-137:~/bin-unsigned/fmk$ grep -ir 'paraphrase'
rootfs/gpg/secret.txt:PARAPHRASE: Santa@2022
```

### Step 4 - Decrypting the Encrypted Firmware

Let's import the keys using the following command:

```text
test@ip-10-10-204-137:~/bin-unsigned$ gpg --import fmk/rootfs/gpg/private.key
gpg: key 56013838A8C14EC1: secret key imported
gpg: Total number processed: 1
gpg:               imported: 1
gpg:       secret keys read: 1
gpg:   secret keys imported: 1

test@ip-10-10-204-137:~/bin-unsigned$ gpg --import fmk/rootfs/gpg/public.key 
gpg: key 56013838A8C14EC1: "McSkidy <mcskidy@santagift.shop>" not changed
gpg: Total number processed: 1
gpg:              unchanged: 1
```

Verify the keys are exported:

```text
test@ip-10-10-204-137:~/bin-unsigned$ gpg --list-secret-keys 
/home/test/.gnupg/pubring.kbx
-----------------------------
sec   rsa3072 2022-11-17 [SC] [expires: 2024-11-16]
      514B4994E9B3E47A4F89507A56013838A8C14EC1
uid           [ unknown] McSkidy <mcskidy@santagift.shop>
ssb   rsa3072 2022-11-17 [E] [expires: 2024-11-16]
```

Let's decrypt the encrypted firmware binary with the above keys.

```text
test@ip-10-10-204-137:~/bin$ gpg firmwarev2.2-encrypted.gpg
gpg: WARNING: no command supplied.  Trying to guess what you mean ...
gpg: encrypted with 3072-bit RSA key, ID 1A2D5BB2F7076FA8, created 2022-11-17
      "McSkidy "

test@ip-10-10-204-137:~/bin$ ls -la
total 7528
drwxrwxr-x 2 test test    4096 Dec 20 18:07 .
drwxr-xr-x 8 test test    4096 Nov 23 18:01 ..
-rw-rw-r-- 1 test test 3990016 Dec 20 18:07 firmwarev2.2-encrypted
-rw-rw-r-- 1 test test 3705655 Dec  1 05:45 firmwarev2.2-encrypted.gpg
```

With the firmware decrypted, we can now use either `binwalk` or `FMK` to extract the code. Let's use `FMK`.

```text
test@ip-10-10-204-137:~/bin$ extract-firmware.sh firmwarev2.2-encrypted
Firmware Mod Kit (extract) 0.99, (c)2011-2013 Craig Heffner, Jeremy Collake

Scanning firmware...

Scan Time:     2022-12-20 18:15:37
Target File:   /home/test/bin/firmwarev2.2-encrypted
MD5 Checksum:  714c30af5db1e156e35b374f87c59d6f
Signatures:    344

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             TP-Link firmware header, firmware version: 0.-15360.3, image ver
sion: "", product ID: 0x0, product version: 138412034, kernel load address: 0x0, kernel entry 
point: 0x80002000, kernel offset: 4063744, kernel length: 512, rootfs offset: 849104, rootfs l
ength: 1048576, bootloader offset: 2883584, bootloader length: 0
13344         0x3420          U-Boot version string, "U-Boot 1.1.4 (Apr  6 2016 - 11:12:23)"
13392         0x3450          CRC32 polynomial table, big endian
14704         0x3970          uImage header, header size: 64 bytes, header CRC: 0x5A946B00, cr
eated: 2016-04-06 03:12:24, image size: 35920 bytes, Data Address: 0x80010000, Entry Point: 0x
80010000, data CRC: 0x510235FE, OS: Linux, CPU: MIPS, image type: Firmware Image, compression 
type: lzma, image name: "u-boot image"
14768         0x39B0          LZMA compressed data, properties: 0x5D, dictionary size: 3355443
2 bytes, uncompressed size: 93944 bytes
131584        0x20200         TP-Link firmware header, firmware version: 0.0.3, image version:
 "", product ID: 0x0, product version: 138412034, kernel load address: 0x0, kernel entry point
: 0x80002000, kernel offset: 3932160, kernel length: 512, rootfs offset: 849104, rootfs length
: 1048576, bootloader offset: 2883584, bootloader length: 0
132096        0x20400         LZMA compressed data, properties: 0x5D, dictionary size: 3355443
2 bytes, uncompressed size: 2494744 bytes
1180160       0x120200        Squashfs filesystem, little endian, version 4.0, compression:lzm
a, size: 2809007 bytes, 605 inodes, blocksize: 131072 bytes, created: 2022-12-01 05:42:58

Extracting 1180160 bytes of tp-link header image at offset 0
Extracting squashfs file system at offset 1180160
3990016
3990016
0
Extracting squashfs files...
Firmware extraction successful!
Firmware parts can be found in '/home/test/bin/fmk/*'
```

The flag can be found under `/home/test/bin/fmk/rootfs/flag.txt`: `THM{WE_GOT_THE_FIRMWARE_CODE}`

Using the `ls -lah *` command, we can find the build-number of `rootfs`: `2.6.31`