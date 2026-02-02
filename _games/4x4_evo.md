---
layout: post
author: OldGamesCracking
title: "4x4 Evo"
date: 2026-02-02
tags:
    - "4x4 Evo"
    - "Game Cracking"
    - "Reverse Engineering"
    - "CodeLok"
    - "CopyLok"
---

## Game Specs

| Name | 4x4 Evo |
| ------------- | ------------- |
| Release-Date | 10/2001 |
| Redump ID | [48359](http://redump.org/disc/48359/) |
| Protection | CopyLok / CodeLok v2.20 |
| Cracked under | Win 10 |
| Tested under | Win 10 |
| Scene-Crack by | [RAZOR1911](https://www.nfohump.com/index.php?switchto=nfos&menu=quicknav&item=viewnfo&id=5440) |

![Cover]({{site.url}}/assets/4x4_evo/cover.jpg)

*Needed Tools:*

- x32dbg
- The original Game-CD of course ;)
- (DxWnd)
- (Python)


### Disclaimer

- The games are cracked for educational purpose and to regain compatibility with modern systems
- The games are more than 20 years old and can be found freely on the net via e.g. archive.org
- No parts of the game are distributed

# Intro

This game runs on my Win 10 machine, but it takes ages to boot up and once it runs the graphics are messed up and you could not really call this playable. I figured out that [DxWnd](https://sourceforge.net/projects/dxwnd/) works quite well for this game. Still, it takes ages to boot (I have no idea why), but once it runs, everything looks fine, so if you're having problems, try using DxWnd.

# How to Crack

At first, I did not find a way to figure out the exact version of CopyLok / CodeLok - which by the way must not be confused with CodeLock ([Code-Lock](https://web.archive.org/web/20040225072021/http://chosenbytes.com/)) or [Copylock](https://en.wikipedia.org/wiki/Rob_Northen_copylock) - but the [last archived website of the manufacturer](https://web.archive.org/web/20041208041041/http://panlok.com/historyframe.htm) is from 2004 which names a date of March 2001, since then no new News were reported, so I'm guessing that there are not many different versions around, especially none that are newer than the version on this game.

So let's open the game in x64dbg and have a look around. Interestingly the debugger is not detected. If you install a breakpoint at _CreateFileW_ you will see the classic [MeltICE](https://web.archive.org/web/19980128151826/http://www.2goodsoft.com/softice/) trick, but since we use a different debugger, that's none of our concern. Also it tries to create a file called _A:\\CL.LOG_.

# A sidemission

Ok, the file _A:\\CL.LOG_ caught my attention. Drive letter _A_ is somewhat uncommon these days. It was typically used for the first floppy disk drive.<br>

Sidenote: In the early days it was common to have a second floppy disk drive (drive letter _B_), later, when a computer also had a hard disc drive it was assigned to drive letter _C_ and that's what we still use today.<br>

The file needs to be present (dwCreationDisposition=OPEN\_EXISTING) and if not, it will not be created automatically. So as a first step, I manually changed the path so that it points to a non-system drive that needs no admin rights (like _D:\\_), later I discovered that one can just use a USB drive and re-assign the drive letter to _A_ which might be easier if you do not have a second hard drive. If the file is present, the game will log some (encrypted) binary data to it.<br>

![]({{site.url}}/assets/4x4_evo/encrypted_data.png)

Ok, time to dig a bit deeper.<br>

It didn't took me too long to figure out, that the content that gets written to the file are really some log-messages as the name implies. The encryption is done in two stages. First, the message is obfuscated by replacing all alpha-chars with a 'rotated' version. A bit like the good old [Caesar cipher](https://en.wikipedia.org/wiki/Caesar_cipher) but the rotation is changed for each letter. Every other char that is non-alpha stays the same. In a second step, the message is then encrypted by XORing each char with a round-key. Actually, both steps calculate the key/rotation in the same fashion.<br>
The encrypted messages are then written to the file (with no additional headers/markers).<br>
In order to parse and decrypt the file, one first needs to figure out the length of each original message (since the length is part of the key). In theory this would not be possible since the file does not contain additional markers, but luckily the original messages are all terminated by a Carriage Return (_\\n_) and during encryption, all MSBs are set to 1 (OR 0x80) except for when a Carriage Return is detected. In this case, the MSB is cleared (AND 0x7f).
This means that we can find the end of each string by checking the MSB for a 0.

![]({{site.url}}/assets/4x4_evo/terminators.png)

With that out of the way, we can parse the logfile, decrypt and de-obfuscate it and have a look at what gets logged:

```
PROC GetCommandLineA 6 ff 25 a0 16 e6 76 cc cc cc cc
MSTART = Sun Feb 01 17:11:01 2026 Command line not logged yet!!
Version=2.10
mjd = ADB0B985
OS 6 2 23f0 2 []
PROC MessageBoxA 0 8b ff 55 8b ec 83 3d b4 6c 62
PROC GetDriveTypeA 6 ff 25 d0 11 e6 76 cc cc cc cc
PROC GetLogicalDriveStringsA 0 8b ff 55 8b ec 83 ec 14 53 56   
...
SPTI inferface loaded OK
CDROM [E]
No CD modes work
CDROM [I]
0 ReadCDAspiC OK
Read Sector 16 using 0
RN 7040 (0) time=149
...
PROC SetDebugErrorLevel 3 c2 04 00 cc cc cc cc cc cc cc
...
RSTART = Sun Feb 01 17:11:07 2026
...
PROC DirectDrawCreate 0 8b ff 55 8b ec 81 ec 14 01 00
PROC <> 0 77 73 32 5f 33 32 2e 73 68 75
...
GSTART = Sun Feb 01 17:11:09 2026
```

This is interesting. First, it is easy to see that the first 10 bytes from some procs (like _MessageBoxA_, _GetDriveTypeA_, _GetLogicalDriveStringsA_, ...) are logged and there are two more values that caught my attention. Namely _mjd_ and _Version_.

Both values are read from an encrypted part of the _.idata_ section. I did not bother to reverse engineer the decryption routine as we can just use the logfile. I then downloaded a few ISOs of games that are also protected with CopyLok just to see if the logfile-trick also works. Note that the logfile is created even if the CD-Check fails.<br>
This are the results:

| Game | [Sudden Strike](https://archive.org/details/Sudden_Strike_2000_Windows_Eng) |
| ------------- | ------------- |
| Release | 10/2000 |
| Version | 2.08 |
| mjd | B6E4AECC |
| Logfile | A:\\CL.LOG |

| Game | [Motocross Mania](https://www.myabandonware.com/game/motocross-mania-lli) |
| ------------- | ------------- |
| Release | 11/2000 |
| Version | 2.10 |
| mjd | 998B2A2F |
| Logfile | A:\\CL.LOG |

| Game | [Cossacks: European Wars](https://archive.org/details/cossacks_202301) |
| ------------- | ------------- |
| Release | 11/2000 |
| Version | 2.20 |
| mjd | BC791175 |
| Logfile | C:\\icd\\asd.dat |

So, it looks like the _mjd_ value is game-specific, maybe some key or just a game-identifier. The _Version_ value might actually be the CopyLok-Version we were looking for. I have written a [Python-Script]({{site.url}}/assets/4x4_evo/decrypt.py) to decrypt the contents of the logfile.

# Back on track

As discussed earlier, the game does not seem to detect the debugger (asides from SoftICE), but still it seems to use exceptions to delete hardware breakpoints and it also verifies the code at various points, so using breakpoints is kinda complicated. Moreover it seems that it checks the entry point of various library functions, so when you want to place a breakpoint there, make sure to place it a few instructions deep into the function.<br>
Besides all that, the game itself does not seem to use the 'classic' stuff around the OEP (_GetVersion_, _GetCommandLine_, ...) or at least it does that in some nested functions, so it took me some while to figure out a good method to find the tail jump.<br>
Sidenote: The reason why my breakpoints did not trigger might have also been the stolen bytes in the import-stubs (more on that later).<br>
After trying a few common functions, I ended up using good old _GetProcAddress_ and waited for it to load _"ws2_32.WSAGetLastError"_ which seems to be the last import it reconstructs. Once that's done, step out and hit "step over" a few times. It takes a moment, but ultimately you should arrive here:

![]({{site.url}}/assets/4x4_evo/tail_jump.png)

Yay, we have made it to the tail-jump! Single step into the CALL and you are at the OEP (although the code may not look like it).<br>

When we try to dump the game now, we have some invalid imports. Having a short look reveals that some thunks point to temporary buffers. They look like the following:

![]({{site.url}}/assets/4x4_evo/stolen_bytes.png)

So, a few instructions and then a JMP to the original proc.<br>
For reference, the original proc looks like the following:

![]({{site.url}}/assets/4x4_evo/proc.png)

In this example the first 2 instructions (7 bytes) were 'stolen' and placed in an external buffer. Folling the two instructions a jump was installed that jumps back to the third instruction in the original proc (at 0x755A8777).<br>

Luckily for us, this is easiy repairable via script:

- Go through the IAT and check for thunks that point to a temporary buffer.
- Go through the buffer and parse the instructions to find the last instructions (the JMP). Count the number of bytes until there.
- From the last instruction (the JMP), take the destination address and subtract the number of bytes of the preceeding instructions.
- You should have the address of the proc now.

After the imports are fixed we are good to go. There are no additional checks ;)<br>

You can find the script [here]({{site.url}}/assets/4x4_evo/fix_iat.txt)
