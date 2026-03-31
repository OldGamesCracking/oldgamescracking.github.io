---
layout: post
author: OldGamesCracking
title: "Tomb Raider III"
date: 2026-03-31
tags:
    - "Tomb Raider III"
    - "Game Cracking"
    - "Reverse Engineering"
    - "CD Lock"
---

## Game Specs

| Name | Tomb Raider III: Adventures of Lara Croft  |
| ------------- | ------------- |
| Release-Date | 11/1998 |
| Redump ID | [34982](http://redump.org/disc/34982/) |
| Protection | CD Lock |
| Cracked under | Win 10 |
| Tested under | Win 10 |
| Scene-Crack by | DVNiSO |

![Cover]({{site.url}}/assets/tomb_raider_3/cover.jpg)

*Needed Tools:*

- x32dbg
- The original Game-CD of course ;)
- 5 minutes of your free time


### Disclaimer

- The games are cracked for educational purpose and to regain compatibility with modern systems
- The games are more than 20 years old and can be found freely on the net via e.g. archive.org
- No parts of the game are distributed

# Intro

It's nice to see that this game still installs and runs on a fairly modern PC, although it's nearly 30 years old. The only thing you need to do is enable the compatibility mode for Win98. Also there is a Sound-Bug that loops the fist second of some of the audio files (menu-music etc.) in an infinite loop. But as far as I can tell this bug was introduced way back when the game was released and has nothing to do with modern PCs, just get the [patch](https://www.tombraiderchronicles.com/tr3/fixes.html) that was published shortly after the game's release and start cracking from there.

# How to crack

Open the game in x64dbg and start it without having the CD inserted. After a few seconds we get a nice nagscreen:

![]({{site.url}}/assets/tomb_raider_3/nag.png)

Now, use the classic trick of pausing the debugger, then pressing _"Run to user code"_ and finally click the _OK_ button. You should break right after the call to _DialogBoxParamA_. Step out of the routine and have a look around.

![]({{site.url}}/assets/tomb_raider_3/routine.png)

This is a super simple routine that one can simply blackbox without even trying understand much of it. The routine at _0x004825D0_ simply checks for the presence of a CD(-Drive) and the routine at _0x0048e530_ contains our nagscreen. So for a short test, make one of the marked `JNE` / `JE` jump and have a short look at what the game does next. It tries to open the files _VFAW.AFP_,  _NEIR.AFP_, _OKET.AFP_ and _AWCS.AFP_ from the next drive that would come after your last drive (if your last drive is _D:_, it would try to load the files from _E:_). The drive letter is loaded from address _0x00633F38_ (also marked in the image). If you have a look at the mentioned files on the disc, you will realizte that they have been altered in such a way that they have a very large size, at least that's what Windows thinks. This is the 'copy protection' as many programs back in the days would refuse to copy the CD as the total size  would be larger than a single CD could hold.<br>
If you step 'til the end of the function, you will realize that it will either return 1 or 0, depending on the fact that a CD was inserted and it could open the previously mentioned files or not. So at that point it should be clear that we need at least a good old `MOV AL, 1`, `RET` patch.<br>

If you try to run the game with just that patch now, it will start, but after a short second it will display the following message which already hints at what we need to do next:

![]({{site.url}}/assets/tomb_raider_3/script_file.png)

If you have a look in the install-dir now, it's obvious that nearly all game-files were left on the CD. So as a first measure, copy all folders (audio, cuts, data, ...) to the install-dir. Now we need to think of a way to force Windows to load the files locally. For most games this can be done by replacing the drive letter (and the preceeding colon) with a simple dot (`.`). This game is no exception to that trick. Just have a look at the strings in the binary or put a breakpoint on _CreateFileA/W_ and try to find the place where the paths to the files are constructed. Soon you should land here:

![]({{site.url}}/assets/tomb_raider_3/printf.png)

This is actually super nice. Instead of hard-coding the path to the files, they use printf to generate the path on the fly. Also the previously seen address of 0x00633F38 is seen.<br>
So just patch the format-string to "%c\\%s" and apply the following patch at 0x0048D2E0 to write a dot instead of the drive-letter:

```asm
mov al, 1
mov byte ptr ds:[0x00633F38], 0x2E
ret
```

If you prefer a x64dbg patch-file, you can use:

```
0008D2E0:56->B0
0008D2E1:57->01
0008D2E2:E8->C3
0008D2E9:75->2E
000C87FA:3A->25
000C87FB:5C->73
000C87FC:25->00
```

(Patches are for the version with the sound-patch, CRC: 14BD1751)

* * *