---
layout: post
author: OldGamesCracking
title: "Die Siedler (Settlers) IV"
date: 2025-05-31
tags:
    - "Die Siedler IV"
    - "Settlers IV"
    - "Game Cracking"
    - "Reverse Engineering"
    - "SafeDisc"
---

## Game Specs

| Name | Die Siedler IV |
| ------------- | ------------- |
| Release-Date | 02/2001 |
| Redump ID | [48590](http://redump.org/disc/48590/) |
| Protection | SafeDisc v2.10.030 + ??? |
| Cracked under | Win XP + Win 10 |
| Tested under | Win 10 |
| Scene-Crack by | [Myth](https://www.nfohump.com/index.php?switchto=nfos&menu=quicknav&item=viewnfo&id=216) |

*Needed Tools:*

- Good Old PC (Windows XP)
- x32dbg
- ProcMon 3.1 (Win XP compatible)
- PE tool of your choice (e.g. PE-bear)
- The original Game-CD of course ;)
- The previous articles on SafeDisc
- Eine Kiste Club-Mate

### Disclaimer

- The games are cracked for educational purpose and to regain compatibility with modern systems
- The games are more than 20 years old and can be found freely on the net via e.g. archive.org
- No parts of the game are distributed

# How to Crack

*Note:* This game won't run on any of my PCs so I could not fully test it and I guess the crack is not complete.<br>

I got this game a while ago in a bundle of many other games. Upon checking Redump, I discovered, that it was using the same protection I had tackled in the [last writeup](/games/gta3), only a slightly earlier version, so I thought I might see how they differ. I won't go into much details this time, for that, see the GTA 3 writeup.<br>

By the way, if you wonder, how to detect the exact SafeDisc version (at least for v2.x), search for the string `BoG_ *90.0&!!  Yy>` in the .exe file, the three 32-Bit values after that are the Major, Minor, Fix version:

![SafeDisc Version]({{site.url}}assets/siedler_iv/safedisc_version.png)

This would be v2.10.030.<br>

I again used ProcMon to give myself a short overview and it looked like this version already does this tempfile thing, so we can stay within the process. The real game.exe is actaully s4\_main.exe in the _Exe_ subfolder.<br>

The debugger detection is the same as before (PEB & NtQueryInformationProcess), so I simply used ScyllaHide this time to tackle that more easily:

![Scylla Settings]({{site.url}}assets/siedler_iv/scylla_settings.png)

This time I was interested in where the tail jump actually is, so I started off by breaking in _LoadLibraryA_ in hope to see the transition from SafeDisc code to game code.
I filtered down the results by only breaking on _version.dll_ (which I found was one of the last loads) by the following breakpoint code:

```asm
$addr_LoadLibraryA = LoadLibraryA + dis.len(LoadLibraryA)
bphws $addr_LoadLibraryA
bphwcond $addr_LoadLibraryA, "stristr(utf8(arg.get(0)), \"version.dll\") == 1"
```

From there I climbed my way up, past some Resolver stubs we know already and finally ended up on this bit which smelled like a tail (jump):

![Tail Jump]({{site.url}}assets/siedler_iv/tail_jump.png)

To get up with a more general solution for next time, I then restarted the game, typed in the address of the jump and was rather surprised to see that the jump was already there:

![Tail Jump Start]({{site.url}}assets/siedler_iv/tail_jump_2.png)

So, place a HW BP there, let it rip and after one single step we can create a snapshot of our VM session.<br>

A short look around reveals that the intermodular calls look like the ones we know from GTA 3 already.
So I let the script run, just added a minor check and after a few seconds everything was fixed ;)<br>
The only thing I had to manually fix was to remove the one left over import from the SafeDisc DLL:

![Imports]({{site.url}}assets/siedler_iv/imports.png)

But turns out, the game won't start. Took me some moments to realize that game calls other modules via registers. For example:

![Call via register]({{site.url}}assets/siedler_iv/call_via_register.png)

Well, this is annoying since the CALL and thus the return address is seperate from the place where the thunk is MOVed to the register, so how do we figure out the return address? Maybe we just don't care and use zero as return address since sometimes you have many _CALL ESI_ one after another and that would have complicated things for SafeDisc also. So, just ignore it ;)<br>
Turns out, this idea works fine ;) The only tideous task was to implement the check for all x86 Registers (except ESP).<br>

Unfortunately, while SafeDisc seems to be defeated now, the game still crashes on all of my PCs. I guess it has problems with modern GPUs. So let's leave it that way and cary on to another game. Was still a nice challenge and the Script grew a bit.<br>

[The unpacking script (At the time of writing this article)](https://github.com/OldGamesCracking/oldgamescracking.github.io/blob/4e4dd0a1f3dd004ca2bee712dca122df3d53ad0e/assets/safedisc/safedisc_import_fixer.txt)

The settings are:

```
$iat_start = 0x0057A000
$iat_size = 0x000008E8
$user_code_end = 0x18000000
```

* * *