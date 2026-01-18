---
layout: post
author: OldGamesCracking
title: "Grand Theft Auto"
date: 2025-05-18
tags:
    - "Grand Theft Auto"
    - "Game Cracking"
    - "Reverse Engineering"
---

## Game Specs

| Name | Grand Theft Auto |
| ------------- | ------------- |
| Release-Date | 1997 |
| Redump ID | [31971](http://redump.org/disc/31971/) |
| Protection | CD-Check |
| Tested under | Win 10 |
| Scene-Crack by | [Acetate](https://archive.org/details/gta1_cdcrack) |

### Disclaimer

- The games are cracked for educational purpose and to regain compatibility with modern systems
- The games are more than 20 years old and can be found freely on the net via e.g. archive.org
- No parts of the game are distributed

# How to Crack

It's nice to see that this game still starts up after all these years (it's nearly 30 years old now), but it runs much too fast on my machine, but that is not our concern right now, we only want to crack the CD-Check ;)<br>

As usual, start the game and you are greeted with a warning text:

![CD-Check]({{site.url}}/assets/grand_theft_auto/no_cd.png)

Ok, now that we know what we are dealing with, it's time to crack that thing ;)<br>

Fire up your debugger (ideally on the second screen) and let the game run until the warning. In the debugger, search for strings containing "warning" (maybe you need to play in english for that to work) and you should find this: 

![CD-Check]({{site.url}}/assets/grand_theft_auto/warning.png)

So, there are two jumps, a conditional and an unconditional. The conditional will jump based upon the value at 0x004BEDC0 (which I have already labeled with _cd\_check_). Search for all appearences of this value and you should find this place:

![CD-Check]({{site.url}}/assets/grand_theft_auto/check_1.png)

So, based on the value at 0x004BFAE0 (_cd\_check\_0_), _cd\_check_ is set or not. Repeat the reference-search with _cd\_check\_0_ but you will probably draw a blank.
So indstead, place a hardware breakpoint on access there and re-run the game again. But still, we land at 0040738D. This is strange. My guess is, that this is a constant value, probably some flag that the developers put there to disable the CD check during development since - as I realized just now - the address 0x004BFAE0 is
in the idata (initialized) section and is set to 1 right from the start. So open up a hex editor and patch location 0xBE2E0 to a nice zero ;)<br>

Well, that was easy :D<br><br>

But wait, there is more. Did you realize that when you start the game now, the iconinc music is missing? That's because back in the days HDD space was limited so games often left large files like audio or video on the CD and loaded them dynamically when needed. For this game (and probably many others), the audio was stored as real CDDA audio tracks, which means you could put the game in a regular CD player and enjoy the cool soundtrack or rip it to MP3/Flac with a CD-ripper. So a real full-blown NO-CD-Crack would be quite complicated to pull off, you would need to replace all the _AIL\_redbook_ functions in the game with some functions that load audio files from the gamefolder on your harddrive which is probably doable but beyond the scope of this writeup. Until then, simply create a virtual image of the disc or use the one from [archive.org](https://archive.org/details/GrandTheftAuto_201903) :)<br><br>

With that in mind, it could also be an option to patch the _JE_ in line 00407394 to a _JMP_, that way you would end up with the best of both worlds: Have audio when the CD is inserted and still be able to play without a CD :)<br><br>

GTA London can be patched in the exact same manner, for my version of the game I just had to put a _JMP_ at 00436AC7.<br><br>

By the way, a while ago, Rockstar put the game for free on the net, so you could also search for that instead ;)

* * *

# How did the Pros do it?

Also on [archive.org](https://archive.org/details/gta1_cdcrack) we find a NO-CD-Crack by a group named _Acetate_. Unluckily I couldn't find more background info on them. So if you have any, send it to me ;)<br>

The Crack is actually a 16-Bit executeable from the Win95-Era that won't run under modern Windows. Also having a look with Ghidra did not work out well, so I would need to install a Win98 VM which did not work so far... I guess I have to test this on another day.

* * *