---
layout: post
author: OldGamesCracking
title: "MotoGP 2"
date: 2025-06-12
tags:
    - "MotoGP 2"
    - "Ultimate Racing Technology 2"
    - "Game Cracking"
    - "Reverse Engineering"
    - "Bitpool"
---

## Game Specs

| Name | MotoGP 2 |
| ------------- | ------------- |
| Release-Date | 06/2003 |
| Redump ID | [35480](http://redump.org/disc/35480/) |
| Protection | Bitpool |
| Cracked under | Win 10 |
| Tested under | Win 10 |
| Scene-Crack by | ??? |

![Cover]({{site.url}}/assets/motogp_2/cover.jpg)

*Needed Tools:*

- x32dbg
- RegEdit
- The original Game-CD of course ;)

### Disclaimer

- The games are cracked for educational purpose and to regain compatibility with modern systems
- The games are more than 20 years old and can be found freely on the net via e.g. archive.org
- No parts of the game are distributed

# How to Crack

This game was so easy to crack, you hardly need a debugger at all, you could have figured that out just by making some wild guesses ;)<br><br>

By browsing the list of supported protections that [BinaryObjectScanner](https://github.com/SabreTools/BinaryObjectScanner) can detect, I came across one named [Bitpool](https://github.com/TheRogueArchivist/DRML/blob/main/Entries/Bitpool/Bitpool.md). Since I'm interested in games that have unusual protections, I bought this game and gave it a go :)<br>

If we start the game via the _motogp2.exe_ without the CD inserted, we instantly get a warning:

![CD Check]({{site.url}}/assets/motogp_2/cd.png)

This is nice since - judging by the speed the messagebox popped up - it means that usually the check is quite simple. Time to attach the debugger and have a look around:

![Message Box]({{site.url}}/assets/motogp_2/messagebox.png)

The messagebox call is easy to find and if you scroll up a bit you will notice quite fast, that the call at 0x0041A20B checks if the file _elf.42_ is present in the game dir and if not, it gets the path of the CD drive with which you installed the game via the registry (0x0041A22B) and then searches the file on the disc (0x0041A282).

![Message Box]({{site.url}}/assets/motogp_2/calls.png)

So, let's copy that file from the disc to the install dir and start the game.<br>
It first starts up nicely but as soon as we try to start a game, a nagscreen pops up:

![No CD]({{site.url}}/assets/motogp_2/no_cd.png)

I then put a breakpoint on a few things and figured out, that the _CDPath_ registry key we saw earlier is also used here:

![CD Path]({{site.url}}/assets/motogp_2/cdpath.png)

So, let's have a look at that in RegEdit:

![RegEdit]({{site.url}}/assets/motogp_2/regedit.png)

Well, why not change the path to the same as _InstallPath_? That works surprisingly well and the nagscreen is gone ;)<br>

That means we do not have to change the game.exe at all. Just copy the _elf.42_ file to the installdir and change _CDPath_ to the same as _InstallPath_.<br><br>

By the way, the _elf.42_ file is actually 1:1 the same as motogp2.exe, just with a changed name.<br><br>

* * *