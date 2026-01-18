---
layout: post
author: OldGamesCracking
title: "Kreed"
date: 2026-01-18
tags:
    - "Kreed"
    - "Game Cracking"
    - "Reverse Engineering"
    - "3PLock"
---

## Game Specs

| Name | Kreed |
| ------------- | ------------- |
| Release-Date | 08/2003 |
| Redump ID | [52635](http://redump.org/disc/52635/) |
| Protection | 3PLock |
| Cracked under | Win 10 |
| Tested under | Win 10 |
| Scene-Crack by | [RELOADED](https://www.nfohump.com/index.php?switchto=nfos&menu=quicknav&item=viewnfo&id=70874) |

![Cover]({{site.url}}/assets/kreed/cover.jpg)

*Needed Tools:*

- x32dbg
- (Ghidra)
- The original Game-CD of course ;)
- 5 minutes of your free time


### Disclaimer

- The games are cracked for educational purpose and to regain compatibility with modern systems
- The games are more than 20 years old and can be found freely on the net via e.g. archive.org
- No parts of the game are distributed

# Intro

After finishing the [last article](/games/harry_potter_2), I jumped right into the next game, came quite far (it involves a VM which I had to reverse) but then summer came into my way and so I paused for a few months.
Now my interest came back and while sifting through some games I acquired on eBay as a bundle, I came across *Kreed*.
I have actually never heard of it and reviews seem to be kinda mixed, so I guess it's nothing special. Nevertheless the protection it uses (3PLock) sounded interesting as I had also not heard of it.

When you start the game it takes ages (like 30+ seconds) before anything happens. First, I thought it would not work on modern systems but then the game started without showing any loading screen.
I did not try to understand the 'protection' in-depth, but it looks like it is just checking if some files are present on the disc (KREED.ACC), reads multiple chunks from the file for multiple times and finally starts the game.
I'm not sure if reading the files actually serves any purpose besides of checking if a CD is present, but as I said, it takes ages to do so, so the No-CD-Crack will at least save you from the initial waiting time ;)


# How to crack

Stepping through the program is not super interesting and there is no anti-debugging trickery and the code is not obfuscated so it's up to you to dig through the internals if you are interested (use Ghidra to make it more readable). The only bit that matters is the following section of the code which is a few lines below the entry point and marks the end of the loader:

![OEP Jump]({{site.url}}/assets/kreed/oep.png)

The JMP at the end is the OEP-Jump so you can place a breakpoint there, hit F9, single step to the OEP and dump the game via Scylla. But wait! Since the game is not encrypted in any way, and the CD-Checks have no real purpose (and no side-effects), you can just NOP out the CALL to the *check_files* routine and you're good to go, no dumping needed ;)

![No CD Check]({{site.url}}/assets/kreed/no_check.png)

So it's up to you to make it a 5-Byte patch or dump the game at the OEP and remove the loader ;)

* * *