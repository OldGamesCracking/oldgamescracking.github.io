---
layout: post
author: OldGamesCracking
title: "Robin Hood - Die Legende von Sherwood"
date: 2025-06-12
tags:
    - "Robin Hood"
    - "Die Legende von Sherwood"
    - "Game Cracking"
    - "Reverse Engineering"
    - "Sysiphus"
---

## Game Specs

| Name | Robin Hood |
| ------------- | ------------- |
| Release-Date | 09/2002 |
| Redump ID | [71268](http://redump.org/disc/71268/) |
| Protection | Sysiphus 1.5 |
| Cracked under | Win XP |
| Tested under | WinXP & Win 10 |
| Scene-Crack by | [Fairlight](https://www.nfohump.com/index.php?switchto=nfos&menu=quicknav&item=viewnfo&id=17617) |

![Cover]({{site.url}}assets/robin_hood/cover.jpg)

*Needed Tools:*

- Good Old PC (Windows XP)
- (x32dbg)
- ProcMon
- The original Game-CD of course ;)

### Disclaimer

- The games are cracked for educational purpose and to regain compatibility with modern systems
- The games are more than 20 years old and can be found freely on the net via e.g. archive.org
- No parts of the game are distributed

# How to Crack

Another game that is quite easy to crack. So easy you actually don't need any tools.<br><br>
A first short research on the net resulted in _"Sysiphus 1.5"_ as the used protection. I could not really find more info on that. My guess is that this is what ProtectionId sais when you scan the game files with it. But I have no idea how it came up with that. Anyways, let's start the game and make some first observations with ProcMon.<br>

So it's reading a bunch of data from AZKUK\_F\_P.PAK from disc and _Robin Hood.icd_ and then creates _rh.tmp_. The rh.tmp is then started as new process. Looks like the game is unpacked somehow and then started.<br><br>

If you copy this file from the temp folder (while the game is running) back to the game dir, you will realize that this is actually the original game.exe without any additional layers of protection, not even a CD-Check. You can just copy it (rename it) and use it as it is :)<br><br>

By the way, the original (protected) game wouldn't start for me sometimes, I had to re-start it about 5 times, probably my disc is already dying :( But the 'cracked' version runs fine on my Win 10 machine ;)<br><br>

* * *