---
layout: post
author: OldGamesCracking
title: "Grand Theft Auto: Vice City"
date: 2025-06-20
tags:
    - "GTA VC"
    - "Vice City"
    - "Grand Theft Auto: Vice City"
    - "Game Cracking"
    - "Reverse Engineering"
    - "SecuROM"
---

## Game Specs

| Name | Grand Theft Auto: Vice City |
| ------------- | ------------- |
| Release-Date | 05/2003 |
| Redump ID | [19050](http://redump.org/disc/19050/) & [10500](http://redump.org/disc/10500/) |
| Protection | SecuROM 4.84.69 |
| Cracked under | Win 10 |
| Tested under | Win 10 |
| Scene-Crack by | [FAIRLIGHT](https://www.nfohump.com/index.php?switchto=nfos&menu=quicknav&item=viewnfo&id=31424) |

![Cover]({{site.url}}/assets/gta_vice_city/cover.jpg)

*Needed Tools:*

- x32dbg
- The original Game-CD of course ;)

### Disclaimer

- The games are cracked for educational purpose and to regain compatibility with modern systems
- The games are more than 20 years old and can be found freely on the net via e.g. archive.org
- No parts of the game are distributed

# How to Crack

After having cracked GTA 1, GTA 2 and GTA 3 it just felt natural to also have a look at one of my favorite games of all times: _Grand Theft Auto: Vice City_. This game has nearly the same SecuROM version as the game in the [previous article](/games/rollercoaster_tycoon_2) so it shouldn't be too hard to adapt the gained knowledge.<br><br>

Using the _GetCommandLineA_ trick we find the OEP quite fast which is at 0x00667BF0 and via the script from the last article we can break there easily. Having a look at the intermodular calls reveals that not much has changed and we can also use the [Import Fixer Script]({{site.url}}/assets/rollercoaster_tycoon_2/import_fixer.txt) from last time. The only questions remains: Where is the IAT? Luckily for us, some original imports are still intact and we can find them via a _rightclick/Search for/All user modules/Intermodular calls_. Watch out to only have a look at CALLS that are within the .text section of the OEP.

![Calls]({{site.url}}/assets/gta_vice_city/calls.png)

Then, after a bit of scrolling up and down the dump, I figured out that the IAT must be starting at 0x006F23C0 with a size of 0x2E0. To find the start/end of the IAT, have a look at the addresses. Are they within external modules? Usually you get somewhat of a 'visual change' in the data or you hit the page border. 

![Calls]({{site.url}}/assets/gta_vice_city/iat.png)

See how all values before 0x006F23C0 start with 00 and after that with 7x? Another good method is to see if there is a _.idata_ section, ususally the IAT is within that:

![Idata]({{site.url}}/assets/gta_vice_city/idata.png)

With the imports fixed, it's time to dump the game... Well, we hit a somewhat unexpedted roadblock:

![Scylla]({{site.url}}/assets/gta_vice_city/scylla.png)
