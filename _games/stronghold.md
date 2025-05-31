---
layout: post
author: OldGamesCracking
title: "Stronghold"
date: 2025-05-31
tags:
    - "Stronghold"
    - "Game Cracking"
    - "Reverse Engineering"
    - "SafeDisc"
---

## Game Specs

| Name | Stronghold |
| ------------- | ------------- |
| Release-Date | 10/2001 |
| Redump ID | [52624](http://redump.org/disc/52624/) |
| Protection | SafeDisc v2.40.010 |
| Cracked under | Win XP |
| Tested under | Win XP |
| Scene-Crack by | [CLASS](https://www.nfohump.com/index.php?switchto=nfos&menu=quicknav&item=viewnfo&id=5132) / [Fairlight](https://www.nfohump.com/index.php?switchto=nfos&menu=quicknav&item=viewnfo&id=5134) |

*Needed Tools:*

- Good Old PC (Windows XP)
- x32dbg
- ProcMon 3.1 (Win XP compatible)
- PE tool of your choice (e.g. PE-bear)
- The original Game-CD of course ;)
- The previous articles on SafeDisc
- Kaffee, Kaffee, Kaffee

### Disclaimer

- The games are cracked for educational purpose and to regain compatibility with modern systems
- The games are more than 20 years old and can be found freely on the net via e.g. archive.org
- No parts of the game are distributed

# How to Crack

This was probably one of THE games of my childhood, I guess I have spent multiple weeks in the Freebuilds mode. Time to finally crack this open ;)<br>

With the knowledge of the [last game](/games/siedler_iv) we can find the OEP in less then 10 seconds:

![Tail Jump]({{site.url}}/assets/stronghold/tail_jump.png)

Why is this so easy?<br>

So, time to strip off SafeDisc. For that, let our script from last time run with the following settings:

```
$iat_start = 0x00538000
$iat_size = 0x000002D8
$user_code_end = 0x21100000
```

It takes some time, but eventually, it finishes without any error. Scylla is happy and we can start the game. But it won't :(<br>
Upon further inspection I realized that this time another flavor is added to the mix: Indirect jumps.
Which we saw already in GTA 3, but this time they are not added by SafeDisc but are intentional by the game:

![Indirect Jumps]({{site.url}}/assets/stronghold/indirect_jumps.png)

Well, this is pretty much the same as normal CALLs only a different Opcode is used. For the return address, again, I simply ignored it and used zero just as we did [the last time](/games/siedler_iv). This actually works surprisingly well.<br>

One thing that did not work so well was testing the game under Win 10. It crashes and I don't have a clue why (probably some Video Card driver issue). Interestingly the game works absolutely perfect in the VM including animations, videos and all the other stuff, which it normally doesn't. So I would still call this a success. And also the developer were so nice to not include any additional CD-Checks :)

[The unpacking script (At the time of writing this article)](https://github.com/OldGamesCracking/oldgamescracking.github.io/blob/ea0a33b08e53aef5a7df1898101db537168e5415/assets/safedisc/safedisc_import_fixer.txt)