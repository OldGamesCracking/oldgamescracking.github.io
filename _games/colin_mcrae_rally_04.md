---
layout: post
author: OldGamesCracking
title: "Colin McRae Rally 04"
date: 2025-06-20
tags:
    - "Colin McRae Rally 04"
    - "Game Cracking"
    - "Reverse Engineering"
    - "SecuROM"
---

## Game Specs

| Name | Colin McRae Rally 04 |
| ------------- | ------------- |
| Release-Date | 04/2004 |
| Redump ID | [37749](http://redump.org/disc/37749/) |
| Protection | SecuROM v5.03.04 |
| Cracked under | Win 10 |
| Tested under | Win 10 |
| Scene-Crack by | [DEVIANCE](https://www.nfohump.com/index.php?switchto=nfos&menu=quicknav&item=viewnfo&id=61467) |

![Cover]({{site.url}}/assets/colin_mcrae_rally_04/cover.jpg)

*Needed Tools:*

- x32dbg
- The fixed Scylla version from [last article](/games/gta_vice_city)
- The original Game-CD of course ;)

### Disclaimer

- The games are cracked for educational purpose and to regain compatibility with modern systems
- The games are more than 20 years old and can be found freely on the net via e.g. archive.org
- No parts of the game are distributed

# How to Crack

Not much has changed OEP-wise in this version of SecuROM. We can still find the OEP in no time via using e.g. _GetCommandLineA_ as 'anchor' and then having a look around. I was able to identify it to be located at 0x00542829. Also using the script from [RollerCoaster Tycoon 2](/games/rollercoaster_tycoon_2) to break at the OEP still works fine. But when it comes to fixing the intermodular calls, only a subset of the calls is restored. Upon analyzing the problem one can realize quite quick that there is now more than one SecuROM stub:

![Calls]({{site.url}}/assets/colin_mcrae_rally_04/calls.png)

The thunks for these calls are all within the _.bgxb_ section, but the stubs itself are spread all over the place. In order to fix them, let's modify the script from the previous articles to perform the following algorithm:

- Search for all CALLs having a thuk in the _.bgxb_ section
- Find the next CALL after the OEP
- Repair them in alternating fashion (see RCT2 article for that)

This worked for a handfull of imports then the script stopped working. Upon closer inspection I realized that there are now 4 different types of stubs that need to be handled a bit differently:

### Type 1

![Type 1]({{site.url}}/assets/colin_mcrae_rally_04/type_1.png)

This is the one we know already. It ends in a _JMP EAX_ and we can simply read the address from EAX.

### Type 2

![Type 2]({{site.url}}/assets/colin_mcrae_rally_04/type_2.png)

This one pops the value of EBP into EAX and then performs a _XCHG EBP, EAX_. We can get address via single-stepping until we land on a _RET_.

### Type 3

![Type 3]({{site.url}}/assets/colin_mcrae_rally_04/type_3.png)

This is nearly the same as Type 1 only with an additional level of indirection.

### Type 4

![Type 4a]({{site.url}}/assets/colin_mcrae_rally_04/type_4a.png)

In this type the values on the stack are re-organized thats why our breakpoint triggers early. We just re-enable the breakpoint, but this time on the address where _EDI_ points to, then we let the stub continue and land on this bit:

![Type 4b]({{site.url}}/assets/colin_mcrae_rally_04/type_4b.png)

Just a simple return, so the real address of the remote proc is on the stack and we can simply grab it.<br><br>

So far, so good. So nothing special, just a few extra lines for our script. But when I tried to run the dumped game.exe it wouldn't start. Upon closer inspection I realized that some of the indirect CALLS (_FF 15_) had been replaced by relative CALLS (_E8_) to a stub within the _.geso_ section. The additional byte was replaced with a _NOP_ or other 1-byte instructions that have no effect in the context of the call:

![Relative Call 1]({{site.url}}/assets/colin_mcrae_rally_04/rel_call_1.png)

![Relative Call 2]({{site.url}}/assets/colin_mcrae_rally_04/rel_call_2.png)

![Relative Call 3]({{site.url}}/assets/colin_mcrae_rally_04/rel_call_3.png)

So we need to add another few lines to our script to search for relative CALLS that call an address in the SecuROM section. Unfortunately there are also some calls where the stuffed byte is appended to the call:

![Relative Call 4]({{site.url}}/assets/colin_mcrae_rally_04/rel_call_4.png)

![Relative Call 5]({{site.url}}/assets/colin_mcrae_rally_04/rel_call_5.png)

For this case I added a check to see if the preceding instruction is a _PUSH_ of some sort (1 Byte, 3 Byte and 6 Byte version). To make things more complicated there is also a version with the stuffed byte after the call, but without a preceeding push/pop:

![Relative Call 6]({{site.url}}/assets/colin_mcrae_rally_04/rel_call_6.png)

For this case, I checked if on one side of the call there is an instruction of length 1 and on the other there isn't which was actually sufficient.

You can find my script [here]({{site.url}}/assets/colin_mcrae_rally_04/import_fixer.txt). It's kind of a mess and some stuff is probably redundant, but well, it gets the job done ;)<br>

So, as we see, SecuROM v5 is actually not that far from v4 and not super complicated to fix.<br><br>