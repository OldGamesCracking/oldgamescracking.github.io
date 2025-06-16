---
layout: post
author: OldGamesCracking
title: "Zoo Tycoon 2"
date: 2025-06-16
tags:
    - "Zoo Tycoon 2"
    - "Game Cracking"
    - "Reverse Engineering"
    - "SmartE"
---

## Game Specs

| Name | Zoo Tycoon 2 |
| ------------- | ------------- |
| Release-Date | 11/2004 |
| Redump ID | [121332](http://redump.org/disc/121332/) |
| Protection | SmartE |
| Cracked under | Win 10 |
| Tested under | Win 10 |
| Scene-Crack by | ??? |

![Cover]({{site.url}}/assets/zoo_tycoon_2/cover.jpg)

*Needed Tools:*

- x32dbg
- ProcMon
- Compiler, Dev-IDE and stuff (e.g. VisualStudio)
- The original Game-CD of course ;)


# How to Crack

This protection is quite unusual in some regards. I have never heard of it and judging by the entries at [redump.org](http://redump.org/discs/quicksearch/smarte/protection/only) there are not many games that used it though it might have been in action from roughly 2004 to 2007. I found it while browsing the supported protections that [BinaryObjectScanner](https://github.com/SabreTools/BinaryObjectScanner) can detect.<br>

Anyways, since I did not knew what to expect, I first used ProcMon to get myself an overview and could see right ahead that the game.exe seems to spawn an external process:

![Temp Process]({{site.url}}/assets/zoo_tycoon_2/temp_file.png)

This worker is always named _insXXXX.tmp_ with _XXXX_ beeing randomly (?) chosen chars.<br>
I then tried to run the game in the debugger which worked fine, even without having Scylla enabled at all, but as soon as I tried to break in interesting places, the game was shut down. So it was kinda clear that the _insXXXX.tmp_ process was probably overlooking the whole situation and as soon as anything went wrong, it would shut the game.exe down.<br>

To figure out more details about the inner mechanism of the protection, I used the same setup as described in the [Stronghold Deluxe](/games/stronghold_deluxe) article and injected a DLL in the game.exe and also in the _insXXXX.tmp_ (worker.exe) to hook some functions. From there I could see that both processes communicate via two events that are set/reset many times. Also the NetBIOS protocol is used, probably as a way to transfer larger data chunks (imports, decrypted game data ?) between the two processes. I did not dig deeper into this since it was not mandatory to do so, but I believe that this communication channel is also used to detect if the game.exe is beeing debugged via checking if the game responds to requests within a certain timeframe and if it does not, it is probably beeing debugged because the debugger halted execution (breakpoint etc.).<br>

Just for the record: The first event I mentioned earlier is called _BITARTSxxxxxxxxxx_ and is created by the game.exe. The _xxxxxxxxxx_ part is passed to the worker.exe via the _lpCommandLine_ parameter in the call to _CreateProcessA_.<br>
The second event is called _BITARTSYYYY_ and is created by the worker.exe. I did not figure out where the _YYYY_ part is generated, but I guess it's based upon the pid of the worker.exe or is encoded in the _xxxxxxxxxx_ string. In the end it does not matter since we actually do not need this information to crack it ;)<br>

What I did then was to figure out the place where the loader code transitions to the game code. For that I did some wild guesses and installed hooks for some functions that are usually called around the OEP (_GetVersion_, _GetCommandLineA_, ...). I got some results for _GetCommandLineA_ and displayed a MessageBox once the function was called which is a simple but effective trick to halt the program at a certain point. Once the MessageBox was displayed, I attached x32dbg, placed a breakpoint after the call to _MessageBoxA_, stepped out and had a look around:

![OEP]({{site.url}}/assets/zoo_tycoon_2/oep.png)

The two other intermodular function calls (_GetVersionExA_ and _GetModuleHandleA_) gave me the confirmation that we were indeed just a few lines past the OEP and that the actual OEP must be at 0x006C3781. The question was now, how can we reach it? Simply putting a HW BP there did not seemed to do the trick. After a bit of fiddling around, I realized that - contrary to my initial believes - there is actually an anti-debugging mechanism in place that kills the HW Breakpoints. Checking the Scylla options _KiUserExceptionDispatcher_ and _NtContinue_ is enough to make the program break on the OEP. The corresponding SEH where the breakpoints are killed is here:

![SEH]({{site.url}}/assets/zoo_tycoon_2/seh.png)

Now that we know where the OEP is, let's put a HW BP there, restart the program and break right on the OEP ;) From here we can directly use Scylla to dump the game and restore the IAT, there are no scrambled imports. For me, two imports were replaced with stubs from _aclayers.dll_. Scylla can not reconstruct these imports. Luckily there are debug strings that we can use to get the original functions:

![aclayers]({{site.url}}/assets/zoo_tycoon_2/aclayers.png)

That's it. I hope there are no late checks in the game, but upon playing for a few minuted, I could not find anything unusual.<br><br>