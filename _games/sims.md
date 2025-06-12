---
layout: post
author: OldGamesCracking
title: "Die Sims"
date: 2025-06-13
tags:
    - "Sims"
    - "The Sims"
    - "Die Sims"
    - "Game Cracking"
    - "Reverse Engineering"
    - "SafeDisc"
---

## Game Specs

| Name | Die Sims |
| ------------- | ------------- |
| Release-Date | 1997 |
| Redump ID | [48103](http://redump.org/disc/48103/) |
| Protection | SafeDisc 1.40.004 |
| Cracked under | Win XP + Win 10 |
| Tested under | Win 10 |
| Scene-Crack by | [CLASS](https://www.nfohump.com/index.php?switchto=nfos&menu=quicknav&item=viewnfo&id=2821) / [Fairlight](https://www.nfohump.com/index.php?switchto=nfos&menu=quicknav&item=viewnfo&id=2822) |

*Needed Tools:*

- Good Old PC (Windows XP)
- x32dbg
- The original Game-CD of course ;)


# How to Crack

I found this one on a local flea market for a few bucks and I couldn't resist. So let's crack that one open ;)<br><br>

Since I have discussed SafeDisc v1.3 already in the [GTA 2 Article](/games/gta2), I will not go through all details again. We will only have a short look at imports reconstruction since it's a bit different, but I will use the techniques described in the [GTA 3 Article](/games/gta3), they are quite compareable.<br><br>

Already during the installation we are greeted with a serial check:

![Serial Check]({{site.url}}/assets/sims/serial.png)

Cracking installers is a pain in the ass and I tried to reverse the serial routine but gave up after quite some while. I think it's not too complicated but you'll find a valid key on the net relatively fast, so no real need for a Keygen.<br><br>

To get to the OEP, I used the following script:

```asm
bpc
bphwc

$addr_WriteProcessMemory = WriteProcessMemory + dis.len(WriteProcessMemory)
bphws $addr_WriteProcessMemory

$peb_addr = peb()
byte:[$peb_addr + 2] = 0

$addr_NtQueryInformationProcess = NtQueryInformationProcess

bphws $addr_NtQueryInformationProcess, x, 1
bphwcond $addr_NtQueryInformationProcess, "arg.get(1)==7"
SetHardwareBreakpointSilent $addr_NtQueryInformationProcess, 1

loop:
	erun
	cmp eip, $addr_NtQueryInformationProcess
	jne patch_stub
	$pi = dword:[esp+0x0C]
	rtr
	dword:[$pi] = 0
	jmp loop

patch_stub:
	bphwc $addr_WriteProcessMemory
	$start_address = arg.get(1)
	$addr_buffer = arg.get(2)
	find $addr_buffer, 53C3
	$real_address = $start_address + ($RESULT - $addr_buffer)
	word:[$RESULT] = 0xfeeb
	msg "Loop will be installed now. Start second debugger AFTER this message and paste the commands shown in the logwindow. Then pause the program and execute the second script."
	log "bp mod.entry(mod.main())"
	log "word:[0x{p:$real_address}] = 0xc353"
	run

end:
```

The stubs used to hide the imports look kinda like the ones from GTA 2, but they are deceiving:

![Stub]({{site.url}}/assets/sims/stubs.png)

The _JMP_ after isn't actually executed, probably a leftover from the last version to fool us. We use the "Hardware Breakpoint on ESP after pushfd" trick here to get to the end of the stub. We actually need to execute a few _STO_ to really get to the end of the stub but that's the main differecen here. Also I found a few "MOV REG [ADDR], CALL REG" combinations. So I decided to modify my SafeDisc v2 script to now also support v1.40.

As always: [the unpacking script (At the time of writing this article)](https://github.com/OldGamesCracking/oldgamescracking.github.io/blob/666d33a0ecf176e6ac1f44e65e68ff75555fcd15/assets/safedisc/safedisc_import_fixer.txt)<br>

That's it, there seems to be no additional CD-Checks and the game runs kinda ok on Win 10 besides that we have no audio at all, let's see if we can fix that.<br>
With the CD inserted, we have audio back, but that's not what we want :)<br><br>
After a short search we land on this bit:

![Sims Music]({{site.url}}/assets/sims/sims_music.png)

Looks like some kind of lookup that returns "I:\" (my install drive). With a bit more digging, we find out, that this is a registry key which is looked up under "Software\Maxis\The Sims" and we should probably change it to our install-dir. Since we changed the exe anyways, we can re-use another key that's already there: SIMS\_DATA.

![Registry]({{site.url}}/assets/sims/registry.png)

So simply change the string at 0x005F2EC8 (SIMS\_MUSIC) to SIMS\_DATA and copy the _Music_ folder on disc to the install dir and we're done ;)<br><br>