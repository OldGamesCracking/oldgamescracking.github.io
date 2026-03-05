---
layout: post
author: OldGamesCracking
title: "The Sims 2 - Part VI"
date: 2026-03-05
tags:
    - "The Sims 2"
    - "Game Cracking"
    - "Reverse Engineering"
    - "SafeDisc"
    - "VM"
    - "Virtual Machine"
    - "DLL Injection"
    - "Self Debugging"
---

## Game Specs

| Name | The Sims 2 |
| ------------- | ------------- |
| Release-Date | 9/2004 |
| Redump ID | [49162](http://redump.org/disc/49162/) |
| Protection | SafeDisc v3.20.020 |
| Cracked under | Win XP |
| Tested under | Win XP & Win 10 |
| Scene-Crack by | [MONEY](https://www.nfohump.com/index.php?switchto=nfos&menu=quicknav&item=viewnfo&id=75985) |

*Needed Tools:*

- Good Old PC (Windows XP)
- x32dbg
- Ghidra
- ProcMon
- The original Game-CD of course ;)
- Compiler, Dev-IDE and stuff (e.g. VisualStudio)
- The previous articles on SafeDisc
- Koffeinhaltige Kaltgetränke


### Disclaimer

- The games are cracked for educational purpose and to regain compatibility with modern systems
- The games are more than 20 years old and can be found freely on the net via e.g. archive.org
- No parts of the game are distributed

# Recap

In the [last article](/games/sims_2_part_5) we managed to de-virtualize the SafeDisc VM, but after reading the logile, I came across this strange far-Call to a location outside the codesection which didn't seemed quite right:

![]({{site.url}}/assets/sims_2/strange_code.png)

# Eine Sonderlocke (an edge case)

When you look at the unfixed game, you see that this is an initially encrypted function (identifiable by the Call to 0x0056F429), nothing special, we've dealt with them in [Part IV](/games/sims_2_part_4):

![]({{site.url}}/assets/sims_2/step1.png)

After decryption, it still doesent look right. Now there are a bunch of `INT3` which are probably Nanomites which we've seen in [Part III](/games/sims_2_part_3):

![]({{site.url}}/assets/sims_2/step2.png)

In fact, the first two bytes are Nanomites and after fixing, they look as follows:

![]({{site.url}}/assets/sims_2/step3.png)

A jump was installed - directly jumping into the other Nanomites... If we fix the other Nanomites we can see one of the rare cases where the data is written back to an address that is not equal to the address of the exception. Here the exception (Nanomite) happened at 0x00C8B0F5, but the data was written to 00C8B0EF. Interestingly this overwrites the `JMP`:

![]({{site.url}}/assets/sims_2/step4.png)

And finally we get to the third group of Nanomites which get restored to the code we saw before:

![]({{site.url}}/assets/sims_2/strange_code.png)

Intrestingly, if you have a look at the preceeding function which looks quite similar, you can already guess which bytes we should actually put there:

![]({{site.url}}/assets/sims_2/jmp.png)

But guessing is not what we want :) So I started to investigate the cause. At some point I realized that for whatever reasons - probably to fool us poor crackers - in this particular case, the data that normally holds information on how to restore a Nanomite now actually holds data to emulate the instruction instead (Via the VM). But since we patched the SafeDisc code in [Part III](/games/sims_2_part_3) to always write the Nanomite back, we end up forcingly writing 2 bytes of the VM instruction data.<br>

The solution I came up with to deal with the situation is a bit hacky, but it get's the job done. This is how I do it:

- I hook a place in the SafeDisc code where I can read the unencrypted Nanomite data and copy it to a buffer every time the hook triggers (_Callback\_Nanomites_).
- The signal to let me know when there is an emulated instruction instead of a Nanomite is when SafeDisc calls _ReadProcessMemory_ two times in a row (_Callback\_ReadProcessMemory_).
- I then interpret the Nanomite data as an IV (see [Part V](/games/sims_2_part_3)), de-virtualize the instruction and ignore the next _WriteProcessMemoryEx_.

The underlying struct in which the Nanomite data is stored did not change much since previous versions of SafeDisc, so I could identify it easily. It can hold up to 8 bytes, but since we need 12 bytes for the IV, the IV0 part was hardcoded to be always zero. The recovered IV is (0x00000000, 0x9CA0618D, 0x71C760C9) which results in an OpCode of 4 (`JNE`/`JNZ`), operandA is 10 (_EIP_) and operandB is 8 (_IMM_) and the Immediate value is 6. So a 'JNE +6' - exactly as we expected ;)

# The final chapter

At this point I was able to properly dump and start up the game. Just out of curiosity, I did a diff between the text section of my game.exe and the one provided by MONEY. The first thing I noticed is that they differed a bit in size (0x1ff bytes). The cut-away data is all zeros so they probably removed some padding bytes - nothing to worry about I guess. And after ignoring the exact IAT-Addresses (FF 15 XXXXXXXX) I was quite surprised that both text-sections actually matched perfectly ;) This means - at least in theory - that we were able to re-create the original game and thus fully removing SafeDisc once and for all...<br>

But wait a minute.<br>

Didn't I say the game was nuked because the MONEY crack did not work properly? Time to figure out why ;)<br>

First, let's try to understand the situation. We can start the game, load a family and everything looks fine at first but once we open the build menu, nothing happens. We can not change tiles etc.

![]({{site.url}}/assets/sims_2/build_menu.jpg)

Now comes the tricky part: How do you solve this? If you are unlucky, the logic is buried deep inside the game and since there is no error-message, we have nothing to track down. If nothing would help, we would need to reverse-engineer the game logic to see where things go south - uncool!<br>
The solution is surprisingly simple :) Initially I thought that the game would either check if it was altered by e.g. checking if the Nanomites or Calls to the VM were still intact. Alternatively it had somehow detected the presence of our DLL and then silently swapped one of the reconstructed instructions. In order to get a feeling for where I had to look, I exported a list of all the locations where we fixed the game (Nanomites, Emulated Instructions, Calls, ...) and imported them in x32dbg to place a breakpoint on every location. After checking and silencing most of the breakpoints I eventually figured out that two breakpoint triggered every time I opened the build menu that were located in a rather short function starting at 0x004BAC9C:

![]({{site.url}}/assets/sims_2/breakpoints.png)

Have a look at the address of the first breakpoint. Coincidence? I think not!

![]({{site.url}}/assets/sims_2/4bad.jpg)

Ok, but what does this function do? It's quite simple to reverse and translates to something like that:

```c
bool IsFileMappingPresent()
{
    char nameBuffer[0x100];
    char pidStrBuffer[0x100];

    strcpy(nameBuffer, "Mo6puAp1arDeM8ryUst9sdB2ySaei7scToC5laonuhpdf4m0tr");
    memset(pidStrBuffer, 0, sizeof(pidStrBuffer));

    DWORD ProcessId = GetCurrentProcessId();
    _itoa(ProcessId, pidStrBuffer, 16);

    strcat(nameBuffer, pidStrBuffer);

    HANDLE hFile = OpenFileMappingA(FILE_MAP_READ, FALSE, nameBuffer);

    if (hFile != NULL)
    {
        CloseHandle(hFile);
    }

    return (hFile != NULL);
}
```

So the game simply checks if a file mapping is present that was created by the SafeDisc loader during the startup routine. Since the mapping is not created by the game on it's own, the function will return false for every consecutive start. Simply patching a `MOV EAX, 1; RET` at the start of the function is actually enough to make the crack work properly. You can even do this with the MONEY release if you like ;)

# Conclusion

Well, that was a fun one ;) It definitely took much longer than initially anticipated but I certainly learned a lot! It still facinates me how people back then were able to crack that in just a few days.

* * *