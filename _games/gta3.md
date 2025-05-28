---
layout: post
author: OldGamesCracking
title: "Grand Theft Auto 3 - Part I"
date: 2025-05-28
tags:
    - "GTA3"
    - "Grand Theft Auto 3"
    - "Game Cracking"
    - "Reverse Engineering"
    - "SafeDisc"
---

## Game Specs

| Name | Grand Theft Auto 3 |
| ------------- | ------------- |
| Release-Date | 05/2002 |
| Redump ID | [9700](http://redump.org/disc/9700/) |
| Protection | SafeDisc v2.51.021 + CD-Checks |
| Cracked under | Win XP + Win 10 |
| Tested under | Win 10 |
| Scene-Crack by | [DEVIANCE](https://www.nfohump.com/index.php?switchto=nfos&menu=quicknav&item=viewnfo&id=10506) / [MYTH](https://www.nfohump.com/index.php?switchto=nfos&menu=quicknav&item=viewnfo&id=10510) |

*Needed Tools:*

- Good Old PC (Windows XP)
- x32dbg
- ProcMon 3.1 (Win XP compatible)
- PE tool of your choice (e.g. PE-bear)
- Gimp :)
- The original Game-CD of course ;)
- Lots of sleepless nights
- [Luca D'Amico](https://www.lucadamico.dev/) whote wrote a nice [Paper](https://www.lucadamico.dev/papers/drms/securom/ArabianNights.pdf) on the topic which I partly used as inspiration.

### Disclaimer

- The games are cracked for educational purpose and to regain compatibility with modern systems
- The games are more than 20 years old and can be found freely on the net via e.g. archive.org
- No parts of the game are distributed

# How to Crack

After I had dived into [GTA 2](/games/gta2) I thought I might have a look into GTA 3 as well. As you can read on the net, it seems to use SafeDisc v2.5, so we'll see how this differs from the previous versions.<br>

As always, open the Game in x32dbg (disable ScyllaHide and pass all exceptions) and have a look around. We are instantly detected, but that was no surprise:

![No disc]({{site.url}}/assets/gta3/busted.png)

If we are lucky, they did not change the detection scheme. So let's try the script from last time:

```asm
; Start script at ep

bpd
bphc

$peb_addr = peb()
byte:[$peb_addr + 2] = 0

$addr_NtQueryInformationProcess = NtQueryInformationProcess
$addr_CreateProcessA = CreateProcessA
$addr_CreateFileA = CreateFileA

bphws $addr_NtQueryInformationProcess, x, 1
bphwcond $addr_NtQueryInformationProcess, "arg.get(1)==7"
SetHardwareBreakpointSilent $addr_NtQueryInformationProcess, 1

bphws SetThreadContext, x, 1
bphws WriteProcessMemory, x, 1
bphws ResumeThread, x, 1

SetHardwareBreakpointSilent SetThreadContext
SetHardwareBreakpointSilent WriteProcessMemory
SetHardwareBreakpointSilent ResumeThread

loop:
    erun
    cmp eip, $addr_NtQueryInformationProcess
    jne end
    $pi = dword:[esp+0x0C]
    rtr
    dword:[$pi] = 0
    jmp loop

end:
```

So the script hides the debugger from PEB-checking and checks to NtQueryInformationProcess and breaks on the first call to either _SetThreadContext_, _WriteProcessMemory_ or _ResumeThread_ which were the interesting ones last time.<br>

The disc spins up it does some readings and after about 10 seconds, we break in _ResumeThread_ which is kinda unexpected since that means that the Game process is already up and running.<br>

By snooping around a bit, I discovered, that there does not seem to be an ICD file anymore (ICD = encrypted game in separete file) and also some strange temporary files are created. I guess it's time for Process Monitor (Procmon). The current version does not seem to work under Win XP but version 3.1 seems to work well enough. I played a bit with the filters to reduce the noise and then it started to give a clearer image:

![Temp File]({{site.url}}/assets/gta3/temp_file.png)

So it seems that a temp file is created that is read from the _gta3.exe_ starting at offset 2,811,727 (0x2AE74F). The file is 515,600 bytes in size and is extracted in chunks of 2kb. Having a look with a hex editor at location 0x2AE74F in _gta3.exe_ reveals that the data seems to be encrypted and is decrypted in memory. The temp file itself turns out to be a DLL and as we can see from the imports, the original name seemed to have been _SecServ.dll_ so this is probably part of the SafeDisc driver.

![Temp DLL]({{site.url}}/assets/gta3/temp_dll.png)

Another file is created in the same manner:

![Temp File]({{site.url}}/assets/gta3/temp_file_2.png)

Judging by the strings in the file and the fact that this file will not be removed after the game closes, I get the feeling it's some kind of cleanup worker that removes the temp files, so we will call it _worker.exe_ from now on:

![Cleanup]({{site.url}}/assets/gta3/cleanup.png)

A third file is opened, but nothing gets written to it. My guess is that this is just a dummy file that is monitored by the worker and when the game closes, Windows will release the handle automaticly, until then the worker can not access the file which signals to it that the game is still running.<br>
Then _worker.exe_ is started. More files (_SECDRV.SYS_ and _DrvMgt.dll_) are created and data is written to them. And finally, a fourth file with a temp name is created. Judging from the info we find in our PE tool, the original name was _AuthServ.dll_ and you can find many "please insert CD" strings in it. So this has all to do with interacting with the disc.<br>
Next, multiple files from the disc are opened:

![Files on disc]({{site.url}}/assets/gta3/disc.png)

The _00000001.TMP_ file seems to contain encrypted binary data. The other files are bitmaps and contain the logo that is displayed once the game starts. Interestingly they all contain some small artifacts at different locations which I don't know the reason for yet.

![Artifacts Logo]({{site.url}}/assets/gta3/artifacts.png)

The first 28 bytes from _00000001.TMP_ are read and a threat is created. Then the disc drive is constantly read at various locations, so at that moment the disc is probably checked for authenticity (you can monitor some SCSI commands). Afterwards the thread is closed, so the check routine probably ran in a background thread. Shortly afterwards you can see that the game reads stuff that GTA-fans may recognize: 

![GTA Game files]({{site.url}}/assets/gta3/gta_stuff.png)

So, this in theory means that we never left _gta3.exe_ like we did with SafeDisc v1 and no new process was created. This means that the OEP must be somewhere in the current process. Time to figure out where. So we need what I call an 'anchor' - a known location that will at least tell us that we are past the loader and within the game code. If the anchor stops execution we don't know how far we are in the code, but at least we get a feeling of where the OEP might be.<br>

So as a first rough start, let's use the famous _gta3.img_ and break once we have a _CreateFile_ containing that location. For that we can use the script from GTA 2 and just change the name and function. But I was having a hard time and it did not break. After a few minutes of struggling and thinking I thought I solved the first part of the problem: stupid wide-char strings :D So we need to use CreateFileW. But then again, I could not break on _gta.img_, although _peds.col_ (the second file that is loaded) worked fine and in contrast the file is also opened via _CreateFileA_, so where is _gta3.img_ !?! So far, I have no freakin idea :D Let's use ped.col then. (As it later turned out - at least that's what I think, ProcMon shows the real filenames on disc not the strings that were passed to CreateFile. So if the program requests GTA3.IMG (uppercase), ProcMon still shows the name from disc - hence gta3.img. I think I could have used _stristr_ to solve that issue).

```asm
bpc
bphwc

$addr_CreateFileA = CreateFileA + dis.len(CreateFileA)
bphws $addr_CreateFileA
bphwcond $addr_CreateFileA, "strstr(utf8(arg.get(0)), \"peds.col\") == 1"

$peb_addr = peb()
byte:[$peb_addr + 2] = 0

$addr_NtQueryInformationProcess = NtQueryInformationProcess

bphws $addr_NtQueryInformationProcess, x, 1
bphwcond $addr_NtQueryInformationProcess, "arg.get(1)==7"
SetHardwareBreakpointSilent $addr_NtQueryInformationProcess, 1

loop:
    erun
    cmp eip, $addr_NtQueryInformationProcess
    jne end
    $pi = dword:[esp+0x0C]
    rtr
    dword:[$pi] = 0
    jmp loop

end:
```

Anyways, with the script above we finally break within the game and have a look at unobfuscated code. We can climb up the call stack a few times and see some interesting strings on the stack one of them being "-vms". I have absolutely no Idea what that means but it sounds like a switch that is passed to the game which got me thinking that _GetStartupInfoA_ might be a good place to break next in order to climb our way back to the OEP. I had to break at the 4-th hit:

```asm
bpc
bphwc

$addr_GetStartupInfoA = GetStartupInfoA + dis.len(GetStartupInfoA)
bphws $addr_GetStartupInfoA
bphwcond $addr_GetStartupInfoA, "$breakpointcounter >= 4"

$peb_addr = peb()
byte:[$peb_addr + 2] = 0

$addr_NtQueryInformationProcess = NtQueryInformationProcess

bphws $addr_NtQueryInformationProcess, x, 1
bphwcond $addr_NtQueryInformationProcess, "arg.get(1)==7"
SetHardwareBreakpointSilent $addr_NtQueryInformationProcess, 1

loop:
    erun
    cmp eip, $addr_NtQueryInformationProcess
    jne end
    $pi = dword:[esp+0x0C]
    rtr
    dword:[$pi] = 0
    jmp loop

end:
```

Stepping out and looking around, we start to realize that we are already quite close:

![Close]({{site.url}}/assets/gta3/close.png)

The _push ebp_ at the top and the _nops_ before that look like a classic Entry Point. So we write that down: 0x005C1E70 and add a _"bphws 0x005C1E70, x, 1"_ to the script.
Restart and - booom :) We are there ;)<br>

![OEP]({{site.url}}/assets/gta3/oep.png)

Well, that was kinda easy. Time for the fun part: fixing the IAT.<br><br>

By the way, you can make a snapshot of the VM now so you can save on the time that the loader needs to load the data from the CD and also spare your drive from this jittery SafeDisc thing and you could also remove the CD now, at least for fixing the IAT. Thanks to Luca D'Amico / Antelox for that trick.<br>

Ok, let's have a closer look at the imports. In the image above we can already see a remote call. Step into that call and we see the following code:

![Call]({{site.url}}/assets/gta3/call.png)

Not exactly the same as SafeDisc 1 but kinda similar. If you try to step over the call, bad things happen. There are probably timing checks in there and the return address is probably checked for a 0xCC to detect a snoopy cracker ;) ... at least that's what I thought first, but it turns out that the problem is that the CALL actually never returned where I thought it would (address 0019992D0 in the image), all this "popad, popfd" was probably only added to confuse us, this code is never reached. In order to figure out the actual remote call address and how we return, this is what I did:

I single stepped past the _pushfd_ and placed a hardware breakpoint on the top of the stack. Then hit F9 and landed here:

![At return]({{site.url}}/assets/gta3/ret.png)

See how the address of the procedure that we actually tried to call is on the stack? If we return now, we land in that procedure. And the original return address is also there. Ok, this seems repairable:

- Go through the IAT and check for addresses that are in user sections (I used < 0x21100000)
- Place a HW BP 'on access' on the stack once the first value is pushed in the stub
- Run freely and then the BP will trigger two times (the first time is when the function address is written)
- We should be in the procedure and can retrieve its address 

```asm
$iat_start = 0x0061D3B4
$iat_size = 0x000002D4

bpc
bphwc

$iat_end = $iat_start + $iat_size
$fixed = 0

$eip_org = eip
$esp_org = esp

loop:
    ; Always restore stack first
    esp = $esp_org

    cmp $iat_start, $iat_end
    je end
    $target = dword:[$iat_start]
    cmp $target, 0
    je next
    cmp $target, 0x21100000
    ja next
    $rva = $iat_start - mod.main()
    ; Check if reachable
    cmp mem.valid($target), 1
    jne next
    ; Check if import routine -> has 'pusfd' as second instruction
    $second = $target + dis.len($target)
    $isimport = streq(dis.mnemonic($second), "pushfd")
    cmp $isimport, 1
    jne next
    ; Execute that routine
    eip = $target
    ; Note: x32dbg sometimes swallows an sti right after eip has changed, so we use a BP instead
    bp $second
    erun
    bpc $second
    ; Place HW BP on stack so we break right in function later
    $hw_bp = esp
    bphws $hw_bp, r
    erun
    ; The address is not written to the stack, you will find the value in EDX
    erun
    ; We should be in the real function now
    bphwc $hw_bp
    $fixed += 1
    log "Fix #{u:$fixed}: VA:{p:$iat_start}, RVA:{p:$rva} -> {p:$target} ->{p:eip}"
    dword:[$iat_start] = eip

next:
    $iat_start += 4
    jmp loop

end:
    esp = $esp_org
    eip = $eip_org
```

This works well and the imports are all fixed, but once we start the game, it crashes. I tried to track down the cause and realized that some imports were different to the original. So it looks like we either tripped a tripwire and SafeDisc will mess up the imports if we call them out of order or there is some setup going on that we miss. Let's check. The particular CALL that is messed up is the one at 0x005C85B8. Normally it should call _InitializeCriticalSection_ but it was resolved to _WriteFile_ by the script.<br>

In order to address the issue, I modified the script to only resolve that function (not the whole IAT) and it also returned _WriteFile_, so it looks like the order is not important, but we might miss some setup step. Maybe SafeDisc expects us to call one particular function first that they injected in the game code. After some minutes of poking in the dark and testing different things I found out that the return address on the stack seems to play an important role. Well, that means we need to find a corresponding CALL for every freakin' thunk... ooouf!<br>

Let's try if we can pull that off with a script...<br>

- Go through the IAT and select the addresses that go to a stub (idientified via the address)
- Find a CALL to that stub via a searchpattern
- Push the return address of that CALL on the stack
- Modify EIP to point to the stub
- Use the pushfd trick from above to break in the remote procedure
- Fix the thunk by checking if we know the remote procedure already or if we need to add it to the IAT
- Cleanup. Done ;) 

During the writing of the script I realized that the calls are not unique. Multiple CALLs seem to share the same stub but end up in a different remote procedure. The only common thing is the call to the function at 0x10057CE0 which I have called 'Resolver' and which we will see again later ;)<br>
The Resolver is one hell of a mess and I tried to reverse it but gave up since there are tripwires everywhere and the control flow is fucked up, also the tripwires are silent so sometimes you just end up in a valid but different remote procedure. At one point I decided to just blackbox it.<br>
That makes things slightly more complicated :( Looks like we also have to patch the CALLs itself to point to the right thunk in order to prevent collisions. But the problem is, where do we put the collided thunks? Well, my first approach was to simply use the empty thunks and hope for the best ;)<br>

![Call Stub]({{site.url}}/assets/gta3/call_stub.png)

So in order to make that happen, we need to modify the script so that it will find all CALLs associated with a given thunk not just a single one.<br>

The script ran fine up to a certain point and the imports were restored but from time to time the game crashed completely or exited while the script was still running. I spent a fair amount of time tracking down the cause and I still don't know the real cause but while searching for similarities amongst the imoprts that were crashing, I discovered, that every crashing import had a CALL that was directly located below a _RET_.<br>
Either they are fake-Calls that deliberately crash upon using the Resolver on them, probably placed in the empty space that some linkers leave between compilation units, or they serve internal purposes to SafeDisc. Or maybe these were once some kind of Unit-Testing thingies or some guards or whatever but the underlaying library was removed so the Resolver is unable to find the proc addresses... who knows, I did not dig deeper into that.

![Broken Call]({{site.url}}/assets/gta3/broken_call.PNG)

Also x32dbg could not find any execution paths to these strange CALLs (at least the once I checked), so I gave it a shot and simply ignored every CALL with _RET_ in front of it:

```asm
$iat_start = 0x0061D3B4
$iat_size = 0x000002D4

bpc
bphwc

$iat_start_org = $iat_start
$code_base = mem.base(eip)

log "Code base: {p:$code_base}"

$iat_end = $iat_start + $iat_size
$fixed = 0

$eip_org = eip
$esp_org = esp

loop:
    ; Always restore stack first
    esp = $esp_org

    cmp $iat_start, $iat_end
    je end
    $target = dword:[$iat_start]
    
    cmp $target, 0
    je next
    cmp $target, 0x21100000
    ja next
    $rva = $iat_start - mod.main()
    ; Check if reachable
    cmp mem.valid($target), 1
    jne next
    ; Check if import routine -> has 'pusfd' as second instruction
    $second = $target + dis.len($target)
    ;$isimport = streq(dis.mnemonic($second), "pushfd")
    ;cmp $isimport, 1
    ;jne next

    ; Clear the thunk slot for later
    dword:[$iat_start] = 0

    ; Find a CALL to that routine
    findasm "call [0x{p:$iat_start}]", $code_base
    $call_count = $result
    cmp $call_count, 0
    je next
    $call_id = 0
    process_calls:
        cmp $call_id, $call_count
        je next_fixed 
        $call_from = ref.addr($call_id)
        log "Call from {p:$call_from}"

        ; Check if there is a 'ret' in front of the call
		cmp byte:[$call_from - 1], 0xc3
		jne not_ignored
		jmp next
    
    not_ignored:
        ; Put the return address on the stack
        esp -= 4
        dword:[esp] = $call_from + dis.len($call_from)

        ; Execute that routine
        eip = $target
        ; Note: x32dbg sometimes swallows an sti right after eip has changed, so we use a BP instead
        bp $second
        erun
        bpc $second
        ; Place HW BP on stack so we break right in function later
        $hw_bp = esp
        bphws $hw_bp, r
        erun
        ; The address is now written to the stack, you will find the value in EDX
        erun
        ; We should be in the real function now
        bphwc $hw_bp

        $func_address = eip

        ; Do we have this thunk already?
        $search_iat_start = $iat_start_org
        $search_iat_end = $search_iat_start + $iat_size

        search_thunk:
            cmp $search_iat_start, $search_iat_end
            je thunk_not_found

            cmp dword:[$search_iat_start], $func_address
            jne next_thunk
            ; log "Thunk already in use at {p:$search_iat_start}"
            dword:[$call_from + 2] = $search_iat_start
            jmp search_thunk_done

        next_thunk:
            $search_iat_start += 4
            jmp search_thunk

        thunk_not_found:
        
        ; Search for an empty slot
        $search_iat_start = $iat_start_org
        $search_iat_end = $search_iat_start + $iat_size

        search_empty_slot:
            cmp $search_iat_start, $search_iat_end
            je error_import

            cmp dword:[$search_iat_start], 0
            jne next_slot
            ; log "Empty slot at {p:$search_iat_start} used"
            dword:[$call_from + 2] = $search_iat_start
            dword:[$search_iat_start] = $func_address
            jmp search_thunk_done

        next_slot:
            $search_iat_start += 4
            jmp search_empty_slot
        
        search_thunk_done:

        $call_id += 1
        jmp process_calls

next_fixed:
    $fixed += 1
    log "Fix #{u:$fixed}: VA:{p:$iat_start}, RVA:{p:$rva} -> {u:$call_count} Call(s) fixed"

next:
    $iat_start += 4
    jmp loop

error_import:
    log "Could not find thunk"

end:
    esp = $esp_org
    eip = $eip_org
```

What a monstrosity of a script...<br><br>

After the script finally passed without crashing I dumped and fixed the game just to discover that it still crashes on me. I tracked down the cause and landed on this strange thing:

![Far Jump]({{site.url}}/assets/gta3/far_jump.png)

A JMP to some quite far away portion of the memory, the code there looks something like that:

![Import]({{site.url}}/assets/gta3/import.png)

So basically it first retrieves EIP via the CALL to the next line and then gets the address of a stub and places it on the stack to jump there via a return. The stub looks just like we know it:

![Import Stub]({{site.url}}/assets/gta3/stub.png)

It's like the other stubs, just with an additional return address in front of it. So this is some kind of jump pad code that ends up in a stub and finally in the Resolver:

![Jump Pad]({{site.url}}/assets/gta3/jumppad.png)

It looks like the stub is for one specific JMP in the code. That makes things easier this time.<br>
So how does the script look like?<br>

- Find the extended stub (stub with return address) via a searchpattern
- Subtract 6 from the return address to get the original jump location
- Maybe do a sanity check, to see if there really is a JMP
- Get the address of the remote procedure just as before
- Get the slot in the IAT just as before
- Replace the JMP with a CALL

That was rather straight forward and worked without any hassle. Time to start the game... and it crashed. Dammit! What's the cause this time?<br>

Turns out, SafeDisc has a third Ace up it's sleeve: The *_Jump Pad Driven, Byte-Stealing, Self-Aware Stub_* (JPDBSSAS) :D<br>
This one took nearly four days to solve and is the most whacky/hacky part of the script, also because x32dbg has - at the time of the writing - some bugs I had to maneuver around, but well, it gets the job done ;)<br>
Enough talk, let's see some code.<br>

At - for example - 0x0048C0BD you find a call to a routine that looks like the following:

![Small Trampoline]({{site.url}}/assets/gta3/small_trampoline.PNG)

This is a tiny jump pad that will just put an address on the stack and jump there via a _RET_. So far, nothing special. At the address we see:

![Resolver 2]({{site.url}}/assets/gta3/byte_stealer.png)

This looks and behaves pretty much as the Resolver before, only that I got quite confused on to where it will resolve to. It turned out, that it resolves to the address of the initial CALL from the user code, where the jump pad is but it had altered (decrypted) the code so that the jump pad was replaced with the real code now (compare the addresses):

![Real Code]({{site.url}}/assets/gta3/real_code.png)

Well, that seemed labor intensive but easy enough I thought, I just had to:

- Go through all regular CALLs in the program (Pattern "E8", jep, just 1 byte)
- Check the code at the CALL destination and see if it resembles the jump pad (jep, make sure to include different registers [I think two are used])
- Proceed as above to exit the Resolver and land in the user code
- Done ;)

Well, yes, that works exactly one time and then things go south :( After some while I realized that once we land back in user-code, the return value on the stack points back to the Resolver. That means that - for whatever reason - the Resolver wants to have a second look at things. Well, how bad can it be to place a BP at the original return address and let the Resolver do it's Resolver thingies? Quite bad :D<br>
Turns out, now the Resolver was not crashing anymore and the script ran finde, but the code gets re-scrambled again by the Resolver O.o<br>
Now comes the challenge: How can we reconstruct the code if we must pass execution back to the Resolver but this will ultimately fuck things up again?<br>
Well, let's try for the following:

- Let the Resolver unscramble the code
- Intercept the jump back to the code just as before (BP on pushfd)
- Copy the unscrambled code
- Instantly return via a "eip = [esp]; esp += 4"
- Place BP on original return address, run and break there
- Overwrite jump pad with copied code
- Done

Sounds easy and straight forward, right? Well, there is one samll detail: No one ever told us how many bytes to copy and the information seems nowhere around :(<br>
In order to obtain that information I placed a HW BP on 'write' on the first byte of the scrambled code hoping to land in a loop in the Resolver that would iterater over some control variable. I had to break multiple times since the code seems to be unscrambled in multiple passes, but then I found something:

![Number of Bytes]({{site.url}}/assets/gta3/num_bytes.png)

The _CMP_ is what we were looking for. Strangely, when you run the Resolver for a given stub the first time, this value only holds a quite small value (0x2C in my case), the second time it holds the real value (0x301). I'm guessing for the first time, the data is unscrambled in chunks and for every other run it unscrambles the whole data in one go. Luckily you can always get the total byte-count at ebp+0x5C (at the time your HW BP breaks within the loop).<br>
With that out of the way, we finally know how many bytes to copy to and from the buffer.<br>

Moment of truth: The game starts up and is running fine - yay :) (besides some menu glitches which are probably not caused by our crack).<br>

Since the final script got really long, it is not included in the article, you can fin it [here](/assets/gta3/import_fixer.txt).<br>

In Part II we will have a look at the CD-Checks.<br>

![CD Check]({{site.url}}/assets/gta3/ch_check.jpg)