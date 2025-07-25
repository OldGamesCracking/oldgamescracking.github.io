---
layout: post
author: OldGamesCracking
title: "RollerCoaster Tycoon 2"
date: 2025-06-17
tags:
    - "RollerCoaster Tycoon 2"
    - "Game Cracking"
    - "Reverse Engineering"
    - "SecuRom"
---

## Game Specs

| Name | RollerCoaster Tycoon 2 |
| ------------- | ------------- |
| Release-Date | 10/2002 |
| Redump ID | [35619](http://redump.org/disc/35619/) |
| Protection | SecuROM v4.83.11 |
| Cracked under | Win XP |
| Tested under | Win 10 |
| Scene-Crack by | [RAZOR1911](https://www.nfohump.com/index.php?switchto=nfos&menu=quicknav&item=viewnfo&id=16156) |

![Cover]({{site.url}}assets/rollercoaster_tycoon_2/cover.jpg)

*Needed Tools:*

- Good Old PC (Windows XP)
- x32dbg
- The original Game-CD of course ;)
- CFF Explorer
- [Luca D'Amico](https://www.lucadamico.dev/) whote wrote a nice [Paper](https://www.lucadamico.dev/papers/drms/securom/ArabianNights.pdf) on the topic which I partly used as inspiration.


# How to Crack

To make everything work fine, pass all exceptions to the game.exe and delete all breakpoints. I have not checked it deeply, but I believe that the SEH trick that was already used in the [early versions](/games/hexplore) of SecuROM is still present, they only added a bunch of stuff, so let's better not trip any wires by placing breakpoints of any kind on user code!<br>

Instead, we are first going to find the OEP by the classic trick of putting a breakpoint on _GetCommandLineA_. I found out that I had to stop on the 6th call, which is the second call after the cursor turns into the little spinny CD. If you are lazy to count to 6, use the following script. As always, I made sure not to place the BP on the first instruction to be extra stealthy ;)

```asm
; Make sure to be at the entry point, delete all BP, pass all exceptions
$addr_GetCommandLineA = GetCommandLineA + dis.len(GetCommandLineA)
bp $addr_GetCommandLineA
bpcond $addr_GetCommandLineA, $breakpointcounter==6
erun
```

After we finally break, we step out and have a look around:

![Cover]({{site.url}}assets/rollercoaster_tycoon_2/oep.png)

That smells a lot like we've found the OEP. The first marked call is probably _GetVersion_. So we remember 0x006F09B7 as possible OEP (bookmark it if you like).<br>
Now comes the first tricky part. As you've probably already found out, the code at the OEP is encrypted upon program startup, but since we can not use (HW) breakpoints on user code, we need another 'anchor' that tells us when we are about to make the tail jump. Two classic methods to do this are _VirtualProtect_ and _WriteProcessMemory_. Luca D'Amico suggested to use _WriteProcessMemory_ which can be absolutely fine, but since in theory, the process can just write to it's own memory via memcpy or a simple loop, I will go with _VirtualProtect_. I found out that there is only one call that is interesting to us. Once we've passed that, we can place a HW BP on the OEP and were done. Again, I used the following script to make my life a bit easier:

```asm
; Make sure to be at the entry point, pass all exceptions
bpc
bphwc
$oep = 0x006F09B7
$addr_VirtualProtect = VirtualProtect + dis.len(VirtualProtect)
bp $addr_VirtualProtect
bpcond $addr_VirtualProtect, arg.get(0) < $oep && $oep < arg.get(0) + arg.get(1)
erun
bpc $addr_VirtualProtect
bphws $oep
erun
bphwc $oep
cmt eip, "OEP :)"
```

Once at the OEP, don't forget to make a snapshot of your VM ;)<br>

Time to repair the imports.<br>
If we step into the first intermodular call, we end up in quite a large stub that will ultimately jump to the real function via a _JMP EAX_ at the end. Luckily the stub starts with a _PUSH EBP_ and a corresponding _POP EBP_ directly before the _JMP_, we can use this for our advantage:

![Stub Start]({{site.url}}assets/rollercoaster_tycoon_2/stub_start.png)<br>

![Stub End]({{site.url}}assets/rollercoaster_tycoon_2/stub_end.png)<br>

Simply put a HW BP on the top stack element once the _PUSH EBP_ is executed. Then, when the BP hits, read out EAX. But we have to face one last problem. Remember the image I showed you when we found the OEP? Have a closer look at the marked function calls. Although we expected them to be two different functions (_GetVersion_ and _GetCommandLineA_), they both call the same thunk. If you've read the later articles about SafeDisc, you might recognize this trick. We actually need to make sure that we call the thunk from where it would be called in the normal program flow, or in other words: We need to put the real return address on the stack before we repair the import. So the process goes like this:

- Identify the CALL to the SecuROM stub (there is only one)
- Get all calls within the .text section and execute them
- Go through the original IAT and check if the address is already known
- If so, point the CALL to the known thunk, if not, create a new one

```asm
; Make sure to be at the OEP
$iat_start = 0x008A4000
$iat_size = 0x2D0
$iat_end = $iat_start + $iat_size
$txt_base = mem.base(eip)
$txt_size = mem.size($txt_base)
$txt_end = $txt_base + $txt_size

$eip_org = eip
$esp_org = esp

; Find first relative call, this is used as the SecuROM stub
find $eip_org, FF15????????
$stub_addr = dword:[$RESULT + 2]
log "Stub: {p:$stub_addr}"
$stub_addr = bswap($stub_addr)

; Find all Calls
findmemall 0, "FF15{p:$stub_addr}", -1, module
$num_calls = $RESULT

; Find CALL-ID that is closest to the OEP
$call_id = 0
find_next_call:
    $call_at = ref.addr($call_id)
    cmp $call_at, $eip_org
    ja first_call_found
    $call_id += 1
    jmp find_next_call

first_call_found:
    $call_id_offset = 0
    $offset_positive = 1

loop:
    cmp $call_id_offset, $num_calls
    jae end

    cmp $offset_positive, 1
    je add_offset

subtract_offset:
    cmp $call_id_offset, $call_id
    ja next_call
    $call_id_adjusted = $call_id - $call_id_offset
    jmp get_call

add_offset:
    $call_id_adjusted = $call_id + $call_id_offset
    cmp $call_id_adjusted, $num_calls
    jae next_call

get_call:
    $call_at = ref.addr($call_id_adjusted)

    cmp $call_at, $txt_base
    jb next_call
    cmp $call_at, $txt_end
    jae next_call

    $call_to = dword:[dword:[$call_at + 2]]

    esp = $esp_org
    eip = $call_at
    call sti_safe
    call sti_safe
    $stack_top = esp
    bphws $stack_top, r, 4
    SetHardwareBreakpointSilent $stack_top
    erun
    bphwc $stack_top
    $func_addr = eax

    ; Check if we know that address already
    $thunk_check = $iat_start
find_used_thunk:
    cmp $thunk_check, $iat_end
    je find_empty_thunk_init
    cmp dword:[$thunk_check], $func_addr
    je thunk_found
    $thunk_check += 4
    jmp find_used_thunk

find_empty_thunk_init:
    $thunk_check = $iat_start
find_empty_thunk:
    cmp dword:[$thunk_check], 0
    je empty_thunk_found
    $thunk_check += 4
    jmp find_empty_thunk

empty_thunk_found:
    dword:[$thunk_check] = $func_addr
thunk_found:
    dword:[$call_at + 2] = $thunk_check
    ;log "Call at {p:$call_at} -> {p:$func_addr}"

next_call:
    ; flip
    $offset_positive = 1 - $offset_positive
    cmp $offset_positive, 0
    jne loop
    $call_id_offset += 1
    jmp loop

sti_safe:
    $eip_old = eip
perform_sti:
    sti
    cmp eip, $eip_old
    je perform_sti
    ret

end:
    eip = $eip_org
    esp = $esp_org
    log "Done ;)"
```

You can find the script [here]({{site.url}}assets/rollercoaster_tycoon_2/import_fixer.txt)

If you've read the script thoroughly, you should have realized that the main trick here was to reconstruct the CALLs not in a linear fashion, but in an 'arbitrary' pattern since the stub seems to detect such a scenario, also going through the CALLs in reverse order will be detected by SecuROM and the resolved addresses get messed up. I ended up with a solution where I alternate between one CALL after the OEP then one CALL before the OEP. Luca D'Amico also wrote a [script](https://github.com/x64dbg/Scripts/pull/25) that we could have used. His script goes through the CALLs in chunks which also seems to work.<br><br>

After the imports are restored, SecuROM is defeated :) For bonus points you can cut the SecuROM sections (cms\_t and cms\_d). There is actually one last disc check which is easily defeated by altering an entry in the registry, but I'll leave that to you to figure out. Just make sure to rename the cracked/dumped game.exe back to _rct2.exe_.<br><br>
