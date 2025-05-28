---
layout: post
author: OldGamesCracking
title: "Hexplore"
date: 2025-05-23
tags:
    - "Hexplore"
    - "Game Cracking"
    - "Reverse Engineering"
    - "SecuROM"
---

## Game Specs

| Name | Hexplore |
| ------------- | ------------- |
| Release-Date | 1998 |
| Redump ID | [35457](http://redump.org/disc/35457/) |
| Protection | SecuROM (Version unknown, probably v1) |
| Tested under | Win 10 |
| Scene-Crack by | Laxity |

*Needed Tools:*

- x32dbg
- (Ghidra)

### Disclaimer

- The games are cracked for educational purpose and to regain compatibility with modern systems
- The games are more than 20 years old and can be found freely on the net via e.g. archive.org
- No parts of the game are distributed

### Prologue

This article got quite long and I still haven't figured out all the details on how SecuROm works in it's core, but I guess I have already found out many details and will maybe come back in one of the next articles to perform a deep dive on all aspects. 

# How to Crack (a journey)

I have actually never played this game and don't plan to, I just figured out that it is one of the earliest games to have the SecuROM protection on it and you can get it easily for a few bucks, so maybe we can use it to get a start into cracking SecuROM ;)<br>

By the way, you can get it on GOG.com, Steam and [archive.org](https://archive.org/details/hexplore-germany).<br>

The game won't run properly on my Win 10 machine, but at least I can get to the main menu with the CD inserted and without it gives me an error message, so I guess that's enough to crack it ;)<br>

![No disc]({{site.url}}/assets/hexplore/no_disc.png)

As always, start by loading the _hexplore.exe_ in x32dbg and try to find the error message and then work your way back. By the way, you should disable ScyllaHide or it will spoil the fun ;) For the start, pass all exceptions to the game and place a breakpoint on _MessageBoxA_ via _'bp MessageBoxA'_. You should find the CALL at 00433B76. If you put a software breakpoint directly on the call, the game will hang which is probably a sign that an integrity-check or a debug-check is taking place somewhere. To understand the protection a bit better, remove the software breakpoint and place a hardware breakpoint 'on access' at 00433B76 and hit F9.<br><br>

Aaaand we break ... somewhere 🤔

![Unknown breakpoint]({{site.url}}/assets/hexplore/breakpoint.png)

Have a look around, a few lines above is something you should have seen before:

```asm
pushf
xor byte ptr ss:[ebp-0x01], 0x01
popf
```

The classic trick to generate a _SINGLE\_STEP_ (0x80000004) exception. Place a breakpoint on the _pushf_, restart the program, run until the BP and have a look at the installed SEH handlers. There should be two. The one we are interested in starts at 00433010. So put a BP there, hit F9 and let the exception happen so we land in the SEH handler. A few single steps down the line and we can reconstruct the handler to something like this:

```c
EXCEPTION_DISPOSITION seh_handler(
    PEXCEPTION_RECORD ExceptionRecord,
    PVOID             EstablisherFrame,
    PCONTEXT          ContextRecord,
    PVOID             DispatcherContext)
{
    // Some stuff
    ContextRecord->Dr0 = ContextRecord->Eip + 3;
    ContextRecord->Dr1 = 0;
    ContextRecord->Dr2 = 0;
    ContextRecord->Dr3 = 0;
    ContextRecord->Dr6 = 0;
    ContextRecord->Dr7 = 3;
    // Some stuff
    ContextRecord->EFlags |= TRAP_FLAG;
    // Some stuff
    if (*((uint8_t*)ContextRecord->Eip) == 0xcc)
    {
        // Things happen
    }
    // Some stuff
    return ExceptionContinueExecution;
}
```

Which will kill all our hardware breakpoints except the first one, which is set 3 bytes after where the exception occured (which is in the middle of the CALL?!?). Moreover the Trap flag is set again so it will immeadeately call the SEH handler again. And also the location where Eip points to is checked for an INT3 breakpoint. There are some flags that are set/cleared (0x590D74, 0x590D70, 0x591240, 0x5911D0, 0x590DB0) which I could not figure out immeadeately. To get a better understanding, place a BP on all occurrences of these flags and restart the program.<br>
The first time, we break at 004356D0 where 0x5911D0 is set to some location (004361B4) which looks like a function that just returns zero, so this might be a function pointer. 0x591240 is set to 0x4338B0 one line below. 0x4338B0 is the start of some routine, so it's probably also some function pointer. At 004356ff it's set to the section base. At address 004357A0 the value at 0x590D74 is set to 1 (true). This does not make much sense yet so restart the program and let's have a fresh look at the SEH. This time we have a closer look at the variables and make some guesses:<br>

```c
// Note: I did not came up with this right from the start
// I went over it multiple times and made smaller changes every time

EXCEPTION_DISPOSITION seh_handler(
    PEXCEPTION_RECORD ExceptionRecord,
    PVOID             EstablisherFrame,
    PCONTEXT          ContextRecord,
    PVOID             DispatcherContext)
{
    switch (ExceptionRecord->ExceptionCode)
    {
        case (STATUS_ACCESS_VIOLATION):
        {
            // later ;)
        }
        
        case (STATUS_SINGLE_STEP):
        {
            if ((ContextRecord->Dr6 & 0x0f) != 0)
            {
                ContextRecord->Dr0 = 0;
                ContextRecord->Dr1 = 0;
                ContextRecord->Dr2 = 0;
                ContextRecord->Dr3 = 0;
                ContextRecord->Dr6 = 0;
                ContextRecord->Dr7 = 3;
            }

            if (firstTime && some_state == 0)
            {
                ContextRecord->Dr0 = ContextRecord->Eip + 3;
                ContextRecord->Dr1 = 0;
                ContextRecord->Dr2 = 0;
                ContextRecord->Dr3 = 0;
                ContextRecord->Dr6 = 0;
                ContextRecord->Dr7 = 3;

                firstTime = false;
                some_state = 1;
            }
            else
            {
                if (firstTime && some_state == 1)
                {
                    firstTime = false;
                    some_state = 0;
                }
            }
            
            if (some_state == 1)
            {
                ContextRecord->EFlags |= TRAP_FLAG;
            }
            
            if (some_state == 2)
            {
                ContextRecord->EFlags |= TRAP_FLAG;

                some_state = 1;
            }

            if (some_state == 0)
            {
                ContextRecord->EFlags &= ~TRAP_FLAG;

                ContextRecord->Dr0 = 0;
                ContextRecord->Dr1 = 0;
                ContextRecord->Dr2 = 0;
                ContextRecord->Dr3 = 0;
                ContextRecord->Dr6 = 0;
                ContextRecord->Dr7 = 3;
            }

            if (ContextRecord->Eip < base_ptr || ContextRecord->Eip > end_of_code)
            {
                /* We landed outside of the code */
                some_state == 2;

                /* Clear trap flag */
                ContextRecord->EFlags &= ~TRAP_FLAG;

                ContextRecord->Dr0 = *ContextRecord->Esp;
                ContextRecord->Dr1 = 0;
                ContextRecord->Dr2 = 0;
                ContextRecord->Dr3 = 0;
                ContextRecord->Dr6 = 0;
                ContextRecord->Dr7 = 3;
            }

            if (some_state == 1)
            {
                uint8_t nextInstruction = *((uint8_t*)ContextRecord->Eip);

                if (nextInstruction == 0xcc)
                {
                    ContextRecord->Eip = base_ptr + some_func(base_ptr - end_of_code);
                }

                instruction_counter++;

                integrity_check += nextInstruction;

                if (reset_integrity_check)
                {
                    reset_integrity_check = false;
                    integrity_check = 0;
                    instruction_counter = 0;
                }
            }
            
            return ExceptionContinueExecution;
        }
    }

    return ExceptionContinueSearch;
}
```

So it goes something like this:

* The program raises a SINGLE\_STEP exception via setting the trap flag
* A hardware BP is installed and the trap flag is set
* Execution is resumed, but we land in the SEH right again, this time from within OS code since the next instruction was the CALL at 004357B6. The trap flag is cleared, a HW BP is set to the return address of the call, hence we break again, right after the call. 
* Because of the HP BP, we land in the SEH handler the third time. This time the status bits in Dr6 are set. All HW BPs are cleared, but the trap flag is set again.
* The SEH handler is called a fourth time but from now on we basically just repeat the previous steps until either an INT3 is found or a ACCESS_VIOLATION exception is risen (we will see that later).

Or in other words, the whole program is single-stepped, intermodular calls are stepped over and INT3 breakpoints set by us are searched and if one is found some yet unexplored function is called.<br><br>

Ok, this will be kinda annoying so we need to find a way so that we can place breakpoints but do not trigger the checks in the SEH which will alter the EIP to some place I have not figured out yet.
For the moment it would be best if we NOPed out the instruction at 004357AF so the SEH is never called in the first place.<br><br>

```
000357AF:80->90
000357B0:75->90
000357B1:FF->90
000357B2:01->90
```

Anyways, where were we? I have kinda lost track :D But during all that stuff going on in the SEH I realized that the CALL that will ultimatively trigger the badboy-messagebox is at 00435ED0 and the location it is calling (004338B0) is CALLed multiple times between 004357AD (first SEH trigger) and 00435ED0 (badboy). So maybe we should just pretend nothing happened, set a breakpoint on 004357B6 and step over a few calls to get a better understanding of the code.<br><br>

The first thing we can write down is that the value at 0x00590D8C probably means something like _is\_win\_nt_ and depending on that either "cms32\_nt.dll" or "cms32\_95.dll" is loaded. From that DLL many functions are imported and the first one that is called is _C32_ (also exported as _FGDM32_ or _GGDM32_) at 00435C73. Step into it and... well, that's not much. Probably something like:

```c
/// <summary>
/// Guessed name: C??? 
/// De-/Initializes the Library
/// </summary>
/// <param name="init"></param>
/// <returns></returns>
BOOL C32(BOOL init)
{
    (void)init;

    return TRUE;
}
```

Next we have a CALL to _TC32_ at 00435CA0 which I can not make much sens of right now, my best guess would be that it initializes some keys, but we will see that probably later.<br><br>

Right after that we have a call with two parameters. You will realize that this is just good old _strcpy_ but the first time it is called, no strings are passed so it's hard to see at the moment.
Then follows a CALL to _GGDM32_ (alias for _C32_) which is probably a leftover and probably means something like "Get Global DOS Memory" (judging by the error message) and finally the first real interesting function: _GNOCD32_.

```c
/// <summary>
/// Guessed name: Get Number Of CD Drives
/// </summary>
/// <param name="out_numberOfCDDrives">The number of CD drives present in the system</param>
/// <param name="first">The letter of the first drive</param>
/// <returns>??? (see return)</returns>
BOOL GNOCD32(DWORD *out_numDrives, DWORD *first)
{
    /** Start with letter Z */
    DWORD presentMask = 1 << 25;
    
    *out_numDrives = 0;

    const DWORD drives = GetLogicalDrives();

    int driveLetter = 25;

    while (driveLetter >= 0)
    {
        if ((drives & presentMask) != 0)
        {
            /** Device is present */
            char testStr[4] = { 'A' + (char)driveLetter, ':', '\\', '\0'};

            if (GetDriveTypeA(&testStr[0]) == DRIVE_CDROM)
            {
                *first = driveLetter;
                *out_numDrives += 1;
            }
        }

        /** Next drive */
        presentMask >>= 1;
        driveLetter--;
    }

    /** Probably a bug and should rather be "*out_numDrives != 0" */
    return out_numDrives != NULL;
}
```

By the way, the code is mainly my own recreation and is not 1:1 the same but the functionality should be idential and you get the idea.<br><br>

Next up we have a small routine starting at 00435CF1 that will decrypt 30 bytes at 0x58D488 (I called it expected\_volume\_identifier) with the bytes starting at 0x58D489. The resulting data is a string containing "Hexplore".

![Volume Identifier]({{site.url}}/assets/hexplore/volume_identifier.png)

Next up we will see that the _first_ value that _GNOCD32_ returned is used to create a string of the following form: "\\\\.\\\letter:" which is then used in conjunction with _CreateFileA_ to open the drive as a raw device.

![Raw Access]({{site.url}}/assets/hexplore/raw_access.png)

The returned handle is then given to _GDS32_ that checks if a CD is present. So from now on we need a CD in the drive (or an image as we will see later).

```c
#define DRIVE_DISC_PRESENT      0x000
#define DRIVE_DISC_NOT_PRESENT  0x800

/// <summary>
/// Guessed name: Get Drive Storage
/// Checks if a CD is present in the drive 
/// </summary>
/// <param name="letter"></param>
/// <param name="out_discPresent">True if a CD is present</param>
/// <param name="hDrive">The handle of the drive</param>
BOOL GDS32(DWORD letter, DWORD *out_discPresent, HANDLE hDrive)
{
    (void)letter;

    DWORD bytesReturned;

    *out_discPresent = DRIVE_DISC_PRESENT;

    const BOOL result = DeviceIoControl(
        hDrive,
        IOCTL_STORAGE_CHECK_VERIFY,
        NULL,
        0,
        NULL,
        0,
        &bytesReturned,
        NULL
    );

    if (!result)
    {
        *out_discPresent = DRIVE_DISC_NOT_PRESENT;
    }

    return result;
}
```

Notice how a special value is returned and not a simple true/false. In case the CD is present, the bitmask 0x00000200 (I called it CHECK_DISC_PRESENT) is applied to 
0x00590DB8 which we don't know the meaning of yet, but I guess it is important.<br><br>

The next function call follows right ahead in the form of _INQ32_:

```c
typedef struct
{
    BYTE OperationCode;
    BYTE CDBInfo : 3;
    DWORD LogicalBlockAddress : 21;
    BYTE Length;
    BYTE Control;
} CDB6_t;

typedef struct
{
    SCSI_PASS_THROUGH passthrough;
    SENSE_DATA sense_info;
    BYTE buffer[0x24];
} SCSI_PASS_THROUGH_WITH_SENSE;

/// <summary>
/// Guessed name: Inquiry
/// Sends Inquiry command to the device
/// </summary>
/// <param name="letter"></param>
/// <param name="unknown"></param>
/// <param name="hDrive"></param>
/// <returns></returns>
BOOL INQ32(DWORD letter, DWORD *unknown, HANDLE hDrive)
{
    (void)letter;

    SCSI_PASS_THROUGH_WITH_SENSE pt = { 0 };

    pt.passthrough.Length = sizeof(SCSI_PASS_THROUGH);
    pt.passthrough.PathId = 0;
    pt.passthrough.TargetId = 0;
    pt.passthrough.Lun = 0;

    /*
     * For more details on CDB see https://www.t10.org/ftp/t10/document.00/00-269r2.pdf
     * or https://www.seagate.com/files/staticfiles/support/docs/manual/Interface%20manuals/100293068j.pdf
     */
    pt.passthrough.CdbLength = CDB6GENERIC_LENGTH;
    pt.passthrough.SenseInfoLength = sizeof(SENSE_DATA); // 0x18
    pt.passthrough.DataIn = SCSI_IOCTL_DATA_IN;
    pt.passthrough.DataTransferLength = 0x24;
    pt.passthrough.TimeOutValue = 2;
    pt.passthrough.DataBufferOffset = offsetof(SCSI_PASS_THROUGH_WITH_SENSE, buffer);
    pt.passthrough.SenseInfoOffset = offsetof(SCSI_PASS_THROUGH_WITH_SENSE, sense_info);
    
    CDB6_t *cdb = (CDB6_t*)&pt.passthrough.Cdb;
    cdb->OperationCode = SCSIOP_INQUIRY;
    cdb->CDBInfo = 0;
    cdb->LogicalBlockAddress = 0;
    cdb->Length = 0x24;
    cdb->Control = 0;

    DWORD bytesReturned = 0;

    const BOOL result = DeviceIoControl(
        hDrive,
        IOCTL_SCSI_PASS_THROUGH,
        &pt,
        sizeof(SCSI_PASS_THROUGH),
        &pt,
        sizeof(pt),
        &bytesReturned,
        NULL
    );

    if (result)
    {
        // Things happen
    }

    return result;
}
```

Strangely the command does not work but the return value seems not to be unused anyways.<br><br>

Time for the next function: _RLOS32_:

```c
/// <summary>
/// Guessed name: Read L??? O??? Sector
/// Reads 1 sector (0x800, 2048 bytes) of user data or
/// 1 sector (0x930, 2352 bytes) of raw data
/// </summary>
/// <param name="letter"></param>
/// <param name="unused"></param>
/// <param name="buffer"></param>
/// <param name="useDeviceIOControl"></param>
/// <param name="hDrive"></param>
/// <returns></returns>
BOOL RLOS32(DWORD letter, DWORD sector, BYTE *buffer, BOOL rawData, HANDLE hDrive)
{
    (void)letter;

    BOOL result = FALSE;

    DWORD bytesRead;

    if (!rawData)
    {
        const DWORD READ_SIZE = 0x800;

        OVERLAPPED overlapped;
        overlapped.Internal = 0;
        overlapped.InternalHigh = 0;
        overlapped.hEvent = 0;
        overlapped.OffsetHigh = 0;
        overlapped.Offset = sector * 2048;

        result = ReadFile(hDrive, buffer, READ_SIZE, (DWORD*)&bytesRead, &overlapped);

        if (!result || (bytesRead < READ_SIZE))
        {
            result = FALSE;
        }
    }
    else
    {
        SCSI_PASS_THROUGH_WITH_SENSE pt = { 0 };

        pt.passthrough.Length = sizeof(SCSI_PASS_THROUGH);
        pt.passthrough.PathId = 0;
        pt.passthrough.TargetId = 0;
        pt.passthrough.Lun = 0;

        /*
         * For more details on CDB see https://www.t10.org/ftp/t10/document.00/00-269r2.pdf
         * or https://www.seagate.com/files/staticfiles/support/docs/manual/Interface%20manuals/100293068j.pdf
         */
        pt.passthrough.CdbLength = sizeof(_CDB::_READ_CD);
        pt.passthrough.SenseInfoLength = sizeof(SENSE_DATA); // 0x18
        pt.passthrough.DataIn = SCSI_IOCTL_DATA_IN;
        pt.passthrough.DataTransferLength = 0x930;
        pt.passthrough.TimeOutValue = 2;
        pt.passthrough.DataBufferOffset = (ULONG_PTR)buffer;
        pt.passthrough.SenseInfoOffset = offsetof(SCSI_PASS_THROUGH_WITH_SENSE, sense_info);

        _CDB::_READ_CD* cdb = (CDB::_READ_CD*)&pt.passthrough.Cdb;
        cdb->OperationCode = SCSIOP_READ;
        cdb->StartingLBA[0] = (BYTE)(sector >> 24);
        cdb->StartingLBA[1] = (BYTE)(sector >> 16);
        cdb->StartingLBA[2] = (BYTE)(sector >> 8);
        cdb->StartingLBA[3] = (BYTE)(sector >> 0);
        cdb->TransferBlocks[0] = 0;
        cdb->TransferBlocks[1] = 0;
        cdb->TransferBlocks[2] = 1;

        cdb->Reserved2 = 1;
        cdb->ErrorFlags = 1;
        cdb->IncludeEDC = 1;
        cdb->IncludeUserData = 1;
        cdb->HeaderCode = 0;
        cdb->IncludeSyncData = 0;

        cdb->SubChannelSelection = 0;
        cdb->Reserved3 = 0;
        cdb->Control = 0;

        BOOL result = DeviceIoControl(
            hDrive,
            IOCTL_SCSI_PASS_THROUGH,
            &pt,
            sizeof(SCSI_PASS_THROUGH),
            &pt,
            sizeof(pt),
            &bytesRead,
            NULL
        );

        if (pt.passthrough.ScsiStatus == 2) // RAM error ?
        {
            result = false;
        }
    }

    return result;
}
```

RLOS32 reads sector 16 of the CD where the Primary Volume Descriptor (PVD) sits. It then compares the Volume Identifier with the string we decrypted earlier ("Hexplore"). If it matches, another flag is set in the value at 0x00590DB8: 0x00002000 (I called it CHECK_DISC_NAME_MATCHES).<br>

A few instructions down the road the flags are checked and if they are ok, we land on the next function _ADI32_:

```c
/// <summary>
/// Guessed name: Acquire Disc Info
/// Reads the TOC of the disc and returns it's size (in sectors)
/// </summary>
/// <param name="letter"></param>
/// <param name="out_firstTrackId"></param>
/// <param name="out_lastTrackId"></param>
/// <param name="out_discSize"></param>
/// <param name="hDrive"></param>
BOOL ADI32(DWORD letter, DWORD *out_firstTrackId, DWORD *out_lastTrackId, DWORD *out_discSize, HANDLE hDrive)
{
    (void)letter;

    DWORD bytesReturned;
    CDROM_TOC toc;

    const BOOL result = DeviceIoControl(
        hDrive,
        IOCTL_CDROM_READ_TOC,
        NULL,
        0,
        &toc,
        sizeof(toc),
        &bytesReturned,
        NULL
    );

    if (result)
    {
        *out_firstTrackId = toc.FirstTrack;
        *out_lastTrackId = toc.LastTrack;
        DWORD tocLength = (((DWORD)toc.Length[0]) << 8) + (DWORD)toc.Length[1] - 2;       
        DWORD tracks = tocLength / sizeof(TRACK_DATA);

        DWORD track = 0;

        while (track < tracks)
        {
            TRACK_DATA *data = &toc.TrackData[track];

            if (data->TrackNumber == 0xaa)
            {
                *out_discSize = data->Address[1] * 60 * 75 + data->Address[2] * 75 + data->Address[3];

                break;
            }

            track++;
        }
    }

    return result;
}
```

If the disc has more than one track (firstTrackId != lastTrackId), the function _ATI32_ is called, but this is not the case here, so I did not check it.<br>
The returned disc size is then compared against a hardcoded value at 0x0058D4D4 (should be 0004BC35) and if it matches, we earn the next flag 0x00040000 (CHECK_DISC_SIZE_MATCHES).<br><br>

At 00435FDD starts a routine that reads 491 DWORDs from the PVD and sums them up:

```c
DWORD sum = 0;
BYTE pvd[];

for (int i = 0x15; i < 0x200; i++)
{
    DWORD value = ((PDWORD)&pvd)[i];

    value = _byteswap_ulong(value);

    sum += value;
}
```

I couldn't really find anything specific about the start (84) and end addresses (512), they might have been chosen at random. The sum is then again compare to a hardcoded value (0x22524560 at 0x0058D4D0) and if it matches, a new checkpoint is passed: 0x01000000 (CHECK_DISC_PVD_MATCHES).<br><br>

Next, we land in a function at 00433C10. It seems to do some strange calculations, from the look of it I would say there are are two nested loops and it looks a bit like a decryption routine. Thanks to Ghidra I could break it down a bit:

```c
for (int i = 0; i < 4; i++)
{
    DWORD sector = sectors_org[i];
    
    for (int j = 0; j < 6; j++)
    {
        uint bVar5 = (char)j * 105 + 75;
        
        sector += (byte)lookup[i + (uint)integrity_check - (uint)bVar5];
        
        sectors_new[i * 0x6 + j] = sector;
    }

    integrity_check += 151;
}
```

So, basically it takes 4 sector-addresses (as I found out later) and increments each address six times by some random value. But what is integrity_check? This value is generated in the SEH handler and is based upon the instructions we have passes by so far. So if anything went slightly unexpected since the last _reset_integrity_check_ (at 00433C28), the values are all messed up.<br>
Ok, now it got me thinking. Normally the exact values are not of our concern since we could just break after the routine and just look in the memory at 0x58D4C0, but I got curious what the actual offsets are :) So we need to find a way to stop the SEH at the right time so it can tell us the exact value of "i + (uint)integrity_check - (uint)bVar5". This exact moment is at address 00433CF7. So let's try to write a small debugger script that will do exactly that:

```asm
bp 0x004332D1
bpcond 0x004332D1, eax==0x00433CF7 || eax==0x00433d12
break_counter = 0

perform_breaks:
	erun
	cmp eax, 0x00433CF7
	jne lookup
	ic_value = byte:[0x00590DB4]
	jmp perform_breaks
lookup:
	cmp eax, 0x00433d12
	jne perform_breaks
	inc break_counter
	ctx = dword:[ebp + 0x10]
	eax_val = dword:[ctx + 0xb0]
	log "#{u:break_counter}: {u:ic_value} -> lookup[{u:eax_val}]"
	cmp break_counter, 0x18
	jne perform_breaks
```

We get the following output:

```
#1: 211 -> lookup[0]
#2: 43 -> lookup[1]
#3: 149 -> lookup[2]
#4: 255 -> lookup[3]
#5: 105 -> lookup[4]
#6: 211 -> lookup[5]
#7: 193 -> lookup[1]
#8: 43 -> lookup[2]
#9: 149 -> lookup[3]
#10: 255 -> lookup[4]
#11: 105 -> lookup[5]
#12: 211 -> lookup[6]
#13: 193 -> lookup[2]
#14: 43 -> lookup[3]
#15: 149 -> lookup[4]
#16: 255 -> lookup[5]
#17: 105 -> lookup[6]
#18: 211 -> lookup[7]
#19: 193 -> lookup[3]
#20: 43 -> lookup[4]
#21: 149 -> lookup[5]
#22: 255 -> lookup[6]
#23: 105 -> lookup[7]
#24: 211 -> lookup[8]
```

So it looks like they managed to construct the values in the lookup so that always 6 consecutive bytes are read from the table.<br>

For those of you who are playing along at home, this is the final result (24 sector addresses):

![Sectors]({{site.url}}/assets/hexplore/sectors.png)

But, what are these addresses? We'll see later let's first have a look at _LD32_ down the line:

```c
/// <summary>
/// Guessed name: Lock Drive
/// Enables or disables the mechanism that ejects media.
/// </summary>
/// <param name="letter"></param>
/// <param name="lock"></param>
/// <param name="hDrive"></param>
BOOL LD32(DWORD letter, BOOL lock, HANDLE hDrive)
{
    (void)letter;

    DWORD bytesReturned;
    BYTE buffer[1];

    buffer[0] = lock ? 1 : 0;

    const BOOL result = DeviceIoControl(
        hDrive,
        IOCTL_STORAGE_MEDIA_REMOVAL,
        &buffer[0],
        sizeof(buffer),
        NULL,
        0,
        &bytesReturned,
        NULL
    );

    return result;
}
```

This simply locks/unlocks the drive (for whatever reason).<br><br>

Now comes the most complicated part of it all, so complicated that I couldn't even give it much meaning with Ghidra. From hooking some functions, I could figure out that the code must do something like that:

- Read a random sector via _RLOS32_
- Seek to a random sector 65 times via _STS32_
- Repeat the above two steps 4 times

The sectors seem to come from the sectors we have calculated before, so in the first round it reads/seeks somewhere in the 0xA0xx..0xA2xx region, in the second round in the 0xA3xx..0xA6xx region and so on. The sectors probably all have the same content so they are interchangeable (at least after some calculations/XORs or whatever). Interestingly _RLOS32_ is always used with rawData=false, so only user data is read and you could easily burn the CD or use a simple .ISO, no need for complicated copy software.<br><br>

Sadly that's all I can say right now, even in Ghidra and even after I cleaned up the code it's still +300 lines of meaningless nonsense so I did not understand much of it :(<br><br>

By the way, if you would like to kill the SEH at any given time to place a BP somewhere, first place a BP on 004332E5, then place the BP at the desired location and let the BP in the SEH kick in. After that, simply execute the following script:

```
; undo the JNE
eip -= 2
eflags &= 0xffffffbf
rtr
$ctx = dword:[esp+0x0c]
; Disable HW PB
dword:[$ctx + 0x18], 0
; Unset trap flag
dword:[$ctx + 0xC0] &= 0xfffffeff
run
```

For the record, this is what _STS32_ looks like:

```c
/// <summary>
/// Guessed name: Seek To Sector
/// The Seek Extended command (see table 186) requests that the disk drive seek to the specified logical block address.
/// </summary>
/// <param name="letter"></param>
/// <param name="A"></param>
/// <param name="hDrive"></param>
/// <returns></returns>
BOOL STS32(DWORD letter, DWORD sector, HANDLE hDrive)
{
    (void)letter;

    SCSI_PASS_THROUGH_WITH_SENSE pt = { 0 };

    sector -= some_offset[sector_counter % 9];

    pt.passthrough.Length = sizeof(SCSI_PASS_THROUGH);
    pt.passthrough.PathId = 0;
    pt.passthrough.TargetId = 0;
    pt.passthrough.Lun = 0;

    /*
     * For more details on CDB see https://www.t10.org/ftp/t10/document.00/00-269r2.pdf
     * or https://www.seagate.com/files/staticfiles/support/docs/manual/Interface%20manuals/100293068j.pdf
     */
    pt.passthrough.CdbLength = sizeof(CDB::_SEEK);
    pt.passthrough.SenseInfoLength = 0x18;
    pt.passthrough.DataIn = SCSI_IOCTL_DATA_IN;
    pt.passthrough.DataTransferLength = 0;
    pt.passthrough.TimeOutValue = 2;
    pt.passthrough.DataBufferOffset = offsetof(SCSI_PASS_THROUGH_WITH_SENSE, buffer);
    pt.passthrough.SenseInfoOffset = offsetof(SCSI_PASS_THROUGH_WITH_SENSE, sense_info);

    CDB::_SEEK *cdb = (CDB::_SEEK*)&pt.passthrough.Cdb;
    cdb->OperationCode = SCSIOP_SEEK;
    cdb->LogicalUnitNumber = 0;
    cdb->LogicalBlockAddress[0] = (BYTE)(sector >> 24);
    cdb->LogicalBlockAddress[1] = (BYTE)(sector >> 16);
    cdb->LogicalBlockAddress[2] = (BYTE)(sector >> 8);
    cdb->LogicalBlockAddress[3] = (BYTE)(sector >> 0);

    DWORD bytesReturned = 0;

    const BOOL result = DeviceIoControl(
        hDrive,
        IOCTL_SCSI_PASS_THROUGH,
        &pt,
        sizeof(SCSI_PASS_THROUGH),
        NULL,
        0x50, // ???
        &bytesReturned,
        NULL
    );

    return result;
}
```

Back on topic... Step out of the function (the one starting at 00433C10, if you've lost track where we are), step over some _memcpy_ and a _CloseHandle_ (closes the raw drive access) and we land on this bit:

```c
mov eax, 0x42BDE0
nop
nop
jmp 0x0043618C
pop eax
jmp eax
```

If we ignore the first jump, this looks suspiciously like an OEP jump, so we should definitely keep an eye on 0x42BDE0. At the moment there is some nonsense, but maybe this will change soon ;)<br><br>
The following CALL at 0x00436191 will first take the address of the (what we think) OEP and replace the last 3 niblles with a hard-coded value (0xce0). This is probably the start of the game-code. It then reads the hardcoded size of the encrypted code (0x200 bytes) and allocates this size. Afterwards it reads the amount of bytes from the start of the code (0x0042bc02), decrypts it and writes it back. So if we have a look at 0042BDE0 afterwards, we will see something that very much looks like the start of a program :)<br>
The next CALL will simply check the integrity of the decryption (which will of course fail if you've single stepped throuh the code before).

By the way, if you wonder when the STATUS_ACCESS_VIOLATION-branch of the SEH will kick in (if you haven't already figured out because you program crashed), have a look at the CALL to 00434B50 at 00434887. In there are strange instructions:

![Exception]({{site.url}}/assets/hexplore/exception.png)

This will trigger an exception and we land in the SEH, but this time in the _STATUS\_ACCESS\_VIOLATION_ branch:

```c
case (STATUS_ACCESS_VIOLATION):
{
    ContextRecord->Eax = 0x592924;

    ContextRecord->EFlags |= TRAP_FLAG;

    firstTime = true;

    ContextRecord->Dr1 = 0;
    ContextRecord->Dr2 = 0;
    ContextRecord->Dr3 = 0;
    ContextRecord->Dr0 = ContextRecord->Eip + 6;
    ContextRecord->Dr6 = 0;
    ContextRecord->Dr7 = 3;

    return ExceptionContinueExecution;
}
```

Or in other words, EAX is filled with a new value and the instruction is repeated again.<br><br>

Ok, back on topic. We are nearly there. We finally land at the exit function, this time with 0x2c as parameter. As I said, there is not much going, mostly cleanup stuff etc. But for the first time, we exit normally, without a messagebox :) Instead we JMP, POP, JMP aaaand we are there :D<br><br>

WOW! What a journey. You can now dump the game with Scylla (use the normal result, not the advanced one: VA: 00595250, Size: 000001BC), get a bunch of errors and after some digging you find out, that Microsoft has replaced some of the original functions with some place-ins to increase compatibility but decrease debugability :)<br>
I fixed them manually by having a look at the addresses. Sometimes you can already see Debug Strings with the name of the function, sometimes you need to set the EIP to the import manually and step in a but, most of the time the name pops up somewhere quite fast.

![Fixing IAT]({{site.url}}/assets/hexplore/imports.png)

After all is fixed and dumped, remove the CD, start the dumped exe and you are greeted with one last enemy:

![Last Stand]({{site.url}}/assets/hexplore/cd_check.png)

I leave that to you to figure this out, it's really easy ;)<br><br>

But wait a minute, there is one last thing that comes to my mind. What was the last instruction? _JMP EAX_ ?

![JMP]({{site.url}}/assets/hexplore/jmp.jpg)

Oh, come on! They did not encrypt that part? So all we had to do was:

```asm
findasm "jmp eax"
bp ref.addr(0)
erun
sti
```

Shiiiiit :D

* * *

# How did the Pros do it?

Coming