---
layout: post
author: OldGamesCracking
title: "Spider-Man"
date: 2025-05-18
tags:
    - "Spider-Man"
    - "Game Cracking"
    - "Reverse Engineering"
---

## Game Specs

| Name | Spider-Man |
| ------------- | ------------- |
| Release-Date | 2001 |
| Redump ID | [38060](http://redump.org/disc/38060/) |
| Protection | CD-Check |
| Tested under | Win 10 |
| Scene-Crack by | ??? |

# How to Crack

This game has probably the most simplest form of a protection. As far as I can tell the game does not use any anti-debugging-tricks or copy-protection whatsoever, just a simple CD-Check, but we will see this under _'Protection Details'_.<br>

To crack it, open the _SpideyPC.exe_ in your favorite debugger (I use x86dbg) and let it run without the CD inserted. You should get a messagebox with the famous message:<br>

![CD-Check]({{site.url}}/assets/spider_man/cd_check.png)

Now use the ages-old trick to locate the messagebox via 'Pause Debugger' + 'Run to user code' and then press the Ok button. You should break right after the messagebox. Look around, the check and the jump are right above:

![check]({{site.url}}/assets/spider_man/check.png)

Place a breakpoint on the call and restart the program. Once you break there, observe ESP before and after the call (in both cases it should be 0x0019FE34) which means that no parameter was passed to the CALL and we can savely place the following instructions right at the start of the subroutine:

```asm
xor al, al
ret
```

Well, that was it, the game should run without the CD now ;)<br>


* * *

# Protection Details

If you're interested how the protection works, step into the CALL to 005153E0. There you will find, that in the first CALL to 00516250 it gets the path to the game exe, appends _"texture.dat"_ and reads the file content (from the installdir).<br>
After that, it XOR-decrypts the content of the file starting from the 4th byte with some hard-coded bytes starting at 00560140 RVA (00160140 as file offset). The decrypted data is the string "V01.000 Overburn" followed by some zeros and then the string "V.2".<br>
The "V." part of the second string is then checked (probably some simple integrity check).<br>
In the CALL to 00516470 the good old _GetDriveTypeA_ is used to find a CD-Drive and then _mciSendCommand_ is used to first open the drive via _MCI\_OPEN_ (0x803) (_Open_ as in open a file handle, not open the tray :D).<br>
Then _MCI\_SET_ (0x80D) is used together with _MCI\_SET\_TIME\_FORMAT_ (0x400) and _MCI\_FORMAT\_MILLISECONDS_ (0) as parameter to probably set the returned values of the following commands in milliseconds, which is strange, since we do not have a music CD but a CD-ROM, but I guess they simply misused the API to get a vague reading of the CD size in bytes.<br>
Then _MCI\_STATUS_ (0x814) together with _MCI\_STATUS\_ITEM_ (0x100) and dwItem=MCI\_STATUS\_NUMBER\_OF\_TRACKS (3) is used to to query the number of tracks the disc has. It has 2 by the way.<br>
The next call is again a _MCI\_STATUS_ (0x814) with _MCI\_STATUS\_ITEM_ (0x100), but with the option MCI\_TRACK (0x10) and dwItem=MCI\_STATUS\_LENGTH (1) and dwTrack=1 (2, ...), or in other words, it gets the size of the given track, which should be 00328CF1 and 00129573 for the two tracks (the values are never used by the way).<br>
Another _MCI\_STATUS_ (0x814) with _MCI\_STATUS\_ITEM_ (0x100) and dwItem=MCI\_STATUS\_LENGTH (1) follows, but without _MCI\_TRACK_ which will return the length (size) of the whole CD. 00452263 is returned, the value is then compared against 004434F0 and 0049B330 and as long as it is between these two, the program is happy.<br>
So in the end it seems to boil down to the simple fact that we need a CD that has 2 tracks on it and the size (length) must be between 004434F0 and 0049B330, that's it.<br>
By the way. While searching the net on background info to all this _mciSendCommand_ stuff, I discovered [krystalgamer's Blog](https://krystalgamer.github.io/spidey-breaking/index.html) who seems to had a look into this game before, what a coincidence :)
