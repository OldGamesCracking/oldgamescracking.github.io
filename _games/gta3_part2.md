---
layout: post
author: OldGamesCracking
title: "Grand Theft Auto 3 - Part 2"
date: 2025-05-30
tags:
    - "GTA3"
    - "Grand Theft Auto 3"
    - "Game Cracking"
    - "Reverse Engineering"
    - "CD-Checks"
---

## Game Specs

| Name | Grand Theft Auto 3 |
| ------------- | ------------- |
| Release-Date | 05/2002 |
| Redump ID | [9700](http://redump.org/disc/9700/) |
| Protection | SafeDisc v2.51.021 + CD-Checks |
| Cracked under | Win 10 |
| Tested under | Win 10 |
| Scene-Crack by | [DEVIANCE](https://www.nfohump.com/index.php?switchto=nfos&menu=quicknav&item=viewnfo&id=10506) / [MYTH](https://www.nfohump.com/index.php?switchto=nfos&menu=quicknav&item=viewnfo&id=10510) |

*Needed Tools:*

- x32dbg
- PE tool of your choice (e.g. PE-bear)
- The dumped game .exe from Part I
- Ideally the original crack from the Myth/Deviance release

### Disclaimer

- The games are cracked for educational purpose and to regain compatibility with modern systems
- The games are more than 20 years old and can be found freely on the net via e.g. archive.org
- No parts of the game are distributed

# How to Crack

The cliffhanger I left you off with in Part I was the following image that appears when you start the unpacked game but no CD is inserted:

![CD Check]({{site.url}}assets/gta3/cd_check.jpg)

So at the moment, we have defeated SafeDisc and should be able to play the game with either the original CD, a burned CD or with a mounted [ISO](https://archive.org/details/grand-theft-auto-iii_202110) and it should also run on modern PCs (at least it ran without any problems under my Win 10 machine). This is already much better then using your decades old game discs or rickety CD drives. But can we do better?<br>
For this article I decided to do a bit of a dive into how the Scene cracks work and at which points they differ from our self-made crack.

## Long time ago...

If you've grown up in the 90s and early 2000s, chances are high you remember the time without a (fast) internet connection, very limited HDD space and video games being sold on CDs (that's why you read my stuff, right?).<br>
Cracking groups for that reason also came up with an idea to save up on HDD space but made it so you would still be able to play the whole game. The idea: Rips. What is a Rip you may ask. This was a - by todays standards - ancient tradition or technique were specialized scene groups tried to strip down the game as much as possible to save space. This was done by e.g. removing intro videos, music or re-encoding audio from WAV to MP3 etc. These Rips were sometimes fascinatingly small compared to a so called ISO release, which is the exact opposite and consists of the (untouched) game disc and the crack (if needed).<br>

Two of these groups were Deviance and Myth (they were probably the same group but that's another story). While Deviance did ISO releases, Myth did mostly Rips. The Deviance Release of GTA 3 has the original size of both CDs (roughly 1.2GB in total), but the Myth release is only a whooping 128MB, so roughly 10% of the original size.<br>
While the Deviance release was meant to be played with a burned ISO or emulated CD present, the Myth release is a true No-CD-Crack, so for further investigations, we will use this one.<br>

You can get the original Myth release [here](https://archive.org/details/grand.-theft.-auto.-3-myth). For those of you who are playing along at home, please note that shortly after the release a fix of the Crack was created. We will also have a look at that and what was fixed. But first, run the installer and... ahhh the nostalgic!<br>

![CD Check]({{site.url}}assets/gta3/myth_installer.png)

The original 'Installation' of the Myth version did not work on my machine, but I figured that if you copy the "Audio" folder from CD2 to the installdir, you could use the gta3.exe of Myth and play the game without a CD or ISO (copying the Audio folder is actually one part of the solution and that's also what Myth did). But still, how did they tell the game to load the files locally?<br>
In order to find the differences between the unpacked but unaltered version (ours/Deviance) and the No-CD-Crack from Myth, I dumped the text section of both EXEs and masked out all the intermodular CALLs since our/their IAT looks slightly different of course.<br>
The first thing I noticed is that they reconstructed some of the orphaned jump pads, e.g. at 0x0046B0D0 which I did not touch. They are orphaned since there is no corresponding CALL to them. I have no idea how they reconstructed them, maybe by hand, since I had absolutely no luck reconstructing them automatically, because every time I tried I could reconstruct the first one and then something internally in the SafeDisc code broke. Also saving/copying the whole SafeDisc Module to restore the original state did not seem to work. Maybe they just reversed the inner bits of the Resolver, who knows - it doesen't matter anyways, I guess.<br>
One thing I actually seem to have missed (although the games runs fine) is the reconstruction of one large part of the code starting at 0x00590A00 (Called from 0x0048C7CC). There is a push/ret combination that ends up in a stub. Interestingly that thing did not break down on us, maybe it's an unreached part of the code or it is used for something later in the game. I have added this one to the new script.

![Missed Call]({{site.url}}assets/gta3/missed.png)

Also I have found that one needs to run the jumppad-fixes multiple times to cover all parts of the code since some calls are only available once they are unscrambled and some locations are even re-scrambled that were perfectly valid at the start. This is actually what Myth might have missed in their initial release. The code at 0x005454D0 is somewhat ok in the freshly unpacked exe:<br>

![Right after unpacking]({{site.url}}assets/gta3/after_unpacking.png)

Then gets replace with a jump pad on the first pass of the script as a side-effect of fixing 0x00590A00 (see above):

![Right after unpacking]({{site.url}}assets/gta3/after_unpacking.png)

And finally, in the third pass we see the real code:

![Final code]({{site.url}}assets/gta3/final_code.png)

This is somewhat unique, at least I did not find any other location in the code that works like that.<br>
Took me another whole day to figure that all out, so I really can't blame them ;)<br><br>

With that out of the way, we can finally have a look at the real No-CD-Crack, it's surprisingly simple:

First, they replaced the drive-letter with a dot, so that the OS will look up the files locally:

![Check for Drive]({{site.url}}assets/gta3/drive_letter.png)<br>

![Local files]({{site.url}}assets/gta3/replaced.png)

Then patched the check so that the local folder is seen as a CD-Drive:

![CD drive]({{site.url}}assets/gta3/cd_drive.png)

That's pretty much it. There is another check they NOPed out, but I don't know when this gets triggered, so I couldn't test it:

![NOPed out code]({{site.url}}assets/gta3/noped_out.png)

As I've already said in Part I, I have changed the script in various aspects, you can find it [here](/assets/gta3/import_fixer_v2.txt)<br><br>

That was fun ;)<br><br>

## (Famous) Last words

MYTH: Always Ahead Of The Class!

* * *