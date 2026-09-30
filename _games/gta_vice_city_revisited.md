---
layout: post
author: OldGamesCracking
title: "Grand Theft Auto: Vice City (Revisited)"
date: 2026-09-30
tags:
    - "GTA VC"
    - "Vice City"
    - "Grand Theft Auto: Vice City"
    - "Game Cracking"
    - "Reverse Engineering"
    - "SecuROM"
    - "Silent Checks"
---

## Game Specs

| Name | Grand Theft Auto: Vice City |
| ------------- | ------------- |
| Release-Date | 05/2003 |
| Redump ID | [19050](http://redump.info/disc/19050/) & [10500](http://redump.info/disc/10500/) |
| Protection | SecuROM v4.84.69 |
| Cracked under | Win 10 |
| Tested under | Win 10 |
| Scene-Crack by | [FAIRLIGHT](https://www.nfohump.com/index.php?switchto=nfos&menu=quicknav&item=viewnfo&id=31424) |

*Needed Tools:*

- x32dbg
- Ghidra
- Python + Lief
- The original Game-CD of course ;)
- Ideally the crack by FAIRLIGHT
- THUGSTOOLS
- PROFESSIONALTOOLS
- NUTTERTOOLS

### Disclaimer

- The games are cracked for educational purpose and to regain compatibility with modern systems
- The games are more than 20 years old and can be found freely on the net via e.g. archive.org
- No parts of the game are distributed

# How to (really) Crack

After the [initial article](/games/gta_vice_city) I played the game a bit and was kinda surprised that it immedeately started to rain at the start of the game - something I had never encountered and which seemed odd for the sun-drenched setting of Vice City. Ultimately I didn't bother too much and thought it was just bad RNG. But then - over a year after writing the article - I came across [this video](https://youtu.be/gqUmXuDIDbc&t=465) where I learned that the game has some hidden checks to see if the protection was still active. All the checks are silent and will just make the game annoying or hard to play, but there will be no error message or crashes, that's why I didn't notice the checks at first. The code that is seen in the Video can be found [here](https://github.com/mrxenginner/reVC/tree/miami).<br>

Strangely, the code doesn't really tell us, how the check is done. All we have is an undefined `#define`:

```c
#ifdef SECUROM
	if ((myrand() & 3) == 2){
		// if pirated game
		CWeather::ForceHurricaneWeather();
	}
#endif
```

```c
#ifdef SECUROM
void CWeather::ForceHurricaneWeather()
{
	for (int i = 0; i < ARRAY_SIZE(WeatherTypesList_WithHurricanes); i++)
	{
		WeatherTypesList[i] = WEATHER_HURRICANE;
		WeatherTypesList_WithHurricanes[i] = WEATHER_HURRICANE;
	}

	CWeather::OldWeatherType = WEATHER_HURRICANE;
	CWeather::NewWeatherType = WEATHER_HURRICANE;
	CWeather::ForcedWeatherType = WEATHER_HURRICANE;
}
#endif
```

It's somewhat hard to pin down the exact location of these checks, especially for the people back in the day that didn't have the reverse engineered code at hand. So let's do it methodically; at the moment I can imaginge a few methods the game could use to detect the absence of SecuROM:

1. Some kind of Handle, FileMapping, Event etc. is created by the protection, the game checks for that and if it is not present, the protection never ran. This was used in [Sims 2](/games/sims_2_part_6#the-final-chapter).
2. The game checks if e.g. some Calls point to the real procs instead of the SecuROM stubs. Hence, the IAT was reconstructed.
3. The game performs some checksum-tests (which is a more general version of the check above).
4. The game checks it's own executeable on disc or in memory (size, checksum, section names etc.).
5. The SecuROM loader initializes some variables to a specific value that are normally un-initialized or have a different value.
6. A SecuROM thread is normally running in the background that can do all sorts of things.

And probably a lot more.<br>

So let's start with the simplest of them all: Number 2.<br>
For that, we just need to break at the OEP, fix the imports and then let it run - still in the debugger. If it still starts with rainy weather (chance: 25%) or the sniper doesen't work (use the cheat *NUTTERTOOLS*), the game checks for the presence of the fixed IAT/Intermodular Calls.<br>

To my surprise, this really turned out to be a hit! With the imports fixed, I got the rainy weather and the sniper wouldn't work!<br>
In order to locate the exact spot where the check is made, I modified the import fixer script to only fix a handfull of the imports. With only a few imports fixed, the game ran fine, but after exactly 0x180 fixed Calls, the sniper wouldn't work anymore. I tracked down the address of the Call that caused the issue and landed here:

![]({{site.url}}/assets/gta_vice_city/sniper_pirate_check.png)

If you read the [reVC source code](https://github.com/mrxenginner/reVC/blob/miami/src/weapons/Weapon.cpp#L2287) you will be able to identify this bit. But what's going on? The call you see resolves to `GetCurrentThread`, a method that has no parameters and is only three instructions long, so it's very lightweight and can be used as a dummy-call to get back into SecuROM code, where all sorts of things can happen.

![]({{site.url}}/assets/gta_vice_city/getcurrentthread.png)

Also, have a close look what's going on before and after the call. First, the original values of EAX, EBX and ECX are saved, then EAX and ECX are loaded with some quite arbitrary values and EBX is loaded with the address of the *sniperPirateCheck*-variable. After the call, ECX and EBX are restored. I don't know why EAX isn't restored, I guess it was optimized away by the compiler.<br>
Initially *sniperPirateCheck* holds a value of 0x00797743 which could be interpreted as the string *'Cwy\0'*. Within the call, *sniperPirateCheck* is zeroed-out and all succeeding calls to the outer routine (*CWeapon::FireSniper*) will skip this bit, that's why I called it a dummy-call, there was never an intention to get the handle of the current thread, the only reason was to get back to SecuROM code.<br>
If we fix this call now back to `GetCurrentThread` and dump the game, noone will nullify *sniperPirateCheck* and the later check fails:


![]({{site.url}}/assets/gta_vice_city/sniper_pirate_check_2.png)

Or in assembly:

![]({{site.url}}/assets/gta_vice_city/sniper_pirate_check_2_asm.png)

Judging by the code, I'm somewhat sure that the developers of GTA had some kind of SecuROM-Macros that they could integrate in the code, that might have looked like the following:

```cpp
SECVAR_t sec_var = MAKE_SEC_VAR();

INIT_SEC_VAR(sec_var);

if (PIRATED(sec_var))
{
	// Perform anti-pirate measure
}
```

With the help of some script/preprocessor/linker magic, this would be evaluated to:

```cpp
DWORD *sec_var = ...; // Needs to be global

if (*sec_var != 0)
{
	__asm
	{
		push eax;
		push ebx;
		push ecx;

		mov eax, 0x937502A4; // Token A
		lea ebx, sec_var;
		mov ecx, 0xCC2F0AB3; // Token B

		call GetCurrentThread; // Dummy call

		pop ecx;
		pop ebx;
		pop eax;
	}
}

if (*sec_var != 0)
{
	// Perform anti-pirate measure
}
```

Within the SecuROM code they then somehow check for the presence of the tokens and nullify the data at *\*sec_var*.<br>


# Down the Rabbit Hole we go

After inspecting a few other Calls, I couldn't figure out a common pattern, so my only choice was to reverse engineer the SecurROM code. Luckily it's somewhat readable and not obfuscated so it took me roughly two evenings to get behind most of the details. Implementing a crack was then another tricky task since - spoiler - we need to leave some parts of the SecuROM code intact.<br><br>

So, let's step into the function at 0x00A19A00 and have a look around. The first thing we notice is that the context is saved, together with five potential function arguments - wether the original function actually has arguments or not. Then the ThreadId is stored in an array to make the function re-entrant. In another array at the same index, the return address is stored. Nothing too special so far.

![]({{site.url}}/assets/gta_vice_city/import_1.png)

Then some sort of hash is calculated from the Call-Address which is used to look up an index in the *CallsMap* hashmap. The reconstructed code might have looked as follows:

```c
const uint8_t HashKeys[] = {0xE6, 0xAD, 0x6F, 0x0F, 0xE7, 0x1F, 0x90, 0xD0, 0xEA};

// Points to the address-part of the instruction, not the start of the instruction!
uint32_t CallFrom = ReturnAddress - 0x4;
uint16_t CallFrom_Hash = (CallFrom >> 0x10) ^ CallFrom;

// 'Decrypt' second byte of hash, using first one as key-index
CallFrom_Hash ^= (uint16_t)HashKeys[(CallFrom_Hash & 0xff) % sizeof(HashKeys)] << 0x8;

// 'Decrypt' first byte of hash, using second as key-index
size_t HashMap_idx = (CallFrom_Hash ^ HashKeys[(CallFrom_Hash >> 0x8) % sizeof(HashKeys)]) % CallsMap_Len) + 0x1;

uint32_t CallFrom_Test = 0;

while (true)
{
	// Use lower 2 bits as key-index to decrypt bits[4:12]
	CallFrom_Test = CallsMap[HashMap_idx].CallFrom_enc ^ (HashKeys[CallsMap[HashMap_idx].CallFrom_enc % 0x4] << 4);

	if (CallFrom_Test == CallFrom)
	{
		break;
	}

	// Mask out bits[14:15] (CallCounter)
	HashMap_idx = CallsMap[HashMap_idx].Next & 0xffff3fff;
}

DWORD CallCounter = (CallsMap[HashMap_idx].Next & 0xc000) >> 0xe;
DWORD IATEntryAddress_enc = CallsMap[HashMap_idx].IATEntryAddress_enc;
```

With each hashmap node looking like this:

```c
typedef struct
{
	uint32_t CallFrom_enc;
	uint16_t Next; // + CallCounter
	uint32_t CalledLast;
	uint32_t IATEntryAddress_enc;
	uint16_t IsSpecial;
} HASHMAP_NODE_t;
```

The *IATEntryAddress* is what we ultimately want, but it is also encrypted. The decryption process is rather strange:

```c
// Make upper WORD same as lower, decrypt with lower 2 bits as key-index
DWORD DecryptionInstrctions = ((CallFrom << 16) + (CallFrom & 0xffff)) ^ *(DWORD*)&HashLookup[CallFrom % 0x4];

DWORD NibbleMask = 0x0f;

for (int i = 0; i < 8; i++)
{
	DWORD Instruction = ((DecryptionInstrctions & NibbleMask) >> (i * 4)) % 12;

	switch (DecryptionInstrctions & NibbleMask)
	{
		case 0:
		{
			IATEntryAddress_enc ^= 0xF9BF;
			break;
		}
		case 1:
		{
			IATEntryAddress_enc ^= 0x5F444B55; // First 4 bytes of "UKD_590160.001"
			break;
		}
		case 2:
		{
			IATEntryAddress_enc ^= 0;
			break;
		}
		case 3:
		{
			IATEntryAddress_enc ^= 0x1CD6089;
			break;
		}
		case 4:
		{
			IATEntryAddress_enc -= 0xB476;
			break;
		}
		case 5:
		{
			IATEntryAddress_enc += 0x9A10;
			break;
		}
		case 6:
		{
			IATEntryAddress_enc ^= 0x1FEA;
			break;
		}
		case 7:
		{
			IATEntryAddress_enc ^= 0xA512;
			break;
		}
		case 8:
		{
			IATEntryAddress_enc -= 0x74F00;
			break;
		}
		case 9:
		{
			IATEntryAddress_enc += 0xFD;
			break;
		}
		case 10:
		{
			IATEntryAddress_enc ^= SomeByteArray[CallFrom % 37];
			break;
		}
		case 11:
		{
			IATEntryAddress_enc = (((IATEntryAddress_enc >> 0) + 0) >> 0) + 0;
			break;
		}
		default:
		{
			break;
		}
	}

	NibbleMask <<= 4;
}
```

So from the Call-Site 8 "Instructions" are generated. These then decrypt the IAT-Slot via reversible operations.<br>

I'm not entirely sure if the values are really constant or if they are calculated by the loader. They might be machine-dependent or are derived by some characteristics of the CD. Instruction 1 is based upon some string which I think I have seen before, but I was too lazy to track it down. Instructions 2 and 11 are probably some tamper detection. If everything is ok, they act as a neutral operation, but if anything goes wrong, the values will change and the address is decrypted incorrectly. Anyways, we don't really care, this was more informative then needed.<br>

Next, we see some information we can use for the fixing script:

![]({{site.url}}/assets/gta_vice_city/limits.png)

So the addresses of the first and last call are known which limits the address range we need to scan later for the calls ;)<br>

Also, a few lines below at 0x00A1A05F and 0x00A1A3F0 with a bit of reversing and thinking, we can see the following code:

```c
// 0x00A1A05F
if ((CallCounter == 0x0) && !CallsMap[HashMap_idx].IsSpecial)
	*CallFrom = IATEntryAddress;

// 0x00A1A3F0
DWORD Now = TimeGetTime();
DWORD TimeDelta = Now - CallsMap[HashMap_idx].CalledLast;

if (TimeDelta < 16)
{
	if (CallCounter != 0x0)
	{
		// Mask-out CallCounter
		CallsMap[HashMap_idx].Next = CallsMap[HashMap_idx].Next & 0x3fff;
		// Decrement
		CallsMap[HashMap_idx].Next = CallsMap[HashMap_idx].Next | ((CallCounter - 1) << 16);
	}
```

So if some Call was called up to 4 times (2 bits) within 16ms and it is not marked as special, the original Call will be restored, probably to counteract lags introduced by the SecuROM code.<br>

There is a bit more going on like checking if too many calls are made in ascending/descending order which would indicate that someone tries to fix the game and some randomized integrity checks but ultimately, the bit that we've been waiting for comes here:

![]({{site.url}}/assets/gta_vice_city/special.png)

So the whole context and the 5 arguments that were saved before, plus 4 out-variables are passed to some function. The code of that function is quite readable, here is an excerpt:


![]({{site.url}}/assets/gta_vice_city/process_special_call.png)

So always, three different values are checked against some expected values (checking of values 2 and 3 is sometimes deactivated). The three values are either registers, arguments or some local variable (EBP + offset). There are 9 different types. If the check succeeded, the three values are returned. Also the index to the *SPECIAL_CALL_ARRAY* is returned.<br>

Remember the call we saw earlier with EAX=0x937502A4, EBX=0x00797743 (*sniperPirateCheck*) and ECX=0xCC2F0AB3 ? This is a type 0 Call with index 6. The call after each finished mission at 0x004518BE that will change the weather (*ForceHurricaneWeather*) is of type 16 at index 5 and so on.<br>

But what can we do with this information now? Well, we fist need to figure out where the returned values are used. There are two more functions:

![]({{site.url}}/assets/gta_vice_city/cd_check.png)

The first one is where all the bad stuff happens. SecuROM will check for the presence of the CD by different measures and if the checks succeeds, will return true. Luckily it will not alter any of the parameters so we can skip this call in our patch later and jump straight to the next call. In there, the context is restored and finally the EBX value will be nullified.<br><br>

Phew! What a mess. Let's think of a way we can get out of this misery.<br>

What new know so far:

- There are some special calls that need a special handling but only when certain parameters match
- Most of the intermodular calls in the game are of non-special type and SecuROM will even restore them on it's own when called too often
- The CD checks and integrity checks do not seem to interfere with performing the calls to the remote proc, they were just interwoven randomly into the stub
- The SecuROM code is part of the EXE-image and is not generated on the fly (ok, I didn't told you that, but you might have found that out already). No temporary buffers - yay :)
- We know where the first and the last call is and the others are easily findable since they all share exactly the same call-destination

So, we should get away with the following solution:

1. Restore all Calls that are non-special (we can check this if a breakpoint at 0x00A1A5CB hits, see above)
2. For every other Call, we can at least note down the return-address/Call-Site and the address of the IAT slot once it is decrypted at 0x00A19FA4 or at the `JMP EAX` at the end of the stub
3. Patch the SecuROM code in such a way that it will jump straight to *ProcessSpecialFunction* and inject the IAT entry address we obtained earlier to skip the decryption process
4. Jump past the CD check and we are done ;)

For 1 and 2 I have written a new [Import Fixer Script]({{site.url}}/assets/gta_vice_city/import_fixer.txt), you can find the exported special_calls.bin [here]({{site.url}}/assets/gta_vice_city/special_calls.bin).<br>

I'm too lazy to fully explain points 3 and 4, but you can find a patchfile with some comments [here]({{site.url}}/assets/gta_vice_city/patch_imports.1337), just make sure to remove the comments from the patchfile before applying as x64dbg currently does not support that.

That's it? Not quite, but we are nearly there.

If your start the game right after fixing it, everything is fine end even a restart of the game might work. It will start without the CD and everything, but once you restart the PC, it will break eventually. So, what's going on? Well, the answer is simple. The SecuROM stub uses some intermodular calls on it's own that are not routed through the game's IAT. Luckily, the SecuROM code uses the original IAT which we can simply read from the original EXE and merge it with the IAT created by Scylla. Just make sure that Scylla places the imports in a new section at the end of the EXE as that makes it very easy to extend it. I used Lief to do that, you can find a Python script [here]({{site.url}}/assets/gta_vice_city/merge_imports.py). And finally, we have a fully running game ;)

If you've lost track what to do in which order (as I did myself at some point), here is a quick recap:

- Start the game in x64dbg, duh!
- Find the OEP via the methods and the script described in [this article](http://127.0.0.1:4000/games/rollercoaster_tycoon_2) and break there
- Use the [Import Fixer Script]({{site.url}}/assets/gta_vice_city/import_fixer.txt) to reconstruct all non-special imports and export the [special_calls.bin]({{site.url}}/assets/gta_vice_city/special_calls.bin)
- Optional: Use [this script]({{site.url}}/assets/gta_vice_city/clear_thread_array.txt) to clear the thread array
- Optional: Fix some AcLayers bullshit with [this script]({{site.url}}/assets/gta_vice_city/fix_aclayers.txt) (might not be sufficient for you)
- Patch the import stub manually or use [my patch]({{site.url}}/assets/gta_vice_city/patch_imports.1337)
- Remove the CD Checks as described in the [initial article](/games/gta_vice_city) or use [my patch]({{site.url}}/assets/gta_vice_city/cd_checks.1337)
- Dump the game using Scylla
- Merge the new imports with the original ones via [this script]({{site.url}}/assets/gta_vice_city/merge_imports.py)

* * *
