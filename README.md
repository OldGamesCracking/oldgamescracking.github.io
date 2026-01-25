My take on cracking old game protections in order to make them playable on newer systems and help others preserve their games.

If you are new to the topic, I recommed reading the articles in the following order:

# Very Easy

[Spider-Man](https://oldgamescracking.github.io/games/spider_man)

- No protection, just a simple CD check

[GTA 1](https://oldgamescracking.github.io/games/grand_theft_auto)

- Just CD-Checks
- Audio on Disc

[Kreed](https://oldgamescracking.github.io/games/kreed)

- Very simple packer

# Easy

[Hexplore](https://oldgamescracking.github.io/games/hexplore)

- Somewhat in-depth article on SecurROM 1
- Actually quite easy
- Some CALLs will get replaced by apphelp.dll, but CALLs are not replaced by a stub

[GTA 2](https://oldgamescracking.github.io/games/gta2)

- Some easy Anti-Debugging going on
- Game.exe will be started externally
- Imports are easily fixable 
- Multiple CD-Checks

[MotoGP 2](https://oldgamescracking.github.io/games/motogp_2)

- No real cracking needed

[Stealth Combat](https://oldgamescracking.github.io/games/stealth_combat)

- Basic packer/cryptor
- No anti-debugging
- Messed up program flow via exceptions
- Easily repairable imports

# Medium

[Zoo Tycoon 2](https://oldgamescracking.github.io/games/zoo_tycoon_2)

- A second worker process is spwarned, but no self-debuggin is used
- OEP is easy to reach as soon as you know where it is
- Some easily defeatable Anti-Debugging
- No mangled imports

[RollerCoaster Tycoon 2](https://oldgamescracking.github.io/games/rollercoaster_tycoon_2)

- OEP easily findable
- Imports are - in theory - easy to reconstruct, but they need to be reconstructed in a non-linear fashion (randomly, alternating, ...)

[GTA: Vice City](https://oldgamescracking.github.io/games/gta_vice_city) / [Colin McRae Rally 04](https://oldgamescracking.github.io/games/colin_mcrae_rally_04)

- Pretty much the same as RollerCoaster Tycoon 2
- A special patch for Scylla is needed

[GTA 3](https://oldgamescracking.github.io/games/gta3)

- Different types of mangled imports, some are used later in the game and you will not find them right away
- Relayed CALLs
- Stolen bytes
- Easily fixable CD-Checks

# Harder

[Stronghold Deluxe](https://oldgamescracking.github.io/games/stronghold_deluxe)

- Same as GTA 3
- Self-Debugging (Nanomites)
- Nanomites are restored via brute-force by injected DLL
- Imports are restored via Script

[Stronghold Crusader](https://oldgamescracking.github.io/games/stronghold_crusader)

- Same as Stronghold Deluxe
- Self-Debugging (Nanomites)
- Deep-Dive on how Nanomites are stored
- Nanomites are restored by decrypting the underlaying data
- Imports are restored via injected DLL

[Harry Potter and the Chamber of Secrets](https://oldgamescracking.github.io/games/harry_potter_2)

- Same as Stronghold Crusader
- Deep-Dive on how Virtualized Jumps are stored
- Fake Nanomites