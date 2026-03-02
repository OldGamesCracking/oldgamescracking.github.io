---
layout: post
author: OldGamesCracking
title: "The Sims 2 - Parser OpCode Reference"
date: 2026-03-01
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

# OpCodes

| OpCode 1 | Memory Transfer CS -> DS (Load) |
| ------------- | ------------- |
| Handler Location | 66747380 |
| Equivalent RISC Instruction | lw |

Moves data from the Code Segment to the Data Segment. In relative addressing mode, a value from the Data Segment is used as lookup.

```
ds:[DEST] = cs:[SRC]
ds:[DEST] = cs:[ds:[SRC_HIGH]]

lw rd, imm(r0)
lw rd, 0(rs1)
```

| OpCode 2 | Memory Transfer DS -> CS (Store) |
| ------------- | ------------- |
| Handler Location | 66747260 |
| Equivalent RISC Instruction | sw |

Moves data from the Data Segment to the Code Segment. In relative addressing mode, a value from the Data Segment is used as lookup.
Note that for this command DEST and SRC are swapped or else values past 255 could not be reached. 

```
cs:[SRC] = ds:[DEST]
cs:[ds:[SRC_HIGH]] = ds:[DEST]

sw rs2, imm(r0)
sw rs2, 0(rs1)
```

| OpCode 3 | Memory Transfer const/DS -> DS (Load Immediate) |
| ------------- | ------------- |
| Handler Location | 667474B0 |
| Equivalent RISC Instruction | li, mv |

Moves either a constant value to the Data Segment or copies a value in relative addressing mode.

```
ds:[DEST] = SRC
ds:[DEST] = ds:[SRC_HIGH]

li rd, imm
mv rd, rs1
```

| OpCode 4 | Shift Left |
| ------------- | ------------- |
| Handler Location | 66748860 |
| Equivalent RISC Instruction | sll, slli |

Left-Shifts a value in the Data Segment. Only the lower part of the operand is used.
For relative addressing mode, the value at `ds:[SRC_HIGH]` is left-shifted, the result is stored in `ds:[DEST]`.

```
ds:[DEST] = ds:[DEST] << SRC_LOW
ds:[DEST] = ds:[SRC_HIGH] << byte:ds:[SRC_LOW]

slli rd, rs1, shamt
sll rd, rs1, rs2
```

| OpCode 5 | Shift Right |
| ------------- | ------------- |
| Handler Location | 66748A30 |
| Equivalent RISC Instruction | srl, srli |

Right-Shifts a value in the Data Segment. Only the lower part of the operand is used.
For relative addressing mode, the value at `ds:[SRC_HIGH]` is right-shifted, the result is stored in `ds:[DEST]`.

```
ds:[DEST] = ds:[DEST] >> SRC_LOW
ds:[DEST] = ds:[SRC_HIGH] >> byte:ds:[SRC_LOW]

srli rd, rs1, shamt
srl rd, rs1, rs2
```

| OpCode 6 | Bitwise AND |
| ------------- | ------------- |
| Handler Location | 66747B00 |
| Equivalent RISC Instruction | and, andi |

Performs a bitwise AND on a value in the Data Segment.
For relative addressing mode, the value at `ds:[SRC_HIGH]` is AND-ed, the result is stored in `ds:[DEST]`.

```
ds:[DEST] = ds:[DEST] & SRC
ds:[DEST] = ds:[SRC_HIGH] & ds:[SRC\_LOW]

andi rd, rs1, imm
and rd, rs1, rs2
```

| OpCode 7 | Bitwise OR |
| ------------- | ------------- |
| Handler Location | 66747C70 |
| Equivalent RISC Instruction | or, ori |

Performs a bitwise OR on a value in the Data Segment.
For relative addressing mode, the value at `ds:[SRC_HIGH]` is OR-ed, the result is stored in `ds:[DEST]`.

```
ds:[DEST] = ds:[DEST] | SRC
ds:[DEST] = ds:[SRC_HIGH] | ds:[SRC\_LOW]

ori rd, rs1, imm
or rd, rs1, rs2
```

| OpCode 8 | Bitwise XOR |
| ------------- | ------------- |
| Handler Location | 66747f50 |
| Equivalent RISC Instruction | xor, xori |

Performs a bitwise XOR on a value in the Data Segment.
For relative addressing mode, the value at `ds:[SRC_HIGH]` is XOR-ed, the result is stored in `ds:[DEST]`.

```
ds:[DEST] = ds:[DEST] ^ SRC
ds:[DEST] = ds:[SRC_HIGH] ^ ds:[SRC\_LOW]

xori rd, rs1, imm
xor rd, rs1, rs2
```

| OpCode 9 | Bit Invert |
| ------------- | ------------- |
| Handler Location | 66748120 |
| Equivalent RISC Instruction | binv, binvi |

Inverts a single Bit.

```
ds:[DEST] = ds:[DEST] ^ (1 << SRC)
ds:[DEST] = ds:[SRC_HIGH] ^ (1 << ds:[SRC_LOW])

binvi rd, rs1, shamt
binv rd, rs1, rs2
```

| OpCode 10 | Bit Set |
| ------------- | ------------- |
| Handler Location | 667482F0 |
| Equivalent RISC Instruction | bset, bseti |

Sets a single Bit.

```
ds:[DEST] = ds:[DEST] | (1 << SRC)
ds:[DEST] = ds:[SRC_HIGH] | (1 << ds:[SRC_LOW])

bseti rd, rs1, shamt
bset rd, rs1, rs2
```

| OpCode 11 | Bit Clear |
| ------------- | ------------- |
| Handler Location | 66748690 |
| Equivalent RISC Instruction | bclr, bclri |

Clears a single Bit.

```
ds:[DEST] = ds:[DEST] & ~(1 << SRC)
ds:[DEST] = ds:[SRC_HIGH] & ~(1 << ds:[SRC_LOW])

bclri rd, rs1, shamt
bclr rd, rs1, rs2
```

| OpCode 12 | Bit Test |
| ------------- | ------------- |
| Handler Location | 667484c0 |
| Equivalent RISC Instruction | bext, bexti |

Sets DEST to the value of the selected Bit (0/1).

```
ds:[DEST] = (ds:[DEST] >> SRC) & 0x1
ds:[DEST] = (ds:[SRC_HIGH] >> ds:[SRC_LOW]) & 0x1

bexti rd, rs1, shamt
bext rd, rs1, rs2
```

| OpCode 14 | Add Values |
| ------------- | ------------- |
| Handler Location | 66748c00 |
| Equivalent RISC Instruction | add, addi |

Adds two values together.

```
ds:[DEST] = ds:[DEST] + SRC
ds:[DEST] = ds:[SRC_HIGH] + ds:[SRC_LOW]

addi rd,rs1,imm
add rd,rs1,rs2
```

| OpCode 15 | Subtract Values |
| ------------- | ------------- |
| Handler Location | 66748DD0 |
| Equivalent RISC Instruction | sub, subi |

Subtracts two values from each other.

```
ds:[DEST] = ds:[DEST] - SRC
ds:[DEST] = ds:[SRC_HIGH] - ds:[SRC_LOW]

subi rd, rs1, imm
sub rd, rs1, rs2
```

| OpCode 16 | Multiply Values |
| ------------- | ------------- |
| Handler Location | 66748FA0 |
| Equivalent RISC Instruction | mul |

Multiply two values.

```
ds:[DEST] = ds:[DEST] * SRC
ds:[DEST] = ds:[SRC_HIGH] * ds:[SRC_LOW]

muli rd, rs1, imm
mul rd, rs1, rs2
```

| OpCode 17 | Divide Values |
| ------------- | ------------- |
| Handler Location | 66748FA0 |
| Equivalent RISC Instruction | div |

Divide two values.

```
ds:[DEST] = ds:[DEST] / SRC
ds:[DEST] = ds:[SRC_HIGH] / ds:[SRC_LOW]

divi rd, rs1, imm
div rd, rs1, rs2
```

| OpCode 18 | Remainder |
| ------------- | ------------- |
| Handler Location | 66749340 |
| Equivalent RISC Instruction | rem |

Calculates the remainder of a division (mod)

```
ds:[DEST] = ds:[DEST] % SRC
ds:[DEST] = ds:[SRC_HIGH] % ds:[SRC_LOW]

remi rd, rs1, imm
rem rd, rs1, rs2
```

| OpCode 19 | Compare Values for Equality |
| ------------- | ------------- |
| Handler Location | 66749510 |
| Equivalent RISC Instruction | seq, seqi (?) |

Compares two values and stores the result (0/1) in _DEST_.
I'm not sure if this really is a common RISC instruction.

```
ds:[DEST] = (ds:[DEST] == SRC) ? 1 : 0
ds:[DEST] = (ds:[SRC_HIGH] == ds:[SRC_LOW]) ? 1 : 0

seqi rd, imm
seq rd, rs1, rs2
```

| OpCode 20 | Set Less Than |
| ------------- | ------------- |
| Handler Location | 66749710 |
| Equivalent RISC Instruction | slt, slti |

Sets _DEST_ to 0/1 if one of the values is lower (unequal).

```
ds:[DEST] = (ds:[DEST] < SRC) ? 1 : 0
ds:[DEST] = (ds:[SRC_HIGH] < ds:[SRC_LOW]) ? 1 : 0

slti rd, imm
slt rd, rs1, rs2
```

| OpCode 21 | Check Overflow - Subtraction |
| ------------- | ------------- |
| Handler Location | 66749AE0 |
| Equivalent RISC Instruction | ??? |

I don't know if that instruction represents a real RISC instruction.
It subtracts the given values and returns the overflow flag.

```
ds:[DEST] = get_overflow_sub(ds:[DEST], SRC)
ds:[DEST] = get_overflow_sub(ds:[SRC_HIGH], ds:[SRC_LOW])

sofsubi rd, imm
sofsub rd, rs1, rs2 
```

| OpCode 22 | Check Carry - Subtraction |
| ------------- | ------------- |
| Handler Location | 667498C0 |
| Equivalent RISC Instruction | ??? |

Same as 21, but returns the Carry Flag

```
ds:[DEST] = get_carry_sub(ds:[DEST], SRC)
ds:[DEST] = get_carry_sub(ds:[SRC_HIGH], ds:[SRC_LOW])

scfsubi rd, imm
scfsub rd, rs1, rs2 
```

| OpCode 23 | Check Overflow - Addition |
| ------------- | ------------- |
| Handler Location | 66749F90 |
| Equivalent RISC Instruction | ??? |

Same as 21, but for addition

```
ds:[DEST] = get_overflow_add(ds:[DEST], SRC)
ds:[DEST] = get_overflow_add(ds:[SRC_HIGH], ds:[SRC_LOW])

sofaddi rd, imm
sofadd rd, rs1, rs2 
```

| OpCode 24 | Check Carry - Addition |
| ------------- | ------------- |
| Handler Location | 66749D20 |
| Equivalent RISC Instruction | ??? |

Same as 23, but returns the Carry Flag

```
ds:[DEST] = get_carry_add(ds:[DEST], SRC)
ds:[DEST] = get_carry_add(ds:[SRC_HIGH], ds:[SRC_LOW])

scfaddi rd, imm
scfadd rd, rs1, rs2 
```

| OpCode 25 | Check Adjust - Addition |
| ------------- | ------------- |
| Handler Location | 6674A1F0 |
| Equivalent RISC Instruction | ??? |

Same as 23, but returns the Adjust Flag (Auxiliary Carry Flag)

```
ds:[DEST] = get_adjust_add(ds:[DEST], SRC)
ds:[DEST] = get_adjust_add(ds:[SRC_HIGH], ds:[SRC_LOW])

safaddi rd, imm
safadd rd, rs1, rs2 
```

| OpCode 26 | Check Adjust - Addition |
| ------------- | ------------- |
| Handler Location | 6674A450 |
| Equivalent RISC Instruction | ??? |

Same as 23, but returns the Adjust Flag (Auxiliary Carry Flag)

```
ds:[DEST] = get_adjust_add(ds:[DEST], SRC)
ds:[DEST] = get_adjust_add(ds:[SRC_HIGH], ds:[SRC_LOW])

safaddi rd, imm
safadd rd, rs1, rs2 
```

| OpCode 27 | Jump if not Zero |
| ------------- | ------------- |
| Handler Location | 6674A610 |
| Equivalent RISC Instruction | bnez |

This is a complex opcode, it tests _DEST_ for being NOT zero and if so, the value at address 0xff in the Data Segent is set to a value from either the Code Segment (absolute addressing mode) or the Code Segment (relative addressing mode).
It's not obvious right away, but address 0xff is used as the program counter `pc`, so this really is a bnez. If _DEST_ is 0x00, this becomes a NOP since this address is always set to zero.
Also ds:[0xfd] is set to the previous value of ds:[0xff] (EIP) which at that time already points to the next instruction. So ds:[0xfd] can be used as the return address.

```
IF ds:[DEST] != 0 THEN
    ds:[0xfd] = ds:[0xff]
    ds:[0xff] = cs:[SRC]
FI

IF ds:[DEST] != 0 THEN
    ds:[0xfd] = ds:[0xff]
    ds:[0xff] = ds:[SRC_HIGH];
FI

bnez rs1, rs2, imm
```

| OpCode 28 | Jump if Zero |
| ------------- | ------------- |
| Handler Location | 6674a8c0 |
| Equivalent xRISC Instruction | beqz |

This is the same as OpCode 27, only the logic is inverted. If _DEST_ is 0x00, this becomes a JMP since this address is always set to zero.<br>
Also, if SRC is the `t0` register - which is used to store the return address - this can be seen as a _'return from subroutine'_ instruction.

```
IF ds:[DEST] == 0 THEN
    ds:[0xfd] = ds:[0xff]
    ds:[0xff] = cs:[SRC]
FI

IF ds:[DEST] == 0 THEN
    ds:[0xfd] = ds:[0xff]
    ds:[0xff] = ds:[SRC_HIGH];
FI

beqz rs1, imm
call symbol ; (implicit, if dest == r0)
rts ; (implicit, if src == ra)
```

| OpCode 29 | Stop Execution |
| ------------- | ------------- |
| Handler Location | 66747250 |
| Equivalent RISC Instruction | RET |

This is not a real OpCode, it will set the _'done'_ Flag in the VM and thus stop executing the code. So this is somewhat of a _RET_ instruction.

<br>

There are two more instructions (27, 28), but since they are not used, I did not bother to figure out their meaning. If I had to guess I would say they are some kind of jump/call instructions.<br>


* * *