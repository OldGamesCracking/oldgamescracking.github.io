---
layout: post
author: OldGamesCracking
title: "The Sims 2 - VM OpCode Reference"
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

Note: These are the OpCodes that get derived from the _'Initialization Vectors'_ (IV). They represent the emulated instructions and should be de-virtualizeable back to x86 assembly. They are not to be confused with the internal static [Parser OpCodes]({{site.url}}/assets/sims_2/parser_opcode_reference) of the VM.  

| OpCode 0 | Register Transfer |
| ------------- | ------------- |
| Handler Location | 015D |
| Used Parameters | a0: destination, a1: source |
| Equivalent x86 Instruction | MOV, JMP |

Moves a value from one register to another.
Note that this can be used to perform an unconditional absolute far-jump if _EIP_ is chosen as destination register.

```
REG[a0] = REG[a1]

MOV <reg>, <reg>
MOV <reg>, IMM
JMP <address>
```

| OpCode 1 | Jump |
| ------------- | ------------- |
| Handler Location | 0160 |
| Used Parameters | a0: base, a1: offset |
| Equivalent x86 Instruction | JMP |

This adds the second operand to the first, so in theory this can be a generic ADD-instruction, but since the flags are not updated, one can guess that only _EIP_ as first operand makes sense, thus it performs a relative jump.

```
REG[a0] += REG[a1]

JMP <offset>
```

| OpCode 2 | CALL |
| ------------- | ------------- |
| Handler Location | 019F |
| Used Parameters | a0: base, a1: offset |
| Equivalent x86 Instruction | CALL |

Like JMP, this adds the second operand to the first, so it could be an _ADD_ instruction, but the flags are not updated. So it only makes sense to use this with _EIP_ as first parameter.
Note that no return address needs to be pushed onto the stack since it is already on the stack by calling the VM-Entry, ESP just needs to be decremented by 4 so the return address will not get popped of in the cleanup routine.

```
REG[ESP] -= 4
REG[a0] += REG[a1]

CALL <offset>
```

| OpCode 3 | Jump if Equal/Zero |
| ------------- | ------------- |
| Handler Location | 0163 |
| Used Parameters | a0: base, a1: offset, a2: EFLAGS |
| Equivalent x86 Instruction | JE/JZ |

```
if ((a2 & (1 << 6)) != 0)
{
    REG[a0] += REG[a1]
}

JE <offset>
```

| OpCode 4 | Jump if NOT Equal/Zero |
| ------------- | ------------- |
| Handler Location | 0169 |
| Used Parameters | a0: base, a1: offset, a2: EFLAGS |
| Equivalent x86 Instruction | JNE/JNZ |

```
if ((a2 & (1 << 6)) == 0)
{
    REG[a0] += REG[a1]
}

JNE <offset>
```

| OpCode 5 | Jump if Below |
| ------------- | ------------- |
| Handler Location | 016F |
| Used Parameters | a0: base, a1: offset, a2: EFLAGS |
| Equivalent x86 Instruction | JB |

```
if ((a2 & (1 << 0)) != 0)
{
    REG[a0] += REG[a1]
}

JB <offset>
```

| OpCode 6 | Jump if NOT Below/Above or equal |
| ------------- | ------------- |
| Handler Location | 016F |
| Used Parameters | a0: base, a1: offset, a2: EFLAGS |
| Equivalent x86 Instruction | JNB/JAE |

```
if ((a2 & (1 << 0)) == 0)
{
    REG[a0] += REG[a1]
}

JNB <offset>
```

| OpCode 7 | Jump if Overflow |
| ------------- | ------------- |
| Handler Location | 0181 |
| Used Parameters | a0: base, a1: offset, a2: EFLAGS |
| Equivalent x86 Instruction | JO |

```
if ((a2 & (1 << 11)) != 0)
{
    REG[a0] += REG[a1]
}

JO <offset>
```

| OpCode 8 | Jump if NOT Overflow |
| ------------- | ------------- |
| Handler Location | 017B |
| Used Parameters | a0: base, a1: offset, a2: EFLAGS |
| Equivalent x86 Instruction | JNO |

```
if ((a2 & (1 << 11)) == 0)
{
    REG[a0] += REG[a1]
}

JNO <offset>
```


| OpCode 9 | Jump if Parity |
| ------------- | ------------- |
| Handler Location | 0187 |
| Used Parameters | a0: base, a1: offset, a2: EFLAGS |
| Equivalent x86 Instruction | JP |

```
if ((a2 & (1 << 2)) != 0)
{
    REG[a0] += REG[a1]
}

JP <offset>
```

| OpCode 10 | Jump if NOT Parity |
| ------------- | ------------- |
| Handler Location | 018D |
| Used Parameters | a0: base, a1: offset, a2: EFLAGS |
| Equivalent x86 Instruction | JNP |

```
if ((a2 & (1 << 2)) == 0)
{
    REG[a0] += REG[a1]
}

JNP <offset>
```

| OpCode 11 | Jump if Sign |
| ------------- | ------------- |
| Handler Location | 0193 |
| Used Parameters | a0: base, a1: offset, a2: EFLAGS |
| Equivalent x86 Instruction | JS |

```
if ((a2 & (1 << 7)) != 0)
{
    REG[a0] += REG[a1]
}

JS <offset>
```

| OpCode 12 | Jump if NOT Sign |
| ------------- | ------------- |
| Handler Location | 0199 |
| Used Parameters | a0: base, a1: offset, a2: EFLAGS |
| Equivalent x86 Instruction | JNS |

```
if ((a2 & (1 << 7)) == 0)
{
    REG[a0] += REG[a1]
}

JNS <offset>
```

| OpCode 13 | TEST |
| ------------- | ------------- |
| Handler Location | 006F |
| Used Parameters | a0: operandA, a1: operandB, a2: EFLAGS |
| Equivalent x86 Instruction | TEST |

Bitwise ANDs the operands and updates the EFLAGS according to the result.

```
result = REG[a0] & REG[a1]
update_eflags(result)

TEST <operandA>, <operandB>
```

| OpCode 14 | Bitwise AND |
| ------------- | ------------- |
| Handler Location | 008C |
| Used Parameters | a0: operandA, a1: operandB, a2: EFLAGS |
| Equivalent x86 Instruction | AND |

Bitwise ANDs the operands and updates the EFLAGS according to the result.
Writes back the result to the first operand.

```
REG[a0] &= REG[a1]
update_eflags(REG[a0])

AND <operandA>, <operandB>
```

| OpCode 15 | Bitwise XOR |
| ------------- | ------------- |
| Handler Location | 00AA |
| Used Parameters | a0: operandA, a1: operandB, a2: EFLAGS |
| Equivalent x86 Instruction | XOR |

Bitwise XORs the operands and updates the EFLAGS according to the result.
Writes back the result to the first operand.

```
REG[a0] ^= REG[a1]
update_eflags(REG[a0])

XOR <operandA>, <operandB>
```

| OpCode 16 | Bitwise OR |
| ------------- | ------------- |
| Handler Location | 00C8 |
| Used Parameters | a0: operandA, a1: operandB, a2: EFLAGS |
| Equivalent x86 Instruction | OR |

Bitwise ORs the operands and updates the EFLAGS according to the result.
Writes back the result to the first operand.

```
REG[a0] |= REG[a1]
update_eflags(REG[a0])

OR <operandA>, <operandB>
```

| OpCode 17 | Compare values |
| ------------- | ------------- |
| Handler Location | 0136 |
| Used Parameters | a0: operandA, a1: operandB, a2: EFLAGS |
| Equivalent x86 Instruction | CMP |

Subtracts the operands and updates the EFLAGS according to the result.

```
result = REG[a0] - REG[a1]
update_eflags(result)

CMP <operandA>, <operandB>
```

| OpCode 18 | Subtract values |
| ------------- | ------------- |
| Handler Location | 010E |
| Used Parameters | a0: operandA, a1: operandB, a2: EFLAGS |
| Equivalent x86 Instruction | SUB |

Subtracts the operands and updates the EFLAGS according to the result.
Writes back the result to the first operand.

```
REG[a0] -= REG[a1]
update_eflags(REG[a0])

SUB <operandA>, <operandB>
```

| OpCode 20 | Add values |
| ------------- | ------------- |
| Handler Location | 00E6 |
| Used Parameters | a0: operandA, a1: operandB, a2: EFLAGS |
| Equivalent x86 Instruction | ADD |

Add the operands and updates the EFLAGS according to the result.
Writes back the result to the first operand.

```
REG[a0] += REG[a1]
update_eflags(REG[a0])

ADD <operandA>, <operandB>
```


* * *