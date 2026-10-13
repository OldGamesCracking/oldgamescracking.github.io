; Annotated version of the VM code at 0x13961EC
; Note: The bytes of the instructions are my own interpretation and mainly for debug purposes, real instructions are encrypted and have a different length!
;		Addresses are realtive to the start of the code.
;		<addr> is a DWORD-Offset within VM.Data, see sr_structs.h

; <0x20> should be zero at this point, so <0x1E>=0
:0000   2F 20 1E            MOV <0x1E>, <0x20>
; RunningKey = 0x1F
:0004   2D 04 1F 00 00 00   MOV <0x04>, 0x1F
; i = 20
:000C   2D 1E 14 00 00 00   MOV <0x1E>, 0x14
; VM.Exit == NULL ? (should always be the case)
:0014   00 C8 00 00 00 00   CMP <0xC8>, 0x00
:001C   38 C0 60 00 00      JNZ 0x60DC
:0026   21                  NOP ; #1
:002A   21                  NOP ; #1
:002E   21                  NOP ; #1
:0032   4E                  NOP ; #2 (Check TRAP flag)
; i--
:0036   3F 1E 01 00 00 00   SUB <0x1E>, 0x01
:003E   00 1E 00 00 00 00   CMP <0x1E>, 0x00
:0046   38 CE FF FF FF      JNZ 0x0014
; RunningKey = 0x21
:0050   2D 04 21 00 00 00   MOV <0x04>, 0x21
; i = 10
:0058   2D 1E 0A 00 00 00   MOV <0x1E>, 0x0A
:0060   21                  NOP ; #1
:0064   21                  NOP ; #1
:0068   21                  NOP ; #1
:006C   21                  NOP ; #1
:0070   21                  NOP ; #1
:0074   21                  NOP ; #1
:0078   21                  NOP ; #1
:007C   21                  NOP ; #1
:0080   21                  NOP ; #1
:0084   21                  NOP ; #1
; i--
:0088   3F 1E 01 00 00 00   SUB <0x1E>, 0x01
:0090   00 1E 00 00 00 00   CMP <0x1E>, 0x00
:0098   38 C8 FF FF FF      JNZ 0x0060
; RunningKey = 0x63
:00A2   2D 04 63 00 00 00   MOV <0x04>, 0x63
; i = 30
:00AA   2D 1E 1E 00 00 00   MOV <0x1E>, 0x1E
:00B2   21                  NOP ; #1
:00B6   21                  NOP ; #1
:00BA   21                  NOP ; #1
:00BE   21                  NOP ; #1
:00C2   21                  NOP ; #1
:00C6   21                  NOP ; #1
:00CA   21                  NOP ; #1
:00CE   21                  NOP ; #1
:00D2   21                  NOP ; #1
:00D6   21                  NOP ; #1
; i--
:00DA   3F 1E 01 00 00 00   SUB <0x1E>, 0x01
:00E2   00 1E 00 00 00 00   CMP <0x1E>, 0x00
:00EA   38 C8 FF FF FF      JNZ 0x00B2
; RunningKey = 0x0E
:00F4   2D 04 0E 00 00 00   MOV <0x04>, 0x0E
:00FC   17                  NOP ; #3 (IP + (CPUID - Handler6))
; pHandlers = VM.Handlers_Enc
:0100   45                  MOV <0x78>, <0x00>
; pHandlers += VM.VMEnter -> <0x78> points to first element in Handlers-Array
:0104   29 78 03            ADD <0x78>, <0x03>
; checksum1 = 0
:0108   2D 82 00 00 00 00   MOV <0x82>, 0x00
; checksum2 = 0
:0110   2D BD 00 00 00 00   MOV <0xBD>, 0x00
:0118   2D 8C 00 00 00 00   MOV <0x8C>, 0x00
; checksum1 += Handler_Enc[i]
:0120   44 82 78            ADD <0x82>, mem:[<0x78>]
:0124   21                  NOP ; #1
:0128   21                  NOP ; #1
; checksum2 += Handler_Enc[i]
:012C   44 BD 78            ADD <0xBD>, mem:[<0x78>]
; pHandlers++
:0130   16 78 04 00 00 00   ADD <0x78>, 0x04
; Last entry is zero -> end of list marker
:0138   19 78 8C            CMP mem:[<0x78>], <0x8C>
:013C   38 E4 FF FF FF      JNZ 0x0120
:0146   4E                  NOP ; #2 (Check TRAP flag)
; ??? -> no effect
:014A   34 82 82            MOV <0x82>, <0x82>
; <0x58> = VM.Handlers
:014E   12 58 08            MOV <0x58>, <0x08>
; Points <0x58> 36 bytes past the VMHandlers which are at [0x014A06D8]
; This is some struct ???
; <0x58> = &SomeStruct
:0152   16 58 24 00 00 00   ADD <0x58>, 0x24
; <0x58> = SomeStruct.ExpectedChecksum_Enc
:015A   15 58 58            MOV <0x58>, mem:[<0x58>]
; <0x58> = SomeStruct.ExpectedChecksum
:015E   24 58 81 DE 17 29   XOR <0x58>, 0x2917DE81
; checksum1 == SomeStruct.ExpectedChecksum (3 times)
:0166   0F 58 82            CMP <0x58>, <0x82>
:016A   38 8E 5E 00 00      JNZ 0x5FF8
:0174   0F 58 82            CMP <0x58>, <0x82>
:0178   38 80 5E 00 00      JNZ 0x5FF8
:0182   0F 58 82            CMP <0x58>, <0x82>
:0186   38 FA 5E 00 00      JNZ 0x6080
; checksum2 == SomeStruct.ExpectedChecksum ?
:0190   0F 58 BD            CMP <0x58>, <0xBD>
:0194   38 58 5F 00 00      JNZ 0x60EC
; ... checksums are ok
:019E   4E                  NOP ; #2 (Check TRAP flag)
; <0x1E> = VM.Program
:01A2   45                  MOV <0x1E>, <0x06>
; <0x1E> = &VM.Program.Second
:01A6   16 1E 04 00 00 00   ADD <0x1E>, 0x04
; <0x1F> = VM.Program.Second
:01AE   15 1F 1E            MOV <0x1F>, mem:[<0x1E>]
; VM.Program.Second == 0x5E2F9AC1 ?
:01B2   00 1F C1 9A 2F 5E   CMP <0x1F>, 0x5E2F9AC1
:01BA   4C 3C 5C 00 00      JZ 0x5DF6

; Code skipped

; <0x2D> = SomeStruct.ExpectedChecksum
:5DF6   1C 2D 58            MOV <0x2D>, <0x58>
; <0x1E> = &SomeStruct2
:5DFA   40                  MOV <0x1E>, 0x14A0664 ; Hardcoded
; <0x1E> = &SomeStruct2.ImageBase
:5DFE   16 1E 60 00 00 00   ADD <0x1E>, 0x60
; <0xE9> = SomeStruct2.ImageBase
:5E06   15 E9 1E            MOV <0xE9>, mem:[<0x1E>]
; Points <0x1A> to ImageBase + 0xF9622C -> 0x0139622C -> Key
; <0x1A> = &Key
:5E0A   2D 1A 2C 62 F9 00   MOV <0x1A>, 0xF9622C
:5E12   29 1A E9            ADD <0x1A>, <0xE9>
; <0x1A> = Key
:5E16   15 1A 1A            MOV <0x1A>, mem:[<0x1A>]
; Points <0x15> to ImageBase + 0xF979BC -> 0x013979BC -> Pointer to Functions-struct
; <0x15> = &pFunctions
:5E1A   2D 15 BC 79 F9 00   MOV <0x15>, 0xF979BC
:5E22   29 15 E9            ADD <0x15>, <0xE9>
; <0x15> = &Functions
:5E26   15 15 15            MOV <0x15>, mem:[<0x15>]
; <0x14> = Functions.NumFunctions
:5E2A   09 14 15            MOV <0x14>, mem:[<0x15>]
; <0x15> = &Functions.Funcs
:5E2E   16 15 04 00 00 00   ADD <0x15>, 0x04
; <0x16> = &VM.Context
:5E36   1C 16 07            MOV <0x16>, <0x07>
; <0x16> = &VM.Context.ReturnAddress
:5E3A   16 16 24 00 00 00   ADD <0x16>, 0x24
; <0x16> = &VM.Context.Arg2 aka OriginalReturnAddress
:5E42   16 16 08 00 00 00   ADD <0x16>, 0x08
; <0x16> = VM.Context.OriginalReturnAddress
:5E4A   09 16 16            MOV <0x16>, mem:[<0x16>]
; i = 0
:5E4E   2D 17 00 00 00 00   MOV <0x17>, 0x00
; i < Functions.NumFunctions ?
:5E56   0F 17 14            CMP <0x17>, <0x14>
:5E5A   3E 7C 01 00 00      JBE 0x5FD6
; <0x15> = &Functions.Funcs[i].ReturnAddress_Enc
:5E64   16 15 30 00 00 00   ADD <0x15>, 0x30
; <0xCB> = Functions.Funcs[i].ReturnAddress_Enc
:5E6C   09 CB 15            MOV <0xCB>, mem:[<0x15>]
; <0xCB> ^= Key
:5E70   48                  XOR <0xCB>, <0x1A>
; <0xCB> == VM.Context.OriginalReturnAddress ?
:5E74   0F CB 16            CMP <0xCB>, <0x16>
:5E78   4C 30 00 00 00      JZ 0x5EA8
; <0x15> = &Functions.Funcs[i] (reset pointer)
:5E82   3F 15 30 00 00 00   SUB <0x15>, 0x30
; <0x15> = &Functions.Funcs[i + 1]
:5E8A   16 15 34 00 00 00   ADD <0x15>, 0x34
; i++
:5E92   16 17 01 00 00 00   ADD <0x17>, 0x01
; Always jumps
; Either the VM doesen't have a JMP instruction
; or this was made so that we can not set a breakpoint to when the JZ at :5E78 jumps
:5E9A   0F 00 00            CMP <0x00>, <0x00>
:5E9E   4C B8 FF FF FF      JZ 0x5E56
; The ReturnAddress was found...
:5EA8   12 00 00            MOV <0x00>, <0x00>
; pCode_Enc = &Functions.Funcs[i].StolenBytes_Enc[0] (reset pointer)
:5EAC   3F 15 30 00 00 00   SUB <0x15>, 0x30
; pCallSite = &CallSite (reset pointer)
:5EB4   3F 16 05 00 00 00   SUB <0x16>, 0x05
; StolenBytes_Enc = *pCode_Enc
:5EBC   09 64 15            MOV <0x64>, mem:[<0x15>]
; StolenBytes_Enc ^= Key
:5EC0   48                  XOR <0x64>, <0x1A>
; *pCallSite = StolenBytes
:5EC4   4F 16 64            MOV mem:[<0x16>], <0x64>
; pCode_Enc++
:5EC8   16 15 04 00 00 00   ADD <0x15>, 0x04
; pCallSite++
:5ED0   16 16 04 00 00 00   ADD <0x16>, 0x04
; StolenBytes_Enc = *pCode_Enc
:5ED8   09 64 15            MOV <0x64>, mem:[<0x15>]
; StolenBytes_Enc ^= Key
:5EDC   48                  XOR <0x64>, <0x1A>
; <0x15> = &Functions.Funcs[i] (reset pointer)
:5EE0   3F 15 04 00 00 00   SUB <0x15>, 0x04
; *pCallSite = StolenBytes
:5EE8   4F 16 64            MOV mem:[<0x16>], <0x64>
; pCallSite = &CallSite (reset pointer)
:5EEC   3F 16 04 00 00 00   SUB <0x16>, 0x04
; <0x15> = &Functions.Funcs[i].DataLen_Enc
:5EF4   16 15 08 00 00 00   ADD <0x15>, 0x08
; DataLen_Enc = Functions.Funcs[i].DataLen_Enc
:5EFC   09 18 15            MOV <0x18>, mem:[<0x15>]
; CodeLen = DataLen_Enc ^ Key
:5F00   48                  XOR <0x18>, <0x1A>
; <0x15> = &Functions.Funcs[i] (reset pointer)
:5F04   3F 15 08 00 00 00   SUB <0x15>, 0x08
; <0x15> = &Functions.Funcs[i].DataKey_Enc
:5F0C   16 15 10 00 00 00   ADD <0x15>, 0x10
; DataKey_Enc = Functions.Funcs[i].DataKey_Enc
:5F14   15 19 15            MOV <0x19>, mem:[<0x15>]
; DataKey = DataKey_Enc ^ Key
:5F18   48                  XOR <0x19>, <0x1A>
; <0x15> = &Functions.Funcs[i] (reset pointer)
:5F1C   3F 15 10 00 00 00   SUB <0x15>, 0x10
; offset = 0
:5F24   2D 17 00 00 00 00   MOV <0x17>, 0x00
:5F2C   2D 67 08 00 00 00   MOV <0x67>, 0x08
; <0x64> = pCallSite
:5F34   45                  MOV <0x64>, <0x16>
; <0x64> += offset
:5F38   29 64 17            ADD <0x64>, <0x17>
; <0x1B> = *pCallSite
:5F3C   15 1B 64            MOV <0x1B>, mem:[<0x64>]
; Mask out everything but first byte
:5F40   05 1B 00 FF FF FF   AND <0x1B>, 0xFFFFFF00
; <0x1B> = *pCallSite
:5F48   09 1C 64            MOV <0x1C>, mem:[<0x64>]
; Mask out first byte only
:5F4C   05 1C FF 00 00 00   AND <0x1C>, 0xFF
; <0x65> = DataKey
:5F54   2F 19 65            MOV <0x65>, <0x19>
; Mask out 1 byte from key
:5F58   05 65 FF 00 00 00   AND <0x65>, 0xFF
; Decrypt 1 byte at pCallSite
:5F60   48                  XOR <0x1C>, <0x65>
; Recombine decrypted byte with the 3 original bytes
:5F64   29 1C 1B            ADD <0x1C>, <0x1B>
; <0x64> = pCallSite
:5F68   34 64 16            MOV <0x64>, <0x16>
; <0x64> += offset
:5F6C   29 64 17            ADD <0x64>, <0x17>
; Write back the decrypted byte
:5F70   4F 64 1C            MOV mem:[<0x64>], <0x1C>
; Next key
:5F74   22 19 67            ROR <0x19>, lo(<0x67>)
; offset++
:5F78   16 17 01 00 00 00   ADD <0x17>, 0x01
; offset == CodeLen ?
:5F80   0F 17 18            CMP <0x17>, <0x18>
:5F84   38 B0 FF FF FF      JNZ 0x5F34
; <0x28> = &VM.Context
:5F8E   10 28 07            MOV <0x28>, <0x07>
; <0x28> = &VM.Context.ReturnAddress
:5F92   16 28 24 00 00 00   ADD <0x28>, 0x24
; VM.Context.ReturnAddress = pCallSite
:5F9A   4F 28 16            MOV mem:[<0x28>], <0x16>
; Install VM.Exit
:5F9E   2D 32 58 81 EB 04   MOV <0x32>, 0x4EB8158
:5FA6   2D 33 00 00 00 8A   MOV <0x33>, 0x8A000000
:5FAE   2D 34 43 01 86 03   MOV <0x34>, 0x3860143
:5FB6   2D 35 9D 61 C2 08   MOV <0x35>, 0x8C2619D
:5FBE   2D 36 00 90 90 90   MOV <0x36>, 0x90909000
; <0x37> = &VM.Data
:5FC6   2F 05 37            MOV <0x37>, <0x05>
; <0x37> = &VM.Exit
:5FCA   16 37 C8 00 00 00   ADD <0x37>, 0xC8
; Jumps to VM.Exit
:5FD2   41                  JMP <0x37>