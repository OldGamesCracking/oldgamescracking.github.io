; <0x61> = VM.Context
:0000   2F 07 61            MOV <0x61>, <0x07>
; <0x61> = &VM.Context.ReturnAddress
:0004   16 61 24 00 00 00   ADD <0x61>, 0x24
; <0x61> = VM.Context.ReturnAddress
:000C   09 61 61            MOV <0x61>, mem:[<0x61>]
; <0x36> = VM.Context
:0010   12 36 07            MOV <0x36>, <0x07>
; <0x36> = &VM.Context.arg1
:0014   16 36 28 00 00 00   ADD <0x36>, 0x28
; &VM.Context.arg1 = VM.Context.ReturnAddress (Replace additional argument with return address)
:001C   36                  MOV mem:[<0x36>], <0x61>
:0020   4E                  NOP ; #2 (Check TRAP flag)
; <0x36> = VM.Context
:0024   45                  MOV <0x36>, <0x07>
; <0x36> = &VM.Context.ReturnAddress
:0028   16 36 24 00 00 00   ADD <0x36>, 0x24
; <0x23> = 0x8580A0 (Address of IAT slot)
:0030   2D 23 A0 80 85 00   MOV <0x23>, 0x8580A0
; <0x23> = [0x8580A0] (Gives the proc address)
:0038   15 23 23            MOV <0x23>, mem:[<0x23>]
; VM.Context.ReturnAddress = ProcAddress
:003C   36                  MOV mem:[<0x36>], <0x23>
:0040   37                  RET