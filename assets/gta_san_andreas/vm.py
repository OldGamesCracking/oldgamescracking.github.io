import struct

"""
    VM Emulator for the SecuROM v7 VM as found in GTA San Andreas

    Usage:
        vm = VM(handlers, program, eflags, vmenter, reader, return_address)

        while vm.Running:
            instruction, formatted = vm.Step()
    
    Note:
        The Emulator will not write back data it uses an internal buffer for that purpose so you can stop the emulation at any time,
        but it eventually needs to load some live data to work properly, that's what the reader-callback is for
"""

class VM:

    NUM_REGS = 0x1000
    INITIAL_RUNNING_KEY = 0x95
    FIRST_OPCODE = 0x2F
    IMM1_KEY = 0x43E2AB9D
    FAKE_CONTEXT_ADDRESS = 0x00112233

    def __init__(self, handlers:int, program:int, vmenter:int, reader, return_address:int = 0):
        """
            @param handlers: Pointer to the VM_HANDLER_t struct
            @param program: The first argument that is passed to VMEnter
            @param vmenter: Adress of VMEnter
            @param reader: Callback to a reader function so that the Emulator can load needed data
            @param return_address: 
        """

        self.Running = True
        
        self._regs = [0 for _ in range(self.NUM_REGS)]
        self._nextOpCode = self.FIRST_OPCODE
        self._reader = reader
        self._return_address = return_address

        self.FirstHandler = struct.unpack("<L", self._reader(handlers, 4))[0]
        self.Instructions = struct.unpack("<L", self._reader(program, 4))[0]
        
        self.Handlers_Enc = self.FirstHandler - vmenter
        self.IP_Offset = self.Instructions - vmenter
        self.EFLAGS = 0
        self.VMEnter = vmenter
        self.RunningKey = self.INITIAL_RUNNING_KEY
        self.Program = program
        self.ProgramOrg = program
        self.Context = self.FAKE_CONTEXT_ADDRESS
        self.Handlers = handlers

        self._shadow_memory = {self.FAKE_CONTEXT_ADDRESS + i : b'\0' * 4 for i in range(0, 0x100, 4)}
        # Install the return address
        self._write(self.FAKE_CONTEXT_ADDRESS + 0x24 + 0x08, return_address)

    def _read(self, address:int, size:int) -> bytes:
        if address in self._shadow_memory:
            return self._shadow_memory[address]

        return self._reader(address, size)

    def _write(self, address:int, value:int):
        self._shadow_memory[address] = struct.pack("<L", value)

    def AdaptFlags(self, flags):
        self.CF = flags["CF"]
        self.ZF = flags["ZF"]
        self.SF = flags["SF"]
        self.OF = flags["OF"]
        self.AF = flags["AF"]
        self.PF = flags["PF"]

    def KeyTransform(self, old, new):
        return (old + new) & 0xff

    def KeyTransform_Alt(self, current, next, opcodeNext, operandA, operandB):
        return (current + (opcodeNext - (next + operandA + operandB))) & 0xff

    def Instruction(self, inst:bytes) -> int:
        return struct.unpack("<BBBB", inst)

    def NextKey(self, inst:bytes) -> int:
        return self.Instruction(inst)[0]

    def NextOpCode_Enc(self, inst:bytes) -> int:
        return self.Instruction(inst)[1]

    def OperandA_Enc(self, inst:bytes) -> int:
        return self.Instruction(inst)[2]

    def OperandB_Enc(self, inst:bytes) -> int:
        return self.Instruction(inst)[3]

    def NextOpCode(self, inst:bytes, key) -> int:
        return (self.NextOpCode_Enc(inst) + key) & 0xff

    def OperandA(self, inst:bytes, key) -> int:
        return ror8(self.OperandA_Enc(inst), key)

    def OperandB(self, inst:bytes, key) -> int:
        return rol8(self.OperandB_Enc(inst), key)

    def OperandA_Alt(self, inst:bytes, key) -> int:
        return rol8(self.OperandA_Enc(inst), key)

    def OperandB_Alt(self, inst:bytes, key) -> int:
        return ror8(self.OperandB_Enc(inst), key)
            
    def Imm(self, imm_enc:bytes, key:int, imm_key:int) -> int:
        immA_Enc, immB_Enc, immC_Enc, immD_Enc = struct.unpack("<BBBB", imm_enc)        
        immA = ror8(immA_Enc, key)
        immB = ror8(immB_Enc, key)
        immC = ror8(immC_Enc, key)
        immD = ror8(immD_Enc, key)
        immediate1 = immA | (immB << 8) | (immC << 16) | (immD << 24)
        immediate1 ^= imm_key

        return immediate1

    def Imm2(self, imm2_enc:bytes, key:int) -> tuple[int, int]:
        imm2A_Enc, imm2B_Enc = struct.unpack("<BB", imm2_enc)        
        imm2A = ror8(imm2A_Enc, key)
        imm2B = rol8(imm2B_Enc, key)

        return (imm2A, imm2B)
    
    def Step(self) -> tuple[int, str]:

        data = self._read(self.IP, 4 + 4 + 2)

        inst = data[:4]
        imm_enc = data[4:4+4]
        imm2_enc = data[4+4:4+4+2]

        opcode = self._nextOpCode

        # OK
        if opcode == 0x00:

            key = self.RunningKey
                
            self.RunningKey = self.KeyTransform(key, self.NextKey(inst))
            imm = self.Imm(imm_enc, key, self.IMM1_KEY)
            opB = self.OperandB(inst, key)
            _, flags = sub_flags(self.GetReg(opB), imm)
            self.AdaptFlags(flags)
            self.IP_Offset += 8

            self._nextOpCode = self.NextOpCode(inst, key)

            return ([opcode, opB] + list(struct.pack("<L", imm)), "CMP <0x{:02X}>, 0x{:02X}".format(opB, imm))

        # OK
        elif opcode == 0x05:
            
            key = self.RunningKey

            self.RunningKey = self.KeyTransform(self.RunningKey, self.NextKey(inst))
            imm = self.Imm(imm_enc, key, self.IMM1_KEY)
            opB = self.OperandB(inst, key)

            result, flags = and_flags(self.GetReg(opB), imm)

            self.SetReg(opB, result)
            self.AdaptFlags(flags)

            self._nextOpCode = self.NextOpCode(inst, key)
                        
            self.IP_Offset += 8

            return ([opcode, opB] + list(struct.pack("<L", imm)), "AND <0x{:02X}>, 0x{:02X}".format(opB, imm))
        
        # OK
        elif opcode == 0x09:

            key = self.RunningKey
                        
            self.RunningKey = self.KeyTransform_Alt(self.RunningKey, self.NextKey(inst), self.NextOpCode_Enc(inst), self.OperandA_Enc(inst), self.OperandB_Enc(inst))
            
            opB = self.OperandB_Alt(inst, key)
            self._nextOpCode = opB

            opA = self.OperandA_Alt(inst, key)
            src = (self.NextKey(inst) - key) & 0xff

            value = struct.unpack("<L", self._read(self.GetReg(src), 4))[0]
    
            self.SetReg(opA, value)
            
            self.IP_Offset += 4
                        
            return ([opcode, opA, src], "MOV <0x{:02X}>, mem:[<0x{:02X}>]".format(opA, src))

        elif opcode == 0x0B:
        
            key = self.RunningKey
                    
            self.RunningKey = self.KeyTransform(self.RunningKey, self.NextKey(inst))

            opA = self.OperandA_Enc(inst)
            opB = self.OperandB_Enc(inst)

            self.SetReg(opB, self.GetReg(opA))

            self.IP_Offset += 4

            self._nextOpCode = self.NextOpCode_Enc(inst)
                                    
            return ([opcode, opB, opA], "MOV <0x{:02X}>, <0x{:02X}>".format(opB, opA))

        # OK
        elif opcode == 0x0f:
        
            key = self.RunningKey

            self.RunningKey = self.KeyTransform(self.RunningKey, self.NextKey(inst))

            opA = self.OperandA(inst, key)
            opB = self.OperandB(inst, key)

            _, flags = sub_flags(self.GetReg(opB), self.GetReg(opA))
            self.AdaptFlags(flags)

            self.IP_Offset += 4

            self._nextOpCode = self.NextOpCode(inst, key)

            return ([opcode, opB, opA], "CMP <0x{:02X}>, <0x{:02X}>".format(opB, opA))

        elif opcode == 0x10:

            key = self.RunningKey
            
            self.RunningKey = self.KeyTransform_Alt(self.RunningKey, self.NextKey(inst), self.NextOpCode_Enc(inst), self.OperandA_Enc(inst), self.OperandB_Enc(inst))

            opB = self.OperandB_Alt(inst, key)
            self._nextOpCode = opB

            src = (self.NextKey(inst) - key) & 0xff

            opA = self.OperandA_Alt(inst, key)
                        
            self.SetReg(opA, self.GetReg(src))

            self.IP_Offset += 4
                        
            return ([opcode, opA, src], "MOV <0x{:02X}>, <0x{:02X}>".format(opA, src))

        # OK
        elif opcode == 0x12:

            key = self.RunningKey
            
            self.RunningKey = self.KeyTransform_Alt(self.RunningKey, self.NextKey(inst), self.NextOpCode_Enc(inst), self.OperandA_Enc(inst), self.OperandB_Enc(inst))
            
            opB = self.OperandB_Alt(inst, key)
            self._nextOpCode = opB

            src = (self.NextKey(inst) - key) & 0xff
            opA = self.OperandA_Alt(inst, key)
            
            self.SetReg(opA, self.GetReg(src))

            self.IP_Offset += 4
                        
            return ([opcode, opA, src], "MOV <0x{:02X}>, <0x{:02X}>".format(opA, src))

        # OK
        elif opcode == 0x15:
                
            key = self.RunningKey
                    
            opA = self.OperandA(inst, key)
            opB = self.OperandB(inst, key)

            value = struct.unpack("<L", self._read(self.GetReg(opA), 4))[0]
            self.SetReg(opB, value)

            self.RunningKey = self.KeyTransform(self.RunningKey, self.NextKey(inst))

            self.IP_Offset += 4

            self._nextOpCode = self.NextOpCode(inst, key)
            
            return ([opcode, opB, opA], "MOV <0x{:02X}>, mem:[<0x{:02X}>]".format(opB, opA))

        # OK
        elif opcode == 0x16:
            
            key = self.RunningKey
                  
            self.RunningKey = self.KeyTransform(self.RunningKey, self.NextKey(inst))
            imm = self.Imm(imm_enc, key, self.IMM1_KEY)
            opB = self.OperandB(inst, key)
            # Note: This opcode does not check for flags!
            self.SetReg(opB, self.GetReg(opB) + imm)

            self._nextOpCode = self.NextOpCode(inst, key)
            
            self.IP_Offset += 8
            
            return ([opcode, opB] + list(struct.pack("<L", imm)), "ADD <0x{:02X}>, 0x{:02X}".format(opB, imm))

        # OK
        elif opcode == 0x17:

            key = self.RunningKey
      
            self.RunningKey = self.KeyTransform(self.RunningKey, self.NextKey(inst))
            self.IP_Offset += 4

            self._nextOpCode = self.NextOpCode(inst, key)
            
            return ([opcode], "NOP ; #3 (IP + (CPUID - Handler6))")

        # OK
        elif opcode == 0x19:
        
            key = self.RunningKey

            opA = self.OperandA(inst, key)
            opB = self.OperandB(inst, key)

            value = struct.unpack("<L", self._read(self.GetReg(opB), 4))[0]

            _, flags = sub_flags(value, self.GetReg(opA))
            self.AdaptFlags(flags)
                  
            self.RunningKey = self.KeyTransform(self.RunningKey, self.NextKey(inst))
            self.IP_Offset += 4

            self._nextOpCode = self.NextOpCode(inst, key)
    
            return ([opcode, opB, opA], "CMP mem:[<0x{:02X}>], <0x{:02X}>".format(opB, opA))

        # OK
        elif opcode == 0x1C:

            key = self.RunningKey

            self.RunningKey = self.KeyTransform_Alt(self.RunningKey, self.NextKey(inst), self.NextOpCode_Enc(inst), self.OperandA_Enc(inst), self.OperandB_Enc(inst))

            opB = self.OperandB_Alt(inst, key)
            self._nextOpCode = opB

            src = (self.NextKey(inst) - key) & 0xff

            opA = self.OperandA_Alt(inst, key)

            self.SetReg(opA, self.GetReg(src))

            self.IP_Offset += 4
                                   
            return ([opcode, opA, src], "MOV <0x{:02X}>, <0x{:02X}>".format(opA, src))

        # OK
        elif opcode == 0x1E:

            key = self.RunningKey
        
            self.RunningKey = self.KeyTransform(self.RunningKey, self.NextKey(inst))

            opA = self.OperandA_Enc(inst)
            opB = self.OperandB_Enc(inst)

            self.SetReg(opB, self.GetReg(opA))

            self.IP_Offset += 4

            self._nextOpCode = self.NextOpCode_Enc(inst)
                                    
            return ([opcode, opB, opA], "MOV <0x{:02X}>, <0x{:02X}>".format(opB, opA))

        # OK
        elif opcode == 0x21:
                    
            key = self.RunningKey
                
            self.RunningKey = self.KeyTransform(key, self.NextKey(inst))
            self.IP_Offset += 4

            self._nextOpCode = self.NextOpCode(inst, key)
            
            return ([opcode], "NOP ; #1")

        # OK
        elif opcode == 0x22:
            
            key = self.RunningKey

            self.RunningKey = self.KeyTransform(self.RunningKey, self.NextKey(inst))
            opA = self.OperandA(inst, key)
            opB = self.OperandB(inst, key)

            value = ror32(self.GetReg(opB), self.GetReg(opA) & 0xff)

            self.SetReg(opB, value)

            self.IP_Offset += 4
            
            self._nextOpCode = self.NextOpCode(inst, key)

            return ([opcode, opB, opA], "ROR <0x{:02X}>, lo(<0x{:02X}>)".format(opB, opA))

        # OK
        elif opcode == 0x24:
        
            key = self.RunningKey
                            
            self.RunningKey = self.KeyTransform(key, self.NextKey(inst))
            imm = self.Imm(imm_enc, key, self.IMM1_KEY)
            opB = self.OperandB(inst, key)

            self.SetReg(opB, self.GetReg(opB) ^ imm)

            self.IP_Offset += 8

            self._nextOpCode = self.NextOpCode(inst, key)

            return ([opcode, opB] + list(struct.pack("<L", imm)), "XOR <0x{:02X}>, 0x{:02X}".format(opB, imm))
        
        # OK
        elif opcode == 0x29:

            key = self.RunningKey
        
            self.RunningKey = self.KeyTransform(self.RunningKey, self.NextKey(inst))
            opA = self.OperandA(inst, key)
            opB = self.OperandB(inst, key)
            result, flags = add_flags(self.GetReg(opA), self.GetReg(opB))
            self.AdaptFlags(flags)
            self.SetReg(opB, result)
            self.IP_Offset += 4

            self._nextOpCode = self.NextOpCode(inst, key)

            return ([opcode, opB, opA], "ADD <0x{:02X}>, <0x{:02X}>".format(opB, opA))

        # OK
        elif opcode == 0x2D:

            key = self.RunningKey
    
            self.RunningKey = self.KeyTransform(key, self.NextKey(inst))
            imm = self.Imm(imm_enc, key, self.IMM1_KEY)
            opB = self.OperandB(inst, key)
            self.SetReg(opB, imm)
            self.IP_Offset += 8

            self._nextOpCode = self.NextOpCode(inst, key)
    
            return ([opcode, opB] + list(struct.pack("<L", imm)), "MOV <0x{:02X}>, 0x{:02X}".format(opB, imm))

        # OK
        elif opcode == 0x2F:

            key = self.RunningKey
    
            self.RunningKey = self.KeyTransform(key, self.NextKey(inst))
            opA = self.OperandA(inst, key)
            opB = self.OperandB(inst, key)
            self.SetReg(opB, self.GetReg(opA))
            self.IP_Offset += 4

            self._nextOpCode = self.NextOpCode(inst, key)

            return ([opcode, opA, opB], "MOV <0x{:02X}>, <0x{:02X}>".format(opB, opA))

        # OK
        elif opcode == 0x34:
        
            key = self.RunningKey
            
            self.RunningKey = self.KeyTransform_Alt(self.RunningKey, self.NextKey(inst), self.NextOpCode_Enc(inst), self.OperandA_Enc(inst), self.OperandB_Enc(inst))
            
            opB = self.OperandB_Alt(inst, key)
            self._nextOpCode = opB

            src = (self.NextKey(inst) - key) & 0xff

            opA = self.OperandA_Alt(inst, key)

            self.SetReg(opA, self.GetReg(src))

            self.IP_Offset += 4
                       
            return ([opcode, opA, src], "MOV <0x{:02X}>, <0x{:02X}>".format(opA, src))

        elif opcode == 0x35:

            key = self.RunningKey
                    
            self.RunningKey = self.KeyTransform(self.RunningKey, self.NextKey(inst))

            opA = self.OperandA_Enc(inst)
            opB = self.OperandB_Enc(inst)

            self.SetReg(opB, self.GetReg(opA))

            self.IP_Offset += 4

            self._nextOpCode = self.NextOpCode_Enc(inst)
                                    
            return ([opcode, opB, opA], "MOV <0x{:02X}>, <0x{:02X}>".format(opB, opA))
        
        elif opcode == 0x36:

            key = self.RunningKey
                                    
            self.RunningKey = self.KeyTransform_Alt(self.RunningKey, self.NextKey(inst), self.NextOpCode_Enc(inst), self.OperandA_Enc(inst), self.OperandB_Enc(inst))
            
            opB = self.OperandB_Alt(inst, key)
            self._nextOpCode = opB
            
            opA = self.OperandA_Alt(inst, key)
            src = (self.NextKey(inst) - key) & 0xff

            destination = self.GetReg(opA)

            self._write(destination, self.GetReg(src))

            self.IP_Offset += 4
            
            return ([opcode, opA, src], "MOV mem:[<0x{:02X}>], <0x{:02X}>".format(opA, src))
    
        elif opcode == 0x37:
            self.Running = False
            return ([opcode], "RET")

        # OK
        elif opcode == 0x38:
    
            key = self.RunningKey

            imm = self.Imm(imm_enc, key, self.IMM1_KEY)
            imm2A, imm2B = self.Imm2(imm2_enc, key)

            zf = self.ZF

            # The ZF will always be eliminated
            self.ZF = 0

            ip_org = self.IP

            if zf:
                self._nextOpCode = self.NextOpCode(inst, key)
                self.RunningKey = self.KeyTransform(key, self.NextKey(inst))
                self.IP_Offset += 10
            else:
                self.IP_Offset += imm
                self.RunningKey = self.KeyTransform(self.RunningKey, imm2A)
                self._nextOpCode = imm2B

            offset = toSigned32(imm)
            ip_rel = ip_org - self.Instructions
            destination = ip_rel + offset

            return ([opcode] + list(struct.pack("<l", offset)), "JNZ 0x{:04X}".format(destination))

        # OK
        elif opcode == 0x3E:
    
            key = self.RunningKey

            imm = self.Imm(imm_enc, key, self.IMM1_KEY)
            imm2A, imm2B = self.Imm2(imm2_enc, key)

            ip_org = self.IP

            if (self.ZF or self.CF):
                self._nextOpCode = self.NextOpCode(inst, key)
                self.RunningKey = self.KeyTransform(key, self.NextKey(inst))
                self.IP_Offset += 10
            else:
                self.IP_Offset += imm
                self.RunningKey = self.KeyTransform(self.RunningKey, imm2A)
                self._nextOpCode = imm2B

            offset = toSigned32(imm)
            ip_rel = ip_org - self.Instructions
            destination = ip_rel + offset

            return ([opcode] + list(struct.pack("<l", offset)), "JBE 0x{:04X}".format(destination))
        
        # OK
        elif opcode == 0x3F:

            key = self.RunningKey
                            
            self.RunningKey = self.KeyTransform(key, self.NextKey(inst))
            imm = self.Imm(imm_enc, key, self.IMM1_KEY)
            opB = self.OperandB(inst, key)
            result, flags = sub_flags(self.GetReg(opB), imm)
            self.AdaptFlags(flags)
            self.SetReg(opB, result)
            self.IP_Offset += 8

            self._nextOpCode = self.NextOpCode(inst, key)

            return ([opcode, opB] + list(struct.pack("<L", imm)), "SUB <0x{:02X}>, 0x{:02X}".format(opB, imm))

        # OK
        elif opcode == 0x40:

            key = self.RunningKey

            self.RunningKey = self.KeyTransform(key, self.NextKey(inst))

            opB = self.OperandB(inst, key)

            # TODO: What is that value?
            self.SetReg(opB, 0x14A0664)

            self.IP_Offset += 4

            self._nextOpCode = self.NextOpCode(inst, key)

            return ([opcode], "MOV <0x{:02X}>, 0x14A0664 ; Hardcoded".format(opB))

        # OK
        elif opcode == 0x41:
            
            key = self.RunningKey

            self.RunningKey = self.KeyTransform(self.RunningKey, self.NextKey(inst))
            opB = self.OperandB(inst, key)

            self._nextOpCode = self.NextOpCode(inst, key)

            self.IP_Offset += 4

            self.Running = False

            return ([opcode], "JMP <0x{:02X}>".format(opB))

        # OK
        elif opcode == 0x44:
                
            key = self.RunningKey
                                        
            self.RunningKey = self.KeyTransform(key, self.NextKey(inst))
            opA = self.OperandA(inst, key)
            opB = self.OperandB(inst, key)
            value = struct.unpack("<L", self._read(self.GetReg(opA), 4))[0]
            result, flags = add_flags(value, self.GetReg(opB))
            self.AdaptFlags(flags)
            self.SetReg(opB, result)
            self.IP_Offset += 4

            self._nextOpCode = self.NextOpCode(inst, key)

            return ([opcode, opB, opA], "ADD <0x{:02X}>, mem:[<0x{:02X}>]".format(opB, opA))

        # OK
        elif opcode == 0x45:

            key = self.RunningKey
            
            self.RunningKey = self.KeyTransform_Alt(self.RunningKey, self.NextKey(inst), self.NextOpCode_Enc(inst), self.OperandA_Enc(inst), self.OperandB_Enc(inst))
            
            opB = self.OperandB_Alt(inst, key)
            self._nextOpCode = opB
            
            opA = self.OperandA_Alt(inst, key)
            src = (self.NextKey(inst) - key) & 0xff

            self.SetReg(opA, self.GetReg(src))
            
            self.IP_Offset += 4
            
            return ([opcode], "MOV <0x{:02X}>, <0x{:02X}>".format(opA, src))

        # OK
        elif opcode == 0x48:

            key = self.RunningKey
                                                    
            self.RunningKey = self.KeyTransform(key, self.NextKey(inst))
            opA = self.OperandA(inst, key)
            opB = self.OperandB(inst, key)

            self.SetReg(opB, self.GetReg(opB) ^ self.GetReg(opA))
            self.IP_Offset += 4

            self._nextOpCode = self.NextOpCode(inst, key)

            return ([opcode], "XOR <0x{:02X}>, <0x{:02X}>".format(opB, opA))

        # OK
        elif opcode == 0x4C:
            
            key = self.RunningKey

            imm = self.Imm(imm_enc, key, self.IMM1_KEY)
            imm2A, imm2B = self.Imm2(imm2_enc, key)

            zf = self.ZF

            # The ZF will always be eliminated
            self.ZF = 0

            ip_org = self.IP

            if not zf:
                self._nextOpCode = self.NextOpCode(inst, key)
                self.RunningKey = self.KeyTransform(key, self.NextKey(inst))
                self.IP_Offset += 10
            else:
                self.IP_Offset += imm
                self.RunningKey = self.KeyTransform(self.RunningKey, imm2A)
                self._nextOpCode = imm2B

            offset = toSigned32(imm)
            ip_rel = ip_org - self.Instructions
            destination = ip_rel + offset

            return ([opcode] + list(struct.pack("<l", offset)), "JZ 0x{:04X}".format(destination))

        # OK
        elif opcode == 0x4E:
                    
            key = self.RunningKey
                
            self.RunningKey = self.KeyTransform(key, self.NextKey(inst))
            self.IP_Offset += 4

            self._nextOpCode = self.NextOpCode(inst, key)
            
            return ([opcode], "NOP ; #2 (Check TRAP flag)")

        # OK
        elif opcode == 0x4F:

            key = self.RunningKey

            opA = self.OperandA(inst, key)
            opB = self.OperandB(inst, key)

            self._write(self.GetReg(opB), self.GetReg(opA))

            self.RunningKey = self.KeyTransform(key, self.NextKey(inst))
            self.IP_Offset += 4

            self._nextOpCode = self.NextOpCode(inst, key)

            return ([opcode, opB, opA], "MOV mem:[<0x{:02X}>], <0x{:02X}>".format(opB, opA))

        elif opcode == 0x50:

            key = self.RunningKey
                            
            self.RunningKey = self.KeyTransform(key, self.NextKey(inst))

            imm = self.Imm(imm_enc, key, 0)
            opB = self.OperandB_Enc(inst)

            self.SetReg(opB, self.GetReg(opB) + imm)

            self.IP_Offset += 8

            self._nextOpCode = self.NextOpCode(inst, key)

            return ([opcode, opB] + list(struct.pack("<L", imm)), "ADD <0x{:02X}>, 0x{:02X}".format(opB, imm))
  
        raise Exception("Unknown OpCode: {:02X}".format(self._nextOpCode))

    def GetReg(self, reg):
        return self._regs[reg] & 0xffffffff

    def SetReg(self, reg, value):
        self._regs[reg] = value & 0xffffffff

    @property
    def Handlers_Enc(self):
        return self.GetReg(0)

    @Handlers_Enc.setter
    def Handlers_Enc(self, value):
        self.SetReg(0, value)

    @property
    def IP_Offset(self):
        return self.GetReg(1)

    @IP_Offset.setter
    def IP_Offset(self, value):
        self.SetReg(1, value)

    @property
    def EFLAGS(self):
        return self.GetReg(2)

    @EFLAGS.setter
    def EFLAGS(self, value):
        self.SetReg(2, value)

    @property
    def VMEnter(self):
        return self.GetReg(3)

    @VMEnter.setter
    def VMEnter(self, value):
        self.SetReg(3, value)

    @property
    def RunningKey(self):
        return self.GetReg(4)

    @RunningKey.setter
    def RunningKey(self, value):
        self.SetReg(4, value)

    @property
    def Data(self):
        raise NotImplementedError()

    @Data.setter
    def Data(self, value):
        NotImplementedError()

    @property
    def Program(self):
        return self.GetReg(6)

    @Program.setter
    def Program(self, value):
        self.SetReg(6, value)

    @property
    def Context(self):
        return self.GetReg(7)

    @Context.setter
    def Context(self, value):
        self.SetReg(7, value)

    @property
    def Handlers(self):
        return self.GetReg(8)

    @Handlers.setter
    def Handlers(self, value):
        self.SetReg(8, value)

    def GetFlag(self, flag):
        return (self.EFLAGS >> flag) & 1

    def SetFlag(self, flag, value):
        self.EFLAGS = (self.EFLAGS & ~(1 << flag)) | ((1 << flag) if value else 0)

    @property
    def CF(self):
        return self.GetFlag(0)

    @CF.setter
    def CF(self, value):
        self.SetFlag(0, value)

    @property
    def PF(self):
        return self.GetFlag(2)

    @PF.setter
    def PF(self, value):
        self.SetFlag(2, value)

    @property
    def AF(self):
        return self.GetFlag(4)

    @AF.setter
    def AF(self, value):
        self.SetFlag(4, value)

    @property
    def ZF(self):
        return self.GetFlag(6)

    @ZF.setter
    def ZF(self, value):
        self.SetFlag(6, value)

    @property
    def SF(self):
        return self.GetFlag(7)

    @SF.setter
    def SF(self, value):
        self.SetFlag(7, value)

    @property
    def OF(self):
        return self.GetFlag(11)

    @OF.setter
    def OF(self, value):
        self.SetFlag(11, value)

    @property
    def IP(self):
        return self.IP_Offset + self.VMEnter

def rol8(val, bits):
    bits &= 0x1f
    while bits > 0:
        val = ((val << 1) & 0xfe) | ((val >> 7) & 0x1)
        bits -= 1
    return val

def ror8(val, bits):
    bits &= 0x1f
    while bits > 0:
        val = ((val >> 1) & 0x7f) | ((val << 7) & 0x80)
        bits -= 1
    return val

def ror32(val, bits):
    while bits > 0:
        val = ((val >> 1) & 0x7fffffff) | ((val << 31) & 0x80000000)
        bits -= 1
    return val

def sub_flags(a, b, bits=32):
    """Emulate x86 SUB a, b and return (result, flags)."""
    mask = (1 << bits) - 1
    sign_bit = 1 << (bits - 1)

    a &= mask
    b &= mask
    result = (a - b) & mask

    flags = {
        # Carry: unsigned borrow occurred
        "CF": int(a < b),
        # Zero: result is zero
        "ZF": int(result == 0),
        # Sign: most significant bit of result
        "SF": int((result & sign_bit) != 0),
        # Overflow: operands had different signs AND result sign differs from a
        "OF": int(((a ^ b) & (a ^ result) & sign_bit) != 0),
        # Auxiliary carry: borrow from bit 3 into bit 4
        "AF": int(((a ^ b ^ result) & 0x10) != 0),
        # Parity: set if the lowest byte has an even number of 1 bits
        "PF": int(bin(result & 0xFF).count("1") % 2 == 0),
    }
    return result, flags

def add_flags(a, b, bits=32):
    """Emulate x86 ADD a, b and return (result, flags)."""
    mask = (1 << bits) - 1
    sign_bit = 1 << (bits - 1)

    a &= mask
    b &= mask
    full = a + b
    result = full & mask

    flags = {
        # Carry: unsigned result does not fit into the operand width
        "CF": int(full > mask),
        # Zero: result is zero
        "ZF": int(result == 0),
        # Sign: most significant bit of result
        "SF": int((result & sign_bit) != 0),
        # Overflow: operands had the same sign AND result sign differs from them
        "OF": int((~(a ^ b) & (a ^ result) & sign_bit) != 0),
        # Auxiliary carry: carry from bit 3 into bit 4
        "AF": int(((a ^ b ^ result) & 0x10) != 0),
        # Parity: set if the lowest byte has an even number of 1 bits
        "PF": int(bin(result & 0xFF).count("1") % 2 == 0),
    }
    return result, flags

def _logic_flags(result, bits, af):
    """Build the flag dict shared by AND, OR and XOR."""
    sign_bit = 1 << (bits - 1)
    return {
        # Carry: always cleared by logical instructions
        "CF": 0,
        # Zero: result is zero
        "ZF": int(result == 0),
        # Sign: most significant bit of result
        "SF": int((result & sign_bit) != 0),
        # Overflow: always cleared by logical instructions
        "OF": 0,
        # Auxiliary carry: undefined on x86, value is supplied by the caller
        "AF": af,
        # Parity: set if the lowest byte has an even number of 1 bits
        "PF": int(bin(result & 0xFF).count("1") % 2 == 0),
    }

def and_flags(a, b, bits=32, af=0):
    """Emulate x86 AND a, b and return (result, flags)."""
    mask = (1 << bits) - 1
    result = (a & mask) & (b & mask)
    return result, _logic_flags(result, bits, af)

def or_flags(a, b, bits=32, af=0):
    """Emulate x86 OR a, b and return (result, flags)."""
    mask = (1 << bits) - 1
    result = (a & mask) | (b & mask)
    return result, _logic_flags(result, bits, af)

def xor_flags(a, b, bits=32, af=0):
    """Emulate x86 XOR a, b and return (result, flags)."""
    mask = (1 << bits) - 1
    result = (a & mask) ^ (b & mask)
    return result, _logic_flags(result, bits, af)

def toSigned32(n):
    n = n & 0xffffffff
    return (n ^ 0x80000000) - 0x80000000
