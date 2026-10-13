import struct
from iced_x86 import *


def clip32(val):
    return val & 0xffffffff

class RVM:

    def __init__(self, program:int, reader, return_address:int = 0):

        self._reader = reader
        self._program = program

    def _Add(self, a, b):
        return a + b

    def _Sub(self, a, b):
        return a - b

    def _Xor(self, a, b):
        return a ^ b

    def _Rol32(self, val, bits):
        assert bits <= 32
        return (val >> ((32 - bits) & 0xff)) | (val << (bits & 0xff))

    def _Ror32(self, val, bits):
        assert bits <= 32
        return (val << ((32 - bits) & 0xff)) | (val >> (bits & 0xff))

    def _Shl(self, a, b):
        return a << b

    def Run(self):
        return self.Step(self._program)

    def Step(self, instruction_address):

        instruction, left_val, right_val = struct.unpack("<LLL", self._reader(instruction_address, 12))

        opcode = ((instruction >> 2) & 0x1fffffff) - 2

        jumptable_lookup = {
            0x00 : 0x00,
            0x09 : 0x01,
            0x3D : 0x02,
            0x4E : 0x03,
            0x6B : 0x04,
            0x6D : 0x05,
            0x76 : 0x06,
            0x7D : 0x07,
            0x84 : 0x08,
            0x93 : 0x09,
            0x9B : 0x0A,
            0xA8 : 0x0B,
            0xAD : 0x0C,
            0xC6 : 0x0D,
            0xC9 : 0x0E,
            0xCF : 0x0F,
            0xE6 : 0x10,
            0xF7 : 0x11
        }

        opcode = jumptable_lookup[opcode]

        is_left_const = (instruction & 1) != 0
        is_right_const = (instruction & 2) != 0

        # ADD right, left
        if opcode == 0x00:
            if is_left_const:
                left = left_val
            else:
                left = self.Step(left_val)

            if is_right_const:
                right = right_val
            else:
                right = self.Step(right_val)

            return ("ADD", right, left)

        # ROR left, right
        if opcode == 0x01:
            if is_right_const:
                right = right_val
            else:
                right = self.Step(right_val)

            if is_left_const:
                left = left_val
            else:
                left = self.Step(left_val)

            return ("ROR", left, right)

        # GET_STACK_POINTER
        if opcode == 0x02:
            raise NotImplemented()

        # ???
        if opcode == 0x03:
            raise NotImplemented()

        # ???
        if opcode == 0x04:
            raise NotImplemented()

        # RETURN CONST ZERO
        if opcode == 0x05:
            return 0

        # STACK_FETCH right
        if opcode == 0x06:
            if is_right_const:
                result = right_val
            else:
                result = self.Step(right_val)

            return ("STACK_FETCH", None, result)

        # MEM_WRITE_AND_RETURN left, right
        if opcode == 0x07:
            if is_right_const:
                right = right_val
            else:
                right = self.Step(right_val)

            if is_left_const:
                left = left_val
            else:
                left = self.Step(left_val)

            return ("MEM_WRITE_AND_RETURN", left, right)

        # STACK_WRITE_AND_RETURN left, right
        if opcode == 0x08:
            if is_right_const:
                right = right_val
            else:
                right = self.Step(right_val)

            if is_left_const:
                left = left_val
            else:
                left = self.Step(left_val)

            return ("STACK_WRITE_AND_RETURN", left, right)

        # XOR right, left
        if opcode == 0x09:
            if is_left_const:
                left = left_val
            else:
                left = self.Step(left_val)

            if is_right_const:
                right = right_val
            else:
                right = self.Step(right_val)

            return ("XOR", right, left)

        # ROL left, right
        if opcode == 0x0A:
            if is_right_const:
                right = right_val
            else:
                right = self.Step(right_val)

            if is_left_const:
                left = left_val
            else:
                left = self.Step(left_val)

            return ("ROL", left, right)

        # SUB left, right
        if opcode == 0x0B:
            if is_left_const:
                left = left_val
            else:
                left = self.Step(left_val)

            if is_right_const:
                right = right_val
            else:
                right = self.Step(right_val)

            return ("SUB", left, right)

        # DO_THEN_RETURN right, left
        if opcode == 0x0C:

            do = None
            
            if not is_right_const:
                do = self.Step(right_val)

            if is_left_const:
                result = left_val
            else:
                result = self.Step(left_val)

            return ("DO_THEN_RETURN", do, result)

        # SHR left, right (unused)
        if opcode == 0x0D:
            if is_right_const:
                right = right_val
            else:
                right = self.Step(right_val)

            if is_left_const:
                left = left_val
            else:
                left = self.Step(left_val)

            return ("SHR", left, right)

        # ???
        if opcode == 0x0E:
            raise NotImplemented()

        # SHL left, right
        if opcode == 0x0F:
            if is_right_const:
                right = right_val
            else:
                right = self.Step(right_val)

            if is_left_const:
                left = left_val
            else:
                left = self.Step(left_val)

            return ("SHL", left, right)

        # MEM_FETCH_REL left, right
        if opcode == 0x10:
            raise NotImplemented()

        # DO_THEN_RETURN left, right
        if opcode == 0x11:

            do = None
            
            if not is_left_const:
                do = self.Step(left_val)

            if is_right_const:
                result = right_val
            else:
                result = self.Step(right_val)

            return ("DO_THEN_RETURN", do, result)

        else:
            raise Exception("Unknown opcode: {:02X}".format(opcode))

    def _TryBubbleUp(self, op, l, r):
        
        if isinstance(l, int):
            if isinstance(r, int):
                return clip32(op(l, r))
            
            elif r[0] == "DO_THEN_RETURN" and isinstance(r[2], int):
                return (r[0], r[1], clip32(op(l, r[2])))
        
        elif l[0] == "DO_THEN_RETURN" and isinstance(l[2], int):
            
            if isinstance(r, int):
                return (l[0], l[1], clip32(op(l[2], r)))
            
            elif r[0] == "DO_THEN_RETURN" and isinstance(r[2], int):
                return (r[0], r[1], clip32(op(l[2] + r[2])))

        return None

    def Simplify(self, program):

        if program is None:
            return None

        if isinstance(program, int):
            return program
        
        op, l, r = program

        if op == "ADD":
            l = self.Simplify(l)
            r = self.Simplify(r)

            result = self._TryBubbleUp(self._Add, l, r)

            if result is not None:
                return result

            return ("ADD", l, r)

        elif op == "SUB":
            l = self.Simplify(l)
            r = self.Simplify(r)

            result = self._TryBubbleUp(self._Sub, l, r)
            
            if result is not None:
                return result

            return ("SUB", l, r)

        elif op == "XOR":
            r = self.Simplify(r)
            l = self.Simplify(l)

            result = self._TryBubbleUp(self._Xor, r, l)
                        
            if result is not None:
                return result

            return ("XOR", l, r)

        elif op == "ROL":
            l = self.Simplify(l)
            r = self.Simplify(r)

            result = self._TryBubbleUp(self._Rol32, l, r)
                                    
            if result is not None:
                return result

            return ("ROL", l, r)

        elif op == "ROR":
            l = self.Simplify(l)
            r = self.Simplify(r)

            result = self._TryBubbleUp(self._Ror32, l, r)
                                                
            if result is not None:
                return result

            return ("ROR", l, r)

        elif op == "SHL":
            l = self.Simplify(l)
            r = self.Simplify(r)

            result = self._TryBubbleUp(self._Shl, l, r)
                                                            
            if result is not None:
                return result

            return ("SHL", l, r)

        elif op == "DO_THEN_RETURN":
            do = self.Simplify(l)
            ret = self.Simplify(r)

            if (do is None) or isinstance(do, int):
                return ret

            if do[0] == "DO_THEN_RETURN":
                return (do[0], do[1], ret)

            return ("DO_THEN_RETURN", do, ret)

        elif op == "STACK_WRITE_AND_RETURN":
            dest = self.Simplify(l)
            val = self.Simplify(r)

            return ("STACK_WRITE_AND_RETURN", dest, val)

        elif op == "STACK_FETCH":
            return ("STACK_FETCH", None, self.Simplify(r))

        elif op == "MEM_WRITE_AND_RETURN":
            dest = self.Simplify(l)
            val = self.Simplify(r)

            return ("MEM_WRITE_AND_RETURN", dest, val)

        raise Exception("Opcode not implemented: {}".format(op))

    def _Assemble(self, program):

        if isinstance(program, int):
            return [ Instruction.create_reg_u32(Code.MOV_R32_IMM32, Register.EAX, program) ]
        
        op, l, r = program

        if op == "ADD":
            
            if type(l) not in [int, list]:
                l = self._Assemble(l)

            if type(r) not in [int, list]:
                r = self._Assemble(r)
            
            if isinstance(l, int) and isinstance(r, list):
                r.append(
                    Instruction.create_reg_u32(Code.ADD_EAX_IMM32, Register.EAX, l)
                )

                return r

            elif isinstance(l, list) and isinstance(r, int):
                l.append(
                    Instruction.create_reg_u32(Code.ADD_EAX_IMM32, Register.EAX, r)
                )

                return l

            raise Exception()

        elif op == "SUB":
            if type(l) not in [int, list]:
                l = self._Assemble(l)

            if type(r) not in [int, list]:
                r = self._Assemble(r)
            
            if isinstance(l, list) and isinstance(r, int):
                l.append(
                    Instruction.create_reg_u32(Code.SUB_EAX_IMM32, Register.EAX, r)
                )

                return l

            raise Exception()

        elif op == "XOR":

            if type(r) not in [int, list]:
                r = self._Assemble(r)

            if type(l) not in [int, list]:
                l = self._Assemble(l)

            if isinstance(l, int) and isinstance(r, list):
                r.append(
                    Instruction.create_reg_u32(Code.XOR_EAX_IMM32, Register.EAX, l)
                )

                return r

            elif isinstance(l, list) and isinstance(r, int):
                l.append(
                    Instruction.create_reg_u32(Code.XOR_EAX_IMM32, Register.EAX, r)
                )

                return l

            raise Exception()

        elif op == "ROL":
            if type(r) not in [int, list]:
                r = self._Assemble(r)

            if type(l) not in [int, list]:
                l = self._Assemble(l)

            if isinstance(l, int) and isinstance(r, list):
                r += [
                    Instruction.create_reg_u32(Code.MOV_R32_IMM32, Register.ECX, 32),
                    Instruction.create_reg_reg(Code.MOV_R32_CR, Register.EDI, Register.EAX),
                    Instruction.create_reg_u32(Code.MOV_R32_IMM32, Register.ESI, l),

                    Instruction.create_reg_reg(Code.SUB_R32_RM32, Register.ECX, Register.EDI),
                    Instruction.create_reg_reg(Code.MOV_R32_CR, Register.EAX, Register.ESI),
                    Instruction.create_reg_reg(Code.SHR_RM32_CL, Register.EAX, Register.CL),
                    Instruction.create_reg_reg(Code.MOV_R32_CR, Register.ECX, Register.EDI),
                    Instruction.create_reg_reg(Code.SHL_RM32_CL, Register.ESI, Register.CL),

                    Instruction.create_reg_reg(Code.OR_R32_RM32, Register.EAX, Register.ESI)
                ]

                return r

            elif isinstance(l, list) and isinstance(r, int):
                assert (r <= 0x1f)
                l.append(
                    Instruction.create_reg_u32(Code.ROL_RM32_IMM8, Register.EAX, r)
                )

                return l

            raise Exception()

        elif op == "ROR":
            if type(r) not in [int, list]:
                r = self._Assemble(r)

            if type(l) not in [int, list]:
                l = self._Assemble(l)

            if isinstance(l, int) and isinstance(r, list):
                r += [
                    Instruction.create_reg_u32(Code.MOV_R32_IMM32, Register.ECX, 32),
                    Instruction.create_reg_reg(Code.MOV_R32_CR, Register.EDI, Register.EAX),
                    Instruction.create_reg_u32(Code.MOV_R32_IMM32, Register.ESI, l),

                    Instruction.create_reg_reg(Code.SUB_R32_RM32, Register.ECX, Register.EDI),
                    Instruction.create_reg_reg(Code.MOV_R32_CR, Register.EAX, Register.ESI),
                    Instruction.create_reg_reg(Code.SHL_RM32_CL, Register.EAX, Register.CL),
                    Instruction.create_reg_reg(Code.MOV_R32_CR, Register.ECX, Register.EDI),
                    Instruction.create_reg_reg(Code.SHR_RM32_CL, Register.ESI, Register.CL),

                    Instruction.create_reg_reg(Code.OR_R32_RM32, Register.EAX, Register.ESI)
                ]

                return r

            elif isinstance(l, list) and isinstance(r, int):
                assert (r <= 0x1f)
                l.append(
                    Instruction.create_reg_u32(Code.ROR_RM32_IMM8, Register.EAX, r)
                )

                return l

            raise Exception()

        elif op == "SHL":
            if type(r) not in [int, list]:
                r = self._Assemble(r)

            if type(l) not in [int, list]:
                l = self._Assemble(l)

            if isinstance(l, int) and isinstance(r, list):
                r.append(
                    Instruction.create_reg_reg(Code.MOV_R32_CR, Register.ECX, Register.EAX),
                    Instruction.create_reg_u32(Code.MOV_R32_IMM32, Register.EAX, l),
                    Instruction.create_reg_reg(Code.SHL_RM32_CL, Register.EAX, Register.ECX)
                )

                return r

            elif isinstance(l, list) and isinstance(r, int):
                assert (r <= 0x1f)
                l.append(
                    Instruction.create_reg_u32(Code.SHL_RM32_IMM8, Register.EAX, r)
                )

                return l

            raise Exception()

        elif op == "DO_THEN_RETURN":
            do = self._Assemble(l)

            assert isinstance(do, list)

            return do + self._Assemble(r)

        elif op == "STACK_WRITE_AND_RETURN":

            assert isinstance(l, int)

            dest = l
            val = self._Assemble(r)
            
            assert isinstance(val, list)

            val += [
                Instruction.create_reg_mem(Code.MOV_R32_RM32, Register.ECX, MemoryOperand(Register.ESP, displ=8)),
                Instruction.create_mem_reg(Code.MOV_RM32_R32, MemoryOperand(Register.ECX, displ=(dest * 4)), Register.EAX)
            ]

            return val

        elif op == "STACK_FETCH":

            if isinstance(r, int):
                return [ 
                    Instruction.create_reg_mem(Code.MOV_R32_RM32, Register.EAX, MemoryOperand(Register.ESP, displ=8)),
                    Instruction.create_reg_mem(Code.MOV_R32_RM32, Register.EAX, MemoryOperand(Register.EAX, displ=(r * 4))),
                    ]

            raise Exception()

        elif op == "MEM_WRITE_AND_RETURN":
            assert isinstance(l, int)
        
            dest = l
            val = self._Assemble(r)
            
            assert isinstance(val, list)

            val.append(Instruction.create_mem_reg(Code.MOV_RM32_R32, MemoryOperand(Register.NONE, displ=dest), Register.EAX))

            return val

        raise Exception("Opcode not implemented: {}".format(op))

    def Assemble(self, program):
 
        if isinstance(program, int):
            # Simplified stub
            instructions = [ Instruction.create_reg_u32(Code.MOV_R32_IMM32, Register.EAX, program) ]

        else:
            instructions = self._Assemble(program)

        instructions.append(Instruction.create(Code.RETND))

        return instructions

    def Encode(self, program):
        encoder = BlockEncoder(bitness=32)
        encoder.add_many(program)
        return encoder.encode(0)
