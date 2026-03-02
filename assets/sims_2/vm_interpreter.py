import struct

def reg_name(reg):
    mapping = {
        0: "zero",
        1: "a0",
        2: "a1",
        3: "a2",
        4: "a3",
        5: "a4",
        6: "a5",
        7: "a6",
        9: "a7",

        0x64: "s8",
        0x65: "s9",
        0x66: "s10",
        0x67: "s2",
        0x68: "s3",
        0x69: "s4",
        0x6A: "s5",
        0x6B: "s6",
        0x6C: "t1",
        0x6D: "s11",
        0x6E: "s7",
        0x6F: "t3",
        0x70: "t4",
        0x71: "t5",
        0x72: "t6",

        0x73: "t0",

        0x74: "s1",

        0xfd: "ra",
        0xff: "pc"
    }
    
    if reg in mapping:
        return mapping[reg]
    
    return "???"

def location_name(loc):
    mapping = {
        0x1100: "IV0",
        0x1101: "IV1",
        0x1102: "IV2",

        0x1204: "ESP",
        0x1208: "IMM",
    }
    
    if loc in mapping:
        return mapping[loc]
    
    return "0x{:04X}(zero)".format(loc)

fun_mapping = {
        0x01A5: "sub_hash",
        0x006F: "sub_TEST_x_x",
        0x008C: "sub_AND_r_x",
        0x00AA: "sub_XOR_r_x",
        0x00C8: "sub_OR_r_x",
        0x00E6: "sub_ADD_r_x",
        0x010E: "sub_SUB_r_x",
        0x0136: "sub_CMP_r_x",
        0x015D: "sub_MOV_r_x_JMP_abs",
        0x0160: "sub_JMP_rel",
        0x0163: "sub_JE_rel",
        0x0169: "sub_JNE_rel",
        0x016F: "sub_JB_rel",
        0x0175: "sub_JAE_rel",
        0x017B: "sub_JO_rel",
        0x0181: "sub_JNO_rel",
        0x0187: "sub_JP_rel",
        0x018D: "sub_JNP_rel",
        0x0193: "sub_JS_rel",
        0x0199: "sub_JNS_rel",
        0x019F: "sub_CALL"
    }

def func_name(func):
    if func in fun_mapping:
        return fun_mapping[func]

    return "0x{:04X}".format(func)

if __name__ == "__main__":
    
    with open("parser_p_codes.bin", "rb") as f:
        data = f.read()

    instructions = []
    offset = 0

    while offset < len(data):
        value, = struct.unpack("<L", data[offset:offset+4])
        offset += 4

        opcode = (value >> 25) & 0x7f
        is_immediate = (value >> 24) & 0x01
        dest = (value >> 16) & 0xff
        src = value & 0xffff
        src_high = (value >> 8) & 0xff
        src_low = (value >> 0) & 0xff

        instructions.append((value, opcode, is_immediate, dest, src, src_high, src_low))

    instructions_text = []

    for address, instr in enumerate(instructions):

        if address == 0x01CA:
            break

        value, opcode, is_immediate, dest, src, src_high, src_low = instr

        instr_text = None

        if opcode == 1:
            if is_immediate:
                instr_text = "lw {}, {}".format(reg_name(dest), location_name(src))
            else:
                instr_text = "lw {}, 0({})".format(reg_name(dest), reg_name(src_high))

        elif opcode == 2:
            if is_immediate:
                instr_text = "sw {}, {}".format(reg_name(dest), location_name(src))
            else:
                instr_text = "sw {}, 0({})".format(reg_name(dest), reg_name(src_high))

        elif opcode == 3:
            if is_immediate:
                instr_text = "li {}, 0x{:04X}".format(reg_name(dest), src)
            else:
                instr_text = "mv {}, {}".format(reg_name(dest), reg_name(src_high))

        elif opcode == 4:
            if is_immediate:
                instr_text = "slli {}, {}".format(reg_name(dest), src)
            else:
                instr_text = "sll {}, {}, {}".format(reg_name(dest), reg_name(src_high), reg_name(src_low))

        elif opcode == 5:
            if is_immediate:
                instr_text = "srli {}, {}".format(reg_name(dest), src)
            else:
                instr_text = "srl {}, {}, {}".format(reg_name(dest), reg_name(src_high), reg_name(src_low))

        elif opcode == 6:
            if is_immediate:
                instr_text = "andi {}, 0x{:04X}".format(reg_name(dest), src)
            else:
                instr_text = "and {}, {}, {}".format(reg_name(dest), reg_name(src_high), reg_name(src_low))

        elif opcode == 7:
            if is_immediate:
                instr_text = "ori {}, 0x{:04X}".format(reg_name(dest), src)
            else:
                instr_text = "or {}, {}, {}".format(reg_name(dest), reg_name(src_high), reg_name(src_low))

        elif opcode == 8:
            if is_immediate:
                instr_text = "xori {}, 0x{:04X}".format(reg_name(dest), src)
            else:
                instr_text = "xor {}, {}, {}".format(reg_name(dest), reg_name(src_high), reg_name(src_low))

        elif opcode == 9:
            if is_immediate:
                instr_text = "binvi {}, {}".format(reg_name(dest), src)
            else:
                instr_text = "binv {}, {}, {}".format(reg_name(dest), reg_name(src_high), reg_name(src_low))

        elif opcode == 10:
            if is_immediate:
                instr_text = "bseti {}, {}".format(reg_name(dest), src)
            else:
                instr_text = "bset {}, {}, {}".format(reg_name(dest), reg_name(src_high), reg_name(src_low))

        elif opcode == 11:
            if is_immediate:
                instr_text = "bclri {}, {}".format(reg_name(dest), src)
            else:
                instr_text = "bclr {}, {}, {}".format(reg_name(dest), reg_name(src_high), reg_name(src_low))

        elif opcode == 12:
            if is_immediate:
                instr_text = "bexti {}, {}".format(reg_name(dest), src)
            else:
                instr_text = "bext {}, {}, {}".format(reg_name(dest), reg_name(src_high), reg_name(src_low))

        elif opcode == 14:
            if is_immediate:
                instr_text = "addi {}, 0x{:04X}".format(reg_name(dest), src)
            else:
                instr_text = "add {}, {}, {}".format(reg_name(dest), reg_name(src_high), reg_name(src_low))

        elif opcode == 15:
            if is_immediate:
                instr_text = "subi {}, 0x{:04X}".format(reg_name(dest), src)
            else:
                instr_text = "sub {}, {}, {}".format(reg_name(dest), reg_name(src_high), reg_name(src_low))
        
        elif opcode == 16:
            if is_immediate:
                instr_text = "muli {}, 0x{:04X}".format(reg_name(dest), src)
            else:
                instr_text = "mul {}, {}, {}".format(reg_name(dest), reg_name(src_high), reg_name(src_low))

        elif opcode == 17:
            if is_immediate:
                instr_text = "divi {}, 0x{:04X}".format(reg_name(dest), src)
            else:
                instr_text = "div {}, {}, {}".format(reg_name(dest), reg_name(src_high), reg_name(src_low))

        elif opcode == 18:
            if is_immediate:
                instr_text = "remi {}, 0x{:04X}".format(reg_name(dest), src)
            else:
                instr_text = "rem {}, {}, {}".format(reg_name(dest), reg_name(src_high), reg_name(src_low))

        elif opcode == 19:
            if is_immediate:
                instr_text = "seqi {}, 0x{:04X}".format(reg_name(dest), src)
            else:
                instr_text = "seq {}, {}, {}".format(reg_name(dest), reg_name(src_high), reg_name(src_low))

        elif opcode == 20:
            if is_immediate:
                instr_text = "slti {}, 0x{:04X}".format(reg_name(dest), src)
            else:
                instr_text = "slt {}, {}, {}".format(reg_name(dest), reg_name(src_high), reg_name(src_low))

        elif opcode == 21:
            if is_immediate:
                instr_text = "sofsubi {}, 0x{:04X}".format(reg_name(dest), src)
            else:
                instr_text = "sofsub {}, {}, {}".format(reg_name(dest), reg_name(src_high), reg_name(src_low))
            
        elif opcode == 22:
            if is_immediate:
                instr_text = "scfsubi {}, 0x{:04X}".format(reg_name(dest), src)
            else:
                instr_text = "scfsub {}, {}, {}".format(reg_name(dest), reg_name(src_high), reg_name(src_low))

        elif opcode == 23:
            if is_immediate:
                instr_text = "sofaddi {}, 0x{:04X}".format(reg_name(dest), src)
            else:
                instr_text = "sofadd {}, {}, {}".format(reg_name(dest), reg_name(src_high), reg_name(src_low))

        elif opcode == 24:
            if is_immediate:
                instr_text = "scfaddi {}, 0x{:04X}".format(reg_name(dest), src)
            else:
                instr_text = "scfadd {}, {}, {}".format(reg_name(dest), reg_name(src_high), reg_name(src_low))

        elif opcode == 25:
            if is_immediate:
                instr_text = "safaddi {}, 0x{:04X}".format(reg_name(dest), src)
            else:
                instr_text = "safadd {}, {}, {}".format(reg_name(dest), reg_name(src_high), reg_name(src_low))

        elif opcode == 26:
            if is_immediate:
                instr_text = "safsubi {}, 0x{:04X}".format(reg_name(dest), src)
            else:
                instr_text = "safsub {}, {}, {}".format(reg_name(dest), reg_name(src_high), reg_name(src_low))

        elif opcode == 27:
            if is_immediate:
                instr_text = "bnez {}, {}".format(reg_name(dest), func_name(instructions[src][0]))
            else:
                raise Exception()

        elif opcode == 28:
            if dest == 0:
                if is_immediate:
                    instr_text = "call {}".format(func_name(instructions[src][0]))
                else:
                    if src_high == 0x73:
                        instr_text = "rts"
                    else:
                        raise Exception()
            else:
                if is_immediate:
                    instr_text = "beqz {}, 0x{:04X}".format(reg_name(dest), instructions[src][0])
                else:
                    raise Exception()
            
        elif opcode == 29:
            instr_text = "ret"

        else:
            instr_text = "???"
            continue

        instr_text = "{:04X} : {:08X} : {}".format(address, value, instr_text)

        # print(instr_text)

        instructions_text.append(instr_text)

    with open("parser_instructions.txt", "w") as f:
        for line, instruction in enumerate(instructions_text):
            if line in fun_mapping:
                f.write("\n{}:\n".format(fun_mapping[line]))
            f.write(instruction + "\n")