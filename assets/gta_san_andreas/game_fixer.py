"""
    Game fixer for GTA San Andreas
    Make sure that the debugger is at the OEP or else it might not work
"""

from vm import VM
from rvm import RVM
import struct
import psutil
from x64dbg_automate import X64DbgClient
from x64dbg_automate.models import DisasmInstrType


VM_ENTER = 0x01141980
VM_HANDLERS = 0x014A06D8

# For simplicity we use the first session as the one we are interested in, so make sure to only have once instance of x64dbg running
sessions = X64DbgClient.list_sessions()

if not sessions:
    raise SystemExit("no x64dbg-automate session found - start x64dbg (with the plugin) first")

sess = sessions[0]

client = X64DbgClient(psutil.Process(sess.pid).exe())
client.attach_session(sess.pid)

def read_memory(client):
    def read_memory_inner(addr:int, size:int) -> bytes:
        return client.read_memory(addr, size)
    return read_memory_inner


# Step 1: Determine the IAT slots that are called by the VM
IMPORTS_START = 0x00401005
NUM_IMPORTS = 7

imports_by_vm = [] 

for i in range(NUM_IMPORTS):
    program = IMPORTS_START + 4 * i

    vm = VM(VM_HANDLERS, program, VM_ENTER, read_memory(client))

    iat_slot = None

    while vm.Running:

        instruction, formatted = vm.Step()

        if instruction[0] == 0x2D:
            iat_slot = struct.unpack("<L", bytes(instruction[2:]))[0]

            break

    assert iat_slot is not None

    print("VM Program at {:08X} calls IAT slot at {:08X}".format(program, iat_slot))

    imports_by_vm.append((program, iat_slot))


# Step 2: Decrypt the functions that are normally decrypted by the VM
SOME_STRUCT = 0x14A0664
IMAGE_BASE_OFFSET = 0x60
KEY_OFFSET = 0xF9622C
OFFSET_PFUNCTIONS = 0xF979BC

decrypted_functions = []

ImageBase = client.read_dword(SOME_STRUCT + IMAGE_BASE_OFFSET)
Key = client.read_dword(ImageBase + KEY_OFFSET)
pFunctions = client.read_dword(ImageBase + OFFSET_PFUNCTIONS)

print("Image Base: [{:08X}] -> {:08X}".format(SOME_STRUCT + IMAGE_BASE_OFFSET, ImageBase))
print("Key: [{:08X}] -> {:08X}".format(ImageBase + KEY_OFFSET, Key))
print("pFunctions: [{:08X}] -> {:08X}".format(ImageBase + OFFSET_PFUNCTIONS, pFunctions))

NumFunctions = client.read_dword(pFunctions)

print("NumFunctions: {0:08X} ({0})".format(NumFunctions))

Funcs = pFunctions + 4

active = 0

for i in range(NumFunctions):
    
    ReturnAddress_Enc = client.read_dword(Funcs + i * 0x34 + 0x30)

    if ReturnAddress_Enc == 0:
        continue

    active += 1

    ReturnAddress = ReturnAddress_Enc ^ Key

    CallSite = ReturnAddress - 5

    # print("ReturnAddress: {:08X}".format(ReturnAddress))
    print("Encrypted function at: {:08X}".format(CallSite))

    stolenBytes1 = client.read_dword(Funcs + i * 0x34 + 0) ^ Key
    stolenBytes2 = client.read_dword(Funcs + i * 0x34 + 4) ^ Key
    dataLen = client.read_dword(Funcs + i * 0x34 + 8) ^ Key
    dataKey = client.read_dword(Funcs + i * 0x34 + 16) ^ Key

    #print("stolenBytes1: {:08X}".format(stolenBytes1))
    #print("stolenBytes2: {:08X}".format(stolenBytes2))
    # print("dataLen: {} -> {:08X} - {:08X}".format(dataLen, CallSite, CallSite + dataLen))
    # print("dataKey: {:08X}".format(dataKey))

    assert dataLen >= 8

    encrypted_data = client.read_memory(CallSite, dataLen)

    # replace stolen bytes
    encrypted_data = struct.pack("<L", stolenBytes1) + struct.pack("<L", stolenBytes2) + encrypted_data[8:]

    # Decrypt data
    dataKey = struct.pack("<L", dataKey)
    decrypted_data = bytearray([b ^ dataKey[i % 4] for i, b in enumerate(encrypted_data)])

    decrypted_functions.append((CallSite, decrypted_data))

print("Encrypted functions: {}/{}".format(active, NumFunctions))


# Step 3: Parse the "Recursive VM"/AST and generate x86 equivalent code
RVM_ENTER = 0x01166B30
RVM_PROGRAMS_START = 0x0155FF13
RVM_PROGRAMS_END = 0x015600DB

rvm_programs = []

for program_address in range(RVM_PROGRAMS_START, RVM_PROGRAMS_END, 12):

    rvm = RVM(program_address, read_memory(client))

    result = rvm.Run()
    simplified = rvm.Simplify(result)
    assembled = rvm.Assemble(simplified)
    encoded = rvm.Encode(assembled)

    rvm_programs.append((program_address, encoded))

print("Encoded {} Recursive VMs".format(len(rvm_programs)))

# mov eax, [esp+0x04]
# mov eax, [eax]
# jmp eax
interpreter_patch = bytes([0x8B, 0x44, 0x24, 0x04, 0x8B, 0x00, 0xFF, 0xE0])


# Step 4: Fix the jump bridges
def find_mem_all(client, start, pattern, size=-1, max_results=None):
    """
    Replicates x64dbg's 'findmemall' command via x64dbg-automate.

    Args:
        client: Connected X64DbgClient instance
        start: Address to start searching from
        pattern: Byte pattern, '?' wildcards allowed (e.g. 'EB0?90??8D')
        size: Number of bytes to search, -1 = entire memory map
        max_results: Optional override of x64dbg's max find result limit

    Returns:
        List of addresses where the pattern was found
    """
    # Note: x64dbg parses numbers in commands/expressions as hex by default,
    # so every number is passed explicitly as 0x... to avoid surprises.
    if max_results is not None:
        cmd = "setmaxfindresult 0x{:X}".format(max_results)
        if not client.cmd_sync(cmd):
            raise RuntimeError("Command failed: {}".format(cmd))

    size_arg = "-1" if size < 0 else "0x{:X}".format(size)
    cmd = 'findmemall 0x{:X}, "{}", {}'.format(start, pattern.replace(" ", ""), size_arg)
    if not client.cmd_sync(cmd):
        raise RuntimeError("Command failed: {}".format(cmd))

    # Iterate over what is actually in the reference view
    count, ok = client.eval_sync("ref.count()")
    if not ok:
        raise RuntimeError("Failed to evaluate ref.count()")

    hits = []
    for i in range(count):
        addr, ok = client.eval_sync("ref.addr(0x{:X})".format(i))
        if not ok:
            raise RuntimeError("Failed to read reference #{}".format(i))
        hits.append(addr)
    return hits

def get_game_memory_range(client):
    eip = client.get_reg('eip')

    base, ok = client.eval_sync("mod.base(0x{:08X})".format(eip))
    if not ok:
        raise RuntimeError("Failed to evaluate mode.base")

    size, ok = client.eval_sync("mod.size(0x{:08X})".format(eip))
    if not ok:
        raise RuntimeError("Failed to evaluate mode.size")

    return (base, size)

# findmemall mod.base(eip), "FF742428FF15", mod.size(eip)
base, size = get_game_memory_range(client)

hits = find_mem_all(client, base, "FF15??????", size)

# find the hits that call the base-address of a mem region
jump_bridges = []

for hit in hits:
    call_by = client.read_dword(hit + 2)

    if not client.check_valid_read_ptr(call_by):
        continue

    call_destination = client.read_dword(call_by)

    if not client.check_valid_read_ptr(call_destination):
        continue

    call_destination_base, ok = client.eval_sync("mem.base(0x{:08X})".format(call_destination))
    
    if not ok:
        raise RuntimeError("Failed to evaluate mem.base")

    if call_destination != call_destination_base:
        continue

    eip_org = client.get_reg('eip')
    esp_org = client.get_reg('esp')

    # Step through the stub to get the function address
    client.set_reg('eip', call_destination)

    func_found = False

    while not func_found:
        inst = client.disassemble_at(client.get_reg('eip'))

        if inst.type == DisasmInstrType.Branch:
            # One more step and we are in the function
            while True:
                # Make sure we REALLY stepped (x64dbg bug)
                eip_old = client.get_reg('eip')
                client.stepi(step_count=1, pass_exceptions=False, swallow_exceptions=False, wait_for_ready=True, wait_timeout=2)
                eip_new = client.get_reg('eip')
                if eip_old != eip_new:
                    jump_bridges.append((hit, eip_new))

                    client.set_reg('eip', eip_org)
                    client.set_reg('esp', esp_org)

                    print("Call at {:08X} calls base of mem region at {:08X}, function at {:08X}".format(hit, call_destination, eip_new))

                    func_found = True

                    break
        else:
            client.stepi(step_count=1, pass_exceptions=False, swallow_exceptions=False, wait_for_ready=True, wait_timeout=2)


# Step 5: Write the patches back to the live session

# For the imports, we simply replace the pointers which normally point to the code with the slot-addresses
for i in imports_by_vm:
    programm_address, slot = i
    client.write_memory(programm_address, struct.pack("<L", slot))

# Patch VMEnter so it will jump to the IAT slot
proxy_data = bytes([0x87, 0x44, 0x24, 0x04, 0x8B, 0x00, 0x8B, 0x00, 0x87, 0x04, 0x24, 0x87, 0x44, 0x24, 0x04, 0xC3])
client.write_memory(VM_ENTER, proxy_data)

# Functions can simply be written back
for f in decrypted_functions:
    func_address, data = f
    client.write_memory(func_address, data)

# We place the generated code in the Interpreter code and place the address to the function in the tree-struct
client.write_memory(RVM_ENTER, interpreter_patch)
offset = len(interpreter_patch)

for prog in rvm_programs:
    tree_address, code = prog
    function_address = RVM_ENTER + offset
    client.write_memory(tree_address, struct.pack("<L", function_address))
    client.write_memory(function_address, code)

    print("Function for tree at {:08X} located at {:08X}".format(tree_address, function_address))

    offset += len(code)

# Replace the jump bridges with a direct jump to the function
for jmp in jump_bridges:
    call_from, func_address = jmp
    offset = func_address - call_from - 5
    client.write_memory(call_from, b"\xe8" + struct.pack("<L", offset) + b"\x90")

client.detach_session()

print("Fixing done, now fix the ACLayers stuff if needed and dump using the size-patched version of Scylla!")