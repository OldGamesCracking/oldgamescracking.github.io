import psutil
import struct
from x64dbg_automate import X64DbgClient
from asmsim.deob import BadInstruction, BytesSource, RemoteSource, StubError, is_terminator, simplify
from asmsim.verify import verify

# Settings - Might be different for your system!
VM_ENTER = 0x01141980
VM_HANDLERS = 0x014A06D8
VM_LOCK = 0x014A0240
VM_SPLINLOCK_START = 0x1141987
VM_SPLINLOCK_END = 0x114199d
CPUID = 0xD2 # mov eax, 1; cpuid; and eax, 0xDF

# For simplicity we use the first session as the one we are interested in, so make sure to only have once instance of x64dbg running
sessions = X64DbgClient.list_sessions()

if not sessions:
    raise SystemExit("no x64dbg-automate session found - start x64dbg (with the plugin) first")

sess = sessions[0]

client = X64DbgClient(psutil.Process(sess.pid).exe())
client.attach_session(sess.pid)

source = RemoteSource(client)

def simplify_stub(start, regs_in, regs_out, args, mem, keep):
    return simplify(source, start,
                    regs_in=regs_in,
                    regs_out=regs_out,
                    is_end=is_terminator,
                    mode="compact",
                    keep_unread_stores=True,
                    protect_loaded_stores=True,
                    args=args,
                    mem=mem,
                    keep=keep)

def simplify_and_patch_stub(source, start, regs_in, regs_out, args, mem, keep):
    sim = simplify_stub(start, regs_in, regs_out, args, mem, keep)  # Keep the spinlock code or else it would be optimized away

    assert verify(source, sim, compare_memory=True) is not None, "Code was not simplified correctly"

    assert source.is_running() == False, "Stop debugger first!"

    data = sim.patch_bytes()

    assert source.write(sim.start, data), "Could not write simplified data"
    assert source.read(sim.start, len(data)) == data, "Written data is different"

vm_enter = (VM_ENTER, 
            {},                                        # No need to save any input registers
            {"ebx":None},                              # EBX will hold &VM.Data, so we need to save it
            {"arg0":None, "arg1":None},                # Save return address and the Programm-Address
            {hex(VM_LOCK):1},                          # We need to set VM.Lock=1 or else we might get an infinite loop
            [(VM_SPLINLOCK_START, VM_SPLINLOCK_END)])  # Keep the spinlock code or else it would be optimized away

# simplify_and_patch_stub(source, *vm_enter)

p_handlers = source.read(VM_HANDLERS, 4)
handlers = struct.unpack("<L", p_handlers)[0]

print("Handlers start at {:08X}".format(handlers))

handlers = source.read(handlers, 4*256)
handlers = [struct.unpack("<L", handlers[i*4:(i+1)*4])[0] for i in range(256)]

def ror(value, places):
    while places > 0:
        value = (value >> 1) | ((value & 1) << 31)
        places -= 1

    return value

handler_addresses = []

for i in range(256):
    handler_offset_enc = handlers[i]
    handler_offset = ror(handler_offset_enc, CPUID)
    handler_at = VM_ENTER + handler_offset

    label = client.get_label_at(handler_at)

    if not label:
        client.set_label_at(handler_at, "vm_handler_{:02X}_???".format(i))

    if handler_offset == 0:
        break

    handler_addresses.append(handler_at)
    
    print("{:02X}: {:08X} -> {:08X} -> {:08X}".format(i, handler_offset_enc, handler_offset, handler_at))

print("Number of handlers: {}".format(len(handler_addresses)))

verified_handlers = [0x00, 0x05, 0x09, 0x0b, 0x0f, 0x12, 0x15, 0x16, 0x17, 0x19, 0x1c, 0x21, 0x22, 0x29, 0x2D, 0x2F, 0x34, 0x36, 0x38, 0x3E, 0x3F, 0x40, 0x44, 0x45, 0x48, 0x4c, 0x4E, 0x4f]
# verified_handlers = [0x0b]

for handler in verified_handlers:

    handler_at = handler_addresses[handler]

    print("Simplifying Handler {:02X} at {:08X}".format(handler, handler_at))

    handler = (handler_at, 
                {"ebx":None},   # EBX will hold &VM.Data, so we need to save it (in and out)
                {"ebx":None},
                {},
                {},
                [])

    simplify_and_patch_stub(source, *handler)

source.close()