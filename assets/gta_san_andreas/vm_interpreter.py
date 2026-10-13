import struct
import psutil
import traceback
from vm import VM
from x64dbg_automate import X64DbgClient


# Config
RETURN_ADDRESS = 0x01560FA5
VM_PROGRAM = 0x13979B0 # 0x040100D # 0x013961EC
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

vm = VM(VM_HANDLERS, VM_PROGRAM, VM_ENTER, read_memory(client), RETURN_ADDRESS)

code = {}

while vm.Running:

    ip = vm.IP
    ip_rel = ip - vm.Instructions

    try:
        instruction, formatted = vm.Step()
        
        if ip_rel not in code:
        
            s = ":{:04X}   {}   {}".format(ip_rel, " ".join(["{:02X}".format(i) for i in instruction]).ljust(6*2 + 5), formatted)
    
            code[ip_rel] = s
    
    except Exception as e:

        print(e)
        print(traceback.format_exc())

        vm.Running = False
        
        break

code = sorted([(addr, code[addr]) for addr in code])

for c in code:
    print(c[1])

client.detach_session()