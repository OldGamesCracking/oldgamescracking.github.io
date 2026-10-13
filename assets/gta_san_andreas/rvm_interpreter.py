import psutil
from iced_x86 import *
from rvm import RVM
from x64dbg_automate import X64DbgClient


# Config
RVM_PROGRAMS_START = 0x0155FF13
RVM_PROGRAMS_END = 0x015600DB

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

for program_start in range(RVM_PROGRAMS_START, RVM_PROGRAMS_END, 12):

    print("{:08X}".format(program_start))
    
    rvm = RVM(program_start, read_memory(client))

    result = rvm.Run()
    print(result)

    simplified = rvm.Simplify(result)
    print(simplified)

    assembled = rvm.Assemble(simplified)
    print(assembled)

    encoder = BlockEncoder(bitness=32)
    encoder.add_many(assembled)
    encoded_bytes = encoder.encode(0)

    print()

client.detach_session()