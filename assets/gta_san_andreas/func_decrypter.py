import psutil
import struct
from x64dbg_automate import X64DbgClient

# Config
SOME_STRUCT = 0x14A0664
KEY_OFFSET = 0xF9622C
OFFSET_PFUNCTIONS = 0xF979BC

# For simplicity we use the first session as the one we are interested in, so make sure to only have once instance of x64dbg running
sessions = X64DbgClient.list_sessions()

if not sessions:
    raise SystemExit("no x64dbg-automate session found - start x64dbg (with the plugin) first")

sess = sessions[0]

client = X64DbgClient(psutil.Process(sess.pid).exe())
client.attach_session(sess.pid)

ImageBase = client.read_dword(SOME_STRUCT + 0x60)
Key = client.read_dword(ImageBase + KEY_OFFSET)
pFunctions = client.read_dword(ImageBase + OFFSET_PFUNCTIONS)

print("Image Base: [{:08X}] -> {:08X}".format(SOME_STRUCT + 0x60, ImageBase))
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
    print("CallSite: {:08X}".format(CallSite))

    stolenBytes1 = client.read_dword(Funcs + i * 0x34 + 0) ^ Key
    stolenBytes2 = client.read_dword(Funcs + i * 0x34 + 4) ^ Key
    dataLen = client.read_dword(Funcs + i * 0x34 + 8) ^ Key
    dataKey = client.read_dword(Funcs + i * 0x34 + 16) ^ Key

    #print("stolenBytes1: {:08X}".format(stolenBytes1))
    #print("stolenBytes2: {:08X}".format(stolenBytes2))
    print("dataLen: {} -> {:08X} - {:08X}".format(dataLen, CallSite, CallSite + dataLen))
    # print("dataKey: {:08X}".format(dataKey))

    assert dataLen >= 8

    encrypted_data = client.read_memory(CallSite, dataLen)

    # replace stolen bytes
    encrypted_data = struct.pack("<L", stolenBytes1) + struct.pack("<L", stolenBytes2) + encrypted_data[8:]

    # Decrypt data
    dataKey = struct.pack("<L", dataKey)
    decrypted_data = bytearray([b ^ dataKey[i % 4] for i, b in enumerate(encrypted_data)])

    # Write back
    client.write_memory(CallSite, decrypted_data)

print("Active functions: {}/{}".format(active, NumFunctions))

client.detach_session()