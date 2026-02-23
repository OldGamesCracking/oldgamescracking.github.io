#include <Windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <shlwapi.h>
#include <vector>
#include <string>
#include <tuple>
#include "Worker.h"
#include "Logging.h"
#include "ProcessHelper.h"
#include "MyDebugger.h"


void Worker::PrintProcName(Module *Mod, Proc *Proc, bool Newline)
{
    if (Proc == nullptr)
    {
        Log.Log("%s:???", Mod->Name.c_str());
    }
    else
    {
        Log.Log("%s:%s", Mod->Name.c_str(), Proc->Name.c_str());
    }

    if (Newline)
    {
        Log.Line("");
    }
}

void Worker::PrintProcName(DWORD Address, bool Newline)
{
    Module *mod = Modules.GetModuleAt(Address);

    if (mod == nullptr)
    {
        Log.Log("UNKNOWN");
    }
    else
    {
        Log.Log("%s:", mod->Name.c_str());

        PrintProcName(mod, mod->GetProcAt(Address), false);
    }

    if (Newline)
    {
        Log.Line("");
    }
}

void Worker::PauseHooks()
{
    hook_ContinueDebugEvent.Pause();
    hook_WaitForDebugEvent.Pause();
    hook_WriteProcessMemory.Pause();
}

void Worker::ResumeHooks()
{
    hook_ContinueDebugEvent.Enable();
    hook_WaitForDebugEvent.Enable();
    hook_WriteProcessMemory.Enable();
}

void Worker::InitEntryPoints()
{
    BYTE buffer[sizeof(WCHAR) * (MAX_MODULE_NAME32 + 1)];

    GetModuleFileNameExA(hProcess, NULL, (LPSTR)&buffer[0], sizeof(buffer));

    HANDLE hFile = CreateFileA((LPCSTR)&buffer[0], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    /* Read DOS Header */
    DWORD bytesRead = 0;
    ReadFile(hFile, &buffer[0], sizeof(IMAGE_DOS_HEADER), &bytesRead, NULL);

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)&buffer[0];

    DWORD fileOffset = dosHeader->e_lfanew;

    SetFilePointer(hFile, fileOffset, NULL, FILE_BEGIN);

    ReadFile(hFile, &buffer[0], sizeof(IMAGE_NT_HEADERS32), &bytesRead, NULL);

    PIMAGE_NT_HEADERS32 ntHeaders = (PIMAGE_NT_HEADERS32)&buffer[0];

    ImageBase = ntHeaders->OptionalHeader.ImageBase;
    DWORD entryPoint = ImageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint;
    EntryPoint = entryPoint;
    DWORD numberOfSections = ntHeaders->FileHeader.NumberOfSections;

    fileOffset += sizeof(IMAGE_NT_HEADERS32);

    DWORD sectionHeaders = fileOffset;

    SafeDiscSectionStart = (DWORD)(-1);
    SafeDiscSectionEnd = 0;

    /* Find the section that contains the OEP-Jump (SafeDisc section) */
    for (size_t section = 0; section < numberOfSections; section++)
    {
        SetFilePointer(hFile, fileOffset, NULL, FILE_BEGIN);

        ReadFile(hFile, &buffer[0], sizeof(IMAGE_SECTION_HEADER), &bytesRead, NULL);

        PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)&buffer[0];

        DWORD sectionStartVirt = ImageBase + pSection->VirtualAddress;
        DWORD sectionEndVirt = sectionStartVirt + pSection->SizeOfRawData;

        if (strncmp((char *)pSection->Name, SAFEDISC_SEC_NAME, strlen(SAFEDISC_SEC_NAME)) == 0)
        {
            if (sectionStartVirt < SafeDiscSectionStart)
            {
                SafeDiscSectionStart = sectionStartVirt;
            }

            if (sectionEndVirt > SafeDiscSectionEnd)
            {
                SafeDiscSectionEnd = sectionEndVirt;
            }
        }

        if ((sectionStartVirt <= entryPoint) && (entryPoint < sectionEndVirt))
        {
            DWORD offset = entryPoint - sectionStartVirt;

            LPVOID sectionBuffer = VirtualAlloc(NULL, pSection->SizeOfRawData, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

            SetFilePointer(hFile, pSection->PointerToRawData, NULL, FILE_BEGIN);

            ReadFile(hFile, sectionBuffer, pSection->SizeOfRawData, &bytesRead, NULL);

            /** Search for "CALL EAX; POPAD; POP EBP; JMP XXX"(FFD0 61 5D EB) */
            const BYTE pattern[] = { 0xFF, 0xD0, 0x61, 0x5D, 0xEB };

            for (DWORD address = (DWORD)sectionBuffer + offset; address < (DWORD)sectionBuffer + pSection->SizeOfRawData; address++)
            {
                if (memcmp((BYTE *)address, &pattern[0], sizeof(pattern)) == 0)
                {
                    BYTE jmpOffset = *((BYTE *)address + 5);
                    DWORD oepJmpAt = (DWORD)address + 4 + 2 + jmpOffset;
                    DWORD oepJmpOffset = *(DWORD *)(oepJmpAt + 1);
                    DWORD oepAddress = oepJmpAt + 5 + oepJmpOffset; /* Relative to buffer */

                    oepAddress -= (DWORD)sectionBuffer;
                    oepAddress += ImageBase + pSection->VirtualAddress;

                    OEP = oepAddress;

                    break;
                }
            }

            VirtualFree(sectionBuffer, 0, MEM_RELEASE);

            sectionBuffer = NULL;
        }

        fileOffset += sizeof(IMAGE_SECTION_HEADER);
    }

    Log.Line("SafeDiscSectionStart: 0x%08X", SafeDiscSectionStart);
    Log.Line("SafeDiscSectionEnd: 0x%08X", SafeDiscSectionEnd);

    fileOffset = sectionHeaders;

    /* Find the section that contains the OEP (Text section) */
    for (DWORD section = 0; section < numberOfSections; section++)
    {
        SetFilePointer(hFile, fileOffset, NULL, FILE_BEGIN);

        ReadFile(hFile, &buffer[0], sizeof(IMAGE_SECTION_HEADER), &bytesRead, NULL);

        PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)&buffer[0];

        DWORD sectionStartVirt = ImageBase + pSection->VirtualAddress;
        DWORD sectionEndVirt = sectionStartVirt + pSection->SizeOfRawData;

        if ((sectionStartVirt <= OEP) && (OEP < sectionEndVirt))
        {
            TextSectionStart = sectionStartVirt;
            TextSectionEnd = sectionEndVirt;
            TextSectionSize = sectionEndVirt - sectionStartVirt;

            Log.Line("TextSectionStart: 0x%08X", TextSectionStart);
            Log.Line("TextSectionEnd: 0x%08X", TextSectionEnd);

            break;
        }
    }

    CloseHandle(hFile);
}

void Worker::InitDeadEnds()
{
    std::vector<std::string> deadEnds = {
        "ExitProcess",
        "ExitThread",
        "TerminateProcess",
        "TerminateThread"
    };

    for (const auto &proc : deadEnds)
    {
        DWORD address = Modules.GetProcAddress("Kernel32.dll", proc);

        if (address != NULL)
        {
            DeadEnds.insert(address);
        }
        else
        {
            Log.Error("Could not get proc address for %s", proc.c_str());
        }
    }
}

void Worker::InitProcessData(DWORD dwProcessId)
{
    this->dwProcessId = dwProcessId;
    hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD, FALSE, dwProcessId);

    if (hProcess == NULL)
    {
        Log.Error("Could not open process");

        return;
    }

    InitEntryPoints();
}

void Worker::InitMainThread(DWORD dwThreadId)
{
    this->dwThreadId = dwThreadId;
    hMainThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, dwThreadId);

    Modules.GetModulesFromProcess(hProcess);

    InitDeadEnds();
}

void Worker::StartFixing()
{
    Fixing = true;

    RestoreOEPData();
    PatchNanomitesJump();
    ReadTextSection();
    InitImports();
    InitExplorer();

    LastAction = ExplorationStepAction::None;
}

void Worker::RestoreOEPData()
{
    ProcessHelper p(hProcess);

    /* Get original byte */
    BYTE orgByte;
    p.ReadMemory((LPVOID)EntryPoint, &orgByte, 1);

    p.WriteMemory((LPVOID)OEP, &orgByte, 1);

    FlushInstructionCache(hProcess, (LPVOID)OEP, 1);
}

void Worker::PatchNanomitesJump()
{
    DWORD oldProtect;

    /* Force Nanomites to be always written back */
    VirtualProtect((LPVOID)NANOMITES_WRITE_JMP_ADDRESS, sizeof(DWORD), PAGE_READWRITE, &oldProtect);
    *(DWORD*)NANOMITES_WRITE_JMP_ADDRESS = NANOMITES_WRITE_JMP_PATCH;
    VirtualProtect((LPVOID)NANOMITES_WRITE_JMP_ADDRESS, sizeof(DWORD), oldProtect, &oldProtect);

    /* Preven Bad-Nanomites counter from increasing */
    VirtualProtect((LPVOID)NANOMITES_INCREMENT_BAD_ADDRESS, sizeof(WORD), PAGE_READWRITE, &oldProtect);
    *(WORD*)NANOMITES_INCREMENT_BAD_ADDRESS = (WORD)NANOMITES_INCREMENT_BAD_PATCH;
    VirtualProtect((LPVOID)NANOMITES_INCREMENT_BAD_ADDRESS, sizeof(WORD), oldProtect, &oldProtect);

    /* Preven Good-Nanomites counter from increasing */
    VirtualProtect((LPVOID)NANOMITES_INCREMENT_GOOD_ADDRESS, sizeof(WORD), PAGE_READWRITE, &oldProtect);
    *(WORD*)NANOMITES_INCREMENT_GOOD_ADDRESS = (WORD)NANOMITES_INCREMENT_GOOD_PATCH;
    VirtualProtect((LPVOID)NANOMITES_INCREMENT_GOOD_ADDRESS, sizeof(WORD), oldProtect, &oldProtect);

    FlushInstructionCache(GetCurrentProcess(), NULL, NULL);
}

void Worker::ReadTextSection()
{
    if (TextSectionBuffer != nullptr)
    {
        delete[] TextSectionBuffer;
        TextSectionBuffer = nullptr;
    }

    TextSectionBuffer = new BYTE[TextSectionSize];

    if (TextSectionBuffer == nullptr)
    {
        Log.Error("Could not create text section buffer");
    }

    ProcessHelper(hProcess).ReadMemory((LPVOID)TextSectionStart, TextSectionBuffer, TextSectionSize);
}

void Worker::InitImports()
{
    size_t IATEntries = IAT_SIZE / sizeof(DWORD);

    DWORD *IAT = new DWORD[IATEntries];

    if (IAT == nullptr)
    {
        Log.Error("Could not create IAT buffer");

        delete[] IAT;

        return;
    }

    if (!ProcessHelper(hProcess).ReadMemory((LPVOID)IAT_START, (PBYTE)IAT, IAT_SIZE))
    {
        Log.Error("Could not read IAT");

        delete[] IAT;

        return;
    }

    Log.Debug("Loaded %u Imports", IATEntries);

    for (size_t i = 0; i < IATEntries; i++)
    {
        if (Log.Verbose)
        {
            Log.Log("Thuk %u : %08X -> ", i, IAT[i]);
        }
        
        if (IAT[i] == 0)
        {
            Log.Debug("Empty");

            continue;
        }

        /* Check if in 'good' module */
        Module *mod = Modules.GetModuleAt(IAT[i]);

        if (mod == nullptr)
        {
            Log.Debug("SafeDisc (?)");

            IAT[i] = 0;
        }
        else
        {
            PrintProcName(mod, mod->GetProcAt(IAT[i]));
        }
    }

    Imports.AddIAT(IAT, IATEntries);

    delete[] IAT;
}

void Worker::FixImports()
{
    ProcessHelper p(hProcess);

    Imports.RebuildIAT();

    size_t IATEntries = Imports.GetIATEntries();

    if (IATEntries == 0)
    {
        Log.Line("No Entries need fixing");

        return;
    }

    DWORD *IAT = new DWORD[IATEntries];

    Imports.GetIAT(IAT);

    if (!p.WriteMemory((LPVOID)IAT_START, (PBYTE)IAT, sizeof(DWORD) * IATEntries))
    {
        Log.Error("Could not write IAT");

        delete[] IAT;

        return;
    }

    delete[] IAT;

    Log.Line("IAT written. Entries: %u", IATEntries);

    const std::vector<IntermodularCall> &Calls = Imports.GetCalls();

    for (const auto &call : Calls)
    {
        LPVOID thunkAddress = &((DWORD*)IAT_START)[call.IATIndex];

        Log.Log("%s @ %08X points to thunk #%03u @ %08X -> %08X -> ", (call.IsJump ? "Jump" : "Call"), call.CallAt, call.IATIndex, thunkAddress, call.Destination);

        PrintProcName(call.Destination, true);

        BYTE instruction[6] = { 0xff, 0x15, 0, 0, 0, 0 };
        
        if (call.IsJump)
        {
            instruction[1] = 0x25;
        }
        
        *(DWORD*)&instruction[2] = (DWORD)thunkAddress;

        if (!p.WriteMemory((LPVOID)call.CallAt, instruction, sizeof(instruction)))
        {
            Log.Error("Could not write Call/Jump");

            return;
        }
    }

    Log.Line("Calls restored", IATEntries);
}

void Worker::InitExplorer()
{
    Explorer = new CodeExplorer(TextSectionBuffer, TextSectionStart, TextSectionEnd, IAT_START, IAT_END);

    // Entry point
    Explorer->AddEntryPoint(OEP);

    // Base of text section
    Explorer->AddEntryPoint(TextSectionStart);

    // Add SEH ?

    // Add TLS ?

    /* Exports */
    Module *mod = Modules.GetModuleAt(OEP);

    if (mod != nullptr)
    {
        const std::unordered_map<DWORD, Proc*> &exports = mod->Exports();

        for (const auto &exp : exports)
        {
            Log.Line("Adding %08X as entry point", exp.first);

            Explorer->AddEntryPoint(exp.first, true);
        }
    }
}

bool Worker::HandleReadProcessMemory(LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead)
{
    return ((Resume_ReadProcessMemory_t)hook_ReadProcessMemory.Resume)(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
}

bool Worker::HandleWriteProcessMemory(LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten)
{
    if (IgnoreNextWrite)
    {
        IgnoreNextWrite = false;

        Log.Line("Ignoring this write");

        return true;
    }

    if (LastAction != ExplorationStepAction::Nanomite)
    {
        Log.Warning("Unexpected write");
    }
    else
    {
        NanomitesRecovered++;
    }

    if (lpBaseAddress != (LPVOID)EventAddress)
    {
        Log.Warning("Unexpected BaseAddress");

        if ((DWORD)lpBaseAddress < EventAddress)
        {
            Log.Warning("Address is lower than expected");
        }
        else
        {
            Log.Warning("Address is higher than expected");
        }
    }

    auto bufferOffset = Address2BufferOffset(lpBaseAddress);
    auto remaining = Address2Remaining(lpBaseAddress);

    if (remaining < nSize)
    {
        Log.Error("Data exceeds text section");

        return ((Resume_WriteProcessMemory_t)hook_WriteProcessMemory.Resume)(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
    }

    memcpy(&TextSectionBuffer[bufferOffset], lpBuffer, nSize);

    Explorer->InvalidateCodeStatus((ZyanU64)lpBaseAddress, nSize);

    /* Try again */
    Explorer->AddEntryPoint((ZyanU64)lpBaseAddress, false, true);

    /* Nanomite was handled properly */
    LastAction = ExplorationStepAction::None;

    if (lpNumberOfBytesWritten != NULL)
    {
        *lpNumberOfBytesWritten = nSize;
    }

    return ((Resume_WriteProcessMemory_t)hook_WriteProcessMemory.Resume)(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
}

void Worker::MarkAsNonNanomite(ZyanU64 Address)
{
    Explorer->MarkAs(Address, 1, CodeExplorer::CodeStatus::STATUS_EXPLORED);
    Explorer->MarkAs(Address, 1, CodeExplorer::CodeStatus::STATUS_IGNORED);
    Explorer->MarkAs(Address, 1, CodeExplorer::CodeStatus::STATUS_FILLING);
}

int Worker::FindDiffLen(ZyanU64 address, size_t stopAfter)
{
    const size_t CHUNK_SIZE = 100;

    uint8_t buffer[CHUNK_SIZE];
    const ZyanU64 addressOrg = address;

    int lastChangeAt = -1;
    size_t noChangeCounter = 0;

    ProcessHelper p(hProcess);

    while (true)
    {
        if (!p.ReadMemory((LPVOID)address, &buffer[0], CHUNK_SIZE))
        {
            Log.Error("Could not read data @ %08X", (uint32_t)address);

            return 0;
        }

        auto bufferOffset = Address2BufferOffset((LPVOID)address);

        for (size_t i = 0; i < CHUNK_SIZE; i++)
        {
            if (buffer[i] == TextSectionBuffer[bufferOffset + i])
            {
                noChangeCounter++;
            }
            else
            {
                lastChangeAt = (address - addressOrg) + i;
                noChangeCounter = 0;
            }

            if (noChangeCounter > stopAfter)
            {
                break;
            }
        }

        if (noChangeCounter > stopAfter)
        {
            return lastChangeAt + 1;
        }

        address += CHUNK_SIZE;
    }
}

std::tuple<DWORD, bool> Worker::RecoverIntermodularCall(ZyanU64 address, bool dummyCall)
{
    PauseHooks();

    /*
        Algorithm:
            1) Single-Step until we have passed a 'PUSHAD'
            2) Place HW breakpoint on top of stack
            3) Run
            4) Single-Step until 'RET'
    */
    MyDebugger d(hProcess, dwProcessId, hMainThread, dwThreadId);

    DWORD EipOrg = d.GetEip();
    DWORD EspOrg = d.GetEsp();

    if (dummyCall)
    {
        /* Dummy return address */
        d.Push(0);
    }

    d.SetEip((DWORD)address);
    d.StepIntoUntil(ZYDIS_MNEMONIC_PUSHAD);
    d.StepInto();
    d.EnableHWBP(d.GetEsp(), MyDebugger::HWBPCond::ReadWrite, MyDebugger::HWBPSize::DWord);
    d.Run();
    d.DisableHWBP();
    d.StepIntoUntil(ZYDIS_MNEMONIC_RET);
    d.StepInto();

    DWORD ProcAddress = d.GetEip();

    DWORD EspTest = d.GetEsp();

    bool IsJump = false;

    if (EspOrg == EspTest)
    {
        Log.Warning("Call at %08X did not change the stack, probably a JMP", (DWORD)address);

        IsJump = true;
    }

    /* Restore */
    d.SetEip(EipOrg);
    d.SetEsp(EspOrg);

    ResumeHooks();

    return std::make_tuple(ProcAddress, IsJump);
}

std::tuple<DWORD, bool> Worker::RecoverIntermodularCallFromJumpPadSetup(ZyanU64 address)
{
    PauseHooks();

    /*
        Algorithm:
            1) Single-Step until we land on a 'RET'
            2) Use RecoverIntermodularCall
    */
    MyDebugger d(hProcess, dwProcessId, hMainThread, dwThreadId);

    DWORD EipOrg = d.GetEip();
    DWORD EspOrg = d.GetEsp();

    d.SetEip((DWORD)address);
    d.StepIntoUntil(ZYDIS_MNEMONIC_RET);
    d.StepInto();

    DWORD ProcAddress;
    bool IsJump;

    std::tie(ProcAddress, IsJump) = RecoverIntermodularCall(d.GetEip());

    /* Probably not needed, but the previous call has enabled the hooks */
    PauseHooks();

    /* Restore */
    d.SetEip(EipOrg);
    d.SetEsp(EspOrg);

    ResumeHooks();

    return std::make_tuple(ProcAddress, IsJump);
}

void Worker::ProbeVMInstructions()
{
    if ((NanomiteValid == 0) || (NanomiteData.so.status != NANOMITE_STATUS_VM) )
    {
        Log.Line("Not an emulated instruction");

        return;
    }

    SafeDiscHelper sd(hProcess);

    VM_IV iv
    {
        0,
        NanomiteData.di.iv.IV1,
        NanomiteData.di.iv.IV2
    };

    Log.Debug("IV1: %08X", NanomiteData.di.iv.IV1);
    Log.Debug("IV2: %08X", NanomiteData.di.iv.IV2);

    ZyanU8 instruction_buffer[ZYDIS_MAX_INSTRUCTION_LENGTH];
    ZyanUSize instruction_length = ZYDIS_MAX_INSTRUCTION_LENGTH;

    bool branchShort = (NanomiteData.size < 4);

    sd.VM_Devirtualize(&iv, &instruction_buffer[0], &instruction_length, branchShort);

    if (instruction_length > 0)
    {
        Log.Line("Instruction devirtualized. Length: %u", instruction_length);

        ZydisDisassembledInstruction instruction;

        if (ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LEGACY_32, EventAddress, &instruction_buffer[0], instruction_length, &instruction)))
        {
            Log.Line("-> %s", instruction.text);
        }

        if (instruction_length != NanomiteData.size)
        {
            Log.Error("Unexpected instruction length");

            return;
        }

        auto bufferOffset = Address2BufferOffset((LPVOID)EventAddress);

        memcpy(&TextSectionBuffer[bufferOffset], &instruction_buffer[0], instruction_length);

        PauseHooks();

        if (!ProcessHelper(hProcess).WriteMemory((LPVOID)EventAddress, (PBYTE)&instruction_buffer[0], instruction_length))
        {
            Log.Error("Could not write instruction back to game");

            ResumeHooks();

            return;
        }

        ResumeHooks();

        VirtualInstructionsRecovered++;

        Explorer->InvalidateCodeStatus(EventAddress, NanomiteData.size);

        /* Try again */
        Explorer->AddEntryPoint(EventAddress, false, true);

        /* Nanomite was handled properly */
        LastAction = ExplorationStepAction::None;

        IgnoreNextWrite = true;
    }
    else
    {
        Log.Warning("Could not devirtualize instruction");
    }
}

size_t Worker::RecoverVMInstructions_Inner(DWORD address)
{
    DWORD returnAddress = address + 5;

    SafeDiscHelper sd(hProcess);

    DWORD vmLookup = sd.GetVMLookup(returnAddress, ImageBase);

    Log.Debug("VM Lookup: %08X", vmLookup);

    PCodeDescriptor PCode;

    if (!sd.GetPCodeDescriptor(vmLookup, &PCode))
    {
        Log.Error("Could not find PCode");

        DetachAndExit();

        return 0;
    }

    Log.Debug("CodeType: %u", PCode.code_type);

    Log.Debug("Opcode: ");

    for (auto b = 0; b < 16; b++)
    {
        Log.Debug("%02X%s", PCode.opcode[b], ((b + 1) == 16) ? "\n" : " ");
    }

    Log.Debug("Parsed: ");

    DWORD *parsed = (DWORD *)&PCode.opcode[0];

    for (auto d = 0; d < 4; d++)
    {
        Log.Debug("%08X%s", parsed[d], ((d + 1) == 4) ? "\n" : " ");
    }

    VM_IV iv
    {
        parsed[0],
        parsed[1],
        parsed[2]
    };

    ZyanU8 instruction_buffer[ZYDIS_MAX_INSTRUCTION_LENGTH];
    ZyanUSize instruction_length = ZYDIS_MAX_INSTRUCTION_LENGTH;

    sd.VM_Devirtualize(&iv, &instruction_buffer[0], &instruction_length);

    if (instruction_length > 0)
    {
        Log.Line("Instruction devirtualized. Length: %u", instruction_length);

        ZydisDisassembledInstruction instruction;

        if (ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LEGACY_32, address, &instruction_buffer[0], instruction_length, &instruction)))
        {
            Log.Line("-> %s", instruction.text);
        }

        if (instruction_length < 5)
        {
            Log.Warning("Unexpected instruction length");
        }

        auto bufferOffset = Address2BufferOffset((LPVOID)address);

        memcpy(&TextSectionBuffer[bufferOffset], &instruction_buffer[0], instruction_length);

        PauseHooks();

        if (!ProcessHelper(hProcess).WriteMemory((LPVOID)address, (PBYTE)&instruction_buffer[0], instruction_length))
        {
            Log.Error("Could not write instruction back to game");

            ResumeHooks();

            return 0;
        }

        ResumeHooks();

        VirtualInstructionsRecovered++;

        return instruction_length;
    }
    else
    {
        Log.Warning("Could not devirtualize instruction");
    }

    return 0;
}

size_t Worker::RecoverVMInstructions(ZyanU64 address)
{
    PauseHooks();

    /*
        Note: This will emulate all instructions, including Calls, so one can not foresee the target address

        Algorithm:
            1) Single-Step until we land on a 'PUSHAD'
            2) Place HW breakpoint on top of stack
            3) Run
            4) Check if we landed on a 'POPFD' if not, goto 3)
            5) Step until 'RET' and step out (optionally)
    */
    MyDebugger d(hProcess, dwProcessId, hMainThread, dwThreadId);

    DWORD EipOrg = d.GetEip();
    DWORD EspOrg = d.GetEsp();

    d.SetEip((DWORD)address);
    d.StepIntoUntil(ZYDIS_MNEMONIC_PUSHAD);
    d.StepInto();

    d.EnableHWBP(d.GetEsp(), MyDebugger::HWBPCond::ReadWrite, MyDebugger::HWBPSize::DWord);

    while (true)
    {
        if (!d.Run())
        {
            ResumeHooks();

            return 0;
        }

        bool error;

        if (d.IsMnemonicAtEip(ZYDIS_MNEMONIC_POPFD, &error))
        {
            break;
        }

        if (error)
        {
            break;
        }
    }

    d.DisableHWBP();

    d.StepIntoUntil(ZYDIS_MNEMONIC_RET);
    d.StepInto();

    if (d.GetEip() == address)
    {
        Log.Debug("This is probably an encrypted function, not an emulated instruction");
    }

    /* Restore */
    d.SetEip(EipOrg);
    d.SetEsp(EspOrg);

    int numBytes = FindDiffLen(address);

    ResumeHooks();

    if (numBytes <= 0)
    {
        d.SetEip((DWORD)address);

        Log.Debug("Nothing changed. Trying to interpret this as a VM entry");

        return RecoverVMInstructions_Inner((DWORD)address);
    }

    uint8_t *buffer = new uint8_t[numBytes];

    if (buffer == nullptr)
    {
        Log.Error("Could not create buffer");

        return 0;
    }

    if (!d.ReadMemory(address, buffer, numBytes))
    {
        Log.Error("Something while reading the data went wrong");

        delete[] buffer;

        return 0;
    }

    auto bufferOffset = Address2BufferOffset((LPVOID)address);

    if (memcmp(buffer, &TextSectionBuffer[bufferOffset], numBytes) == 0)
    {
        Log.Error("Data did not change");

        delete[] buffer;

        return 0;
    }

    Log.Line("Recovered %d bytes", numBytes);

    for (auto i = 0; i < numBytes; i++)
    {
        Log.Log("%02X%s", buffer[i], (((i + 1) < numBytes) ? " ": "\n"));
    }

    memcpy(&TextSectionBuffer[bufferOffset], buffer, numBytes);

    delete[] buffer;

    EncryptedFunctionsRecovered++;

    return numBytes;
}

bool Worker::Helper_IntermodularCall(DWORD CallFrom, DWORD CallTo, bool IsJump)
{
    Log.Log("Original proc address is %08X ", CallTo);

    Module *mod = Modules.GetModuleAt(CallTo);

    if (mod == nullptr)
    {
        Log.Warning("(UNKNOWN Module)");

        return false;
    }
    else
    {
        Proc *proc = mod->GetProcAt(CallTo);

        if (proc == nullptr)
        {
            Log.Warning("-> %s:???", mod->Name.c_str());
        }
        else
        {
            Log.Line("-> %s:%s", mod->Name.c_str(), proc->Name.c_str());

            Imports.AddCall(CallFrom, CallTo, false, IsJump);
        }
    }

    // The instruction is broken, we can't just add the next, instead just add 6 bytes (FE 15 XXXXXXXX)
    // processData.Explorer->AddNextAsEntryPoint(resultData.Instruction, true);
    Explorer->MarkAs(CallFrom, 6, CodeExplorer::CodeStatus::STATUS_EXPLORED);
    Explorer->AddEntryPoint(CallFrom + 6, false, true);

    return true;
}

void Worker::PerformExplorationStep()
{
    bool exploreCode = true;
    CodeExplorer::ResultData resultData{ 0 };

    SafeDiscHelper sd(hProcess);

    LastAction = ExplorationStepAction::Done;

    while (exploreCode)
    {
        auto result = Explorer->Explore(&resultData);

        switch (result)
        {
            case (CodeExplorer::ExplorerResult::CallInterSection):
            {
                if (sd.IsVMEntry(resultData.TargetAddress))
                {
                    Log.Line("VMEntry @ %08X", resultData.TargetAddress);

                    size_t recoveredBytes = RecoverVMInstructions(resultData.ResultAddress);

                    if (recoveredBytes > 0)
                    {
                        Explorer->InvalidateCodeStatus(resultData.ResultAddress, recoveredBytes);

                        /* Try again */
                        Explorer->AddEntryPoint(resultData.ResultAddress, false, true);
                    }
                    else
                    {
                        Log.Warning("No data was recovered");

                        Explorer->MarkAsExplored(resultData.Instruction);
                        Explorer->AddEntryPoint(resultData.TargetAddress, true);
                        Explorer->CheckForInt3SlideAndAddNext(resultData.Instruction);
                    }
                }
                else
                {
                    Explorer->MarkAsExplored(resultData.Instruction);
                    Explorer->AddEntryPoint(resultData.TargetAddress, true);
                    Explorer->CheckForInt3SlideAndAddNext(resultData.Instruction);
                }

                break;
            }

            case (CodeExplorer::ExplorerResult::IndirectBranchFromMemory):
            {
                Log.Debug("Handling IndirectBranchFromMemory");

                /** Get the address to where the instruction is pointing */
                auto targetAddress = resultData.TargetAddress;

                if (Explorer->IsInTextSection(targetAddress))
                {
                    DWORD indirectedAddress = *(DWORD *)&TextSectionBuffer[targetAddress - TextSectionStart];

                    if (Explorer->IsInTextSection(indirectedAddress))
                    {
                        // TODO: Check if stub
                        Explorer->AddEntryPoint(indirectedAddress, true);
                    }
                    else
                    {
                        /* Check if in a 'good' module */
                        Module *mod = Modules.GetModuleAt(indirectedAddress);

                        if (mod == nullptr)
                        {
                            Log.Warning("(UNKNOWN Module)");

                            exploreCode = false;
                        }
                        else
                        {
                            if (Log.Verbose)
                            {
                                PrintProcName(mod, mod->GetProcAt(indirectedAddress), true);
                            }

                            if (DeadEnds.find(indirectedAddress) == DeadEnds.end())
                            {
                                Explorer->MarkAsExplored(resultData.Instruction);

                                if (Explorer->IsCall(resultData.Instruction))
                                {
                                    Explorer->AddNextAsEntryPoint(resultData.Instruction, true);
                                }
                                else
                                {
                                    Explorer->CheckForInt3SlideAndAddNext(resultData.Instruction);
                                }

                                break;
                            }
                            else
                            {
                                Log.Debug("This is a guaranteed dead end");
                            }
                        }
                    }
                }
                else
                {
                    DWORD indirectedAddress;

                    ProcessHelper(hProcess).ReadMemory((LPVOID)resultData.TargetAddress, (PBYTE)&indirectedAddress, sizeof(indirectedAddress));

                    if (indirectedAddress != 0)
                    {
                        if (Explorer->IsInTextSection(indirectedAddress))
                        {
                            Log.Debug("IsInTextSection");
                            // TODO: Check if stub
                            Explorer->AddEntryPoint(indirectedAddress, true);
                        }
                        else
                        {
                            /* Check if in data section or in 'good' module */
                            Module *mod = Modules.GetModuleAt(indirectedAddress);

                            if ((mod != nullptr) && !mod->Excluded)
                            {
                                if (Log.Verbose)
                                {
                                    PrintProcName(mod, mod->GetProcAt(indirectedAddress), true);
                                }

                                if (DeadEnds.find(indirectedAddress) == DeadEnds.end())
                                {
                                    Explorer->MarkAsExplored(resultData.Instruction);

                                    if (Explorer->IsCall(resultData.Instruction))
                                    {
                                        Explorer->AddNextAsEntryPoint(resultData.Instruction, true);
                                    }
                                    else
                                    {
                                        Explorer->CheckForInt3SlideAndAddNext(resultData.Instruction);
                                    }

                                    break;
                                }
                                else
                                {
                                    Log.Debug("This is a guaranteed dead end");
                                }
                            }
                            else
                            {
                                /* Check if this is a stub */
                                if (SafeDiscHelper(hProcess).IsRemoteProcStub(indirectedAddress))
                                {
                                    Log.Line("Got a Stub @ %08X", resultData.ResultAddress);

                                    DWORD ProcAddress;
                                    bool IsJump;

                                    std::tie(ProcAddress, IsJump) = RecoverIntermodularCall(resultData.ResultAddress);

                                    exploreCode = Helper_IntermodularCall(resultData.ResultAddress, ProcAddress, IsJump);

                                    if (exploreCode)
                                    {
                                        ImportsRecovered++;
                                    }
                                }
                                else
                                {
                                    Log.Warning("UNKNOWN");

                                    exploreCode = false;
                                }
                            }
                        }
                    }
                    else
                    {
                        Log.Debug("Unpopulated Call");
                    }
                }

                if (Explorer->IsCall(resultData.Instruction))
                {
                    Explorer->CheckForInt3SlideAndAddNext(resultData.Instruction);
                }
                else if (Explorer->IsCondJump(resultData.Instruction))
                {
                    Explorer->AddNextAsEntryPoint(resultData.Instruction, true);
                }

                Explorer->MarkAsExplored(resultData.Instruction);

                break;
            }

            case (CodeExplorer::ExplorerResult::UnusualCode):
            {
                /* This should be a Nanomite */

                Log.Debug("Handling UnusualCode");
                Log.Debug("Nanomite (unusual): %08X", (uint32_t)resultData.ResultAddress);

                EventAddress = resultData.ResultAddress;

                LastAction = ExplorationStepAction::Nanomite;

                exploreCode = false;

                break;
            }

            case (CodeExplorer::ExplorerResult::InvalidCode):
            {
                // TODO: This should be a Nanomite

                Log.Debug("Handling InvalidCode");

                // Not needed

                break;
            }

            case (CodeExplorer::ExplorerResult::UnusualCodeInSlideDown):
            {
                // TODO: Remember this address, this >might< be something but could also be fake

                Log.Error("Handling UnusualCodeInSlideDown\n");

                exploreCode = false;

                break;
            }

            case (CodeExplorer::ExplorerResult::InvalidCodeInSlideDown):
            {
                // TODO: Remember this address, this >might< be something but could also be fake

                Log.Debug("Handling InvalidCodeInSlideDown\n");

                // Not needed

                break;
            }

            case (CodeExplorer::ExplorerResult::JumpOutOfTextSection):
            {
                Log.Debug("Handling JumpOutOfTextSection");

                if (SafeDiscHelper(hProcess).IsJumpPadSetup(resultData.TargetAddress))
                {
                    Log.Line("Got a JumpPadSetup @ %08X", resultData.ResultAddress);

                    DWORD ProcAddress;
                    bool IsJump;

                    std::tie(ProcAddress, IsJump) = RecoverIntermodularCallFromJumpPadSetup(resultData.ResultAddress);

                    exploreCode = Helper_IntermodularCall(resultData.ResultAddress, ProcAddress, IsJump);

                    if (exploreCode)
                    {
                        ImportsRecovered++;
                    }
                }
                else
                {
                    Log.Warning("This is something else");
                }

                break;
            }

            case (CodeExplorer::ExplorerResult::IATCallByRegister):
            {
                Log.Debug("\t-> Handling IATCallByRegister");

                DWORD indirectedAddress;

                ProcessHelper(hProcess).ReadMemory((LPVOID)resultData.TargetAddress, (PBYTE)&indirectedAddress, sizeof(indirectedAddress));

                if (indirectedAddress != 0)
                {
                    /* Check if in data section or in 'good' module */
                    Module *mod = Modules.GetModuleAt(indirectedAddress);

                    if ((mod != nullptr) && !mod->Excluded)
                    {
                        if (Log.Verbose)
                        {
                            PrintProcName(mod, mod->GetProcAt(indirectedAddress), true);
                        }
                    }
                    else
                    {
                        /* Check if this is a stub */
                        if (SafeDiscHelper(hProcess).IsRemoteProcStub(indirectedAddress))
                        {
                            Log.Line("Call to RemoteProcStub @ %08X", indirectedAddress);

                            DWORD ProcAddress;
                            bool IsJump;

                            std::tie(ProcAddress, IsJump) = RecoverIntermodularCall(indirectedAddress, true);

                            mod = Modules.GetModuleAt(ProcAddress);

                            if ((mod != nullptr) && !mod->Excluded)
                            {
                                PrintProcName(mod, mod->GetProcAt(ProcAddress), true);
                                
                                auto iatIndex = ((DWORD)resultData.TargetAddress - IAT_START) / sizeof(DWORD);

                                Imports.SetThunk(iatIndex, ProcAddress);

                                CallsByRegisterRecovered++;
                            }
                            else
                            {
                                Log.Warning("Could not recover proc");

                                exploreCode = false;
                            }
                        }
                        else
                        {
                            Log.Warning("UNKNOWN");

                            exploreCode = false;
                        }
                    }
                }
                else
                {
                    Log.Debug("\t\t-> Unpopulated Call");
                }

                Explorer->MarkAsExplored(resultData.Instruction);
                Explorer->AddNextAsEntryPoint(resultData.Instruction, true);

                break;
            }

            case (CodeExplorer::ExplorerResult::DoneExploring):
            {
                Log.Line("Handling DoneExploring\n");

                exploreCode = false;

                break;
            }

            default:
            {
                Log.Error("Unhandled event\n");

                exploreCode = false;

                break;
            }
        }
    }
}

void Worker::FinalizeFix()
{
    MyDebugger d(hProcess, dwProcessId, hMainThread, dwThreadId);

    d.SetEip(OEP);

    PauseHooks();

    FixImports();
}

void Worker::SetEip(DWORD Eip)
{
    MyDebugger d(hProcess, dwProcessId, hMainThread, dwThreadId);

    d.SetEip(Eip);
}

void Worker::DetachAndExit()
{
    MyDebugger d(hProcess, dwProcessId, hMainThread, dwThreadId);

    d.SetTrap(false);

    SuspendThread(hMainThread);

    ContinueDebugEvent(dwProcessId, dwThreadId, DBG_CONTINUE);

    DebugActiveProcessStop(dwProcessId);

    CloseHandle(hMainThread);

    ExitProcess(0);
}

double Worker::CodeCoverage()
{
    if (Explorer == nullptr)
    {
        return 0.0f;
    }

    return Explorer->CodeCoverage();
}

void Worker::DumpCoverageMap()
{
    Explorer->DumpCoverageMap();
}