#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <shlwapi.h>
#include <Zydis/Zydis.h>
#include "logging.h"
#include "hooking.h"
#include "calls_list.h"
#include "mod_list.h"
#include "Nanomites.h"
#include "virt_jumps.h"

#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Kernel32.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Shlwapi.lib")


/* Config */
// TODO: Replace by automatic methods
#define SAFEDISC_SEC_NAME           "stxt"
#define IAT_START                   0x1098FAE4
#define IAT_END                     0x109903BC // size: 8D8
#define RAW_VIRT_JUMPS_ADDRESS      0x00A5CFB8
#define NUM_VIRT_JUMPS              0x80
#define KEY_VIRT_JUMPS_LOOKUP       0xff069f5f
#define KEY_VIRT_JUMPS_SIZE         0x98caaeb9
#define KEY_VIRT_JUMPS_TYPE         0x9877d4a7
#define KEY_VIRT_JUMPS_OFFSET       0x1138a107
#define RAW_NANOMITES_ADDRESS       0x00BDC1FC
#define NUM_NANOMITES               0x96
#define STOLEN_BYTES_BUFFER_SIZE    0x1000


/* Defines */
#define FLAG_TRAP           (1 << 8)
#define OP_PUSHAD           0x60
#define OP_POPAD            0x61
#define OP_JE_NEAR          0x74
#define OP_JNE_NEAR         0x75
#define OP_JL_NEAR          0x7C
#define OP_JGE_NEAR         0x7D
#define OP_JLE_NEAR         0x7E
#define OP_JG_NEAR          0x7F
#define OP_NOP              0x90
#define OP_PUSHFD           0x9C
#define OP_POPFD            0x9D
#define OP_MOV_EAX_CONST    0xB8
#define OP_RET_POP          0xC2
#define OP_RET              0xC3
#define OP_INT3             0xCC
#define OP_CALL_REL         0xE8
#define OP_JMP_REL          0xE9
#define OP_JMP_NEAR         0xEB
#define OP_CALL_IND         0x15FF
#define OP_JMP_IND          0x25FF
#define OP_JE_FAR           0x840F
#define OP_JNE_FAR          0x850F
#define OP_JLE_FAR          0x8E0F
#define OP_JG_FAR           0x8F0F


typedef BOOL (__stdcall *Resume_DebugActiveProcess_t)(DWORD dwProcessId);
typedef BOOL (__stdcall *Resume_WaitForDebugEvent_t)(LPDEBUG_EVENT lpDebugEvent, DWORD dwMilliseconds);

typedef enum
{
    HW_BP_COND_EXECUTE = 0,
    HW_BP_COND_WRITE = 1,
    HW_BP_COND_IO_READWRITE = 2,
    HW_BP_COND_READWRITE = 3
} HW_BP_COND_t;

typedef enum
{
    HW_BP_SIZE_BYTE = 0,
    HW_BP_SIZE_WORD = 1,
    HW_BP_SIZE_QWORD = 2,
    HW_BP_SIZE_DWORD = 3
} HW_BP_SIZE_t;

typedef struct
{
    DWORD pid;
    HANDLE hProcess;
    DWORD ImageBase;
    DWORD EntryPoint;
    DWORD OEP;
    DWORD SafeDiscSectionStart;
    DWORD SafeDiscSectionEnd;
    DWORD SafeDiscSectionSize;
    DWORD TextSectionStart;
    DWORD TextSectionEnd;
    DWORD TextSectionSize;

    DWORD mainThreadId;
    HANDLE hMainThread;

    CALL_t *calls_Intermodular;
    MOD_t *mods;
} PROCESS_DATA_t;


/* Prototypes */
void WriteMemory(PROCESS_DATA_t* const data, LPVOID address, PBYTE buffer, SIZE_T len);
void GetContext(PROCESS_DATA_t *const data, CONTEXT *const ctx);
void SetContext(PROCESS_DATA_t *const data, CONTEXT *const ctx);
DWORD GetEsp(PROCESS_DATA_t *const data);
void SetEip(PROCESS_DATA_t *const data, DWORD Eip);
BYTE EipPeek8(PROCESS_DATA_t* const data);
void DetachAndExit(PROCESS_DATA_t *const data);
void SingleStepUntil8(DEBUG_EVENT *const event, PROCESS_DATA_t *const data, BYTE value);
BOOL __stdcall Callback_WaitForDebugEvent(LPDEBUG_EVENT lpDebugEvent, DWORD dwMilliseconds);


HOOK_t hook_DebugActiveProcess = { 0 };
HOOK_t hook_WaitForDebugEvent = { 0 };

Logging logger;

BYTE buffer[sizeof(WCHAR) * (MAX_MODULE_NAME32 + 1)];

PROCESS_DATA_t processData = { 0 };

VIRT_JUMPS_CONTAINER_t virtualJumpsContainer;
NANOMITE_CONTAINER_t nanomitesContainer;

DWORD nanomiteWhitelist[] = {
    0x1090AA62,
    0x10917356
};

DWORD stolenBytesBlacklist[] = {
    0x10902178
};


BOOL IsUserCode(PROCESS_DATA_t* const data, DWORD address)
{
    return !mod_list_is_in(data->mods, address);
}

/// <summary>
/// Returns true if there is a (non trivial) path to the address
/// </summary>
/// <param name="buffer"></param>
/// <param name="bufferLen"></param>
/// <param name="to"></param>
/// <returns></returns>
BOOL IsAPathToAddress(const BYTE *const buffer, SIZE_T bufferLen, SIZE_T to, SIZE_T toLen = 1)
{
    for (SIZE_T b = 0; b < bufferLen - 6; b++)
    {
        if ((buffer[b] & 0xf0) == 0x70 || buffer[b] == OP_JMP_NEAR)
        {
            INT8 jmpOffset = (INT8)buffer[b + 1];
            SIZE_T destination = b + 2 + (INT32)jmpOffset;

            if ((to <= destination) && (destination < (to + toLen)) && jmpOffset != (BYTE)(-2))
            {
                return TRUE;
            }
        }

        if (buffer[b] == OP_JMP_REL || buffer[b] == OP_CALL_REL)
        {
            INT32 jmpOffset = *(INT32*)&buffer[b + 1];
            SIZE_T destination = b + 5 + jmpOffset;

            if ((to <= destination) && (destination < (to + toLen)) && jmpOffset != (DWORD)(-5))
            {
                return TRUE;
            }
        }

        if ((*(WORD*)&buffer[b] & 0xf0ff) == 0x800F)
        {
            INT32 jmpOffset = *(DWORD*)&buffer[b + 2];
            SIZE_T destination = b + 6 + jmpOffset;

            if ((to <= destination) && (destination < (to + toLen)) && jmpOffset != (DWORD)(-6))
            {
                return TRUE;
            }
        }
    }

    return FALSE;
}

/// <summary>
/// Fetches needed data from the game process
/// </summary>
/// <param name="dwProcessId"></param>
/// <param name="data"></param>
void GetProcessData(DWORD dwProcessId, PROCESS_DATA_t *const data)
{
    data->pid = dwProcessId;

    data->hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD, FALSE, dwProcessId);

    DWORD bytesCopied = GetModuleFileNameExA(data->hProcess, NULL, (LPSTR)&buffer[0], sizeof(buffer));

    HANDLE hFile = CreateFileA((LPCSTR)&buffer[0], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    /* Read DOS Header */
    DWORD bytesRead = 0;
    ReadFile(hFile, &buffer[0], sizeof(IMAGE_DOS_HEADER), &bytesRead, NULL);

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)&buffer[0];

    DWORD fileOffset = dosHeader->e_lfanew;
    
    SetFilePointer(hFile, fileOffset, NULL, FILE_BEGIN);

    ReadFile(hFile, &buffer[0], sizeof(IMAGE_NT_HEADERS32), &bytesRead, NULL);

    PIMAGE_NT_HEADERS32 ntHeaders = (PIMAGE_NT_HEADERS32)&buffer[0];

    data->ImageBase = ntHeaders->OptionalHeader.ImageBase;
    DWORD entryPoint = data->ImageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint;
    data->EntryPoint = entryPoint;
    DWORD numberOfSections = ntHeaders->FileHeader.NumberOfSections;

    fileOffset += sizeof(IMAGE_NT_HEADERS32);

    DWORD sectionHeaders = fileOffset;

    data->SafeDiscSectionStart = (DWORD)(-1);
    data->SafeDiscSectionEnd = 0;

    /* Find the section that contains the OEP-Jump (SafeDisc section) */
    for (DWORD section = 0; section < numberOfSections; section++)
    {
        SetFilePointer(hFile, fileOffset, NULL, FILE_BEGIN);

        ReadFile(hFile, &buffer[0], sizeof(IMAGE_SECTION_HEADER), &bytesRead, NULL);

        PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)&buffer[0];

        DWORD sectionStartVirt = data->ImageBase + pSection->VirtualAddress;
        DWORD sectionEndVirt = sectionStartVirt + pSection->SizeOfRawData;

        if (strncmp((char*)pSection->Name, SAFEDISC_SEC_NAME, strlen(SAFEDISC_SEC_NAME)) == 0)
        {
            if (sectionStartVirt < data->SafeDiscSectionStart)
            {
                data->SafeDiscSectionStart = sectionStartVirt;
            }

            if (sectionEndVirt > data->SafeDiscSectionEnd)
            {
                data->SafeDiscSectionEnd = sectionEndVirt;
            }
        }

        if ((sectionStartVirt <= entryPoint) && (entryPoint < sectionEndVirt))
        {
            DWORD offset = entryPoint - sectionStartVirt;

            LPVOID sectionBuffer = VirtualAlloc(NULL, pSection->SizeOfRawData, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

            SetFilePointer(hFile, pSection->PointerToRawData, NULL, FILE_BEGIN);

            ReadFile(hFile, sectionBuffer, pSection->SizeOfRawData, &bytesRead, NULL);

            /** Search for "CALL EAX; POPAD; POP EBP; JMP XXX" (FFD0 61 5D EB) */
            const BYTE pattern[] = { 0xFF, 0xD0, 0x61, 0x5D, 0xEB };

            for (DWORD address = (DWORD)sectionBuffer + offset; address < (DWORD)sectionBuffer + pSection->SizeOfRawData; address++)
            {
                if (memcmp((BYTE*)address, &pattern[0], sizeof(pattern)) == 0)
                {
                    BYTE jmpOffset = *((BYTE*)address + 5);
                    DWORD oepJmpAt = (DWORD)address + 4 + 2 + jmpOffset;
                    DWORD oepJmpOffset = *(DWORD*)(oepJmpAt + 1);   
                    DWORD oepAddress = oepJmpAt + 5 + oepJmpOffset; /* Relative to buffer */

                    oepAddress -= (DWORD)sectionBuffer;
                    oepAddress += data->ImageBase + pSection->VirtualAddress;

                    data->OEP = oepAddress;

                    break;
                }
            }

            VirtualFree(sectionBuffer, 0, MEM_RELEASE);

            sectionBuffer = NULL;
        }

        fileOffset += sizeof(IMAGE_SECTION_HEADER);
    }

    logger.Log("\tSafeDiscSectionStart: 0x%08X", data->SafeDiscSectionStart);
    logger.Log("\tSafeDiscSectionEnd: 0x%08X", data->SafeDiscSectionEnd);

    fileOffset = sectionHeaders;

    /* Find the section that contains the OEP (Text section) */
    for (DWORD section = 0; section < numberOfSections; section++)
    {
        SetFilePointer(hFile, fileOffset, NULL, FILE_BEGIN);

        ReadFile(hFile, &buffer[0], sizeof(IMAGE_SECTION_HEADER), &bytesRead, NULL);

        PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)&buffer[0];

        DWORD sectionStartVirt = data->ImageBase + pSection->VirtualAddress;
        DWORD sectionEndVirt = sectionStartVirt + pSection->SizeOfRawData;

        if ((sectionStartVirt <= data->OEP) && (data->OEP < sectionEndVirt))
        {
            data->TextSectionStart = sectionStartVirt;
            data->TextSectionEnd = sectionEndVirt;
            data->TextSectionSize = sectionEndVirt - sectionStartVirt;

            logger.Log("\tTextSectionStart: 0x%08X", data->TextSectionStart);
            logger.Log("\tTextSectionEnd: 0x%08X", data->TextSectionEnd);

            break;
        }
    }

    CloseHandle(hFile);
}

void GetModules(PROCESS_DATA_t* const data)
{
    // Maybe replace by CreateToolhelp32Snapshot

    logger.Log("GetModules");

    SIZE_T numMods = 1024;
    SIZE_T modsBufferSize = numMods * sizeof(HMODULE);
    HMODULE* hMods = (HMODULE*)VirtualAlloc(NULL, modsBufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    DWORD cbNeeded;

    if (EnumProcessModules(data->hProcess, hMods, modsBufferSize, &cbNeeded))
    {
        SIZE_T modsLoaded = cbNeeded / sizeof(HMODULE);

        for (SIZE_T i = 0; i < modsLoaded; i++)
        {
            WCHAR szModName[MAX_PATH];

            if (GetModuleFileNameExW(data->hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(WCHAR)))
            {
                logger.Log("\tmod file name: %S", szModName);
            }

            if (GetModuleBaseNameW(data->hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(WCHAR)))
            {
                logger.Log("\tmod base name: %S", szModName);
            }

            MODULEINFO modInfo;

            if (GetModuleInformation(data->hProcess, hMods[i], &modInfo, sizeof(modInfo)))
            {
                logger.Log("\tlpBaseOfDll: 0x%08X", modInfo.lpBaseOfDll);
                logger.Log("\tSizeOfImage: 0x%08X", modInfo.SizeOfImage);
                logger.Log("\tEntryPoint: 0x%08X", modInfo.EntryPoint);

                data->mods = mod_list_add(data->mods, (DWORD)modInfo.lpBaseOfDll, modInfo.SizeOfImage);
            }
        }
    }

    VirtualFree(hMods, 0, MEM_RELEASE);
}

/// <summary>
/// Restores the byte at the OEP via reading the byte from the entry point
/// </summary>
/// <param name="data"></param>
void RestoreOEPData(PROCESS_DATA_t *const data)
{
    DWORD numBytes;

    /* Get original byte */
    BYTE orgByte;
    ReadProcessMemory(data->hProcess, (LPVOID)data->EntryPoint, &orgByte, 1, &numBytes);

    WriteMemory(data, (LPVOID)data->OEP, &orgByte, 1);

    FlushInstructionCache(data->hProcess, (LPVOID)data->OEP, 1);
}

void ReadMemory(PROCESS_DATA_t *const data, LPVOID address, PBYTE buffer, SIZE_T len)
{
    DWORD oldProtect;
    VirtualProtectEx(data->hProcess, address, len, PAGE_READWRITE, &oldProtect);

    DWORD bytesWritten;
    ReadProcessMemory(data->hProcess, address, buffer, len, &bytesWritten);

    VirtualProtectEx(data->hProcess, address, len, oldProtect, &oldProtect);
}

void WriteMemory(PROCESS_DATA_t *const data, LPVOID address, PBYTE buffer, SIZE_T len)
{
    DWORD oldProtect;
    VirtualProtectEx(data->hProcess, address, len, PAGE_READWRITE, &oldProtect);

    DWORD bytesWritten;
    WriteProcessMemory(data->hProcess, address, buffer, len, &bytesWritten);

    VirtualProtectEx(data->hProcess, address, len, oldProtect, &oldProtect);
}

void EnableHardwareBreakpoint(PROCESS_DATA_t *const data, DWORD address, HW_BP_COND_t condition, HW_BP_SIZE_t size)
{
    CONTEXT ctx;

    GetContext(data, &ctx);

    if ((ctx.Dr7 & 0x03) == 0)
    {
        ctx.Dr0 = address;
        ctx.Dr7 |= (1 << 0);                    /* Local Enable */
        ctx.Dr7 &= ~(0xf << 16);                /* Clear R/W and LEN */
        ctx.Dr7 |= ((DWORD)condition << 16);    /* Set R/W */
        ctx.Dr7 |= ((DWORD)size << 18);         /* Set LEN */
    }
    else if ((ctx.Dr7 & 0x0C) == 0)
    {
        ctx.Dr1 = address;
        ctx.Dr7 |= (1 << 2);
        ctx.Dr7 &= ~(0xf << 20);
        ctx.Dr7 |= ((DWORD)condition << 20);
        ctx.Dr7 |= ((DWORD)size << 22);
    }
    else if ((ctx.Dr7 & 0x30) == 0)
    {
        ctx.Dr2 = address;
        ctx.Dr7 |= (1 << 4);
        ctx.Dr7 &= ~(0xf << 24);
        ctx.Dr7 |= ((DWORD)condition << 24);
        ctx.Dr7 |= ((DWORD)size << 26);
    }
    else if ((ctx.Dr7 & 0xC0) == 0)
    {
        ctx.Dr3 = address;
        ctx.Dr7 |= (1 << 6);
        ctx.Dr7 &= ~(0xf << 28);
        ctx.Dr7 |= ((DWORD)condition << 28);
        ctx.Dr7 |= ((DWORD)size << 30);
    }

    SetContext(data, &ctx);
}

void DisableHardwareBreakpoint(PROCESS_DATA_t *const data, DWORD address)
{
    CONTEXT ctx;

    GetContext(data, &ctx);

    if (ctx.Dr0 == address)
    {
        ctx.Dr0 = 0;
        ctx.Dr6 &= ~(1 << 0);       /* Clear Condition Detected Flag */
        ctx.Dr7 &= ~(0x03 << 0);    /* Clear Enable Flags */
        ctx.Dr7 &= ~(0xf << 16);    /* Clear R/W and LEN */
    }
    else if (ctx.Dr1 == address)
    {
        ctx.Dr1 = 0;
        ctx.Dr6 &= ~(1 << 1);
        ctx.Dr7 &= ~(0x03 << 2);
        ctx.Dr7 &= ~(0xf << 20);
    }
    else if (ctx.Dr2 == address)
    {
        ctx.Dr2 = 0;
        ctx.Dr6 &= ~(1 << 2);
        ctx.Dr7 &= ~(0x03 << 4);
        ctx.Dr7 &= ~(0xf << 24);
    }
    else if (ctx.Dr3 == address)
    {
        ctx.Dr3 = 0;
        ctx.Dr6 &= ~(1 << 3);
        ctx.Dr7 &= ~(0x03 << 6);
        ctx.Dr7 &= ~(0xf << 28);
    }

    SetContext(data, &ctx);
}

/// <summary>
/// Waits for an EXCEPTION_SINGLE_STEP and passes all other continuable exceptions
/// </summary>
/// <param name="event"></param>
/// <param name="data"></param>
void Run(DEBUG_EVENT *const event, PROCESS_DATA_t *const data)
{
    ContinueDebugEvent(data->pid, data->mainThreadId, DBG_CONTINUE);

    while (true)
    {
        hook_disable_fast(&hook_WaitForDebugEvent);

        WaitForDebugEvent(event, INFINITE);

        hook_enable_fast(&hook_WaitForDebugEvent);

        DWORD eventCode = event->dwDebugEventCode;

        if (eventCode == EXCEPTION_DEBUG_EVENT)
        {
            const DWORD exceptionCode = event->u.Exception.ExceptionRecord.ExceptionCode;
            const DWORD exceptionAddress = (DWORD)event->u.Exception.ExceptionRecord.ExceptionAddress;

            if (exceptionCode == EXCEPTION_SINGLE_STEP)
            {
                break;
            }

            logger.Log("Unexpected ExceptionCode: 0x%08X at 0x%08X", exceptionCode, exceptionAddress);
        }
        else
        {
            logger.Log("Unexpected dwDebugEventCode: 0x%08X", eventCode);
        }

        ContinueDebugEvent(event->dwProcessId, event->dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
    }
}

void RunUntil8_any(DEBUG_EVENT *const event, PROCESS_DATA_t *const data, BYTE *const values, SIZE_T count)
{
    while (true)
    {
        for (SIZE_T v = 0; v < count; v++)
        {
            if (values[v] == EipPeek8(data))
            {
                return;
            }
        }

        Run(event, data);
    }
}

/// <summary>
/// Performs 'run' until the byte at [Eip] matches value
/// </summary>
/// <param name="event"></param>
/// <param name="data"></param>
/// <param name="value"></param>
void RunUntil8(DEBUG_EVENT* const event, PROCESS_DATA_t* const data, BYTE value)
{
    BYTE values[1] = { value }; 
    RunUntil8_any(event, data, &values[0], 1);
}

void RunUntil_RET(DEBUG_EVENT *const event, PROCESS_DATA_t *const data)
{
    BYTE values[] = { OP_RET, OP_POPAD, OP_POPFD };
    RunUntil8_any(event, data, &values[0], sizeof(values));

    SingleStepUntil8(event, data, OP_RET);
}

void SingleStep(DEBUG_EVENT *const event, PROCESS_DATA_t *const data, SIZE_T stepCount = 1)
{
    CONTEXT ctx;

    for (SIZE_T steps = 0; steps < stepCount; steps++)
    {
        GetContext(data, &ctx);

        ctx.EFlags |= FLAG_TRAP;

        SetContext(data, &ctx);

        ResumeThread(data->hMainThread);

        Run(event, data);

        if (steps == (stepCount - 1))
        {
            /* Clear Trap Flag */

            GetContext(data, &ctx);

            ctx.EFlags &= ~FLAG_TRAP;

            SetContext(data, &ctx);
        }
    }
}

/// <summary>
/// Performs single steps until the byte at [Eip] matches one of the values
/// </summary>
/// <param name="event"></param>
/// <param name="data"></param>
/// <param name="value"></param>
void SingleStepUntil8_any(DEBUG_EVENT *const event, PROCESS_DATA_t *const data, BYTE *const values, SIZE_T count)
{
    while (true)
    {
        for (SIZE_T v = 0; v < count; v++)
        {
            if (values[v] == EipPeek8(data))
            {
                return;
            }
        }
        
        SingleStep(event, data);
    }
}

void SingleStepUntil8(DEBUG_EVENT *const event, PROCESS_DATA_t *const data, BYTE value)
{
    BYTE values[1] = { value };
    SingleStepUntil8_any(event, data, &values[0], 1);
}

void SingleStepUntil_PUSHFD_PUSHA(DEBUG_EVENT *const event, PROCESS_DATA_t *const data)
{
    BYTE values[] = { OP_PUSHFD, OP_PUSHAD };
    SingleStepUntil8_any(event, data, &values[0], sizeof(values));
}

void GetContext(PROCESS_DATA_t *const data, CONTEXT *const ctx)
{
    memset(ctx, 0, sizeof(CONTEXT));
    ctx->ContextFlags = CONTEXT_ALL;

    GetThreadContext(data->hMainThread, ctx);
}

void SetContext(PROCESS_DATA_t* const data, CONTEXT* const ctx)
{
    SetThreadContext(data->hMainThread, ctx);
}

DWORD GetEip(PROCESS_DATA_t *const data)
{
    CONTEXT ctx;

    GetContext(data, &ctx);

    return ctx.Eip;
}

void SetEip(PROCESS_DATA_t *const data, DWORD Eip)
{
    CONTEXT ctx;

    GetContext(data, &ctx);

    ctx.Eip = Eip;

    SetThreadContext(data->hMainThread, &ctx);
}

BYTE EipPeek8(PROCESS_DATA_t* const data)
{
    DWORD Eip = GetEip(data);

    BYTE value = 0;
    DWORD read;
    ReadProcessMemory(data->hProcess, (LPVOID)Eip, &value, 1, &read);

    return value;
}

DWORD GetEsp(PROCESS_DATA_t *const data)
{
    CONTEXT ctx;

    GetContext(data, &ctx);

    return ctx.Esp;
}

void SetEsp(PROCESS_DATA_t *const data, DWORD Esp)
{
    CONTEXT ctx;

    GetContext(data, &ctx);

    ctx.Esp = Esp;

    SetThreadContext(data->hMainThread, &ctx);
}

DWORD EspPeek32(PROCESS_DATA_t *const data)
{
    DWORD Esp = GetEsp(data);

    DWORD value;
    DWORD bytesRead;
    ReadProcessMemory(data->hProcess, (LPVOID)Esp, &value, sizeof(value), &bytesRead);

    return value;
}

void Push(PROCESS_DATA_t *const data, DWORD value)
{
    DWORD EspNew = GetEsp(data) - 4;
    SetEsp(data, EspNew);

    DWORD numberOfBytes;
    WriteProcessMemory(data->hProcess, (LPVOID)EspNew, &value, sizeof(DWORD), &numberOfBytes);
}

DWORD Pop(PROCESS_DATA_t *const data)
{
    DWORD stackTop = EspPeek32(data);

    DWORD EspNew = GetEsp(data) + 4;
    SetEsp(data, EspNew);

    return stackTop;
}

void GetProc_Raw(DEBUG_EVENT *const event, PROCESS_DATA_t *const data, DWORD startFrom, BOOL runToRet)
{
    SetEip(data, startFrom);
    SingleStepUntil_PUSHFD_PUSHA(event, data);
    SingleStep(event, data);
    DWORD StackTop = GetEsp(data);
    EnableHardwareBreakpoint(data, StackTop, HW_BP_COND_READWRITE, HW_BP_SIZE_DWORD);

    /* Some stubs have the POPAD/POPFD directly before the RET, some don't */
    if (runToRet)
    {
        RunUntil8(event, data, OP_RET); // Some special calls trigger somewhere within the stub first, simply Run again in that case
    }
    else
    {
        Run(event, data);
    }

    DisableHardwareBreakpoint(data, StackTop);
    SingleStepUntil8(event, data, OP_RET);
}

/// <summary>
/// Returns the remote proc address for a stub
/// </summary>
/// <param name="event"></param>
/// <param name="data"></param>
/// <param name="startFrom"></param>
/// <returns></returns>
DWORD GetProc_Generic(DEBUG_EVENT *const event, PROCESS_DATA_t *const data, DWORD startFrom, BOOL runToRet = TRUE, BOOL resolveMultiRelayed = FALSE, DWORD *out_retAddress=NULL)
{
    GetProc_Raw(event, data, startFrom, runToRet);

    DWORD proc = EspPeek32(data);

    if (resolveMultiRelayed)
    {
        if (IsUserCode(data, proc))
        {
            logger.Log("\tIs Multi-Relayed");
            logger.Log("\tintermediate proc: 0x%08X", proc);

            /* Step over RET */
            SingleStep(event, data);

            GetProc_Raw(event, data, proc, runToRet);

            proc = Pop(data);

            if (out_retAddress != NULL)
            {
                *out_retAddress = EspPeek32(data);
            }
        }
    }

    logger.Log("\tproc: 0x%08X", proc);

    return proc;
}

void FixVirtualizedJumps(PROCESS_DATA_t* const processData)
{
    logger.Log("DevirtualizeJumps");

    SIZE_T readSize = sizeof(VIRT_JUMP_t) * NUM_VIRT_JUMPS;
    VIRT_JUMP_t *rawData = (VIRT_JUMP_t*)VirtualAlloc(NULL, readSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ReadMemory(processData, (LPVOID)RAW_VIRT_JUMPS_ADDRESS, (PBYTE)rawData, readSize);

    virt_jumps_init(&virtualJumpsContainer, rawData, NUM_VIRT_JUMPS, KEY_VIRT_JUMPS_LOOKUP, KEY_VIRT_JUMPS_SIZE, KEY_VIRT_JUMPS_TYPE, KEY_VIRT_JUMPS_OFFSET);

    PBYTE textSection = (PBYTE)VirtualAlloc(NULL, processData->TextSectionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    ReadMemory(processData, (LPVOID)processData->TextSectionStart, &textSection[0], processData->TextSectionSize);

    SIZE_T cnt = 0;

    for (DWORD va = 0; va < processData->TextSectionSize; va++)
    {
        if (textSection[va] == OP_CALL_REL)
        {
            DWORD address = processData->TextSectionStart + va;

            DWORD rva = address - processData->ImageBase;

            BYTE buffer[6];

            SIZE_T bytesToCopy = virt_jumps_get_virtualized_code(&virtualJumpsContainer, rva + 5, buffer);

            if (bytesToCopy > 0)
            {
                cnt++;
                logger.Log("\t#%04d: %08X, %d", cnt, address, bytesToCopy);

                WriteMemory(processData, (LPVOID)address, buffer, bytesToCopy);
            }
        }
    }

    VirtualFree(textSection, 0, MEM_RELEASE);
    VirtualFree(rawData, 0, MEM_RELEASE);

    virt_jumps_free(&virtualJumpsContainer);
}

void FixNanomites(PROCESS_DATA_t *const processData)
{
    logger.Log("FixNanomites");

    PBYTE textSection = (PBYTE)VirtualAlloc(NULL, processData->TextSectionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ReadMemory(processData, (LPVOID)processData->TextSectionStart, &textSection[0], processData->TextSectionSize);

    NANOMITE_RAW_DATA_t *rawData = (NANOMITE_RAW_DATA_t*)RAW_NANOMITES_ADDRESS;
    DWORD gameSecret = *(((DWORD*)rawData) - 1);    /* Is directly before the raw data */

    nanomites_init(&nanomitesContainer, rawData, NUM_NANOMITES, gameSecret);

    SIZE_T c = 0;

    for (DWORD address = processData->TextSectionStart; address < processData->TextSectionEnd; address++)
    {
        DWORD rva = address - processData->ImageBase;

        DWORD key;
        DWORD checksum;

        NANOMITE_RAW_DATA_t* dataRaw = nanomites_get_raw_data(&nanomitesContainer, rva, &key, &checksum);

        if (dataRaw != NULL)
        {
            NANOMITE_DATA_t data;

            nanomites_get_data(dataRaw, &data, key);

            if (data.checksum == checksum)
            {
                c++;
                logger.Log("\t%08X, %d, %d (#%04d)", address, data.size, data.offset, c);

                if (data.size > 7)
                {
                    logger.Log("Nanomite too long: %d", data.size);

                    continue;
                }

                /* Check if valid data would be overwritten */
                if (data.offset > 0 || IsAPathToAddress(textSection, processData->TextSectionSize, address - processData->TextSectionStart + 1, data.size - 1))
                {
                    logger.Log("Probably Fake-Nanomite");

                    BOOL whitelisted = FALSE;

                    for (SIZE_T w = 0; w < sizeof(nanomiteWhitelist) / sizeof(nanomiteWhitelist[0]); w++)
                    {
                        if (nanomiteWhitelist[w] == address)
                        {
                            logger.Log("... but whitelisted ;)");

                            whitelisted = TRUE;

                            break;
                        }
                    }

                    if (!whitelisted)
                    {
                        continue;
                    }
                }

                DWORD addressAdjusted = address - data.offset;

                WriteMemory(processData, (LPVOID)addressAdjusted, &data.data[0], data.size);
            }
        }
    }

    nanomites_free(&nanomitesContainer);

    VirtualFree(textSection, 0, MEM_RELEASE);
}

BOOL FixCalls_Generic(DEBUG_EVENT *const event, PROCESS_DATA_t *const data, BYTE *const pattern, SIZE_T patternLen, BOOL dummyCall = FALSE)
{
    logger.Log("FixCalls_Generic");

    BOOL somethingFixed = FALSE;

    PBYTE textSection = (PBYTE)VirtualAlloc(NULL, data->TextSectionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    ReadMemory(data, (LPVOID)data->TextSectionStart, &textSection[0], data->TextSectionSize);

    SIZE_T iatSize = IAT_END - IAT_START;
    PBYTE iat = (PBYTE)VirtualAlloc(NULL, iatSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    ReadMemory(data, (LPVOID)IAT_START, &iat[0], iatSize);

    DWORD EipOrg = GetEip(data);
    DWORD EspOrg = GetEsp(data);

    SIZE_T SearchSize = data->TextSectionSize - (patternLen + sizeof(DWORD));

    for (SIZE_T b = 0; b < SearchSize; b++)
    {
        if (memcmp(&textSection[b], pattern, patternLen) == 0)
        {
            /* Possible CALL/MOV */
            DWORD callAt = data->TextSectionStart + b;

            DWORD thunkAddress = *(DWORD*)&textSection[b + patternLen];

            if (thunkAddress < IAT_START || IAT_END <= thunkAddress)
            {
                continue;
            }

            DWORD target = *(DWORD*)&iat[thunkAddress - IAT_START];

            if (!IsUserCode(data, target))
            {
                continue;
            }

            if (!dummyCall)
            {
                /* Handle special CALLs that are directly after a RET */

                SIZE_T nextInstructionAt = b + patternLen + sizeof(DWORD);
                BYTE nextInstruction = 0;

                if (nextInstructionAt < (SearchSize - 1))
                {
                    nextInstruction = textSection[nextInstructionAt];
                }

                if (
                    (b >= 1 && textSection[b - 1] == OP_RET) ||
                    (b >= 3 && textSection[b - 3] == OP_RET_POP)
                )
                {
                    /* Possibly ignoreable */
                    if (nextInstruction == OP_INT3 || nextInstruction == OP_NOP)
                    {
                        continue;
                    }

                    if (!IsAPathToAddress(textSection, data->TextSectionSize, b))
                    {
                        continue;
                    }
                    else
                    {
                        logger.Log("\tPath to address %08X", callAt);
                    }
                }
            }

            logger.Log("\tCALL/MOV: %08X -> %08X -> %08X", callAt, thunkAddress, target);

            SetEsp(data, EspOrg);

            DWORD startAt;

            if (dummyCall)
            {
                /** Dummy return address */
                Push(data, 0);
                startAt = target;
            }
            else
            {
                startAt = callAt;
            }

            DWORD proc = GetProc_Generic(event, data, startAt);

            data->calls_Intermodular = call_list_add(data->calls_Intermodular, callAt, proc, patternLen);

            /* Delete address or we get an infinite loop */
            DWORD zeros = 0;
            WriteMemory(data, (LPVOID)(callAt + patternLen), (PBYTE)&zeros, sizeof(zeros));

            somethingFixed = TRUE;
        }
    }

    SetEsp(data, EspOrg);
    SetEip(data, EipOrg);

    VirtualFree(iat, 0, MEM_RELEASE);
    VirtualFree(textSection, 0, MEM_RELEASE);

    return somethingFixed;
}

BOOL FixIntermodularCalls(DEBUG_EVENT *const event, PROCESS_DATA_t *const data)
{
    logger.Log("FixIntermodularCalls");

    BYTE call[] = { 0xFF, 0x15 };
    return FixCalls_Generic(event, data, &call[0], sizeof(call));
}

BOOL FixRelayedUserCodeCalls(DEBUG_EVENT* const event, PROCESS_DATA_t *const data, BOOL optional=TRUE)
{
    logger.Log("FixRelayedUserCodeCalls");

    BOOL somethingFixed = FALSE;

    PBYTE textSection = (PBYTE)VirtualAlloc(NULL, data->TextSectionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    DWORD bytesRead;
    ReadProcessMemory(data->hProcess, (LPVOID)data->TextSectionStart, &textSection[0], data->TextSectionSize, &bytesRead);

    DWORD EipOrg = GetEip(data);
    DWORD EspOrg = GetEsp(data);

    // Pattern: B8????????5903C18B00FFE0

    SIZE_T stubsFound = 0;
    DWORD lookupStubAt = 0;

    for (SIZE_T b = 0; b < data->TextSectionSize - 12; b++)
    {
        if (
            (textSection[b] == 0xB8) &&
            (*(DWORD*)&textSection[b + 5] == (DWORD)0x8BC10359UL) &&
            (*(DWORD*)&textSection[b + 8] == (DWORD)0xE0FF008BUL) // Overlapped!
            )
        {
            stubsFound++;
            lookupStubAt = b;
        }
    }

    if (optional && stubsFound == 0)
    {
        logger.Log("No stub found");

        return FALSE;
    }

    if (stubsFound != 1)
    {
        logger.Log("Unexpected number of stubs: %u", stubsFound);

        ExitProcess(-1);
    }

    lookupStubAt += data->TextSectionStart;

    logger.Log("\tLookup stub at: 0x%08X", lookupStubAt);

    DWORD setupStubAt = 0;

    for (SIZE_T b = 0; b < data->TextSectionSize - 5; b++)
    {
        if (textSection[b] == OP_CALL_REL)
        {
            DWORD callAt = data->TextSectionStart + b;
            DWORD callOffset = *(DWORD*)&textSection[b + 1];
            DWORD callTo = callAt + 5 + callOffset;

            if (callTo == lookupStubAt)
            {
                setupStubAt = callAt - 2; // Compensate for PUSH ECX, PUSH EAX

                break;
            }
        }
    }

    if (setupStubAt == 0)
    {
        logger.Log("Could not find setup stub");

        ExitProcess(-1);
    }

    logger.Log("\tSetup stub at: 0x%08X", setupStubAt);

    for (SIZE_T b = 0; b < data->TextSectionSize - 5; b++)
    {
        if (textSection[b] == OP_CALL_REL)
        {
            DWORD callAt = data->TextSectionStart + b;
            DWORD callOffset = *(DWORD*)&textSection[b + 1];
            DWORD callTo = callAt + 5 + callOffset;

            if (callTo == setupStubAt)
            {
                /* Ignore if there is a RET before the CALL */
                if (b >= 1 && textSection[b - 1] == OP_RET)
                {
                    continue;
                }

                if (b >= 3 && textSection[b - 3] == OP_RET_POP)
                {
                    continue;
                }

                logger.Log("\tRelayed call at: 0x%08X", callAt);

                DWORD proc = GetProc_Generic(event, data, callAt);

                BYTE call[5];

                DWORD callOffsetOrg = proc - callAt - 5;

                call[0] = OP_CALL_REL;
                *(DWORD*)&call[1] = callOffsetOrg;

                DWORD numBytes;
                WriteProcessMemory(data->hProcess, (LPVOID)callAt, &call[0], sizeof(call), &numBytes);

                somethingFixed = TRUE;
            }
        }
    }

    SetEsp(data, EspOrg);
    SetEip(data, EipOrg);

    VirtualFree(textSection, 0, MEM_RELEASE);

    return somethingFixed;
}

BOOL FixStolenBytesCall(DEBUG_EVENT* const event, PROCESS_DATA_t* const data, BOOL optional = TRUE)
{
    logger.Log("FixStolenBytesCall");

    DWORD EipOrg = GetEip(data);
    DWORD EspOrg = GetEsp(data);

    BOOL somethingFixed = FALSE;

    PBYTE stolenBytesBuffer = (PBYTE)VirtualAlloc(NULL, STOLEN_BYTES_BUFFER_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    PBYTE textSection = (PBYTE)VirtualAlloc(NULL, data->TextSectionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    ReadMemory(data, (LPVOID)data->TextSectionStart, &textSection[0], data->TextSectionSize);

    // Pattern: B8???????? 59 8D0408 8B00 FFE0

    for (SIZE_T b0 = 0; b0 < data->TextSectionSize - 12; b0++)
    {
        if (
            (textSection[b0] == 0xB8) &&
            (*(DWORD*)&textSection[b0 + 5] == (DWORD)0x08048D59UL) &&
            (*(DWORD*)&textSection[b0 + 9] == (DWORD)0xE0FF008BUL)
            )
        {
            DWORD lookupStubAt = b0 + data->TextSectionStart;

            logger.Log("\tLookup stub at: 0x%08X", lookupStubAt);

            for (SIZE_T b1 = 0; b1 < data->TextSectionSize - 5; b1++)
            {
                if (textSection[b1] != OP_CALL_REL)
                {
                    continue;
                }

                DWORD innerCallAt = data->TextSectionStart + b1;
                DWORD innerCallOffset = *(DWORD*)&textSection[b1 + 1];
                DWORD innerCallTo = innerCallAt + 5 + innerCallOffset;

                if (innerCallTo != lookupStubAt)
                {
                    continue;
                }
                    
                DWORD setupStubAt = innerCallAt - 2; // Compensate for PUSH ECX, PUSH EAX

                logger.Log("\tSetup stub at: 0x%08X", setupStubAt);

                for (SIZE_T b2 = 0; b2 < data->TextSectionSize - 5; b2++)
                {
                    if (textSection[b2] != OP_CALL_REL)
                    {
                        continue;
                    }

                    DWORD outerCallAt = data->TextSectionStart + b2;
                    DWORD outerCallOffset = *(DWORD*)&textSection[b2 + 1];
                    DWORD outerCallTo = outerCallAt + 5 + outerCallOffset;

                    if (outerCallTo != setupStubAt)
                    {
                        continue;
                    }

                    logger.Log("\tStolen bytes call at: 0x%08X", outerCallAt);

                    /* Ignore if there is a RET before the CALL */
                    if (b2 >= 1 && textSection[b2 - 1] == OP_RET && !IsAPathToAddress(textSection, data->TextSectionSize, b2))
                    {
                        logger.Log("\tIGNORING");

                        continue;
                    }

                    if (b2 >= 3 && textSection[b2 - 3] == OP_RET_POP && !IsAPathToAddress(textSection, data->TextSectionSize, b2))
                    {
                        logger.Log("\tIGNORING");

                        continue;
                    }

                    if (b2 > 1)
                    {
                        BYTE nextInstruction = textSection[b2 - 1];

                        /* Possibly ignoreable */
                        if ((nextInstruction == OP_INT3 || nextInstruction == OP_NOP) && !IsAPathToAddress(textSection, data->TextSectionSize, b2))
                        {
                            logger.Log("\tIGNORING");

                            continue;
                        }
                    }

                    SetEsp(data, EspOrg);

                    const DWORD instOriginal = *(DWORD*)&textSection[b2];

                    SetEip(data, outerCallAt);
                    SingleStepUntil_PUSHFD_PUSHA(event, data);
                    SingleStep(event, data);
                    DWORD StackTop = GetEsp(data);
                    EnableHardwareBreakpoint(data, StackTop, HW_BP_COND_READWRITE, HW_BP_SIZE_DWORD);
                    RunUntil_RET(event, data);
                    DisableHardwareBreakpoint(data, StackTop);

                    DWORD proc = Pop(data);

                    /*
                        Now we eiter:
                            1) Landed back on the outerCallAt
                                -> Stolen bytes
                            2) Land outside of the User Code
                                2a) The bytes at the outerCallAt location are untouched
                                    -> Relayed CALL
                                2b) The bytes are changed
                                    -> Virtualized (+ self-repaired) Code (e.g. Jumps)
                    */

                    logger.Log("\tproc: %08X", proc);

                    if (proc == outerCallAt)
                    {
                        logger.Log("\tRestoring stolen bytes");

                        /* Copy data to buffer */
                        SIZE_T remainingBytesInText = data->TextSectionEnd - outerCallAt;

                        SIZE_T copySize = STOLEN_BYTES_BUFFER_SIZE;

                        if (remainingBytesInText < STOLEN_BYTES_BUFFER_SIZE)
                        {
                            copySize = remainingBytesInText;
                        }

                        ReadMemory(data, (LPVOID)outerCallAt, stolenBytesBuffer, copySize);

                        /* We already popped the original RET address, so the address of the second stub should be on the stack and the are also on a RET */

                        SingleStepUntil_PUSHFD_PUSHA(event, data);
                        SingleStep(event, data);
                        DWORD StackTop = GetEsp(data);
                        EnableHardwareBreakpoint(data, StackTop, HW_BP_COND_READWRITE, HW_BP_SIZE_DWORD);
                        RunUntil8(event, data, OP_RET); // Some special calls trigger somewhere within the stub first, simply Run again in that case
                        DisableHardwareBreakpoint(data, StackTop);

                        /* Copy back stolen bytes */
                        WriteMemory(data, (LPVOID)outerCallAt, stolenBytesBuffer, copySize);

                        somethingFixed = TRUE;
                    }
                    else
                    {
                        ReadMemory(data, (LPVOID)data->TextSectionStart, &textSection[0], data->TextSectionSize);

                        const DWORD instNew = *(DWORD*)&textSection[b2];

                        if (instOriginal == instNew)
                        {
                            logger.Log("\tRestoring CALL-BY-JMP");

                            BYTE call[5];

                            DWORD callOffsetOrg = proc - outerCallAt - 5;

                            call[0] = OP_CALL_REL;
                            *(DWORD*)&call[1] = callOffsetOrg;

                            WriteMemory(data, (LPVOID)outerCallAt, &call[0], sizeof(call));

                            somethingFixed = TRUE;
                        }
                        else
                        {
                            logger.Log("\tRestoring virtualized code");

                            SIZE_T remainingBytesInText = data->TextSectionEnd - outerCallAt;

                            SIZE_T copySize = STOLEN_BYTES_BUFFER_SIZE;

                            if (remainingBytesInText < STOLEN_BYTES_BUFFER_SIZE)
                            {
                                copySize = remainingBytesInText;
                            }

                            WriteMemory(data, (LPVOID)outerCallAt, stolenBytesBuffer, copySize);

                            somethingFixed = TRUE;
                        }
                    }
                }
            }
        }
    }

    SetEsp(data, EspOrg);
    SetEip(data, EipOrg);

    VirtualFree(textSection, 0, MEM_RELEASE);
    VirtualFree(stolenBytesBuffer, 0, MEM_RELEASE);

    return somethingFixed;
}

BOOL FixRegisterCalls(DEBUG_EVENT* const event, PROCESS_DATA_t *const data)
{
    logger.Log("FixRegisterCalls");

    BOOL somethingFixed = FALSE;

    BYTE movEax[] = { 0xA1 };
    if (FixCalls_Generic(event, data, &movEax[0], sizeof(movEax), TRUE))
    {
        somethingFixed = TRUE;
    }

    BYTE movEbx[] = { 0x8B, 0x1D };
    if (FixCalls_Generic(event, data, &movEbx[0], sizeof(movEbx), TRUE))
    {
        somethingFixed = TRUE;
    }

    BYTE movEcx[] = { 0x8B, 0x0D };
    if (FixCalls_Generic(event, data, &movEcx[0], sizeof(movEcx), TRUE))
    {
        somethingFixed = TRUE;
    }

    BYTE movEdx[] = { 0x8B, 0x15 };
    if (FixCalls_Generic(event, data, &movEdx[0], sizeof(movEdx), TRUE))
    {
        somethingFixed = TRUE;
    }

    BYTE movEbp[] = { 0x8B, 0x2D };
    if (FixCalls_Generic(event, data, &movEbp[0], sizeof(movEbp), TRUE))
    {
        somethingFixed = TRUE;
    }

    BYTE movEsp[] = { 0x8B, 0x25 };
    if (FixCalls_Generic(event, data, &movEsp[0], sizeof(movEsp), TRUE))
    {
        somethingFixed = TRUE;
    }

    BYTE movEsi[] = { 0x8B, 0x35 };
    if (FixCalls_Generic(event, data, &movEsi[0], sizeof(movEsi), TRUE))
    {
        somethingFixed = TRUE;
    }

    BYTE movEdi[] = { 0x8B, 0x3D };
    if (FixCalls_Generic(event, data, &movEdi[0], sizeof(movEdi), TRUE))
    {
        somethingFixed = TRUE;
    }

    return somethingFixed;
}

BOOL FixJMPCalls(DEBUG_EVENT *const event, PROCESS_DATA_t* const data)
{
    logger.Log("FixJMPCalls");

    BYTE jmp[] = { 0xFF, 0x25 };
    return FixCalls_Generic(event, data, &jmp[0], sizeof(jmp), TRUE);
}

BOOL FixFarJMPCalls(DEBUG_EVENT* const event, PROCESS_DATA_t* const data)
{
    logger.Log("FixFarJMPCalls");

    BOOL somethingFixed = FALSE;

    PBYTE textSection = (PBYTE)VirtualAlloc(NULL, data->TextSectionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ReadMemory(data, (LPVOID)data->TextSectionStart, &textSection[0], data->TextSectionSize);

    DWORD EipOrg = GetEip(data);
    DWORD EspOrg = GetEsp(data);

    // Pattern: E9????????

    SIZE_T stubsFound = 0;
    DWORD lookupStubAt = 0;

    for (SIZE_T b = 0; b < data->TextSectionSize - 5; b++)
    {
        if (textSection[b] == OP_JMP_REL)
        {
            DWORD jmpAt = data->TextSectionStart + b;
            DWORD jmpOffset = *(DWORD*)&textSection[b + 1];
            DWORD jmpTo = jmpAt + 5 + jmpOffset;

            if (jmpTo < data->SafeDiscSectionStart || data->SafeDiscSectionEnd <= jmpTo)
            {
                continue;
            }

            /* Extra check, maybe not needed */
            WORD checkVal;
            ReadMemory(data, (LPVOID)jmpTo, (PBYTE)&checkVal, sizeof(checkVal));

            /* PUSH EBX; CALL */
            if (checkVal != 0xE853)
            {
                continue;
            }

            logger.Log("\tJMP at: 0x%08X", jmpAt);

            DWORD retAddress = 0;
            DWORD proc = GetProc_Generic(event, data, jmpAt, FALSE, TRUE, &retAddress);

            SIZE_T opSize = retAddress - jmpAt;

            if (opSize < 5 || 6 < opSize)
            {
                logger.Log("\tInvalid OP size: %d", opSize);

                continue;
            }

            if (opSize == 5)
            {
                logger.Log("\tIs call to trampoline");
                
                /* Delete address or we get an infinite loop */
                BYTE call[] = { 0xE8, 0x00, 0x00 , 0x00 , 0x00 };
                WriteMemory(data, (LPVOID)jmpAt, &call[0], sizeof(call));

                data->calls_Intermodular = call_list_add(data->calls_Intermodular, jmpAt, proc, 1, TRUE);
            }
            else
            {
                /* Delete address or we get an infinite loop */
                BYTE call[] = { 0xFF, 0x15, 0x00, 0x00 , 0x00 , 0x00 };
                WriteMemory(data, (LPVOID)jmpAt, &call[0], sizeof(call));

                data->calls_Intermodular = call_list_add(data->calls_Intermodular, jmpAt, proc, 2);
            }        

            somethingFixed = TRUE;
        }
    }

    data->SafeDiscSectionSize = data->SafeDiscSectionEnd - data->SafeDiscSectionStart;

    SetEsp(data, EspOrg);
    SetEip(data, EipOrg);

    VirtualFree(textSection, 0, MEM_RELEASE);

    return somethingFixed;
}

void FixIAT(PROCESS_DATA_t *const data)
{
    logger.Log("FixIAT");

    PBYTE textSection = (PBYTE)VirtualAlloc(NULL, data->TextSectionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    SIZE_T IATSize = IAT_END - IAT_START;
    BYTE *IAT = (BYTE*)VirtualAlloc(NULL, IATSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    const BYTE *IATEndVirt = IAT + IATSize;

    DWORD protectionOldIAT;
    VirtualProtectEx(data->hProcess, (LPVOID)IAT_START, IATSize, PAGE_READWRITE, &protectionOldIAT);
    ReadMemory(data, (LPVOID)IAT_START, &IAT[0], IATSize);

    /* Remove all SafeDisc thunks */
    DWORD *thunk = (DWORD*)&IAT[0];

    while(thunk < (DWORD*)IATEndVirt)
    {
        if (IsUserCode(data, *thunk))
        {
            *thunk = 0;
        }

        thunk++;
    }

    DWORD protectionOld;
    VirtualProtectEx(data->hProcess, (LPVOID)data->TextSectionStart, data->TextSectionSize, PAGE_READWRITE, &protectionOld);

    CALL_t *head = data->calls_Intermodular;

    while (head != NULL)
    {
        /* Check if we have this address already in the IAT */
        thunk = (DWORD*)&IAT[0];

        while (thunk < (DWORD*)IATEndVirt)
        {
            if (*thunk == head->Target)
            {
                break;
            }

            thunk++;
        }

        if (thunk >= (DWORD*)IATEndVirt)
        {
            /* Search empty thunk */
            thunk = (DWORD*)&IAT[0];

            while (thunk < (DWORD*)IATEndVirt)
            {
                if (*thunk == 0)
                {
                    *thunk = head->Target;

                    break;
                }

                thunk++;
            }
        }

        if (thunk >= (DWORD*)IATEndVirt)
        {
            logger.Log("IAT Overflow!");

            ExitProcess(-1);
        }

        if (!head->IsTrampoline)
        {
            DWORD thunkReal = IAT_START + ((DWORD)thunk - (DWORD)IAT);

            logger.Log("\t::%08X -> [%08X] -> %08X", head->CallAt, thunkReal, head->Target);

            WriteMemory(data, (LPVOID)(head->CallAt + head->InstructionLen), (PBYTE)&thunkReal, sizeof(DWORD));
        }

        head = head->Next;
    }

    /* Fix trampoline CALLS */
    ReadMemory(data, (LPVOID)data->TextSectionStart, &textSection[0], data->TextSectionSize);

    head = data->calls_Intermodular;

    while (head != NULL)
    {
        if (!head->IsTrampoline)
        {
            head = head->Next;

            continue;
        }

        /* Check if we have this address already in the IAT */
        thunk = (DWORD*)&IAT[0];

        while (thunk < (DWORD*)IATEndVirt)
        {
            if (*thunk == head->Target)
            {
                break;
            }

            thunk++;
        }

        if (thunk >= (DWORD*)IATEndVirt)
        {
            logger.Log("Thunk not found!");

            ExitProcess(-1);
        }

        DWORD thunkReal = IAT_START + ((DWORD)thunk - (DWORD)IAT);

        /* Search trampoline */
        for (SIZE_T b = 0; b < data->TextSectionSize - 6; b++)
        {
            if ((*(WORD*)&textSection[b] == OP_JMP_IND) && (*(DWORD*)&textSection[b + 2] == thunkReal))
            {
                DWORD trampolineAt = data->TextSectionStart + b;
                DWORD offsetToTrampoline = trampolineAt - (head->CallAt + 5);

                logger.Log("\t::%08X -> %08X JMP [%08X] -> %08X", head->CallAt, trampolineAt, thunkReal, head->Target);

                WriteMemory(data, (LPVOID)(head->CallAt + head->InstructionLen), (PBYTE)&offsetToTrampoline, sizeof(DWORD));

                break;
            }
        }   

        head = head->Next;
    }

    VirtualProtectEx(data->hProcess, (LPVOID)data->TextSectionStart, data->TextSectionSize, protectionOld, &protectionOld);

    /* Write back IAT */
    WriteMemory(data, (LPVOID)IAT_START, &IAT[0], IATSize);
    VirtualProtectEx(data->hProcess, (LPVOID)IAT_START, IATSize, protectionOldIAT, &protectionOldIAT);

    VirtualFree(IAT, 0, MEM_RELEASE);
    VirtualFree(textSection, 0, MEM_RELEASE);
}

void DetachAndExit(PROCESS_DATA_t *const data)
{
    SuspendThread(data->hMainThread);

    CONTEXT ctx;

    GetContext(data, &ctx);

    ctx.EFlags &= ~FLAG_TRAP;

    SetContext(data, &ctx);

    ContinueDebugEvent(data->pid, processData.mainThreadId, DBG_CONTINUE);

    DebugActiveProcessStop(data->pid);

    CloseHandle(data->hMainThread);

    ExitProcess(0);
}

void FixGame(LPDEBUG_EVENT event, PROCESS_DATA_t *const data)
{
    RestoreOEPData(data);
    SetEip(data, data->OEP);

    FixVirtualizedJumps(data);    
    FixNanomites(data);

    SIZE_T round = 0;
    BOOL somethingFixed = TRUE;

    while (somethingFixed)
    {
        somethingFixed = FALSE;

        round++;
        logger.Log("FixGame round #%d", round);

       /* if (FixRelayedUserCodeCalls(event, data))
        {
            somethingFixed = TRUE;
        }*/

        if (FixStolenBytesCall(event, data))
        {
            somethingFixed = TRUE;
        }

        if (FixIntermodularCalls(event, data))
        {
            somethingFixed = TRUE;
        }

        if (FixRegisterCalls(event, data))
        {
            somethingFixed = TRUE;
        }

        if (FixJMPCalls(event, data))
        {
            somethingFixed = TRUE;
        }

        if (FixFarJMPCalls(event, data))
        {
            somethingFixed = TRUE;
        }
    }

    FixIAT(data);

    call_list_free(data->calls_Intermodular);
    data->calls_Intermodular = NULL;
}

BOOL __stdcall Callback_DebugActiveProcess(DWORD dwProcessId)
{
    logger.Log("Callback_DebugActiveProcess:");
    logger.Log("\tdwProcessId: %08X", dwProcessId);

    GetProcessData(dwProcessId, &processData);
    logger.Log("\tentryPoint: %08X", processData.EntryPoint);
    logger.Log("\tOEP: %08X", processData.OEP);

    hook_install("Kernel32.dll", "WaitForDebugEvent", &Callback_WaitForDebugEvent, &hook_WaitForDebugEvent);

    BOOL result = ((Resume_DebugActiveProcess_t)hook_DebugActiveProcess.resume)(dwProcessId);

    hook_uninstall(&hook_DebugActiveProcess);

    return result;
}

BOOL __stdcall Callback_WaitForDebugEvent(LPDEBUG_EVENT lpDebugEvent, DWORD dwMilliseconds)
{
    BOOL result = ((Resume_WaitForDebugEvent_t)hook_WaitForDebugEvent.resume)(lpDebugEvent, dwMilliseconds);

    DWORD dwDebugEventCode = lpDebugEvent->dwDebugEventCode;

    /* Filter out uninteresting events */
    if (dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
    {
        logger.Log("Callback_WaitForDebugEvent");
        logger.Log("\tprocess: %08X", lpDebugEvent->dwProcessId);
        logger.Log("\tthread: %08X", lpDebugEvent->dwThreadId);
        logger.Log("\ttimeout: %08X", dwMilliseconds);
        logger.Log("\tcode: %08X", dwDebugEventCode);

        DWORD exceptionAddress = (DWORD)lpDebugEvent->u.Exception.ExceptionRecord.ExceptionAddress;

        logger.Log("\texceptionAddress: %08X", exceptionAddress);

        if (exceptionAddress == processData.OEP)
        {
            /** The game is unpacked now and execution stopped at the OEP */

            GetModules(&processData);

            logger.Log("\tMain ThreadId: %08X", lpDebugEvent->dwThreadId);

            processData.mainThreadId = lpDebugEvent->dwThreadId;
            processData.hMainThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, lpDebugEvent->dwThreadId);

            MessageBoxA(NULL, "Starting Fix", "Starting Fix", MB_OK);

            FixGame(lpDebugEvent, &processData);

            MessageBoxA(NULL, "Done, will detach now", "Done ;)", MB_OK);

            DetachAndExit(&processData);
        }
    }

    return result;
}

DWORD WINAPI WorkerThread(LPVOID data)
{
    logger.Log("Starting Worker");

    hook_install("Kernel32.dll", "DebugActiveProcess", &Callback_DebugActiveProcess, &hook_DebugActiveProcess);

    logger.Log("Hooks installed");

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
        case (DLL_PROCESS_ATTACH):
        {
            DisableThreadLibraryCalls(hModule);

            CreateThread(NULL, 0x1000, WorkerThread, NULL, STACK_SIZE_PARAM_IS_A_RESERVATION, NULL);

            break;
        }

        case (DLL_PROCESS_DETACH):
        {
            logger.Log("Tearing hooks down");

            hook_uninstall(&hook_WaitForDebugEvent);

            logger.Log("Done");

            break;
        }

        default:
        {
            break;
        }
    }

    return TRUE;
}