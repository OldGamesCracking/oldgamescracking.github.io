#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <shlwapi.h>
#include <inttypes.h>
#include "logging.h"
#include "hooking.h"


#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Kernel32.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Shlwapi.lib")


#define NANOMITES_JMP_ADDRESS       0x66725641
#define NANOMITES_JMP_PATCH         0x90C03166  // XOR AX, AX; NOP


typedef BOOL (__stdcall *Resume_WriteProcessMemory_t)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);
typedef BOOL (__stdcall *Resume_ContinueDebugEvent_t)(DWORD dwProcessId, DWORD dwThreadId, DWORD dwContinueStatus);
typedef BOOL(__stdcall *Resume_DebugActiveProcess_t)(DWORD dwProcessId);
typedef BOOL(__stdcall *Resume_WaitForDebugEvent_t)(LPDEBUG_EVENT lpDebugEvent, DWORD dwMilliseconds);

typedef struct
{
    BOOL FixingGame;

    DWORD pid;
    HANDLE hProcess;
    DWORD ImageBase;
    DWORD EntryPoint;

    DWORD mainThreadId;
    HANDLE hMainThread;

} PROCESS_DATA_t;


/* Prototypes */
BOOL __stdcall Callback_WaitForDebugEvent(LPDEBUG_EVENT lpDebugEvent, DWORD dwMilliseconds);


HOOK_t hook_WriteProcessMemory = { 0 };
HOOK_t hook_DebugActiveProcess = { 0 };
HOOK_t hook_WaitForDebugEvent = { 0 };

BYTE buffer[sizeof(WCHAR) * (MAX_MODULE_NAME32 + 1)];

PROCESS_DATA_t processData = { 0 };

FARPROC procExitProcess = NULL;

BOOL nanomitesJumpFixed = false;

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

    CloseHandle(hFile);
}

BOOL __stdcall Callback_WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten)
{
    logger.LogLine("[Callback_WriteProcessMemory]");
    logger.LogLine("\t%d bytes @ %08X", nSize, lpBaseAddress);

    logger.Log("\t");

    for (size_t b = 0; b < nSize; b++)
    {
        logger.Log("%02X%s", ((uint8_t*)lpBuffer)[b], ((b + 1) == nSize) ? "" : " ");
    }

    logger.LogLine("");

    return ((Resume_WriteProcessMemory_t)hook_WriteProcessMemory.resume)(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
}

BOOL __stdcall Callback_DebugActiveProcess(DWORD dwProcessId)
{
    logger.LogLine("[Callback_DebugActiveProcess]");
    logger.LogLine("\tdwProcessId: %08X", dwProcessId);

    GetProcessData(dwProcessId, &processData);
    logger.LogLine("\tentryPoint: %08X", processData.EntryPoint);

    hook_install("Kernel32.dll", "WaitForDebugEvent", &Callback_WaitForDebugEvent, &hook_WaitForDebugEvent);
    hook_install("Kernel32.dll", "WriteProcessMemory", &Callback_WriteProcessMemory, &hook_WriteProcessMemory);

    BOOL result = ((Resume_DebugActiveProcess_t)hook_DebugActiveProcess.resume)(dwProcessId);

    hook_uninstall(&hook_DebugActiveProcess);

    return result;
}

BOOL __stdcall Callback_WaitForDebugEvent(LPDEBUG_EVENT lpDebugEvent, DWORD dwMilliseconds)
{
    if (!nanomitesJumpFixed)
    {
        DWORD oldProtect;
        VirtualProtect((LPVOID)NANOMITES_JMP_ADDRESS, sizeof(DWORD), PAGE_READWRITE, &oldProtect);

        *(DWORD*)NANOMITES_JMP_ADDRESS = NANOMITES_JMP_PATCH;

        VirtualProtect((LPVOID)NANOMITES_JMP_ADDRESS, sizeof(DWORD), oldProtect, &oldProtect);

        FlushInstructionCache(GetCurrentProcess(), NULL, NULL);

        nanomitesJumpFixed = true;
    }
    
    BOOL result = ((Resume_WaitForDebugEvent_t)hook_WaitForDebugEvent.resume)(lpDebugEvent, dwMilliseconds);

    DWORD dwDebugEventCode = lpDebugEvent->dwDebugEventCode;

    /* Filter out uninteresting events */
    if (dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
    {
        logger.LogLine("[Callback_WaitForDebugEvent]");
        logger.LogLine("\tprocess: %08X", lpDebugEvent->dwProcessId);
        logger.LogLine("\tthread: %08X", lpDebugEvent->dwThreadId);
        logger.LogLine("\ttimeout: %08X", dwMilliseconds);
        logger.LogLine("\tcode: %08X", dwDebugEventCode);

        DWORD exceptionAddress = (DWORD)lpDebugEvent->u.Exception.ExceptionRecord.ExceptionAddress;

        logger.LogLine("\texceptionAddress: %08X", exceptionAddress);
    }

    return result;
}

DWORD WINAPI WorkerThread(LPVOID data)
{
    logger.LogLine("Starting Worker");

    hook_install("Kernel32.dll", "DebugActiveProcess", &Callback_DebugActiveProcess, &hook_DebugActiveProcess);

    logger.LogLine("Hooks installed");

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
            logger.LogLine("Tearing hooks down");

            hook_uninstall(&hook_WaitForDebugEvent);

            logger.LogLine("Done");

            break;
        }

        default:
        {
            break;
        }
    }

    return TRUE;
}