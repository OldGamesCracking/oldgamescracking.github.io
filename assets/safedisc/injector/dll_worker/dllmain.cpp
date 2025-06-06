#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include "hooking.h"

#pragma comment(lib, "User32.lib")


typedef BOOL (__stdcall *Resume_WaitForDebugEvent)(LPDEBUG_EVENT lpDebugEvent, DWORD dwMilliseconds);
typedef BOOL (__stdcall *Resume_SetThreadContext)(HANDLE hThread, CONTEXT *lpContext);
typedef BOOL (__stdcall *Resume_WriteProcessMemory)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
typedef BOOL (__stdcall *Resume_ContinueDebugEvent)(DWORD dwProcessId, DWORD dwThreadId, DWORD dwContinueStatus);


HOOK_t hook_WaitForDebugEvent = { 0 };
HOOK_t hook_SetThreadContext = { 0 };
HOOK_t hook_WriteProcessMemory = { 0 };
HOOK_t hook_ContinueDebugEvent = { 0 };

FILE *fp_Log = NULL;
FILE *fp_Opcodes = NULL;

BYTE buffer[sizeof(WCHAR) * (MAX_MODULE_NAME32 + 1)];

BOOL patchfileInitialized = FALSE;
DWORD moduleBase = 0;

DWORD exceptionThreadId = 0;
BOOL threadContextSet = FALSE;
BOOL processMemoryWritten = FALSE;


void Log(FILE *fp, const char *format, ...)
{
    if (fp == NULL)
    {
        return;
    }

    va_list args;
    va_start(args, format);

    vfprintf(fp, format, args);
    fprintf(fp, "\n");
    fflush(fp);

    va_end(args);
}


void InitializePatchfile(DWORD processId)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processId);

    if (hSnapshot != INVALID_HANDLE_VALUE)
    {
        MODULEENTRY32 modEntry;
        modEntry.dwSize = sizeof(modEntry);

        if (Module32First(hSnapshot, &modEntry))
        {
            WideCharToMultiByte(CP_UTF8, 0, &modEntry.szModule[0], -1, (LPSTR)&buffer[0], sizeof(buffer), NULL, NULL);

            Log(fp_Opcodes, ">%s", buffer);

            moduleBase = (DWORD)modEntry.modBaseAddr;

            patchfileInitialized = TRUE;
        }

        CloseHandle(hSnapshot);
    }
}


BOOL __stdcall Callback_WaitForDebugEvent(LPDEBUG_EVENT lpDebugEvent, DWORD dwMilliseconds)
{
    BOOL result = ((Resume_WaitForDebugEvent)hook_WaitForDebugEvent.resume)(lpDebugEvent, dwMilliseconds);

    const DWORD dwDebugEventCode = lpDebugEvent->dwDebugEventCode;

    /* Filter out uninteresting events */
    if (dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
    {
        Log(fp_Log, "Callback_WaitForDebugEvent");
        Log(fp_Log, "\tprocess: %08X", lpDebugEvent->dwProcessId);
        Log(fp_Log, "\tthread: %08X", lpDebugEvent->dwThreadId);
        Log(fp_Log, "\ttimeout: %08X", dwMilliseconds);
        Log(fp_Log, "\tcode: %08X", dwDebugEventCode);

        const DWORD exceptionAddress = (DWORD)lpDebugEvent->u.Exception.ExceptionRecord.ExceptionAddress;

        if (exceptionAddress < 0x60000000)  // TODO: Find better way to determine address
        {
            if (!patchfileInitialized)
            {
                InitializePatchfile(lpDebugEvent->dwProcessId);
            }

            exceptionThreadId = lpDebugEvent->dwThreadId;
            threadContextSet = FALSE;
            processMemoryWritten = FALSE;

            Log(fp_Log, "\texception_at: %08X", exceptionAddress);
            Log(fp_Log, "\tchance: %s", lpDebugEvent->u.Exception.dwFirstChance ? "first" : "second");
        }
    }

    return result;
}


BOOL __stdcall Callback_SetThreadContext(HANDLE hThread, CONTEXT *lpContext)
{
    Log(fp_Log, "Callback_SetThreadContext");
    Log(fp_Log, "\tthread_handle: %08X", hThread);

    threadContextSet = TRUE;

    return ((Resume_SetThreadContext)hook_SetThreadContext.resume)(hThread, lpContext);
}


BOOL __stdcall Callback_WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten)
{
    Log(fp_Log, "Callback_WriteProcessMemory");
    Log(fp_Log, "\t%08X : %08X", lpBaseAddress, nSize);

    processMemoryWritten = TRUE;

    if (nSize < sizeof(buffer))
    {
        /* Read old contents */
        ReadProcessMemory(hProcess, lpBaseAddress, buffer, nSize, lpNumberOfBytesWritten);

        for (SIZE_T i = 0; i < nSize; i++)
        {
            Log(fp_Opcodes, "%08X:%02X->%02X", (DWORD)lpBaseAddress + i - moduleBase, buffer[i], *((BYTE*)lpBuffer + i));
        }
    }

    return ((Resume_WriteProcessMemory)hook_WriteProcessMemory.resume)(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
}


BOOL __stdcall Callback_ContinueDebugEvent(DWORD dwProcessId, DWORD dwThreadId, DWORD dwContinueStatus)
{
    Log(fp_Log, "Callback_ContinueDebugEvent");
    Log(fp_Log, "\tprocess_id: %08X", dwProcessId);
    Log(fp_Log, "\tthread_id: %08X", dwThreadId);
    Log(fp_Log, "\tstatus: %08X", dwContinueStatus);

    if (dwThreadId == exceptionThreadId)
    {
        Log(fp_Log, "\tTerminating thread");

        DWORD exitCode = 0;

        if (threadContextSet && processMemoryWritten)
        {
            /* Nanomite was replaced */
        }
        else if (threadContextSet || processMemoryWritten)
        {
            /* Probably not fixed */
            exitCode = 1;
        }
        else
        {
            /* Probably not a Nanomite at all */
            exitCode = 2;
        }

        HANDLE hThread = OpenThread(THREAD_TERMINATE, FALSE, exceptionThreadId);

        Log(fp_Log, "\tThread handle: %08X", (DWORD)hThread);

        TerminateThread(hThread, exitCode);

        Log(fp_Log, "\tThread terminated");

        CloseHandle(hThread);

        Log(fp_Log, "\tHandle closed");

        return ((Resume_ContinueDebugEvent)hook_ContinueDebugEvent.resume)(dwProcessId, dwThreadId, DBG_EXCEPTION_NOT_HANDLED);

        Log(fp_Log, "\tThread continued");

        exceptionThreadId = 0;
    }
    else
    {
        Log(fp_Log, "\tContinuing thread");

        return ((Resume_ContinueDebugEvent)hook_ContinueDebugEvent.resume)(dwProcessId, dwThreadId, dwContinueStatus);
    }
}


DWORD WINAPI WorkerThread(LPVOID data)
{
    fp_Log = fopen("worker_log.txt", "a");
    fp_Opcodes = fopen("restored_bytes.1337", "w");

    patchfileInitialized = FALSE;
    moduleBase = 0;

    Log(fp_Log, "Starting Worker");

    hook_install("Kernel32.dll", "WaitForDebugEvent", &Callback_WaitForDebugEvent, &hook_WaitForDebugEvent);
    hook_install("Kernel32.dll", "SetThreadContext", &Callback_SetThreadContext, &hook_SetThreadContext);
    hook_install("Kernel32.dll", "WriteProcessMemory", &Callback_WriteProcessMemory, &hook_WriteProcessMemory);
    hook_install("Kernel32.dll", "ContinueDebugEvent", &Callback_ContinueDebugEvent, &hook_ContinueDebugEvent);

    Log(fp_Log, "Hooks installed");

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
            Log(fp_Log, "Tearing hooks down");

            hook_uninstall(&hook_WaitForDebugEvent);
            hook_uninstall(&hook_SetThreadContext);
            hook_uninstall(&hook_WriteProcessMemory);
            hook_uninstall(&hook_ContinueDebugEvent);

            Log(fp_Log, "Done");

            fclose(fp_Log);
            fp_Log = NULL;

            fclose(fp_Opcodes);
            fp_Opcodes = NULL;

            break;
        }

        default:
        {
            break;
        }
    }

    return TRUE;
}
