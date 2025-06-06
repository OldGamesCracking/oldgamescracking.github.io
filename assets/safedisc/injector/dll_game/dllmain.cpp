#include <Windows.h>
#include <shlwapi.h>
#include <iostream>
#include <fcntl.h>
#include "hooking.h"
#include "int3_locations.h"

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "User32.lib")


#define REPAIR_BYTES_RETRIES    100


typedef BOOL(__stdcall *Resume_CreateProcessA_t)(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
typedef HANDLE (__stdcall *Resume_CreateEventA_t)(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCSTR lpName);
typedef DWORD (__stdcall *Resume_WaitForSingleObject)(HANDLE hHandle, DWORD dwMilliseconds);


/*
    We need to find and replace the following opcodes:

    0F 0B:  UD2 (Undefined Instruction)
    0F AA:  RSM (Resume From System Management Mode)
    CD 03:  INT 0x03
    CC:     INT3
*/
WORD twoByteOpcodes[] = {
    0x0B0F,
    0xAA0F,
    0x03CD
};
const SIZE_T twoByteOpcodesCount = sizeof(twoByteOpcodes) / sizeof(twoByteOpcodes[0]);

LPCSTR dll_worker = "dll_worker.dll";
CHAR dll_src_path[MAX_PATH];
CHAR dll_dest_path[MAX_PATH];


HOOK_t hook_CreateProcessA = { 0 };
HOOK_t hook_CreateEventA = { 0 };
HOOK_t hook_WaitForSingleObject = { 0 };

HANDLE hEventStartGame = NULL;

FILE *fp_Pattern = NULL;
HANDLE hBlacklist = NULL;


void ScanMemory()
{
    /* Find out, where the code starts */
    HMODULE imageBase = GetModuleHandle(NULL);
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PBYTE)imageBase + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER textSection = (PIMAGE_SECTION_HEADER)((PBYTE)ntHeaders + sizeof(IMAGE_NT_HEADERS));

    printf("Scanning file\n");

    const DWORD textSectionSize = textSection->Misc.VirtualSize;
    const DWORD sectionBase = (DWORD)imageBase + textSection->VirtualAddress;

    SIZE_T int3Index = 0;
    WORD orgData;
    WORD dataMask;
    DWORD startOffset = 0;

    for (DWORD byte = startOffset; byte < textSectionSize - sizeof(WORD); byte++)
    {
        const PWORD opCodeAddress = (PWORD)((PBYTE)sectionBase + byte);

        BOOL createThread = FALSE;

        for (SIZE_T op = 0; op < twoByteOpcodesCount; op++)
        {
            if (*(WORD*)opCodeAddress == (WORD)twoByteOpcodes[op])
            {
                orgData = twoByteOpcodes[op];
                dataMask = 0xffff;

                createThread = TRUE;

                break;
            }
        }

        if (!createThread)
        {
            while ((int3Index < int3LocationsSize) && (int3Locations[int3Index] < (DWORD)opCodeAddress))
            {
                int3Index++;
            }

            if ((int3Index < int3LocationsSize) && (int3Locations[int3Index] == (DWORD)opCodeAddress))
            {
                if (*(BYTE*)opCodeAddress == (BYTE)0xCC)
                {
                    orgData = 0xCC;
                    dataMask = 0x00ff;

                    createThread = TRUE;
                }
            }
        }

        if (createThread)
        {
            for (int t = 0; t < REPAIR_BYTES_RETRIES; t++)
            {
                /* Create a thread here and let the bytes get repaired by the SafeDisc worker */
                DWORD threadId;

                HANDLE hThread = CreateThread(
                    NULL,
                    0x100,
                    (LPTHREAD_START_ROUTINE)opCodeAddress,
                    NULL,
                    STACK_SIZE_PARAM_IS_A_RESERVATION,
                    &threadId
                );

                if (hThread == NULL)
                {
                    printf("[WARNING] Could not create thread\n");

                    continue;
                }

                WaitForSingleObject(hThread, INFINITE);

                DWORD exitCode = 0xffffffff;

                if (!GetExitCodeThread(hThread, &exitCode))
                {
                    printf("[WARNING] Could not get exit code\n");
                }

                CloseHandle(hThread);

                if (exitCode == 2)
                {
                    /* Probably not a Nanomite, ignoring */
                    break;
                }

                FlushInstructionCache(GetCurrentProcess(), (LPCVOID)sectionBase, textSectionSize);

                /* Has data changed? */
                WORD newData = *(WORD*)opCodeAddress;
                
                if ((newData & dataMask) != orgData)
                {
                    break;
                }

                if ((t + 1) == REPAIR_BYTES_RETRIES)
                {
                    printf("[WARNING] Data did not change\n");
                }
            }
        }
    }

    printf("Scan done :)\n");
}


DWORD __stdcall Callback_WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds)
{
    // printf("\WaitForSingleObject called\n"); --> too much noise

    DWORD result = ((Resume_WaitForSingleObject)hook_WaitForSingleObject.resume)(
        hHandle,
        dwMilliseconds
    );

    if (hEventStartGame != NULL && hHandle == hEventStartGame)
    {
        hook_uninstall(&hook_WaitForSingleObject);

        printf("Game unpacked now\n");

        ScanMemory();

        MessageBoxA(NULL, "All done :)", "Done", MB_OK | MB_ICONEXCLAMATION);

        ExitProcess(0);
    }

    return result;
}


HANDLE __stdcall Callback_CreateEventA(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCSTR lpName)
{
    printf("Callback_CreateEventA:\n");
    printf("\tlpName: %s\n", (lpName!= NULL) ? lpName : "NULL");

    HANDLE event = ((Resume_CreateEventA_t)hook_CreateEventA.resume)(
        lpEventAttributes,
        bManualReset,
        bInitialState,
        lpName
    );

    if ((lpName != NULL) && strncmp(lpName, "BLT_", 4) == 0)
    {
        hook_uninstall(&hook_CreateEventA);

        /* This is the event we've been waiting for, remember the handle */
        hEventStartGame = event;

        printf("\tGot handle for BLT event: 0x%08X\n", (DWORD)event);
    }

    return event;
}


BOOL __stdcall Callback_CreateProcessA_t(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
{
    printf("Callback_CreateProcessA_t:\n");
    printf("\tlpApplicationName: %s\n", (lpApplicationName != NULL) ? lpApplicationName : "NULL");
    printf("\tlpCommandLine: %s\n", (lpCommandLine != NULL) ? lpCommandLine : "NULL");

    DWORD creationFlags = dwCreationFlags;
    BOOL injectDLL = FALSE;
    DWORD entryPoint = 0;

    if ((lpApplicationName != NULL) && (strstr(lpApplicationName, ".tmp") != 0))
    {
        /* DLL-inject the worker */
        creationFlags = CREATE_SUSPENDED | CREATE_NEW_CONSOLE;
        injectDLL = TRUE;

        /* Get the entry point */
        FILE *fp_debugger;
        fp_debugger = fopen(lpApplicationName, "rb");

        IMAGE_DOS_HEADER dosHeader;
        fread(&dosHeader, sizeof(IMAGE_DOS_HEADER), 1, fp_debugger);

        fseek(fp_debugger, dosHeader.e_lfanew, SEEK_SET);

        IMAGE_NT_HEADERS ntHeaders;
        fread(&ntHeaders, sizeof(IMAGE_NT_HEADERS), 1, fp_debugger);

        fclose(fp_debugger);

        entryPoint = ntHeaders.OptionalHeader.ImageBase + ntHeaders.OptionalHeader.AddressOfEntryPoint;

        printf("\tEntry point of debugger at 0x%08X\n", entryPoint);
    }
    
    BOOL result = ((Resume_CreateProcessA_t)hook_CreateProcessA.resume)(
        lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        creationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation
    );

    if (result && injectDLL)
    {
        hook_uninstall(&hook_CreateProcessA);

        printf("\tInjecting DLL into worker\n");

        HANDLE hProcess = lpProcessInformation->hProcess;
        HANDLE hThread = lpProcessInformation->hThread;

        LPCSTR nameBuffer = (LPCSTR)VirtualAllocEx(hProcess, NULL, 0x100, MEM_COMMIT, PAGE_READWRITE);
        printf("\tName buffer: 0x%08X\n", (DWORD)nameBuffer);

        /* Figure out where the DLL is and copy it to the worker folder */
        GetModuleFileNameA(NULL, &dll_src_path[0], MAX_PATH);
        PathRemoveFileSpecA(&dll_src_path[0]);
        PathAppendA(&dll_src_path[0], dll_worker);

        lstrcpyA(&dll_dest_path[0], lpApplicationName);
        PathRemoveFileSpecA(&dll_dest_path[0]);
        PathAppendA(&dll_dest_path[0], dll_worker);

        CopyFileA(&dll_src_path[0], &dll_dest_path[0], FALSE);

        WriteProcessMemory(hProcess, (LPVOID)nameBuffer, dll_worker, strlen(dll_worker) + 1, NULL);

        HMODULE hKernel = GetModuleHandleA("kernel32.dll");
        FARPROC hLoadLibrary = GetProcAddress(hKernel, "LoadLibraryA");

        byte jmp[2] = { 0xeb, 0xfe };
        byte orgBytes[sizeof(jmp)];

        DWORD oldProtect;
        VirtualProtectEx(hProcess, (LPVOID)entryPoint, sizeof(jmp), PAGE_EXECUTE_READWRITE, &oldProtect);
        ReadProcessMemory(hProcess, (LPVOID)entryPoint, &orgBytes[0], sizeof(jmp), NULL);
        WriteProcessMemory(hProcess, (LPVOID)entryPoint, &jmp[0], sizeof(jmp), NULL);

        ResumeThread(hThread);
        Sleep(1000);
        SuspendThread(hThread);

        WriteProcessMemory(hProcess, (LPVOID)entryPoint, &orgBytes[0], sizeof(jmp), NULL);
        VirtualProtectEx(hProcess, (LPVOID)entryPoint, sizeof(jmp), oldProtect, &oldProtect);

        HANDLE hThreadInjector = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)hLoadLibrary, (LPVOID)nameBuffer, 0, NULL);
        WaitForSingleObject(hThreadInjector, INFINITE);

        ResumeThread(hThread);

        printf("\tInjection done\n");
    }

    return result;
}


/* Taken from https://stackoverflow.com/a/57210516 */
void CreateConsole()
{
    if (!AllocConsole())
    {
        return;
    }

    FILE* fDummy;
    freopen_s(&fDummy, "CONOUT$", "w", stdout);
    freopen_s(&fDummy, "CONOUT$", "w", stderr);
    freopen_s(&fDummy, "CONIN$", "r", stdin);
    std::cout.clear();
    std::clog.clear();
    std::cerr.clear();
    std::cin.clear();
}


DWORD WINAPI WorkerThread(LPVOID data)
{
    CreateConsole();

    printf("DLL injected successfully ;)\n");

    hook_install("Kernel32.dll", "CreateProcessA", &Callback_CreateProcessA_t, &hook_CreateProcessA);
    hook_install("Kernel32.dll", "CreateEventA", &Callback_CreateEventA, &hook_CreateEventA);
    hook_install("Kernel32.dll", "WaitForSingleObject", &Callback_WaitForSingleObject, &hook_WaitForSingleObject);

    printf("All hooks installed\n");

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
            hook_uninstall(&hook_CreateProcessA);
            hook_uninstall(&hook_CreateEventA);
            hook_uninstall(&hook_WaitForSingleObject);

            if (fp_Pattern != NULL)
            {
                fclose(fp_Pattern);
                fp_Pattern = NULL;
            }

            if (hBlacklist != NULL)
            {
                CloseHandle(hBlacklist);
                hBlacklist = NULL;
            }

            break;
        }

        default:
        {
            break;
        }
    }

    return TRUE;
}
