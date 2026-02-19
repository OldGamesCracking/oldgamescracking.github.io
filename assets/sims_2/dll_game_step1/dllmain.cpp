#include <Windows.h>
#include <shlwapi.h>
#include <iostream>
#include <fcntl.h>
#include "hooking.h"

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "User32.lib")


typedef BOOL (__stdcall *Resume_CreateProcessA_t)(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);


LPCSTR dll_worker = "dll_worker.dll";
CHAR dll_src_path[MAX_PATH];
CHAR dll_dest_path[MAX_PATH];

HOOK_t hook_CreateProcessA = { 0 };

BOOL __stdcall Callback_CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
{
    printf("Callback_CreateProcessA:\n");
    printf("\tlpApplicationName: %s\n", (lpApplicationName != NULL) ? lpApplicationName : "NULL");
    printf("\tlpCommandLine: %s\n", (lpCommandLine != NULL) ? lpCommandLine : "NULL");

    DWORD creationFlags = dwCreationFlags;
    BOOL injectDLL = FALSE;
    DWORD entryPoint = 0;

    if ((lpApplicationName != NULL) && (strstr(lpApplicationName, ".0001") != 0))
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

        Sleep(3000);
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

        Sleep(3000);

        printf("\tInjecting DLL into worker\n");

        HANDLE hProcess = lpProcessInformation->hProcess;
        HANDLE hThread = lpProcessInformation->hThread;

        LPCSTR nameBuffer = (LPCSTR)VirtualAllocEx(hProcess, NULL, 0x100, MEM_COMMIT, PAGE_READWRITE);

        Sleep(3000);

        /* Figure out where the DLL is and copy it to the worker folder */
        GetModuleFileNameA(NULL, &dll_src_path[0], MAX_PATH);
        PathRemoveFileSpecA(&dll_src_path[0]);
        PathAppendA(&dll_src_path[0], dll_worker);

        Sleep(3000);

        lstrcpyA(&dll_dest_path[0], lpApplicationName);
        PathRemoveFileSpecA(&dll_dest_path[0]);
        PathAppendA(&dll_dest_path[0], dll_worker);

        Sleep(3000);

        CopyFileA(&dll_src_path[0], &dll_dest_path[0], FALSE);

        Sleep(3000);

        WriteProcessMemory(hProcess, (LPVOID)nameBuffer, dll_worker, strlen(dll_worker) + 1, NULL);

        HMODULE hKernel = GetModuleHandleA("kernel32.dll");
        FARPROC hLoadLibrary = GetProcAddress(hKernel, "LoadLibraryA");

        Sleep(3000);

        ResumeThread(hThread);
        Sleep(3000);
        SuspendThread(hThread);

        HANDLE hThreadInjector = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)hLoadLibrary, (LPVOID)nameBuffer, 0, NULL);
        WaitForSingleObject(hThreadInjector, INFINITE);

        Sleep(3000);

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

    hook_install("Kernel32.dll", "CreateProcessA", &Callback_CreateProcessA, &hook_CreateProcessA);

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

            break;
        }

        default:
        {
            break;
        }
    }

    return TRUE;
}
