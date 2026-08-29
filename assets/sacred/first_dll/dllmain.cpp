#include <Windows.h>
#include <shlwapi.h>
#include <iostream>
#include <fcntl.h>
#include "hooking.h"

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "User32.lib")


typedef BOOL (__stdcall *Resume_CreateProcessA_t)(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);


LPCSTR game_exe = "sacred.exe";
LPCSTR second_dll = "second.dll";
CHAR dll_src_path[MAX_PATH];
CHAR dll_dest_path[MAX_PATH];

Hook hook_CreateProcessA;

BOOL __stdcall Callback_CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
{
    printf("Callback_CreateProcessA:\n");
    printf("\tlpApplicationName: %s\n", (lpApplicationName != NULL) ? lpApplicationName : "NULL");
    printf("\tlpCommandLine: %s\n", (lpCommandLine != NULL) ? lpCommandLine : "NULL");

    DWORD creationFlags = dwCreationFlags;
    BOOL injectDLL = FALSE;
    DWORD entryPoint = 0;

    // Note: sacred uses lpCommandLine instead of lpApplicationName
    if ((lpCommandLine != NULL) && (strstr(lpCommandLine, game_exe) != 0))
    {
        /* DLL-inject the worker */
        creationFlags = DETACHED_PROCESS | CREATE_SUSPENDED;

        /* Get the entry point */
        FILE *fp_game;
        fp_game = fopen(game_exe, "rb");

        if (fp_game != NULL)
        {
            printf("Opened %s\n", game_exe);

            IMAGE_DOS_HEADER dosHeader;
            fread(&dosHeader, sizeof(IMAGE_DOS_HEADER), 1, fp_game);

            fseek(fp_game, dosHeader.e_lfanew, SEEK_SET);

            IMAGE_NT_HEADERS ntHeaders;
            fread(&ntHeaders, sizeof(IMAGE_NT_HEADERS), 1, fp_game);

            fclose(fp_game);

            entryPoint = ntHeaders.OptionalHeader.ImageBase + ntHeaders.OptionalHeader.AddressOfEntryPoint;

            printf("\tEntry point of game at 0x%08X\n", entryPoint);

            injectDLL = TRUE;
        }
        else
        {
            printf("Could NOT open file\n");
        }
    }
    
    BOOL result = ((Resume_CreateProcessA_t)hook_CreateProcessA.Resume)(
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
        hook_CreateProcessA.Uninstall();

        Sleep(1000);

        printf("\tInjecting DLL into new process\n");

        HANDLE hProcess = lpProcessInformation->hProcess;
        HANDLE hThread = lpProcessInformation->hThread;

        LPCSTR nameBuffer = (LPCSTR)VirtualAllocEx(hProcess, NULL, 0x100, MEM_COMMIT, PAGE_READWRITE);

        Sleep(1000);

        /* Figure out where the DLL is and copy it to the worker folder */
        GetModuleFileNameA(NULL, &dll_src_path[0], MAX_PATH);
        PathRemoveFileSpecA(&dll_src_path[0]);
        PathAppendA(&dll_src_path[0], second_dll);

        printf("\tDLL path: %s\n", &dll_src_path[0]);

        Sleep(1000);

        WriteProcessMemory(hProcess, (LPVOID)nameBuffer, &dll_src_path[0], strlen(&dll_src_path[0]) + 1, NULL);

        HMODULE hKernel = GetModuleHandleA("kernel32.dll");
        FARPROC hLoadLibrary = GetProcAddress(hKernel, "LoadLibraryA");

        Sleep(1000);

        byte jmp[2] = { 0xeb, 0xfe };
        byte orgBytes[sizeof(jmp)];

        printf("Installing JMP\n");

        DWORD oldProtect;
        if (!VirtualProtectEx(lpProcessInformation->hProcess, (LPVOID)entryPoint, sizeof(jmp), PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            VirtualFreeEx(lpProcessInformation->hProcess, (LPVOID)nameBuffer, 0, MEM_RELEASE);
            CloseHandle(lpProcessInformation->hThread);
            CloseHandle(lpProcessInformation->hProcess);

            printf("Could not set protection\n");
            ExitProcess(-1);
        }

        if (!ReadProcessMemory(lpProcessInformation->hProcess, (LPVOID)entryPoint, &orgBytes[0], sizeof(jmp), NULL))
        {
            VirtualFreeEx(lpProcessInformation->hProcess, (LPVOID)nameBuffer, 0, MEM_RELEASE);
            CloseHandle(lpProcessInformation->hThread);
            CloseHandle(lpProcessInformation->hProcess);

            printf("Could not read from memory\n");
            ExitProcess(-1);
        }

        if (!WriteProcessMemory(lpProcessInformation->hProcess, (LPVOID)entryPoint, &jmp[0], sizeof(jmp), NULL))
        {
            VirtualFreeEx(lpProcessInformation->hProcess, (LPVOID)nameBuffer, 0, MEM_RELEASE);
            CloseHandle(lpProcessInformation->hThread);
            CloseHandle(lpProcessInformation->hProcess);

            printf("Could not write to memory\n");
            ExitProcess(-1);
        }

        printf("JMP installed\n");

        /** Let it run a bit */
        ResumeThread(hThread);
        Sleep(1000);
        SuspendThread(hThread);

        printf("Restoring OEP\n");

        if (!WriteProcessMemory(lpProcessInformation->hProcess, (LPVOID)entryPoint, &orgBytes[0], sizeof(jmp), NULL))
        {
            VirtualFreeEx(lpProcessInformation->hProcess, (LPVOID)nameBuffer, 0, MEM_RELEASE);
            CloseHandle(lpProcessInformation->hThread);
            CloseHandle(lpProcessInformation->hProcess);

            printf("Could not write to memory\n");
            ExitProcess(-1);
        }

        if (!VirtualProtectEx(lpProcessInformation->hProcess, (LPVOID)entryPoint, sizeof(jmp), oldProtect, &oldProtect))
        {
            VirtualFreeEx(lpProcessInformation->hProcess, (LPVOID)nameBuffer, 0, MEM_RELEASE);
            CloseHandle(lpProcessInformation->hThread);
            CloseHandle(lpProcessInformation->hProcess);

            printf("Could not set protection\n");
            ExitProcess(-1);
        }

        printf("OEP restored\n");

        printf("Injecting DLL\n");

        HANDLE hThreadInjector = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)hLoadLibrary, (LPVOID)nameBuffer, 0, NULL);
        
        if (hThreadInjector == NULL)
        {
            VirtualFreeEx(lpProcessInformation->hProcess, (LPVOID)nameBuffer, 0, MEM_RELEASE);
            CloseHandle(lpProcessInformation->hThread);
            CloseHandle(lpProcessInformation->hProcess);

            printf("Could not create remote thread\n");
            ExitProcess(-1);
        }

        printf("Remote thread created\n");
        
        WaitForSingleObject(hThreadInjector, INFINITE);

        Sleep(1000);

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

    hook_CreateProcessA.Install("Kernel32.dll", "CreateProcessA", &Callback_CreateProcessA);

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
            break;
        }

        default:
        {
            break;
        }
    }

    return TRUE;
}
