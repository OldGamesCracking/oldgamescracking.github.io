#include <Windows.h>
#include <shlwapi.h>
#include <iostream>
#include <fcntl.h>
#include "hooking.h"

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "User32.lib")


typedef BOOL (__stdcall *Resume_CreateProcessA_t)(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
typedef BOOL (__stdcall *Resume_VirtualProtect_t)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);


LPCSTR dll_worker = "dll_worker.dll";
CHAR dll_src_path[MAX_PATH];
CHAR dll_dest_path[MAX_PATH];

HOOK_t hook_CreateProcessA = { 0 };
HOOK_t hook_VirtualProtect = { 0 };

DWORD OEP = 0;


DWORD GetSectionMetrics(DWORD address, DWORD *const out_size)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)GetModuleHandle(NULL);
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)dosHeader + dosHeader->e_lfanew);

    PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)((BYTE*)ntHeaders + sizeof(IMAGE_NT_HEADERS));

    if (out_size != NULL)
    {
        *out_size = 0;
    }

    for (DWORD section = 0; section < ntHeaders->FileHeader.NumberOfSections; section++)
    {
        DWORD sectionStart = (DWORD)dosHeader + pSection->VirtualAddress;
        DWORD sectionEnd = sectionStart + pSection->Misc.VirtualSize;

        if ((sectionStart <= address) && (address < sectionEnd))
        {
            if (out_size != NULL)
            {
                *out_size = pSection->Misc.VirtualSize;
            }

            return sectionStart;
        }

        pSection++;
    }

    return 0;
}

DWORD GetEntryPoint()
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)GetModuleHandle(NULL);
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)dosHeader + dosHeader->e_lfanew);

    return (DWORD)dosHeader + ntHeaders->OptionalHeader.AddressOfEntryPoint;
}

DWORD GetOEP()
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)GetModuleHandle(NULL);
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)dosHeader + dosHeader->e_lfanew);

    DWORD entryPoint = (DWORD)dosHeader + ntHeaders->OptionalHeader.AddressOfEntryPoint;

    DWORD sectionSize = 0;
    DWORD sectionStart = GetSectionMetrics(entryPoint , &sectionSize);
    DWORD sectionEnd = sectionStart + sectionSize;

    DWORD oep = 0;

    /** Search for "CALL EAX; POPAD; POP EBP; JMP XXX" (FFD0 61 5D EB) */
    const BYTE pattern[] = {0xFF, 0xD0, 0x61, 0x5D, 0xEB};

    for (DWORD address = entryPoint; address < sectionEnd; address++)
    {
        if (memcmp((BYTE*)address, &pattern[0], sizeof(pattern)) == 0)
        {
            BYTE jmpOffset = *((BYTE*)address + 5);
            DWORD oepJmpAt = address + 4 + 2 + jmpOffset;
            DWORD oepJmpOffset = *(DWORD*)(oepJmpAt + 1);
            oep = oepJmpAt + 5 + oepJmpOffset;

            break;
        }
    }

    return oep;
}

BOOL __stdcall Callback_VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
    DWORD start = (DWORD)lpAddress;
    DWORD end = start + dwSize;

    if ((start <= OEP) && (OEP < end) && (flNewProtect == PAGE_EXECUTE_READ))
    {
        printf("Installing INT3\n");

        /** Place the original byte at the entry point */
        DWORD entryPoint = GetEntryPoint();
        DWORD oldProtect;
        ((Resume_VirtualProtect_t)hook_VirtualProtect.resume)((LPVOID)entryPoint, 1, PAGE_READWRITE, &oldProtect);

        *(BYTE*)entryPoint = *(BYTE*)OEP;

        ((Resume_VirtualProtect_t)hook_VirtualProtect.resume)((LPVOID)entryPoint, 1, oldProtect, &oldProtect);

        /** Install INT3 */
        *(BYTE*)OEP = 0xCC;

        printf("INT3 installed, control should be handed over to the worker now\n");
    }

    return ((Resume_VirtualProtect_t)hook_VirtualProtect.resume)(lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

BOOL __stdcall Callback_CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
{
    printf("Callback_CreateProcessA:\n");
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

    OEP = GetOEP();

    printf("OEP at: 0x%08X\n", OEP);

    hook_install("Kernel32.dll", "CreateProcessA", &Callback_CreateProcessA, &hook_CreateProcessA);
    hook_install("Kernel32.dll", "VirtualProtect", &Callback_VirtualProtect, &hook_VirtualProtect);

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
            hook_uninstall(&hook_VirtualProtect);

            break;
        }

        default:
        {
            break;
        }
    }

    return TRUE;
}
