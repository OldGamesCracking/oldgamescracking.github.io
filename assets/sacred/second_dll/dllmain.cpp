#include <Windows.h>
#include <cinttypes>
#include <cstring>
#include <unordered_map>
#include <codecvt>
#include "Logging.h"
#include "Hooking.h"


#pragma comment(lib, "Kernel32.lib")
#pragma comment(lib, "User32.lib")


/** Defines */
constexpr DWORD OEP_ADDRESS = 0x0073E32B;
constexpr DWORD IAT_START = 0x00762000;
constexpr DWORD IAT_END = 0x007628FF;

struct hardcoded_imports
{
    DWORD Address;
    const char *Module;
    const char *Proc;
} manal_imports[] =
{
    {0x007620B8, "Kernel32.dll", "GetVersion"},             // Recreated
    {0x007620C4, "ntdll.dll", "RtlSetLastWin32Error"},      // Proxied
    {0x00762120, "Kernel32.dll", "GetCommandLineA"},        // Recreated
    {0x0076214C, "Kernel32.dll", "ReadFile"},               // Proxied
    {0x0076216C, "Kernel32.dll", "WaitForSingleObject"},    // Proxied
    {0x00762198, "Kernel32.dll", "GetCurrentThreadId"},     // Proxied
    {0x007621A8, "Kernel32.dll", "CloseHandle"},            // Proxied
    {0x007621B4, "Kernel32.dll", "GetModuleHandleA"},       // Proxied
};


typedef FARPROC (NTAPI *Resume_GetProcAddress_t)(HMODULE hModule, LPCSTR lpProcName);
typedef BOOL (NTAPI *Resume_DeleteFileA_t)(LPCTSTR lpFileName);


/** Prototypes */
FARPROC NTAPI Callback_GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
BOOL NTAPI Callback_DeleteFileA(LPCTSTR lpFileName);
void FixIAT();
long NTAPI UnhandledExceptionHandler(EXCEPTION_POINTERS *ep);


/** Globals */
CRITICAL_SECTION lock = { 0 };

Hook hook_GetProcAddress;
Hook hook_DeleteFileA;

std::list<Hook*> procs;
std::unordered_map<FARPROC, Hook*> procs_lookup;
std::unordered_map<LPVOID, Hook*> trampoline_lookup;


/**
*   Step 1: Intercept all imported procs and place a hook at the start of the proc
*/
FARPROC NTAPI Callback_GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
    EnterCriticalSection(&lock);
    
    Log.Line("[Callback_GetProcAddress]");

    Log.Line("\t-> hModule: 0x%08X", hModule);

    if (lpProcName != NULL)
    {
        if (!IS_INTRESOURCE(lpProcName))
        {
           Log.Line("\t-> lpProcName: %s", lpProcName);
        }
        else
        {
           Log.Line("\t-> Ordinal #%d", MAKEINTRESOURCE(lpProcName));
        }
    }
    else
    {
       Log.Line("\t-> NULL");
    }

    FARPROC proc = ((Resume_GetProcAddress_t)hook_GetProcAddress.Resume)(hModule, lpProcName);

    Log.Line("\t-> proc: 0x%08X", proc);

    if (proc != NULL)
    {
        if (procs_lookup.find(proc) == procs_lookup.end())
        {
            Log.Line("\t-> New proc #%d", (procs_lookup.size() + 1));

            Hook *hook = new Hook(proc);

            Log.Line("\t-> Hook: 0x%08X", hook->OpcodesBuffer);

            procs.push_back(hook);
            procs_lookup.insert(std::pair<FARPROC, Hook*>(proc, hook));
            trampoline_lookup.insert(std::pair<LPVOID, Hook*>(hook->Resume, hook));
        }
        else
        {
            Log.Line("\t-> Known proc");
        }
    }

    Log.Line("");

    LeaveCriticalSection(&lock);

    return proc;
}

/**
*   Step 2: Wait for the temp file to be deleted, this means the loader is done checking the CD
*/
BOOL NTAPI Callback_DeleteFileA(LPCTSTR lpFileName)
{
    Log.Line("[Callback_DeleteFileA]");

    if (lpFileName != NULL)
    {
        Log.Line("\t-> %s", lpFileName);
        
        if (strstr((char*)lpFileName, "Temp\\a0") != nullptr && strstr((char *)lpFileName, ".tmp") != nullptr)
        {
            Log.Line("\t-> Is temp file");

            /** Place memory breakpoint and catch it */
            AddVectoredExceptionHandler(1, &UnhandledExceptionHandler);

            DWORD oldProtect;
            VirtualProtect((LPVOID)OEP_ADDRESS, 4, PAGE_GUARD | PAGE_READWRITE, &oldProtect);
        }
    }
    else
    {
        Log.Line("\t-> NULL");
    }

    return ((Resume_DeleteFileA_t)hook_DeleteFileA.Resume)(lpFileName);
}

/**
*   Step 3: Wait until we get a page violation, we should be at the OEP now
*/
long NTAPI UnhandledExceptionHandler(EXCEPTION_POINTERS *ep)
{
    if (ep->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
    {
        Log.Line("We are at the OEP");

        DWORD oldProtect;
        VirtualProtect((LPVOID)OEP_ADDRESS, 4, PAGE_EXECUTE_READ, &oldProtect);

        FixIAT();

        /**
        * Install a jump to the OEP so we have time to open the debugger
        */
        LPVOID trampoline = VirtualAlloc(NULL, 100, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

        /**
        * JMP -2
        * JMP OEP
        */
        *(WORD*)trampoline = 0xfeeb;
        *(BYTE*)((DWORD)trampoline + 2) = 0xe9;
        *(DWORD*)((DWORD)trampoline + 3) = OEP_ADDRESS - (DWORD)trampoline - 7;

        ep->ContextRecord->Eip = (DWORD)trampoline;

        MessageBoxA(NULL, "We should be at the OEP now, imports should be fixed.\nAfter this MessageBox, the process will go into an infinite loop.\nAttach with a debugger and exit the loop.", "Fixing done", MB_OK);

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

void FixIAT()
{
    Log.Line("Fixing IAT");

    /** Step 1: Shut down hooks */
    hook_GetProcAddress.Pause();
    hook_DeleteFileA.Pause();

    /** Step 2: Restore all proxied procs in reverse order */
    std::list<Hook *>::reverse_iterator it;
    for (it = procs.rbegin(); it != procs.rend(); it++)
    {
        Hook *h = *it;

        h->Pause();
    }

    DWORD oldProtect;
    VirtualProtect((LPVOID)IAT_START, (IAT_END - IAT_START + 4), PAGE_READWRITE, &oldProtect);

    /** Step 3: Recover hardcoded imports */
    for (hardcoded_imports i : manal_imports)
    {
        Log.Line("Manually fixed import at %08X", i.Address);
        Log.Line("\t->%s::%s", i.Module, i.Proc);

        HMODULE hModule = GetModuleHandleA(i.Module);

        Log.Line("\t->%08X", hModule);

        if (hModule == NULL)
        {
            continue;
        }

        FARPROC proc = GetProcAddress(hModule, i.Proc);

        Log.Line("\t->%08X", proc);

        *(FARPROC*)i.Address = proc;
    }

    /** Step 4: Recover the imports that were proxied before */
    DWORD *iat = (DWORD*)IAT_START;

    while (iat <= (DWORD*)IAT_END)
    {
        DWORD address = *iat;

        Log.Log("%08X: %08X -> ", iat, address);
        
        if (address != NULL)
        {
            if (procs_lookup.find((FARPROC)address) != procs_lookup.end())
            {
                /** Good entry, nothing to do */
                Log.Line("Good");
            }
            else
            {
                if (!IsBadReadPtr((VOID*)address, 5))
                {
                    /** Check if there is a hook */
                    BYTE jmp = *(BYTE*)address;

                    if (jmp == 0xE9)
                    {
                        DWORD offset = *(DWORD*)((BYTE*)address + 1);
                        DWORD target = address + offset + 5;

                        std::unordered_map<LPVOID, Hook*>::const_iterator result = trampoline_lookup.find((LPVOID)target);

                        if (result != trampoline_lookup.end())
                        {
                            Hook *hook = result->second;
                            
                            Log.Line("%08X", hook->Proc);

                            /** Fix entry */
                            *iat = (DWORD)hook->Proc;
                        }
                        else
                        {
                            Log.Line("ERROR: UNKNOWN_JUMP");
                        }
                    }
                    else
                    {
                        Log.Line("ERROR: SOMETHING_ELSE");
                    }
                }
                else
                {
                    Log.Line("ERROR: INVALID");
                }
            }
        }
        else
        {
            Log.Line("-");
        }

        iat++;
    }

    VirtualProtect((LPVOID)IAT_START, (IAT_END - IAT_START + 4), oldProtect, &oldProtect);

    Log.Line("Done");
}

DWORD WINAPI WorkerThread(LPVOID data)
{
    Log.Line("Starting Worker");

    InitializeCriticalSection(&lock);

    hook_DeleteFileA.Install("Kernel32.dll", "DeleteFileA", &Callback_DeleteFileA);
    /** Must be the last one */
    hook_GetProcAddress.Install("Kernel32.dll", "GetProcAddress", &Callback_GetProcAddress);

    /** Prevent Multi-Hooking */
    procs_lookup.insert(std::pair<FARPROC, Hook*>(hook_DeleteFileA.Proc, &hook_DeleteFileA));
    procs_lookup.insert(std::pair<FARPROC, Hook *>(hook_GetProcAddress.Proc, &hook_GetProcAddress));

    trampoline_lookup.insert(std::pair<LPVOID, Hook*>(hook_DeleteFileA.Callback, &hook_DeleteFileA));
    trampoline_lookup.insert(std::pair<LPVOID, Hook *>(hook_GetProcAddress.Callback, &hook_GetProcAddress));

    Log.Line("Hooks installed");

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
            Log.Line("Shutting down");

            DeleteCriticalSection(&lock);

            break;
        }

        default:
        {
            break;
        }
    }

    return TRUE;
}