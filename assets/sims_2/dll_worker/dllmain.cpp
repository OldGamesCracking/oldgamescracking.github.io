#include <Windows.h>
#include <stdio.h>
#include "logging.h"
#include "Hooking.h"
#include "Worker.h"


#pragma comment(lib, "User32.lib")


/* Prototypes */
BOOL __stdcall Callback_WaitForDebugEvent(LPDEBUG_EVENT lpDebugEvent, DWORD dwMilliseconds);

/* Globals */
Worker worker;

typedef BOOL(__stdcall *Resume_GetThreadContext_t)(HANDLE hThread, LPCONTEXT lpContext);
typedef BOOL(__stdcall *Resume_SetThreadContext_t)(HANDLE hThread, LPCONTEXT lpContext);

Hook hook_GetThreadContext;
Hook hook_SetThreadContext;
DWORD lastReadAddress = 0;

__declspec(naked) void Callback_Nanomites()
{
    _asm
    {
        /* Used as return address to the jumppad that will then jump back to original program code */
        push 0;
        pushfd;     // +4
        pushad;     // +4 * 8

        /* Install return to jump pad */
        mov eax, worker.hook_Nanomites.Resume;
        mov [esp + (4 + 4*8)], eax;

        /* Copy Nanomite data */
        lea esi, [ebp - 0xE4];
        lea edi, worker.NanomiteData;
        mov ecx, 16;
        repne movsb;

        /* Mark as valid */
        mov worker.NanomiteValid, 1;

        popad;
        popfd;
        ret;
    }
}

BOOL __stdcall Callback_GetThreadContext(HANDLE hThread, LPCONTEXT lpContext)
{
    Log.Debug("[GetThreadContext]");

    BOOL result = ((Resume_GetThreadContext_t)hook_GetThreadContext.Resume)(hThread, lpContext);

    memcpy(&worker.ctx, lpContext, sizeof(CONTEXT));

    return result;
}

BOOL __stdcall Callback_SetThreadContext(HANDLE hThread, LPCONTEXT lpContext)
{
    Log.Debug("[SetThreadContext]");

    BOOL result = ((Resume_SetThreadContext_t)hook_SetThreadContext.Resume)(hThread, lpContext);

    if (worker.ctx.ContextFlags != lpContext->ContextFlags)
    {
        Log.Debug("ContextFlags : %08X -> %08X", worker.ctx.ContextFlags, lpContext->ContextFlags);
    }

    if (worker.ctx.Dr0 != lpContext->Dr0)
    {
        Log.Debug("Dr0 : %08X -> %08X", worker.ctx.Dr0, lpContext->Dr0);
    }

    if (worker.ctx.Dr1 != lpContext->Dr1)
    {
        Log.Debug("Dr1 : %08X -> %08X", worker.ctx.Dr1, lpContext->Dr1);
    }

    if (worker.ctx.Dr2 != lpContext->Dr2)
    {
        Log.Debug("Dr2 : %08X -> %08X", worker.ctx.Dr2, lpContext->Dr2);
    }

    if (worker.ctx.Dr3 != lpContext->Dr3)
    {
        Log.Debug("Dr3 : %08X -> %08X", worker.ctx.Dr3, lpContext->Dr3);
    }

    if (worker.ctx.Dr6 != lpContext->Dr6)
    {
        Log.Debug("Dr6 : %08X -> %08X", worker.ctx.Dr6, lpContext->Dr6);
    }

    if (worker.ctx.Dr7 != lpContext->Dr7)
    {
        Log.Debug("Dr7 : %08X -> %08X", worker.ctx.Dr7, lpContext->Dr7);
    }

    if (worker.ctx.SegGs != lpContext->SegGs)
    {
        Log.Debug("SegGs : %08X -> %08X", worker.ctx.SegGs, lpContext->SegGs);
    }

    if (worker.ctx.SegFs != lpContext->SegFs)
    {
        Log.Debug("SegFs : %08X -> %08X", worker.ctx.SegFs, lpContext->SegFs);
    }

    if (worker.ctx.SegEs != lpContext->SegEs)
    {
        Log.Debug("SegEs : %08X -> %08X", worker.ctx.SegEs, lpContext->SegEs);
    }

    if (worker.ctx.SegDs != lpContext->SegDs)
    {
        Log.Debug("SegDs : %08X -> %08X", worker.ctx.SegDs, lpContext->SegDs);
    }

    if (worker.ctx.Edi != lpContext->Edi)
    {
        Log.Debug("Edi : %08X -> %08X", worker.ctx.Edi, lpContext->Edi);
    }

    if (worker.ctx.Esi != lpContext->Esi)
    {
        Log.Debug("Esi : %08X -> %08X", worker.ctx.Esi, lpContext->Esi);
    }

    if (worker.ctx.Ebx != lpContext->Ebx)
    {
        Log.Debug("Ebx : %08X -> %08X", worker.ctx.Ebx, lpContext->Ebx);
    }

    if (worker.ctx.Edx != lpContext->Edx)
    {
        Log.Debug("Edx : %08X -> %08X", worker.ctx.Edx, lpContext->Edx);
    }

    if (worker.ctx.Ecx != lpContext->Ecx)
    {
        Log.Debug("Ecx : %08X -> %08X", worker.ctx.Ecx, lpContext->Ecx);
    }

    if (worker.ctx.Eax != lpContext->Eax)
    {
        Log.Debug("Eax : %08X -> %08X", worker.ctx.Eax, lpContext->Eax);
    }

    if (worker.ctx.Ebp != lpContext->Ebp)
    {
        Log.Debug("Ebp : %08X -> %08X", worker.ctx.Ebp, lpContext->Ebp);
    }

    if (worker.ctx.Eip != lpContext->Eip)
    {
        Log.Debug("Eip : %08X -> %08X", worker.ctx.Eip, lpContext->Eip);
    }

    if (worker.ctx.SegCs != lpContext->SegCs)
    {
        Log.Debug("SegCs : %08X -> %08X", worker.ctx.SegCs, lpContext->SegCs);
    }

    if (worker.ctx.EFlags != lpContext->EFlags)
    {
        Log.Debug("EFlags : %08X -> %08X", worker.ctx.EFlags, lpContext->EFlags);
    }

    if (worker.ctx.Esp != lpContext->Esp)
    {
        Log.Debug("Esp : %08X -> %08X", worker.ctx.Esp, lpContext->Esp);
    }

    if (worker.ctx.SegSs != lpContext->SegSs)
    {
        Log.Debug("SegSs : %08X -> %08X", worker.ctx.SegSs, lpContext->SegSs);
    }

    return result;
}

BOOL __stdcall Callback_ContinueDebugEvent(DWORD dwProcessId, DWORD dwThreadId, DWORD dwContinueStatus)
{
    /* Prevent the process from really continuing */
    return TRUE;
}

BOOL __stdcall Callback_DebugActiveProcess(DWORD dwProcessId)
{
    Log.Line("[Callback_DebugActiveProcess]");
    Log.Line("\tdwProcessId: %08X", dwProcessId);

    worker.InitProcessData(dwProcessId);
    
    Log.Line("\tentryPoint: %08X", worker.EntryPoint);
    Log.Line("\tOEP: %08X", worker.OEP);

    worker.hook_WaitForDebugEvent.Install("Kernel32.dll", "WaitForDebugEvent", &Callback_WaitForDebugEvent);

    BOOL result = ((Resume_DebugActiveProcess_t)worker.hook_DebugActiveProcess.Resume)(dwProcessId);

    worker.hook_DebugActiveProcess.Uninstall();

    return result;
}

BOOL __stdcall Callback_ReadProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead)
{
    Log.Line("[Callback_ReadProcessMemory]");
    Log.Line("\t%d bytes @ %08X", nSize, lpBaseAddress);

    if (lastReadAddress == (DWORD)lpBaseAddress)
    {
        Log.Warning("Multiple consecutive reads");

        worker.ProbeVMInstructions();
    }

    lastReadAddress = (DWORD)lpBaseAddress;

    return worker.HandleReadProcessMemory(lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
}

BOOL __stdcall Callback_WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten)
{
    Log.Line("[Callback_WriteProcessMemory]");
    Log.Line("\t%d bytes @ %08X", nSize, lpBaseAddress);
    
    for (size_t b = 0; b < nSize; b++)
    {
        Log.Log("%02X%s", ((PBYTE)lpBuffer)[b], ((b + 1) == nSize) ? "\n" : " ");
    }

    lastReadAddress = 0;

    return worker.HandleWriteProcessMemory(lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
}

BOOL __stdcall Callback_WaitForDebugEvent(LPDEBUG_EVENT lpDebugEvent, DWORD dwMilliseconds)
{
    BOOL result;

perform_step:

    if (worker.Fixing)
    {
        /* From here on, we will fake the result */

        worker.hook_ReadProcessMemory.Pause();
        hook_GetThreadContext.Pause();
        hook_SetThreadContext.Pause();

        if (worker.LastAction != ExplorationStepAction::None)
        {
            Log.Debug("Unhandled previous event");

            if (worker.LastAction == ExplorationStepAction::Nanomite)
            {
                Log.Debug("Probably not a Nanomite");

                worker.MarkAsNonNanomite(worker.EventAddress);             
            }
        }

        worker.PerformExplorationStep();

        switch (worker.LastAction)
        {
            case (ExplorationStepAction::Done):
            {
                Log.Line("No more actions");

                worker.FinalizeFix();

                Log.Line("Code Coverage: %0.2f%%", worker.CodeCoverage());

                Log.Line("Nanomites recovered: %u", worker.NanomitesRecovered);
                Log.Line("Virtual Instructions recovered: %u", worker.VirtualInstructionsRecovered);
                Log.Line("Encrypted Functions recovered: %u", worker.EncryptedFunctionsRecovered);
                Log.Line("Imports recovered: %u", worker.ImportsRecovered);
                Log.Line("Calls By Register recovered: %u", worker.CallsByRegisterRecovered);

                worker.DumpCoverageMap();

                MessageBox(NULL, L"Done. You can attach to the game now to dump it.", L"Done", MB_OK);

                worker.SetEip(worker.OEP);
                worker.DetachAndExit();

                break;
            }

            case (ExplorationStepAction::Nanomite):
            {
                Log.Debug("Handling Nanomite @ %08X", (uint32_t)worker.EventAddress);

                worker.SetEip((DWORD)worker.EventAddress + 1);

                lpDebugEvent->dwDebugEventCode = EXCEPTION_DEBUG_EVENT;
                lpDebugEvent->u.Exception.dwFirstChance = 1;
                lpDebugEvent->u.Exception.ExceptionRecord.ExceptionAddress = (PVOID)worker.EventAddress;
                lpDebugEvent->u.Exception.ExceptionRecord.ExceptionCode = EXCEPTION_BREAKPOINT;
                lpDebugEvent->u.Exception.ExceptionRecord.ExceptionFlags = 0;
                lpDebugEvent->u.Exception.ExceptionRecord.NumberParameters = 0;

                worker.hook_ReadProcessMemory.Enable();
                hook_GetThreadContext.Enable();
                hook_SetThreadContext.Enable();

                worker.NanomiteValid = 0;
                worker.IgnoreNextWrite = false;

                /* Pass control back to SafeDisc */
                return TRUE;
            }

            default:
            {
                Log.Error("Unhandlded action");

                worker.DetachAndExit();
            }
        }

        return TRUE;
    }

    /** This part of the function is only reached as long as we have not been at the OEP */

    result = ((Resume_WaitForDebugEvent_t)worker.hook_WaitForDebugEvent.Resume)(lpDebugEvent, dwMilliseconds);

    DWORD dwDebugEventCode = lpDebugEvent->dwDebugEventCode;

    /* Filter out uninteresting events */
    if (dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
    {
        Log.Line("[Callback_WaitForDebugEvent]");
        Log.Line("\tprocess: %08X", lpDebugEvent->dwProcessId);
        Log.Line("\tthread: %08X", lpDebugEvent->dwThreadId);
        Log.Line("\ttimeout: %08X", dwMilliseconds);
        Log.Line("\tcode: %08X", dwDebugEventCode);

        DWORD exceptionAddress = (DWORD)lpDebugEvent->u.Exception.ExceptionRecord.ExceptionAddress;

        Log.Line("\texceptionAddress: %08X", exceptionAddress);

        if (exceptionAddress == worker.OEP)
        {
            /** The game is unpacked now and execution stopped at the OEP */
            Log.Line("\tException at the OEP triggered");

            worker.InitMainThread(lpDebugEvent->dwThreadId);

            int result = MessageBox(NULL, L"The game will be fixed now.\nIf you press cancel, the debugger will just detach and the game is left unchanged.", L"Starting", MB_OKCANCEL);

            if (result == IDCANCEL)
            {
                worker.RestoreOEPData();
                worker.SetEip(worker.OEP);
                worker.DetachAndExit();
            }

            result = MessageBox(NULL, L"Do you want to turn on verbose logging?", L"Logging", MB_YESNO);

            Log.Verbose = (result == IDYES);

            worker.StartFixing();

            worker.hook_ContinueDebugEvent.Install("Kernel32.dll", "ContinueDebugEvent", &Callback_ContinueDebugEvent);
            worker.hook_ReadProcessMemory.Install("Kernel32.dll", "ReadProcessMemory", &Callback_ReadProcessMemory);
            worker.hook_WriteProcessMemory.Install("Kernel32.dll", "WriteProcessMemory", &Callback_WriteProcessMemory);

            worker.hook_Nanomites.Install_Raw((FARPROC)0x66724CB7, Callback_Nanomites);

            worker.hook_ReadProcessMemory.Pause();

            goto perform_step;
        }
    }

    return result;
}

DWORD WINAPI WorkerThread(LPVOID data)
{
    Log.Line("Starting Worker");

    worker.hook_DebugActiveProcess.Install("Kernel32.dll", "DebugActiveProcess", &Callback_DebugActiveProcess);

    hook_GetThreadContext.Install("Kernel32.dll", "GetThreadContext", &Callback_GetThreadContext);
    hook_SetThreadContext.Install("Kernel32.dll", "SetThreadContext", &Callback_SetThreadContext);

    hook_GetThreadContext.Pause();
    hook_SetThreadContext.Pause();

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

            break;
        }

        default:
        {
            break;
        }
    }

    return TRUE;
}