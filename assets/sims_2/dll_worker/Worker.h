#pragma once

#include <Windows.h>
#include <Zydis.h>
#include <set>
#include "Modules.h"
#include "Imports.h"
#include "CodeExplorer.h"
#include "hooking.h"
#include "SafeDiscHelper.h"


#define SAFEDISC_SEC_NAME					"stxt"
#define NANOMITES_WRITE_JMP_ADDRESS			0x66725641
#define NANOMITES_WRITE_JMP_PATCH			0x90C03166  // XOR AX, AX; NOP
#define NANOMITES_INCREMENT_BAD_ADDRESS		0x667257B8
#define NANOMITES_INCREMENT_BAD_PATCH		0x08EB		// JMP SHORT +10
#define NANOMITES_INCREMENT_GOOD_ADDRESS	0x6672CFFD
#define NANOMITES_INCREMENT_GOOD_PATCH		0x01EB		// JMP SHORT +3
#define IAT_START							0x00F28000
#define IAT_SIZE							0x00000620
#define IAT_END								(IAT_START + IAT_SIZE)


typedef BOOL(__stdcall *Resume_ReadProcessMemory_t)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead);
typedef BOOL(__stdcall *Resume_WriteProcessMemory_t)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);
typedef BOOL(__stdcall *Resume_ContinueDebugEvent_t)(DWORD dwProcessId, DWORD dwThreadId, DWORD dwContinueStatus);
typedef BOOL(__stdcall *Resume_DebugActiveProcess_t)(DWORD dwProcessId);
typedef BOOL(__stdcall *Resume_WaitForDebugEvent_t)(LPDEBUG_EVENT lpDebugEvent, DWORD dwMilliseconds);


enum class ExplorationStepAction
{
	None,
	Done,
	Nanomite
};

class Worker
{
private:
	
	void PrintProcName(Module *Mod, Proc *Proc, bool Newline = true);
	void PrintProcName(DWORD Address, bool Newline = true);
	
	void InitEntryPoints();
	void InitDeadEnds();
	void PatchNanomitesJump();
	void ReadTextSection();
	void InitImports();
	void InitExplorer();

	void FixImports();

	void PauseHooks();
	void ResumeHooks();

	int FindDiffLen(ZyanU64 address, size_t stopAfter = 20);

	std::tuple<DWORD, bool> RecoverIntermodularCall(ZyanU64 address, bool dummyCall = false);
	std::tuple<DWORD, bool> RecoverIntermodularCallFromJumpPadSetup(ZyanU64 address);
	size_t RecoverVMInstructions_Inner(DWORD address);
	size_t RecoverVMInstructions(ZyanU64 address);

	bool Helper_IntermodularCall(DWORD CallFrom, DWORD CallTo, bool IsJump);

	size_t Address2BufferOffset(LPVOID address)
	{
		return (DWORD)address - (DWORD)TextSectionStart;
	};

	size_t Address2Remaining(LPVOID address)
	{
		return (DWORD)TextSectionEnd - (DWORD)address;
	};

	std::set<DWORD> DeadEnds;

public:
	~Worker() = default;
	
	void InitProcessData(DWORD dwProcessId);
	void InitMainThread(DWORD dwThreadId);
	void RestoreOEPData();
	void StartFixing();
	
	bool HandleReadProcessMemory(LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead);
	bool HandleWriteProcessMemory(LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);

	void ProbeVMInstructions();

	void MarkAsNonNanomite(ZyanU64 Address);

	void PerformExplorationStep();
	void FinalizeFix();

	void SetEip(DWORD Eip);
	void DetachAndExit();

	double CodeCoverage();
	void DumpCoverageMap();

	bool Fixing = false;

	Modules Modules;

	HANDLE hProcess;
	DWORD dwProcessId;

	DWORD dwThreadId;
	HANDLE hMainThread;

	DWORD ImageBase;
	DWORD EntryPoint;
	DWORD OEP;

	DWORD SafeDiscSectionStart;
	DWORD SafeDiscSectionEnd;
	DWORD SafeDiscSectionSize;
	
	DWORD TextSectionStart;
	DWORD TextSectionEnd;
	DWORD TextSectionSize;
	BYTE *TextSectionBuffer = nullptr;

	CodeExplorer *Explorer = nullptr;
	ExplorationStepAction LastAction;
	ZyanU64 EventAddress;

	Imports Imports;

	Hook hook_ReadProcessMemory;
	Hook hook_WriteProcessMemory;
	Hook hook_DebugActiveProcess;
	Hook hook_WaitForDebugEvent;
	Hook hook_ContinueDebugEvent;
	Hook hook_Nanomites;

	bool IgnoreNextWrite;
	DWORD NanomiteValid;
	struct NanomiteData NanomiteData;

	CONTEXT ctx;

	size_t NanomitesRecovered = 0;
	size_t VirtualInstructionsRecovered = 0;
	size_t EncryptedFunctionsRecovered = 0;
	size_t ImportsRecovered = 0;
	size_t CallsByRegisterRecovered = 0;
};