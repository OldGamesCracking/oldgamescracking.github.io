#include <stdio.h>
#include <Zydis.h>
#include "Hooking.h"


Hook::~Hook()
{
	Uninstall();
}

BOOL Hook::Install_Internal(FARPROC Proc, LPVOID Callback)
{
	if (Proc == NULL || Callback == NULL)
	{
		return FALSE;
	}

	this->Proc = Proc;
	this->Callback = Callback;

	/* Copy at least 5 bytes so we can install a JMP */
	SIZE_T numBytes = 0;

	while (numBytes < 5)
	{
		ZydisDisassembledInstruction Instruction;

		ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LEGACY_32, 0, (BYTE*)Proc + numBytes, ZYDIS_MAX_INSTRUCTION_LENGTH, &Instruction);

		numBytes += Instruction.info.length;
	}

	OpcodesBuffer = (LPBYTE)VirtualAlloc(0, numBytes + 5, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (OpcodesBuffer == NULL)
	{
		return FALSE;
	}

	/* Save original bytes */
	memcpy(OpcodesBuffer, (BYTE*)Proc, numBytes);
	OpcodesLen = numBytes;

	/* Create the jump pad */
	BYTE *jumppad = OpcodesBuffer + numBytes;
	*jumppad = 0xE9;
	*(DWORD *)(jumppad + 1) = (BYTE*)Proc - jumppad - 5 + numBytes;	// -5 to compensate the jump in the jumppad

	/* Place a jmp to the callback */
	DWORD oldProtect;
	VirtualProtect(Proc, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
	*(BYTE*)Proc = 0xE9;
	*(DWORD *)((BYTE *)Proc + 1) = (BYTE *)Callback - (BYTE *)Proc - 5;
	VirtualProtect(Proc, 5, oldProtect, &oldProtect);

	Enabled = TRUE;

	return TRUE;
}

BOOL Hook::Install(LPCSTR Module, LPCSTR Proc, LPVOID Callback)
{
	if (Module == NULL || Proc == NULL || Callback == NULL)
	{
		return FALSE;
	}

	HMODULE hModule = GetModuleHandleA(Module);

	if (hModule == NULL)
	{
		return FALSE;
	}

	FARPROC proc = GetProcAddress(hModule, Proc);

	if (proc == NULL)
	{
		return FALSE;
	}

	return Install_Internal(proc, Callback);
}

BOOL Hook::Install_Raw(FARPROC Proc, LPVOID Callback)
{
	if (Proc == NULL || Callback == NULL)
	{
		return FALSE;
	}

	return Install_Internal(Proc, Callback);
}

BOOL Hook::Uninstall()
{
	if (Proc == NULL || OpcodesBuffer == NULL)
	{
		return FALSE;
	}

	if (!Enabled)
	{
		return TRUE;
	}

	DWORD oldProtect;
	VirtualProtect(Proc, OpcodesLen, PAGE_EXECUTE_READWRITE, &oldProtect);
	memcpy(Proc, OpcodesBuffer, OpcodesLen);
	VirtualProtect(Proc, OpcodesLen, oldProtect, &oldProtect);

	VirtualFree(OpcodesBuffer, 0, MEM_RELEASE);

	OpcodesBuffer = NULL;
	Proc = NULL;
	Enabled = FALSE;

	return TRUE;
}

BOOL Hook::Enable()
{
	if (Proc == NULL || Callback == NULL)
	{
		return FALSE;
	}

	if (Enabled)
	{
		return TRUE;
	}

	DWORD oldProtect;
	VirtualProtect(Proc, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
	*(BYTE*)Proc = 0xE9;
	*(DWORD *)((BYTE*)Proc + 1) = (BYTE*)Callback - (BYTE*)Proc - 5;
	VirtualProtect(Proc, 5, oldProtect, &oldProtect);

	Enabled = TRUE;

	return TRUE;
}

BOOL Hook::Pause()
{
	if (Proc == NULL || OpcodesBuffer == NULL)
	{
		return FALSE;
	}

	if (!Enabled)
	{
		return TRUE;
	}

	DWORD oldProtect;
	VirtualProtect(Proc, OpcodesLen, PAGE_EXECUTE_READWRITE, &oldProtect);
	memcpy(Proc, OpcodesBuffer, OpcodesLen);
	VirtualProtect(Proc, OpcodesLen, oldProtect, &oldProtect);

	Enabled = FALSE;

	return TRUE;
}