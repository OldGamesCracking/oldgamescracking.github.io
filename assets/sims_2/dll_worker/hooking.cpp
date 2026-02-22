#include <stdio.h>
#include <Zydis.h>
#include "hooking.h"

BOOL hook_install_internal(FARPROC proc, LPVOID callback, HOOK_t *const in_out_hook)
{
	if (proc == NULL || callback == NULL || in_out_hook == NULL)
	{
		return FALSE;
	}

	in_out_hook->proc = proc;
	in_out_hook->callback = callback;

	/* Copy at least 5 bytes so we can install a JMP */
	SIZE_T numBytes = 0;

	while (numBytes < 5)
	{
		ZydisDisassembledInstruction Instruction;

		ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LEGACY_32, 0, (BYTE*)proc + numBytes, ZYDIS_MAX_INSTRUCTION_LENGTH, &Instruction);

		numBytes += Instruction.info.length;
	}

	in_out_hook->opcodesBuffer = (LPBYTE)VirtualAlloc(0, numBytes + 5, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (in_out_hook->opcodesBuffer == NULL)
	{
		return FALSE;
	}

	/* Save original bytes */
	memcpy(in_out_hook->opcodesBuffer, (BYTE*)proc, numBytes);
	in_out_hook->opcodesLen = numBytes;

	/* Create the jump pad */
	BYTE *jumppad = in_out_hook->opcodesBuffer + numBytes;
	*jumppad = 0xE9;
	*(DWORD*)(jumppad + 1) = (BYTE*)proc - jumppad - 5 + numBytes;	// -5 to compensate the jump in the jumppad

	/* Place a jmp to the callback */
	DWORD oldProtect;
	VirtualProtect(proc, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
	*(BYTE*)proc = 0xE9;
	*(DWORD*)((BYTE*)proc + 1) = (BYTE*)callback - (BYTE*)proc - 5;
	VirtualProtect(proc, 5, oldProtect, &oldProtect);

	in_out_hook->enabled = TRUE;

	return TRUE;
}

BOOL hook_install(LPCSTR moduleName, LPCSTR procName, LPVOID callback, HOOK_t *const in_out_hook)
{
	if (moduleName == NULL || procName == NULL || callback == NULL || in_out_hook == NULL)
	{
		return FALSE;
	}

	HMODULE hModule = GetModuleHandleA(moduleName);

	if (hModule == NULL)
	{
		return FALSE;
	}

	FARPROC proc = GetProcAddress(hModule, procName);

	if (proc == NULL)
	{
		return FALSE;
	}

	return hook_install_internal(proc, callback, in_out_hook);
}

BOOL hook_install_raw(FARPROC proc, LPVOID callback, HOOK_t *const in_out_hook)
{
	if (proc == NULL || callback == NULL || in_out_hook == NULL)
	{
		return FALSE;
	}

	return hook_install_internal(proc, callback, in_out_hook);
}

BOOL hook_uninstall(HOOK_t *const hook)
{
	if (hook == NULL || hook->proc == NULL || hook->opcodesBuffer == NULL)
	{
		return FALSE;
	}

	if (!hook->enabled)
	{
		return TRUE;
	}

	DWORD oldProtect;
	VirtualProtect(hook->proc, hook->opcodesLen, PAGE_EXECUTE_READWRITE, &oldProtect);
	memcpy(hook->proc, hook->opcodesBuffer, hook->opcodesLen);
	VirtualProtect(hook->proc, hook->opcodesLen, oldProtect, &oldProtect);

	VirtualFree(hook->opcodesBuffer, 0, MEM_RELEASE);

	hook->opcodesBuffer = NULL;
	hook->proc = NULL;
	hook->enabled = FALSE;

	return TRUE;
}

BOOL hook_disable_fast(HOOK_t *const hook)
{
	if (hook == NULL || hook->proc == NULL || hook->opcodesBuffer == NULL)
	{
		return FALSE;
	}

	if (!hook->enabled)
	{
		return TRUE;
	}

	DWORD oldProtect;
	VirtualProtect(hook->proc, hook->opcodesLen, PAGE_EXECUTE_READWRITE, &oldProtect);
	memcpy(hook->proc, hook->opcodesBuffer, hook->opcodesLen);
	VirtualProtect(hook->proc, hook->opcodesLen, oldProtect, &oldProtect);

	hook->enabled = FALSE;

	return TRUE;
}

BOOL hook_enable_fast(HOOK_t *const hook)
{
	if (hook == NULL || hook->proc == NULL || hook->callback == NULL)
	{
		return FALSE;
	}

	if (hook->enabled)
	{
		return TRUE;
	}

	DWORD oldProtect;
	VirtualProtect(hook->proc, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
	*(BYTE*)hook->proc = 0xE9;
	*(DWORD*)((BYTE*)hook->proc + 1) = (BYTE*)hook->callback - (BYTE*)hook->proc - 5;
	VirtualProtect(hook->proc, 5, oldProtect, &oldProtect);

	hook->enabled = TRUE;

	return TRUE;
}