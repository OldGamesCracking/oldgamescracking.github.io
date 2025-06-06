#include "hooking.h"
#define NMD_ASSEMBLY_IMPLEMENTATION
#include "nmd_assembly.h"


BOOL hook_install(LPCSTR moduleName, LPCSTR procName, LPVOID callback, HOOK_t *const in_out_hook)
{
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

	in_out_hook->proc = proc;

	/* Copy at least 5 bytes so we can install a JMP */
	SIZE_T numBytes = 0;

	while (numBytes < 5)
	{
		SIZE_T instructionLen = nmd_x86_ldisasm((BYTE*)proc + numBytes, 15, NMD_X86_MODE_32);
		numBytes += instructionLen;
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
	*(DWORD*)(jumppad + 1) = (BYTE*)proc - jumppad - 5 + 5;	// -5 to compensat the jump in the jumppad, +5 to jump past the jump in the hooked proc

	/* Place a jmp to the callback */
	DWORD oldProtect;
	VirtualProtect(proc, numBytes, PAGE_EXECUTE_READWRITE, &oldProtect);
	*(BYTE*)proc = 0xE9;
	*(DWORD*)((BYTE*)proc + 1) = (BYTE*)callback - (BYTE*)proc - 5;
	VirtualProtect(proc, numBytes, oldProtect, &oldProtect);

	return TRUE;
}

BOOL hook_uninstall(HOOK_t *const hook)
{
	if (hook->proc == NULL)
	{
		/* Hook not installed */
		return FALSE;
	}

	DWORD oldProtect;
	VirtualProtect(hook->proc, hook->opcodesLen, PAGE_EXECUTE_READWRITE, &oldProtect);
	memcpy(hook->proc, hook->opcodesBuffer, hook->opcodesLen);
	VirtualProtect(hook->proc, hook->opcodesLen, oldProtect, &oldProtect);

	VirtualFree(hook->opcodesBuffer, 0, MEM_RELEASE);

	hook->opcodesBuffer = NULL;

	return TRUE;
}
