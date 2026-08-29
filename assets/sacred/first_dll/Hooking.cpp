#include <stdio.h>
#include <Zydis.h>
#include "Hooking.h"


Hook::~Hook()
{
	Uninstall();
}

BOOL Hook::Install_Internal(FARPROC Proc, LPVOID Callback)
{
	if (Proc == NULL)
	{
		return FALSE;
	}

	this->Proc = Proc;
	this->Callback = Callback;

	OpcodesBuffer = (LPBYTE)VirtualAlloc(0, 2 * ZYDIS_MAX_INSTRUCTION_LENGTH + 5, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (OpcodesBuffer == NULL)
	{
		return FALSE;
	}

	OriginalBytesBuffer = (LPBYTE)VirtualAlloc(0, 2 * ZYDIS_MAX_INSTRUCTION_LENGTH + 5, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (OriginalBytesBuffer == NULL)
	{
		VirtualFree(OpcodesBuffer, 0, MEM_RELEASE);
		OpcodesBuffer = NULL;

		return FALSE;
	}

	/* Copy at least 5 bytes so we can install a JMP */
	SIZE_T numBytes = 0;

	BYTE *src = (BYTE*)Proc;
	BYTE *dst = (BYTE*)OpcodesBuffer;

	while (numBytes < 5)
	{
		ZydisDisassembledInstruction Instruction;

		ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LEGACY_32, 0, src, ZYDIS_MAX_INSTRUCTION_LENGTH, &Instruction);

		// TODO: Also check for Jumps
		if ((Instruction.info.mnemonic == ZYDIS_MNEMONIC_CALL) && (Instruction.info.meta.branch_type == ZYDIS_BRANCH_TYPE_NEAR))
		{
			ZyanU64 callTo;

			ZydisCalcAbsoluteAddress(&Instruction.info, &Instruction.operands[0], (ZyanU64)src, &callTo);

			DWORD callOffsetNew = (DWORD)callTo - (DWORD)dst - 5;

			*dst = 0xE8;
			*(DWORD*)(dst + 1) = callOffsetNew;
		}
		else
		{
			memcpy(dst, src, Instruction.info.length);
		}

		src += Instruction.info.length;
		dst += Instruction.info.length;
		numBytes += Instruction.info.length;
	}

	/** Save original bytes in case the bytes were altered (e.g. for a CALL, see above) */
	memcpy(OriginalBytesBuffer, Proc, numBytes);
	
	OpcodesLen = numBytes;

	/* Create the jump pad */
	BYTE *jumppad = OpcodesBuffer + numBytes;
	*jumppad = 0xE9;
	*(DWORD*)(jumppad + 1) = (BYTE*)Proc - jumppad - 5 + numBytes;	// -5 to compensate the jump in the jumppad

	/* Place a jmp to the callback */
	DWORD oldProtect;
	VirtualProtect(Proc, numBytes, PAGE_EXECUTE_READWRITE, &oldProtect);
	*(BYTE*)Proc = 0xE9;

	if (numBytes > 5)
	{
		/** Fill remaining bytes with NOPs to prevent parsing errors */
		for (int i = 0; i < (numBytes - 5); i++)
		{
			*((BYTE*)Proc + 5 + i) = 0x90;
		}
	}
	
	if (Callback != NULL)
	{
		*(DWORD*)((BYTE*)Proc + 1) = (BYTE*)Callback - (BYTE*)Proc - 5;
	}
	else
	{
		/** No Callback present, just forward to the trampoline */
		*(DWORD*)((BYTE*)Proc + 1) = (BYTE*)OpcodesBuffer - (BYTE*)Proc - 5;
	}

	VirtualProtect(Proc, 5, oldProtect, &oldProtect);

	Enabled = TRUE;

	return TRUE;
}

BOOL Hook::Install(LPCSTR Module, LPCSTR Proc, LPVOID Callback)
{
	if (Module == NULL || Proc == NULL)
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
	if (Proc == NULL)
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
	memcpy(Proc, OriginalBytesBuffer, OpcodesLen);
	VirtualProtect(Proc, OpcodesLen, oldProtect, &oldProtect);

	VirtualFree(OpcodesBuffer, 0, MEM_RELEASE);
	VirtualFree(OriginalBytesBuffer, 0, MEM_RELEASE);

	OpcodesBuffer = NULL;
	OriginalBytesBuffer = NULL;
	Proc = NULL;
	Enabled = FALSE;

	return TRUE;
}

BOOL Hook::Enable()
{
	if (Proc == NULL || OpcodesBuffer == NULL)
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

	if (Callback != NULL)
	{
		*(DWORD*)((BYTE*)Proc + 1) = (BYTE*)Callback - (BYTE*)Proc - 5;
	}
	else
	{
		/** No Callback present, just forward to the trampoline */
		*(DWORD*)((BYTE*)Proc + 1) = (BYTE*)OpcodesBuffer - (BYTE*)Proc - 5;
	}

	VirtualProtect(Proc, 5, oldProtect, &oldProtect);

	Enabled = TRUE;

	return TRUE;
}

BOOL Hook::Pause()
{
	if (Proc == NULL || OriginalBytesBuffer == NULL)
	{
		return FALSE;
	}

	if (!Enabled)
	{
		return TRUE;
	}

	DWORD oldProtect;
	if (VirtualProtect(Proc, OpcodesLen, PAGE_EXECUTE_READWRITE, &oldProtect))
	{
		memcpy(Proc, OriginalBytesBuffer, OpcodesLen);

		VirtualProtect(Proc, OpcodesLen, oldProtect, &oldProtect);
	}
	else
	{
		/** Hook probably not valid anymore (DLL was unloaded) */
	}

	Enabled = FALSE;

	return TRUE;
}