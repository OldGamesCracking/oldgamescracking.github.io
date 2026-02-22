#pragma once

#include <Windows.h>
#include <Zydis.h>
#include <vector>


class ProcessHelper
{
private:
	HANDLE hProcess;

public:
	ProcessHelper(HANDLE hProcess);

	BOOL ReadMemory(LPVOID address, PBYTE buffer, SIZE_T len);
	BOOL WriteMemory(LPVOID address, PBYTE buffer, SIZE_T len);

	bool DisassembleAt(ZyanU64 address, ZydisDisassembledInstruction *out_instruction);
	bool GetDestination(ZyanU64 address, ZyanU64 *out_destination);
	bool IsMnemonic(ZyanU64 address, ZydisMnemonic mnemonic, ZyanU64 *const out_address_next);
	bool IsInstructions(ZyanU64 address, std::vector<ZydisMnemonic>&instructions, ZyanU64 *const out_address_last_instruction = nullptr);
};