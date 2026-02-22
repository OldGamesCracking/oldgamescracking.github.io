#include "ProcessHelper.h"
#include "Logging.h"


ProcessHelper::ProcessHelper(HANDLE hProcess) :
	hProcess(hProcess)
{

}

BOOL ProcessHelper::ReadMemory(LPVOID address, PBYTE buffer, SIZE_T len)
{
    DWORD oldProtect;
    if (!VirtualProtectEx(hProcess, address, len, PAGE_READWRITE, &oldProtect))
    {
        return FALSE;
    }

    DWORD bytesWritten;
    if (!ReadProcessMemory(hProcess, address, buffer, len, &bytesWritten))
    {
        return FALSE;
    }

    if (!VirtualProtectEx(hProcess, address, len, oldProtect, &oldProtect))
    {
        return FALSE;
    }

    return TRUE;
}

BOOL ProcessHelper::WriteMemory(LPVOID address, PBYTE buffer, SIZE_T len)
{
    DWORD oldProtect;
	if (!VirtualProtectEx(hProcess, address, len, PAGE_READWRITE, &oldProtect))
	{
		Log.Error("Could not set protection @ %08X", address);

		return FALSE;
	}

    DWORD bytesWritten;
	if (!WriteProcessMemory(hProcess, address, buffer, len, &bytesWritten))
	{
		Log.Error("Could not write @ %08X", address);

		return FALSE;
	}

    return VirtualProtectEx(hProcess, address, len, oldProtect, &oldProtect);
}

bool ProcessHelper::DisassembleAt(ZyanU64 address, ZydisDisassembledInstruction *out_instruction)
{
	uint8_t buffer[ZYDIS_MAX_INSTRUCTION_LENGTH];

	if (!ReadMemory((LPVOID)address, &buffer[0], sizeof(buffer)))
	{
		Log.Error("Something while reading the data at %08X went wrong", (uint32_t)address);

		return false;
	}

	if (!ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LEGACY_32, address, &buffer[0], sizeof(buffer), out_instruction)))
	{
		Log.Error("Could not disassemble instruction at %08X", (uint32_t)address);

		return false;
	}

	return true;
}

bool ProcessHelper::GetDestination(ZyanU64 address, ZyanU64 *out_destination)
{
	ZydisDisassembledInstruction instruction;

	if (!DisassembleAt(address, &instruction))
	{
		return false;
	}

	if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instruction.info, &instruction.operands[0], address, out_destination)))
	{
		return false;
	}

	return true;
}

bool ProcessHelper::IsMnemonic(ZyanU64 address, ZydisMnemonic mnemonic, ZyanU64 *const out_address_next)
{
	ZydisDisassembledInstruction instruction;

	if (!DisassembleAt(address, &instruction))
	{
		return false;
	}

	if (out_address_next != nullptr)
	{
		*out_address_next = address + instruction.info.length;
	}

	return instruction.info.mnemonic == mnemonic;
}

bool ProcessHelper::IsInstructions(ZyanU64 address, std::vector <ZydisMnemonic> &instructions, ZyanU64 *const out_address_last_instruction)
{
	auto index = 0;

	for (const auto &instruction : instructions)
	{
		if ((index + 1) == instructions.size())
		{
			if (out_address_last_instruction != nullptr)
			{
				*out_address_last_instruction = address;
			}
		}

		if (!IsMnemonic(address, instruction, &address))
		{
			return false;
		}

		index++;
	}

	return true;
}
