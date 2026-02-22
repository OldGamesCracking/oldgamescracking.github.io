#pragma once

#include <cinttypes>
#include <Windows.h>
#include <Zydis.h>
#include "logging.h"


class Context
{
private:
	CONTEXT context;
	HANDLE hThread;

	void Get();
	void Set();

public:
	Context(HANDLE hThread);
	~Context();

	DWORD GetDrX(size_t index);
	void SetDrX(size_t index, DWORD value);

	DWORD GetEip();
	void SetEip(DWORD Eip);

	DWORD GetEsp();
	void SetEsp(DWORD Esp);

	void SetTrap(bool set = true);
};

class MyDebugger
{
private:
	HANDLE hProcess;
	DWORD dwProcessId;
	HANDLE hMainThread;
	DWORD dwMainThreadId;

public:
	
	enum class HWBPCond : DWORD
	{
		Execute = 0,
		Write = 1,
		IOReadWrite = 2,
		ReadWrite = 3
	};

	enum class HWBPSize : DWORD
	{
		Byte = 0,
		Word = 1,
		QWord = 1,
		DWord = 3
	};
	
	MyDebugger(HANDLE hProcess, DWORD dwProcessId, HANDLE hMainThread, DWORD dwMainThreadId);
	~MyDebugger();

	DWORD GetEip();
	void SetEip(DWORD Eip);

	DWORD GetEsp();
	void SetEsp(DWORD Esp);

	void Push(DWORD Value);

	void SetTrap(bool set = true);

	DWORD StackTop();

	void Continue();
	bool Run();
	void StepInto(size_t steps=1);
	void StepIntoUntil(ZydisMnemonic mnemonic);

	bool DisassembleAt(ZyanU64 address, ZydisDisassembledInstruction *instruction);
	bool DisassembleAtEip(ZydisDisassembledInstruction *instruction);
	bool IsMnemonicAtEip(ZydisMnemonic mnemonic, bool *out_error);

	void EnableHWBP(DWORD address, HWBPCond condition, HWBPSize size, size_t index = 0);
	void DisableHWBP(size_t index = 0);

	bool WriteMemory(ZyanU64 address, uint8_t *const buffer, size_t len);
	bool ReadMemory(ZyanU64 address, uint8_t *const buffer, size_t len);
};