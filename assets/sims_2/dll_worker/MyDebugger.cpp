#include <utility>
#include <type_traits>
#include <cinttypes>
#include <Zydis.h>
#include <Windows.h>
#include <psapi.h>
#include <shlwapi.h>
#include "MyDebugger.h"
#include "logging.h"


#pragma comment(lib, "Psapi.lib")


#define FLAG_TRAP           (1 << 8)


Context::Context(HANDLE hThread) : 
	hThread(hThread)
{
}

Context::~Context()
{
}

void Context::Get()
{
	memset(&context, 0, sizeof(CONTEXT));
	context.ContextFlags = CONTEXT_ALL;

	GetThreadContext(hThread, &context);
}

void Context::Set()
{
	SetThreadContext(hThread, &context);
}

void Context::SetTrap(bool set)
{
	Get();

	if (set)
	{
		context.EFlags |= FLAG_TRAP;
	}
	else
	{
		context.EFlags &= ~FLAG_TRAP;
	}

	Set();
}

DWORD Context::GetDrX(size_t index)
{
	Get();

	if (index == 0)
	{
		return context.Dr0;
	}

	if (index == 1)
	{
		return context.Dr1;
	}

	if (index == 2)
	{
		return context.Dr2;
	}

	if (index == 3)
	{
		return context.Dr3;
	}

	if (index == 6)
	{
		return context.Dr6;
	}

	if (index == 7)
	{
		return context.Dr7;
	}

	return 0;
}

void Context::SetDrX(size_t index, DWORD value)
{
	Get();

	if (index == 0)
	{
		context.Dr0 = value;
	}

	if (index == 1)
	{
		context.Dr1 = value;
	}

	if (index == 2)
	{
		context.Dr2 = value;
	}

	if (index == 3)
	{
		context.Dr3 = value;
	}

	if (index == 6)
	{
		context.Dr6 = value;
	}

	if (index == 7)
	{
		context.Dr7 = value;
	}

	Set();
}

DWORD Context::GetEip()
{
	Get();

	return context.Eip;
}

void Context::SetEip(DWORD Eip)
{
	Get();

	context.Eip = Eip;

	Set();
}

DWORD Context::GetEsp()
{
	Get();

	return context.Esp;
}

void Context::SetEsp(DWORD Esp)
{
	Get();

	context.Esp = Esp;

	Set();
}

MyDebugger::MyDebugger(HANDLE hProcess, DWORD dwProcessId, HANDLE hMainThread, DWORD dwMainThreadId):
	hProcess(hProcess),
	dwProcessId(dwProcessId),
	hMainThread(hMainThread),
	dwMainThreadId(dwMainThreadId)
{
}

MyDebugger::~MyDebugger()
{
}

DWORD MyDebugger::GetEip()
{
	Context ctx(hMainThread);

	return ctx.GetEip();
}

void MyDebugger::SetEip(DWORD Eip)
{
	Context ctx(hMainThread);

	ctx.SetEip(Eip);
}

DWORD MyDebugger::GetEsp()
{
	Context ctx(hMainThread);

	return ctx.GetEsp();
}

void MyDebugger::SetEsp(DWORD Esp)
{
	Context ctx(hMainThread);

	ctx.SetEsp(Esp);
}

void MyDebugger::Push(DWORD Value)
{
	Context ctx(hMainThread);

	ctx.SetEsp(ctx.GetEsp() - 4);

	WriteMemory(ctx.GetEsp(), (uint8_t*)&Value, sizeof(Value));
}

void MyDebugger::SetTrap(bool set)
{
	Context ctx(hMainThread);

	ctx.SetTrap(set);
}

DWORD MyDebugger::StackTop()
{
	DWORD Esp = GetEsp();
	DWORD value;

	ReadMemory(Esp, (uint8_t*)&value, sizeof(value));

	return value;
}

void MyDebugger::Continue()
{
	if (!ContinueDebugEvent(dwProcessId, dwMainThreadId, DBG_CONTINUE))
	{
		Log.Line("[ERROR] Could not continue debugging (internal)");
	}
}

bool MyDebugger::Run()
{	
	DEBUG_EVENT event{ 0 };

	Continue();
	
	while (true)
	{
		if (!WaitForDebugEvent(&event, INFINITE))
		{
			Log.Line("[ERROR] Something while waiting for a debug event went wrong");

			return false;
		}

		auto eventCode = event.dwDebugEventCode;

		if (event.dwProcessId == dwProcessId && event.dwThreadId == dwMainThreadId)
		{
			if (eventCode == EXCEPTION_DEBUG_EVENT)
			{
				auto exceptionCode = event.u.Exception.ExceptionRecord.ExceptionCode;
				auto exceptionAddress = (DWORD)event.u.Exception.ExceptionRecord.ExceptionAddress;

				if (exceptionCode != EXCEPTION_SINGLE_STEP)
				{
					Log.Error("Unexpected ExceptionCode: 0x%08X at 0x%08X", exceptionCode, exceptionAddress);

					return false;
				}

				break;
			}
			else if (eventCode == CREATE_THREAD_DEBUG_EVENT)
			{
				Log.Warning("Some thread was created. Start address: %08X", event.u.CreateThread.lpStartAddress);
			}
			else if (eventCode == EXIT_THREAD_DEBUG_EVENT)
			{
				Log.Warning("Some thread was exited.");
			}
			else if (eventCode == EXIT_PROCESS_DEBUG_EVENT)
			{
				Log.Warning("Some process was exited.");
			}
			else if (eventCode == LOAD_DLL_DEBUG_EVENT)
			{
				Log.Warning("Some DLL was loaded");

				Log.Warning("hFile: %08X", event.u.LoadDll.hFile);
				Log.Warning("lpBaseOfDll: %08X", event.u.LoadDll.lpBaseOfDll);
				Log.Warning("dwDebugInfoFileOffset: %08X", event.u.LoadDll.dwDebugInfoFileOffset);
				Log.Warning("nDebugInfoSize: %08X", event.u.LoadDll.nDebugInfoSize);
				Log.Warning("lpImageName: %08X", event.u.LoadDll.lpImageName);
				Log.Warning("fUnicode: %08X", event.u.LoadDll.fUnicode);

				char buffer[MAX_PATH];
				const char *dll = "NULL";

				if (event.u.LoadDll.lpImageName != NULL)
				{
					if (ReadMemory((ZyanU64)event.u.LoadDll.lpImageName, (uint8_t *)&buffer[0], sizeof(buffer)))
					{
						size_t lenName = strnlen(&buffer[0], sizeof(buffer));

						Log.Warning("lenName: %u", lenName);

						Log.Warning("buffer: %s", buffer);

						if (lenName < sizeof(buffer))
						{
							dll = buffer;
						}

						char FileName[MAX_PATH];

						if (GetModuleFileNameExA(hProcess, (HMODULE)event.u.LoadDll.lpBaseOfDll, &FileName[0], sizeof(FileName)) > 0)
						{
							Log.Warning("FileName: %s", FileName);
						}
					}
				}

				Log.Warning("Some DLL was loaded: %s", dll);
			}
			else if (eventCode == UNLOAD_DLL_DEBUG_EVENT)
			{
				Log.Warning("Some DLL was unloaded");
			}
			else
			{
				Log.Error("Unexpected dwDebugEventCode: 0x%08X", eventCode);

				return false;
			}
		}
		else
		{
			Log.Warning("Event for other thread. dwDebugEventCode: 0x%08X", eventCode);

			switch (eventCode)
			{
				case (EXCEPTION_DEBUG_EVENT):
				{
					Log.Line("EXCEPTION_DEBUG_EVENT : %08X @ %08X", event.u.Exception.ExceptionRecord.ExceptionCode, event.u.Exception.ExceptionRecord.ExceptionAddress);

					break;
				}

				case (CREATE_THREAD_DEBUG_EVENT):
				{
					Log.Line("CREATE_THREAD_DEBUG_EVENT : %08X", event.u.CreateThread.lpStartAddress);

					break;
				}

				case (CREATE_PROCESS_DEBUG_EVENT):
				{
					Log.Line("CREATE_PROCESS_DEBUG_EVENT : %08X", event.u.CreateProcessInfo.lpStartAddress);

					break;
				}

				case (EXIT_THREAD_DEBUG_EVENT):
				{
					Log.Line("EXIT_THREAD_DEBUG_EVENT");

					break;
				}

				case (EXIT_PROCESS_DEBUG_EVENT):
				{
					Log.Line("EXIT_PROCESS_DEBUG_EVENT");

					break;
				}

				case (LOAD_DLL_DEBUG_EVENT):
				{
					Log.Warning("Some DLL was loaded");

					Log.Warning("hFile: %08X", event.u.LoadDll.hFile);
					Log.Warning("lpBaseOfDll: %08X", event.u.LoadDll.lpBaseOfDll);
					Log.Warning("dwDebugInfoFileOffset: %08X", event.u.LoadDll.dwDebugInfoFileOffset);
					Log.Warning("nDebugInfoSize: %08X", event.u.LoadDll.nDebugInfoSize);
					Log.Warning("lpImageName: %08X", event.u.LoadDll.lpImageName);
					Log.Warning("fUnicode: %08X", event.u.LoadDll.fUnicode);

					char buffer[MAX_PATH];
					const char *dll = "NULL";

					if (event.u.LoadDll.lpImageName != NULL)
					{
						if (ReadMemory((ZyanU64)event.u.LoadDll.lpImageName, (uint8_t *)&buffer[0], sizeof(buffer)))
						{
							size_t lenName = strnlen(&buffer[0], sizeof(buffer));

							Log.Warning("lenName: %u", lenName);

							Log.Warning("buffer: %s", buffer);

							if (lenName < sizeof(buffer))
							{
								dll = buffer;
							}

							char FileName[MAX_PATH];

							if (GetModuleFileNameExA(hProcess, (HMODULE)event.u.LoadDll.lpBaseOfDll, &FileName[0], sizeof(FileName)) > 0)
							{
								Log.Warning("FileName: %s", FileName);
							}
						}
					}

					Log.Warning("Some DLL was loaded: %s", dll);
				}

				case (UNLOAD_DLL_DEBUG_EVENT):
				{
					Log.Line("UNLOAD_DLL_DEBUG_EVENT");

					break;
				}

				case (OUTPUT_DEBUG_STRING_EVENT):
				{
					Log.Line("OUTPUT_DEBUG_STRING_EVENT");

					break;
				}

				case (RIP_EVENT):
				{
					Log.Line("RIP_EVENT");

					break;
				}

				default:
				{
					Log.Error("Unknown dwDebugEventCode: 0x%08X", eventCode);

					return false;
				}
			}
		}

		if (!ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE))
		{
			Log.Error("Could not continue debugging");
		}
	}

	return true;
}

void MyDebugger::StepInto(size_t steps)
{
	for (size_t step = 0; step < steps; step++)
	{
		Context ctx(hMainThread);
		
		ctx.SetTrap();

		Run();

		ctx.SetTrap(false);
	}
}

bool MyDebugger::DisassembleAt(ZyanU64 address, ZydisDisassembledInstruction *instruction)
{
	uint8_t buffer[ZYDIS_MAX_INSTRUCTION_LENGTH];

	Context ctx(hMainThread);

	if (!ReadMemory(address, &buffer[0], sizeof(buffer)))
	{
		Log.Line("[Error] Could not read memory at %08X", (uint32_t)address);

		return false;
	}

	if (!ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LEGACY_32, address, &buffer[0], sizeof(buffer), instruction)))
	{
		Log.Line("[Error] Could not disassemble instruction at %08X", (uint32_t)address);

		return false;
	}

	return true;
}

bool MyDebugger::DisassembleAtEip(ZydisDisassembledInstruction *instruction)
{
	return DisassembleAt(GetEip(), instruction);
}

bool MyDebugger::IsMnemonicAtEip(ZydisMnemonic mnemonic, bool *out_error)
{
	ZydisDisassembledInstruction instruction;

	*out_error = false;

	if (!DisassembleAtEip(&instruction))
	{
		*out_error = true;

		return false;
	}

	// logger.LogLine("%08" PRIX64 "  %s", instruction.runtime_address, instruction.text);

	return instruction.info.mnemonic == mnemonic;
}

void MyDebugger::StepIntoUntil(ZydisMnemonic mnemonic)
{
	bool error;

	while (!IsMnemonicAtEip(mnemonic, &error))
	{
		if (error)
		{
			break;
		}

		// logger.LogLine("Step");
		StepInto();
	}
}

void MyDebugger::EnableHWBP(DWORD address, HWBPCond condition, HWBPSize size, size_t index)
{
	DWORD condition_val = static_cast<DWORD>(condition);
	DWORD size_val = static_cast<DWORD>(index);

	Context ctx(hMainThread);

	DWORD Dr7 = ctx.GetDrX(7);

	if (index == 0)
	{
		ctx.SetDrX(0, address);
		Dr7 |= (1 << 0);                    /* Local Enable */
		Dr7 &= ~(0xf << 16);                /* Clear R/W and LEN */
		Dr7 |= ((DWORD)condition_val << 16);    /* Set R/W */
		Dr7 |= ((DWORD)size_val << 18);         /* Set LEN */
	}

	if (index == 1)
	{
		ctx.SetDrX(1, address);
		Dr7 |= (1 << 2);
		Dr7 &= ~(0xf << 20);
		Dr7 |= ((DWORD)condition_val << 20);
		Dr7 |= ((DWORD)size_val << 22);
	}

	if (index == 2)
	{
		ctx.SetDrX(2, address);
		Dr7 |= (1 << 4);
		Dr7 &= ~(0xf << 24);
		Dr7 |= ((DWORD)condition_val << 24);
		Dr7 |= ((DWORD)size_val << 26);
	}

	if (index == 3)
	{
		ctx.SetDrX(3, address);
		Dr7 |= (1 << 6);
		Dr7 &= ~(0xf << 28);
		Dr7 |= ((DWORD)condition_val << 28);
		Dr7 |= ((DWORD)size_val << 30);
	}

	ctx.SetDrX(7, Dr7);
}

void MyDebugger::DisableHWBP(size_t index)
{
	Context ctx(hMainThread);

	DWORD Dr6 = ctx.GetDrX(6);
	DWORD Dr7 = ctx.GetDrX(7);

	if (index == 0)
	{
		ctx.SetDrX(0, 0);
		Dr6 &= ~(1 << 0);       /* Clear Condition Detected Flag */
		Dr7 &= ~(0x03 << 0);    /* Clear Enable Flags */
		Dr7 &= ~(0xf << 16);    /* Clear R/W and LEN */
	}

	if (index == 1)
	{
		ctx.SetDrX(1, 0);
		Dr6 &= ~(1 << 1);
		Dr7 &= ~(0x03 << 2);
		Dr7 &= ~(0xf << 20);
	}

	if (index == 2)
	{
		ctx.SetDrX(2, 0);
		Dr6 &= ~(1 << 2);
		Dr7 &= ~(0x03 << 4);
		Dr7 &= ~(0xf << 24);
	}

	if (index == 3)
	{
		ctx.SetDrX(3, 0);
		Dr6 &= ~(1 << 3);
		Dr7 &= ~(0x03 << 6);
		Dr7 &= ~(0xf << 28);
	}

	ctx.SetDrX(6, Dr6);
	ctx.SetDrX(7, Dr7);
}

bool MyDebugger::WriteMemory(ZyanU64 address, uint8_t *const buffer, size_t len)
{
	DWORD oldProtect;
	if (!VirtualProtectEx(hProcess, (LPVOID)address, len, PAGE_READWRITE, &oldProtect))
	{
		Log.Line("[ERROR] Could not set to PAGE_READWRITE");

		return false;
	}

	DWORD bytesRead;
	if (!WriteProcessMemory(hProcess, (LPVOID)address, buffer, len, &bytesRead))
	{
		Log.Line("[ERROR] Could not WriteProcessMemory");

		return false;
	}

	if (!VirtualProtectEx(hProcess, (LPVOID)address, len, oldProtect, &oldProtect))
	{
		Log.Line("[ERROR] Could not set to old protect");

		return false;
	}

	return true;
}

bool MyDebugger::ReadMemory(ZyanU64 address, uint8_t *const buffer, size_t len)
{
	DWORD oldProtect;
	if (!VirtualProtectEx(hProcess, (LPVOID)address, len, PAGE_READWRITE, &oldProtect))
	{
		Log.Line("[ERROR] Could not set to PAGE_READWRITE");

		return false;
	}

	DWORD bytesRead;
	if (!ReadProcessMemory(hProcess, (LPVOID)address, buffer, len, &bytesRead))
	{
		Log.Line("[ERROR] Could not ReadProcessMemory");

		return false;
	}

	if (!VirtualProtectEx(hProcess, (LPVOID)address, len, oldProtect, &oldProtect))
	{
		Log.Line("[ERROR] Could not set to old protect");

		return false;
	}

	return true;
}