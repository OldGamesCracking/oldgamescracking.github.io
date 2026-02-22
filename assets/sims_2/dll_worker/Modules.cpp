#include <Windows.h>
#include <psapi.h>
#include <shlwapi.h>
#include "Modules.h"
#include "logging.h"
#include "Helper.h"


#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Shlwapi.lib")


Module::Module(DWORD Base, DWORD Size, std::string Name) :
	Base(Base),
	Size(Size),
	End(Base + Size),
	Name(Name)
{
}

Module::~Module()
{
	Clear();
}

void Module::Clear()
{
	for (auto &exp : ExportsLookup)
	{
		delete exp.second;
	}

	ExportsLookup.clear();
}

bool Module::IsAddressInModule(DWORD address)
{
	return (Base <= address) && (address < End);
}

Proc* Module::GetProcAt(DWORD address)
{
	auto result = ExportsLookup.find(address);

	if (result == ExportsLookup.end())
	{
		return nullptr;
	}

	return result->second;
}

void Module::GetExportsFromProcess(HANDLE hProcess)
{
	Clear();
	
	SIZE_T bytesRead;

	/* Read the DOS header */
	IMAGE_DOS_HEADER DOSHeader;

	if (!ReadProcessMemory(hProcess, (LPCVOID)Base, &DOSHeader, sizeof(IMAGE_DOS_HEADER), &bytesRead))
	{
		Log.Warning("Could not read DOS header");

		return;
	}

	if (DOSHeader.e_magic != IMAGE_DOS_SIGNATURE)
	{
		Log.Warning("Invalid DOS Signature");

		return;
	}

	/* Read NT headers */
	auto addressNTHeaders = Base + DOSHeader.e_lfanew;
	IMAGE_NT_HEADERS32 NTHeaders;

	if (!ReadProcessMemory(hProcess, (LPCVOID)addressNTHeaders, &NTHeaders, sizeof(IMAGE_NT_HEADERS32), &bytesRead))
	{
		Log.Warning("Could not read NT headers");

		return;
	}

	if (NTHeaders.Signature != IMAGE_NT_SIGNATURE)
	{
		Log.Warning("Invalid NT Signature");

		return;
	}

	if (NTHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
	{
		Log.Warning("No exports");

		return;
	}

	auto exportsSize = NTHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	if (exportsSize < sizeof(IMAGE_EXPORT_DIRECTORY))
	{
		Log.Warning("Wrong exports size");

		return;
	}

	BYTE *exportsBuffer = new BYTE[exportsSize];

	if (exportsBuffer == nullptr)
	{
		Log.Warning("Could not create buffer");

		return;
	}

	DWORD bufferVA = NTHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	DWORD addressExports = Base + bufferVA;

	if (!ReadProcessMemory(hProcess, (LPCVOID)addressExports, exportsBuffer, exportsSize, &bytesRead))
	{
		Log.Warning("Could not read exports");

		delete[] exportsBuffer;

		return;
	}

	/* Parse the exports */
	PIMAGE_EXPORT_DIRECTORY exportsDir = (PIMAGE_EXPORT_DIRECTORY)exportsBuffer;

	// Log.Line("NumberOfNames: %u", exportsDir->NumberOfNames);
	// Log.Line("NumberOfFunctions: %u", exportsDir->NumberOfFunctions);

	DWORD *functions = (DWORD*)&exportsBuffer[exportsDir->AddressOfFunctions - bufferVA];
	DWORD *names = (DWORD*)&exportsBuffer[exportsDir->AddressOfNames - bufferVA];
	WORD *nameOrdinals = (WORD*)&exportsBuffer[exportsDir->AddressOfNameOrdinals - bufferVA];

	ExportsLookup.reserve(exportsDir->NumberOfNames);

	for (size_t i = 0; i < exportsDir->NumberOfNames; i++)
	{
		DWORD VAName = names[i];
		char *Name = (char*)&exportsBuffer[VAName - bufferVA];

		WORD Ordinal = nameOrdinals[i];
		WORD OrdinalAdjusted = exportsDir->Base + Ordinal;

		DWORD RVAFunction = functions[Ordinal];
		DWORD VAFunction = Base + RVAFunction;

		// Log.Line("fun %u : %08X : %s (Ordinal %u)", i, VAFunction, Name, Ordinal);

		Proc *proc = new Proc();
		proc->Address = VAFunction;
		proc->Ordinal = Ordinal;
		proc->OrdinalBase = exportsDir->Base;
		proc->Name = std::string(Name);

		ExportsLookup.insert(std::pair<DWORD, Proc*>(VAFunction, proc));
	}

	delete[] exportsBuffer;
}

DWORD Module::GetProcAddress(std::string Proc)
{
	for (const auto &p: ExportsLookup)
	{
		if (iequals(p.second->Name, Proc))
		{
			return p.first;
		}
	}

	return NULL;
}

const std::unordered_map<DWORD, Proc*>& Module::Exports()
{
	return ExportsLookup;
}

Modules::~Modules()
{
	Clear();
}

void Modules::Clear()
{
	for (auto &module : ModulesList)
	{
		delete module;
	}

	ModulesList.clear();
}

Module* Modules::Add(DWORD Base, DWORD Size, std::string Name)
{
	Module *mod = new Module(Base, Size, Name);

	ModulesList.push_back(mod);

	return mod;
}

Module* Modules::GetModuleAt(DWORD address)
{
	for (auto &module : ModulesList)
	{
		if (module->IsAddressInModule(address))
		{
			return module;
		}
	}

	return nullptr;
}

void Modules::GetModulesFromProcess(HANDLE hProcess)
{
	Clear();

	DWORD cbNeeded = 0;

	EnumProcessModules(hProcess, NULL, 0, &cbNeeded);

	auto modsLoaded = cbNeeded / sizeof(HMODULE);

	ModulesList.reserve(modsLoaded);

	HMODULE *hMods = new HMODULE[modsLoaded];

	if (hMods == nullptr)
	{
		return;
	}

	Log.Debug("\n%u modules present\n", modsLoaded);

	if (EnumProcessModules(hProcess, hMods, cbNeeded, &cbNeeded))
	{
		for (size_t i = 0; i < modsLoaded; i++)
		{
			WCHAR szModFileName[MAX_PATH];

			if (GetModuleFileNameExW(hProcess, hMods[i], szModFileName, sizeof(szModFileName) / sizeof(WCHAR)))
			{
				Log.Debug("mod file name: %S", szModFileName);
			}

			WCHAR szModBaseName[MAX_PATH];

			if (GetModuleBaseNameW(hProcess, hMods[i], szModBaseName, sizeof(szModBaseName) / sizeof(WCHAR)))
			{
				Log.Debug("mod base name: %S", szModBaseName);
			}

			MODULEINFO modInfo;

			if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo)))
			{
				Log.Debug("lpBaseOfDll: 0x%08X", modInfo.lpBaseOfDll);
				Log.Debug("SizeOfImage: 0x%08X", modInfo.SizeOfImage);
				Log.Debug("EntryPoint: 0x%08X", modInfo.EntryPoint);

				char modBaseName[MAX_PATH];
				WideCharToMultiByte(CP_ACP, 0, szModBaseName, -1, modBaseName, sizeof(modBaseName), NULL, NULL);

				std::string sModBaseName(modBaseName);

				Module *mod = new Module((DWORD)modInfo.lpBaseOfDll, modInfo.SizeOfImage, sModBaseName);

				if ((i == 0) || (StrStrIW(szModFileName, L"0001.dir") != NULL))
				{
					/* Exclude game.exe and SafeDisc module */
					Log.Debug("EXCLUDED");

					mod->Excluded = true;
				}

				ModulesList.push_back(mod);

				mod->GetExportsFromProcess(hProcess);

				Log.Debug("");
			}
		}
	}

	delete[] hMods;
}

DWORD Modules::GetProcAddress(std::string Module, std::string Proc)
{
	for (const auto &mod : ModulesList)
	{
		if (iequals(mod->Name, Module))
		{
			DWORD address = mod->GetProcAddress(Proc);

			if (address != NULL)
			{
				return address;
			}
		}
	}

	return NULL;
}