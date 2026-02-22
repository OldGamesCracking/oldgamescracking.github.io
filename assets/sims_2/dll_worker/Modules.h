#pragma once


#include <Windows.h>
#include <unordered_map>
#include <vector>


class Proc
{
public:
	Proc() = default;
	~Proc() = default;

	DWORD Address;
	WORD Ordinal;
	WORD OrdinalBase;
	std::string Name;
};

class Module
{
private:
	std::unordered_map<DWORD, Proc*> ExportsLookup;

public:
	Module(DWORD Base, DWORD Size, std::string Name);
	~Module();

	void Clear();

	bool IsAddressInModule(DWORD address);
	Proc* GetProcAt(DWORD address);

	void GetExportsFromProcess(HANDLE hProcess);

	DWORD GetProcAddress(std::string Proc);

	const std::unordered_map<DWORD, Proc*>& Exports();

	DWORD Base;
	DWORD End;
	DWORD Size;
	std::string Name;
	bool Excluded = false;
};

class Modules
{
private:
	std::vector<Module*> ModulesList;

public:
	Modules() = default;
	~Modules();

	void Clear();

	Module* Add(DWORD Base, DWORD Size, std::string Name);

	Module* GetModuleAt(DWORD address);

	void GetModulesFromProcess(HANDLE hProcess);

	DWORD GetProcAddress(std::string Module, std::string Proc);
};