#pragma once

#include <Windows.h>
#include <vector>
#include <map>
#include <set>

class IntermodularCall
{
public:
	IntermodularCall(DWORD CallAt, DWORD Destination, bool ByRegister, bool IsJump) : CallAt(CallAt), Destination(Destination), ByRegister(ByRegister), IsJump(IsJump) {}

	DWORD CallAt;
	DWORD Destination;
	size_t IATIndex;
	bool ByRegister;
	bool IsJump;
};

class Imports
{
private:
	void Clear();
	void PopulateAddressesNotInIAT();
	void ReIndexCalls();
	
	DWORD *IAT = nullptr;
	size_t IATEntries = 0;

	std::set<DWORD> AddressesNotInIAT;
	std::vector<IntermodularCall> Calls;
	std::map<DWORD, size_t> IATLookup;

public:
	Imports() = default;
	~Imports();

	void AddIAT(DWORD *IAT, size_t Entries);
	void AddCall(DWORD CallAt, DWORD Destination, bool ByRegister=false, bool IsJump=false);
	void SetThunk(size_t Index, DWORD ProcAddress);

	bool InUse(size_t Index, DWORD &out_Proc);

	void RebuildIAT();
	size_t GetIATEntries();
	void GetIAT(DWORD *const buffer);
	const std::vector<IntermodularCall>& GetCalls();
};