#include <algorithm>
#include <iterator>
#include "Imports.h"
#include "Logging.h"

Imports::~Imports() {
	Clear();
}

void Imports::Clear()
{
	if (IAT != nullptr)
	{
		delete[] IAT;
		IAT = nullptr;
	}

	IATEntries = 0;

	IATLookup.clear();

	Calls.clear();

	AddressesNotInIAT.clear();
}

void Imports::PopulateAddressesNotInIAT()
{
	if (AddressesNotInIAT.size() == 0)
	{
		Log.Line("No Addresses need fixing");

		return;
	}

	Log.Line("Need to fix %u addresses in the IAT", AddressesNotInIAT.size());

	std::vector<DWORD> newAddresses(AddressesNotInIAT.begin(), AddressesNotInIAT.end());

	std::sort(newAddresses.begin(), newAddresses.end());

	size_t index = 0;

	for (const DWORD &address : newAddresses)
	{
		while (index < IATEntries)
		{
			if (IAT[index] == 0)
			{
				Log.Debug("Placing %08X at thunk #%u", address, index);

				IAT[index] = address;

				IATLookup.insert(std::pair<DWORD, size_t>(address, index));

				index++;

				break;
			}

			index++;
		}

		if (index >= IATEntries)
		{
			Log.Error("IAT Overflow");

			break;
		}
	}

	AddressesNotInIAT.clear();
}

void Imports::ReIndexCalls()
{
	for (auto &call : Calls)
	{
		auto it = IATLookup.find(call.Destination);

		if (it == IATLookup.end())
		{
			Log.Error("Could not find IAT index");

			continue;
		}

		call.IATIndex = it->second;
	}
}

void Imports::AddIAT(DWORD *IAT, size_t Entries)
{
	this->IAT = new DWORD[Entries];

	if (this->IAT == nullptr)
	{
		Log.Error("Could not create IAT buffer");
	}

	memcpy(this->IAT, IAT, Entries * sizeof(DWORD));

	IATEntries = Entries;

	for (size_t entry = 0; entry < Entries; entry++)
	{
		DWORD address = IAT[entry];

		if (address == 0)
		{
			continue;
		}

		auto it = IATLookup.find(address);

		if (it != IATLookup.end())
		{
			Log.Warning("Address %08X already present in IAT", address);

			continue;
		}

		IATLookup.insert(std::pair<DWORD, size_t>(address, entry));
	}
}

void Imports::AddCall(DWORD CallAt, DWORD Destination, bool ByRegister, bool IsJump)
{
	auto it = IATLookup.find(Destination);

	if (it == IATLookup.end())
	{
		AddressesNotInIAT.insert(Destination);
	}
	else
	{
		Log.Line("Destination address already in IAT");
	}

	Calls.push_back(IntermodularCall(CallAt, Destination, ByRegister, IsJump));
}

bool Imports::InUse(size_t Index, DWORD &out_Proc)
{
	if (Index > IATEntries)
	{
		Log.Error("Invalid thunk index");

		return false;
	}

	if (IAT[Index] == 0)
	{
		return false;
	}

	out_Proc = IAT[Index];

	return true;
}

void Imports::SetThunk(size_t Index, DWORD ProcAddress)
{
	if (Index > IATEntries)
	{
		Log.Error("Invalid thunk index");

		return;
	}

	if (IAT[Index] == 0)
	{
		/* Free slot */
		IAT[Index] = ProcAddress;
	}
	else
	{
		if (IAT[Index] != ProcAddress)
		{
			Log.Error("Thunk index %d already in use", Index);

			return;
		}
	}

	auto itLU = IATLookup.find(ProcAddress);

	if (itLU == IATLookup.end())
	{
		IATLookup.insert(std::pair<DWORD, size_t>(ProcAddress, Index));
	}

	AddressesNotInIAT.erase(ProcAddress);
}

void Imports::RebuildIAT()
{
	PopulateAddressesNotInIAT();
	ReIndexCalls();
}

size_t Imports::GetIATEntries()
{
	return IATEntries;
}

void Imports::GetIAT(DWORD *const buffer)
{
	if ((buffer == nullptr) || (IAT == nullptr) || (IATEntries == 0))
	{
		return;
	}

	memcpy(buffer, IAT, sizeof(DWORD) * IATEntries);
}

const std::vector<IntermodularCall>& Imports::GetCalls()
{
	return Calls;
}