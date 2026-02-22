#include <fstream>
#include "Recovery.h"
#include "logging.h"


RecoveryRecord::RecoveryRecord(ZyanU64 Address, const uint8_t *const Buffer, uint32_t Len) :
	_Address(Address),
	_Len(Len)
{
	if (Len > 0)
	{
		_Buffer = new uint8_t[Len];
		
		memcpy(_Buffer, Buffer, Len);
	}
	else
	{
		_Buffer = nullptr;
	}
}

RecoveryRecord::~RecoveryRecord()
{
	if (_Buffer != nullptr)
	{
		delete[] _Buffer;
		_Buffer = nullptr;
		_Len = 0;
	}
}

ZyanU64 RecoveryRecord::Address()
{
	return _Address;
}

uint32_t RecoveryRecord::Len()
{
	return _Len;
}

const uint8_t *RecoveryRecord::Buffer()
{
	return _Buffer;
}

RecoveryFile::RecoveryFile(const std::string &path)
{
	Load(path);
}

RecoveryFile::RecoveryFile()
{
}

RecoveryFile::~RecoveryFile()
{
	if (AutoDump)
	{
		Dump("autodump.bin");
	}

	PurgeRecords();
}

void RecoveryFile::PurgeRecords()
{
	for (auto record : _Records)
	{
		delete record;
	}

	_Records.clear();
}

void RecoveryFile::ParseFile(const uint8_t *const buffer, size_t len)
{
	size_t offset = 0;

	while ((offset + sizeof(uint32_t) + sizeof(ZyanU64)) <= len)
	{
		uint32_t bytes = *(uint32_t*)&buffer[offset];
		offset += sizeof(bytes);

		ZyanU64 address = *(ZyanU64*)&buffer[offset];
		offset += sizeof(address);
		
		size_t remaining = len - offset;

		if (remaining >= bytes)
		{
			AddRecord(address, &buffer[offset], bytes);
		}

		offset += bytes;
	}
}

void RecoveryFile::AddRecord(ZyanU64 Address, const uint8_t *const Buffer, uint32_t Len)
{
	RecoveryRecord *record = new RecoveryRecord(Address, Buffer, Len);

	_Records.push_back(record);
}

void RecoveryFile::Load(const std::string &path)
{
	PurgeRecords();

	std::fstream file(path, std::ios::in | std::ios::binary | std::ios::ate);

	if (!file.good())
	{
		Log.Line("File '%s' does not exist", path.c_str());

		return;
	}

	std::streamsize size = file.tellg();
	file.seekg(0, std::ios::beg);

	uint8_t *buffer = new uint8_t[size];

	if (buffer == nullptr)
	{
		Log.Line("Could not create temp buffer");

		return;
	}

	file.read((char*)buffer, size);

	ParseFile(buffer, size);

	Log.Line("Loaded %d records", _Records.size());

	delete[] buffer;

	file.close();
}

void RecoveryFile::Dump(const std::string &path)
{
	Log.Line("Dumping to '%s'", path.c_str());

	std::ofstream file(path, std::ios::binary | std::ios::trunc);

	if (!file.good())
	{
		Log.Line("File '%s' could not be opened for writing", path.c_str());

		return;
	}

	for (auto record : _Records)
	{
		uint32_t Len = record->Len();
		ZyanU64 Address = record->Address();
		const uint8_t *const Buffer = record->Buffer();

		file.write((char*)&Len, sizeof(Len));
		file.write((char*)&Address, sizeof(Address));
		file.write((char*)Buffer, Len);
	}

	file.close();
}

std::vector<RecoveryRecord*> RecoveryFile::Records()
{
	return _Records;
}