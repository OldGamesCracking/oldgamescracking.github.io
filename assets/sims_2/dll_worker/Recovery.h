#pragma once


#include <cinttypes>
#include <vector>
#include <Zydis.h>


class RecoveryRecord
{
private:
	ZyanU64 _Address;
	uint32_t _Len;
	uint8_t *_Buffer;

public:
	RecoveryRecord(ZyanU64 Address, const uint8_t *const Buffer, uint32_t Len);
	~RecoveryRecord();

	ZyanU64 Address();
	uint32_t Len();
	const uint8_t* Buffer();
};

class RecoveryFile
{
private:
	void PurgeRecords();
	void ParseFile(const uint8_t *const buffer, size_t len);

	std::vector<RecoveryRecord*> _Records;

public:
	RecoveryFile(const std::string &path);
	RecoveryFile();
	~RecoveryFile();

	void AddRecord(ZyanU64 Address, const uint8_t *const Buffer, uint32_t Len);

	void Load(const std::string &path);
	void Dump(const std::string &path);

	std::vector<RecoveryRecord*> Records();
	
	bool AutoDump = false;
};