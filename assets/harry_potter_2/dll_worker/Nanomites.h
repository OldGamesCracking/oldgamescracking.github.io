#pragma once
#include <Windows.h>


#define NANOMITES_NUM_BUCKETS	((1UL << 16) - 1)
#define SALT_BASE				0x4D90AD00
#define SALT_XOR				0x111EE638


typedef struct
{
	DWORD nodeValue;
	BYTE data[16];
} NANOMITE_RAW_DATA_t;

typedef struct
{
	BYTE size;
	BYTE offset;
	BYTE unknown0;
	BYTE data[7];
	BYTE unknown1;
	BYTE unknown2;
	DWORD checksum;
} NANOMITE_DATA_t;

typedef struct node
{
	NANOMITE_RAW_DATA_t *data;
	struct node *next;
} NODE_t;

typedef struct
{
	NANOMITE_RAW_DATA_t *dataBase;
	SIZE_T count;
	NODE_t *nodes;
	NODE_t *buckets[NANOMITES_NUM_BUCKETS];
	DWORD gameSecret;
} NANOMITE_CONTAINER_t;


void nanomites_init(NANOMITE_CONTAINER_t *container, NANOMITE_RAW_DATA_t *dataBase, SIZE_T count, DWORD gameSecret);
void nanomites_free(NANOMITE_CONTAINER_t *container);
NANOMITE_RAW_DATA_t* nanomites_get_raw_data(NANOMITE_CONTAINER_t *container, DWORD rva, DWORD *out_key, DWORD *out_checksum);
void nanomites_get_data(NANOMITE_RAW_DATA_t *rawData, NANOMITE_DATA_t *data, DWORD key);