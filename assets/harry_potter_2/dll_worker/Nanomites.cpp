#include <stdlib.h>
#include "Nanomites.h"
#include "md5.h"


DWORD static nanomites_get_salt(NANOMITE_CONTAINER_t *container)
{
	DWORD salt = SALT_BASE + container->gameSecret;
	
	salt &= 0xffffff00;

	salt ^= SALT_XOR;

	return salt;
}

void nanomites_init(NANOMITE_CONTAINER_t *container, NANOMITE_RAW_DATA_t *dataBase, SIZE_T count, DWORD gameSecret)
{
	container->gameSecret = gameSecret;

	container->dataBase = dataBase;
	container->count = count;
	container->nodes = (NODE_t*)VirtualAlloc(NULL, sizeof(NODE_t) * count, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	memset(&container->buckets, 0, sizeof(NODE_t*) * NANOMITES_NUM_BUCKETS);

	NANOMITE_RAW_DATA_t *nodeData = dataBase;

	for (SIZE_T node = 0; node < count; node++)
	{
		container->nodes[node].data = nodeData;
		container->nodes[node].next = NULL;

		DWORD key = nodeData->nodeValue;
		SIZE_T bucket = key % NANOMITES_NUM_BUCKETS;

		/* Add node to hashmap */
		NODE_t *chain = container->buckets[bucket];

		if (chain == NULL)
		{
			container->buckets[bucket] = &container->nodes[node];
		}
		else
		{
			while (chain->next != NULL)
			{
				chain = chain->next;
			}

			chain->next = &container->nodes[node];
		}

		nodeData++;
	}
}

void nanomites_free(NANOMITE_CONTAINER_t *container)
{
	if (container->nodes != NULL)
	{
		VirtualFree(container->nodes, 0, MEM_RELEASE);
		
		container->nodes = NULL;
	}
}

NANOMITE_RAW_DATA_t* nanomites_get_raw_data(NANOMITE_CONTAINER_t* container, DWORD rva, DWORD *out_key, DWORD *out_checksum)
{
	DWORD salt = nanomites_get_salt(container);
	salt *= rva;
	
	BYTE hashData[2 * sizeof(DWORD)];
	*(DWORD*)&hashData[0] = rva;
	*(DWORD*)&hashData[sizeof(DWORD)] = salt;

	MD5Context md5;

	md5Init(&md5);
	md5Update(&md5, &hashData[0], sizeof(hashData));
	md5Finalize(&md5);

	DWORD lookupKey = _byteswap_ulong(*(DWORD*)&md5.digest[0 * sizeof(DWORD)]);
	DWORD decryptKey = *(DWORD*)&md5.digest[1 * sizeof(DWORD)];
	// DWORD unknown = _byteswap_ulong(*(DWORD*)&md5.digest[2 * sizeof(DWORD)]);
	DWORD checksum = *(DWORD*)&md5.digest[3 * sizeof(DWORD)];

	SIZE_T bucket = lookupKey % NANOMITES_NUM_BUCKETS;
	NODE_t *chain = container->buckets[bucket];

	while (chain != NULL)
	{
		if (chain->data->nodeValue == lookupKey)
		{
			*out_key = decryptKey;
			*out_checksum = checksum;

			return chain->data;
		}

		chain = chain->next;
	}

	return NULL;
}

void nanomites_get_data(NANOMITE_RAW_DATA_t *rawData, NANOMITE_DATA_t *data, DWORD key)
{
	for (SIZE_T b = 0; b < sizeof(NANOMITE_DATA_t); b++)
	{
		((BYTE*)data)[b] = rawData->data[b] ^ ((BYTE*)&key)[b % sizeof(DWORD)];
	}
}