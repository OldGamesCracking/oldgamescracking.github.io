#include "virt_jumps.h"
#include "md5.h"


static DWORD decrypt(DWORD val, DWORD key)
{
	return val ^ key;
}

static DWORD get_lookup_key(DWORD rva)
{
	MD5Context md5;

	md5Init(&md5);
	md5Update(&md5, (BYTE*)&rva, sizeof(DWORD));
	md5Finalize(&md5);

	return *(DWORD*)&md5.digest[0];
}

void virt_jumps_init(VIRT_JUMPS_CONTAINER_t* container, VIRT_JUMP_t* dataBase, SIZE_T count, DWORD key_lookup, DWORD key_opSize, DWORD key_opType, DWORD key_opOffset)
{
	container->dataBase = dataBase;
	container->count = count;
	container->nodes = (VIRT_JUMP_NODE_t*)VirtualAlloc(NULL, sizeof(VIRT_JUMP_NODE_t) * count, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	container->key_lookup = key_lookup;
	container->key_opSize = key_opSize;
	container->key_opType = key_opType;
	container->key_opOffset = key_opOffset;

	memset(&container->buckets, 0, sizeof(VIRT_JUMP_NODE_t*) * JUMPS_NUM_BUCKETS);

	VIRT_JUMP_t *nodeData = dataBase;

	for (SIZE_T node = 0; node < count; node++)
	{
		container->nodes[node].data = nodeData;
		container->nodes[node].next = NULL;

		DWORD key = decrypt(nodeData->lookup_enc, key_lookup);
		SIZE_T bucket = key % JUMPS_NUM_BUCKETS;

		/* Add node to hashmap */
		VIRT_JUMP_NODE_t *chain = container->buckets[bucket];

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

void virt_jumps_free(VIRT_JUMPS_CONTAINER_t *container)
{
	if (container->nodes != NULL)
	{
		VirtualFree(container->nodes, 0, MEM_RELEASE);

		container->nodes = NULL;
	}
}

SIZE_T virt_jumps_get_virtualized_code(VIRT_JUMPS_CONTAINER_t* container, DWORD rva, BYTE *buffer)
{
	DWORD lookupKey = get_lookup_key(rva);

	SIZE_T bucket = lookupKey % JUMPS_NUM_BUCKETS;
	VIRT_JUMP_NODE_t *chain = container->buckets[bucket];

	while (chain != NULL)
	{
		DWORD key = decrypt(chain->data->lookup_enc, container->key_lookup);

		if (key == lookupKey)
		{
			SIZE_T opSize = decrypt(chain->data->op_size_enc, container->key_opSize);

			if (opSize <= 6)
			{
				DWORD type = decrypt(chain->data->op_type_enc, container->key_opType);
				buffer[0] = (BYTE)(type >> 16);
				buffer[1] = (BYTE)(type >> 8);
				buffer[2] = (BYTE)(type >> 0);

				DWORD offset = decrypt(chain->data->offset_enc, container->key_opOffset);

				*(DWORD*)&buffer[opSize - sizeof(DWORD)] = offset;

				return opSize;
			}

			return 0;
		}

		chain = chain->next;
	}

	return 0;
}