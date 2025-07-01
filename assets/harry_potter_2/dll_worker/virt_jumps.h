#pragma once
#include <Windows.h>

#define JUMPS_NUM_BUCKETS		((1UL << 16) - 1)


typedef struct virt_jump
{
	DWORD unknown0;
	struct virt_jump *next;
	SIZE_T op_size_enc;
	DWORD lookup_enc;
	DWORD unknown1;
	DWORD unknown2;
	DWORD unknown3;
	HANDLE hProcess;
	DWORD op_type_enc;
	DWORD offset_enc;
	DWORD op_use_count_enc;
	DWORD unknown4;
} VIRT_JUMP_t;

typedef struct virt_jump_node
{
	VIRT_JUMP_t *data;
	struct virt_jump_node *next;
} VIRT_JUMP_NODE_t;

typedef struct
{
	VIRT_JUMP_t *dataBase;
	SIZE_T count;
	VIRT_JUMP_NODE_t *nodes;
	VIRT_JUMP_NODE_t *buckets[JUMPS_NUM_BUCKETS];

	DWORD key_lookup;
	DWORD key_opSize;
	DWORD key_opType;
	DWORD key_opOffset;
} VIRT_JUMPS_CONTAINER_t;


void virt_jumps_init(VIRT_JUMPS_CONTAINER_t *container, VIRT_JUMP_t *dataBase, SIZE_T count, DWORD key_lookup, DWORD key_opSize, DWORD key_opType, DWORD key_opOffset);
void virt_jumps_free(VIRT_JUMPS_CONTAINER_t *container);
SIZE_T virt_jumps_get_virtualized_code(VIRT_JUMPS_CONTAINER_t *container, DWORD rva, BYTE *buffer);