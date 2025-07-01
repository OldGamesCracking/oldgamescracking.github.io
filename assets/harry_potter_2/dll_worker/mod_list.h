#pragma once


/* Includes */
#include <Windows.h>


typedef struct mod_entry
{
	DWORD Base;
	DWORD End;
	DWORD Size;

	struct mod_entry* Next;

} MOD_t;


MOD_t* mod_list_add(MOD_t *list, DWORD Base, DWORD Size);
BOOL mod_list_is_in(MOD_t *list, DWORD address);
void mod_list_free(MOD_t *list);