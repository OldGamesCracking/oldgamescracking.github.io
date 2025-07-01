#pragma once


/* Includes */
#include <Windows.h>


typedef struct call_entry
{
	DWORD CallAt;
	DWORD Target;
	SIZE_T InstructionLen;
	BOOL IsTrampoline;

	struct call_entry *Next;

} CALL_t;


CALL_t* call_list_add(CALL_t *list, DWORD CallAt, DWORD Target, SIZE_T InstructionLen, BOOL IsTrampoline = FALSE);
void call_list_free(CALL_t *list);