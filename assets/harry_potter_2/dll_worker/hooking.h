#pragma once


/* Includes */
#include <Windows.h>


typedef struct
{
	FARPROC proc;
	union {
		LPVOID resume;
		LPBYTE opcodesBuffer;
	};
	SIZE_T opcodesLen;
	LPVOID callback;
} HOOK_t;


BOOL hook_install(LPCSTR module, LPCSTR proc, LPVOID callback, HOOK_t *const in_out_hook);
BOOL hook_uninstall(HOOK_t *const hook);
BOOL hook_disable_fast(HOOK_t *const hook);
BOOL hook_enable_fast(HOOK_t *const hook);
