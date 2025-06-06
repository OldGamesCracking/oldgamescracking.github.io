#include <Windows.h>


typedef struct
{
	FARPROC proc;
	union {
		LPVOID resume;
		LPBYTE opcodesBuffer;
	};
	SIZE_T opcodesLen;
} HOOK_t;


BOOL hook_install(LPCSTR module, LPCSTR proc, LPVOID callback, HOOK_t *const in_out_hook);
BOOL hook_uninstall(HOOK_t *const hook);
