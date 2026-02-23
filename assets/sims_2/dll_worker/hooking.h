#pragma once


/* Includes */
#include <Windows.h>


class Hook
{
private:
	BOOL Install_Internal(FARPROC Proc, LPVOID Callback);

	FARPROC Proc = NULL;
	SIZE_T OpcodesLen = 0;
	LPVOID Callback = NULL;
	BOOL Enabled = FALSE;

public:
	Hook() = default;
	~Hook();

	BOOL Install(LPCSTR Module, LPCSTR Proc, LPVOID Callback);
	BOOL Install_Raw(FARPROC Proc, LPVOID Callback);
	BOOL Uninstall();
	BOOL Enable();
	BOOL Pause();

	union {
		LPVOID Resume;
		LPBYTE OpcodesBuffer;
	};
};
