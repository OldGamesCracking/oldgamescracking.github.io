#pragma once


/* Includes */
#include <Windows.h>


class Hook
{
private:
	BOOL Install_Internal(FARPROC Proc, LPVOID Callback);

	SIZE_T OpcodesLen = 0;
	BOOL Enabled = FALSE;
	LPBYTE OriginalBytesBuffer = NULL;

public:
	Hook() = default;
	Hook(FARPROC Proc, LPVOID Callback = NULL)
	{
		Install_Raw(Proc, Callback);
	}
	~Hook();

	BOOL Install(LPCSTR Module, LPCSTR Proc, LPVOID Callback = NULL);
	BOOL Install_Raw(FARPROC Proc, LPVOID Callback = NULL);
	BOOL Uninstall();
	BOOL Enable();
	BOOL Pause();

	union {
		LPVOID Resume;
		LPBYTE OpcodesBuffer;
	};

	FARPROC Proc = NULL;
	LPVOID Callback = NULL;
};
