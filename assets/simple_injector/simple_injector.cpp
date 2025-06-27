#include <Windows.h>
#include <stdio.h>


LPCSTR dll = "dll_game.dll";


int main(int argc, char** argv)
{
	printf("Injector started\n");

	if (argc != 2)
	{
		printf("Usage: simple_injector.exe <game.exe>\n");

		ExitProcess(-1);
	}

	/* Get the entry point */
	FILE* fp_game;
	fp_game = fopen(argv[1], "rb");

	if (fp_game == NULL)
	{
		printf("Could not open target\n");

		ExitProcess(-1);
	}

	IMAGE_DOS_HEADER dosHeader;
	fread(&dosHeader, sizeof(IMAGE_DOS_HEADER), 1, fp_game);

	fseek(fp_game, dosHeader.e_lfanew, SEEK_SET);

	IMAGE_NT_HEADERS ntHeaders;
	fread(&ntHeaders, sizeof(IMAGE_NT_HEADERS), 1, fp_game);

	fclose(fp_game);

	DWORD entryPoint = ntHeaders.OptionalHeader.ImageBase + ntHeaders.OptionalHeader.AddressOfEntryPoint;

	printf("Entry point at 0x%08X\n", entryPoint);

	STARTUPINFOA si = { 0 };
	si.cb = sizeof(STARTUPINFOA);

	GetStartupInfoA(&si);

	PROCESS_INFORMATION pi = { 0 };

	printf("Creating process\n");

	if (!CreateProcessA(argv[1], NULL, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi))
	{
		printf("Could not create process\n");
		ExitProcess(-1);
	}

	printf("Process created\n");

	printf("Allocating memory\n");

	LPCSTR nameBuffer = (LPCSTR)VirtualAllocEx(pi.hProcess, NULL, 0x100, MEM_COMMIT, PAGE_READWRITE);

	if (nameBuffer == NULL)
	{
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		
		printf("Could not alloc memory\n");
		ExitProcess(-1);
	}

	printf("Memory allocated\n");

	printf("Writing DLL path to process\n");

	if (!WriteProcessMemory(pi.hProcess, (LPVOID)nameBuffer, dll, strlen(dll) + 1, NULL))
	{
		VirtualFreeEx(pi.hProcess, (LPVOID)nameBuffer, 0, MEM_RELEASE);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);

		printf("Could not write to memory\n");
		ExitProcess(-1);
	}

	printf("Memory written\n");

	HMODULE hKernel = GetModuleHandleA("kernel32.dll");

	if (hKernel == NULL)
	{
		VirtualFreeEx(pi.hProcess, (LPVOID)nameBuffer, 0, MEM_RELEASE);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);

		printf("Could not get module handle\n");
		ExitProcess(-1);
	}

	printf("Got module handle\n");

	FARPROC hLoadLibrary = GetProcAddress(hKernel, "LoadLibraryA");

	if (hLoadLibrary == NULL)
	{
		VirtualFreeEx(pi.hProcess, (LPVOID)nameBuffer, 0, MEM_RELEASE);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);

		printf("Could not get proc address\n");
		ExitProcess(-1);
	}

	printf("Got proc address\n");

	byte jmp[2] = { 0xeb, 0xfe };
	byte orgBytes[sizeof(jmp)];

	printf("Installing JMP\n");

	DWORD oldProtect;
	if (!VirtualProtectEx(pi.hProcess, (LPVOID)entryPoint, sizeof(jmp), PAGE_EXECUTE_READWRITE, &oldProtect))
	{
		VirtualFreeEx(pi.hProcess, (LPVOID)nameBuffer, 0, MEM_RELEASE);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);

		printf("Could not set protection\n");
		ExitProcess(-1);
	}

	if (!ReadProcessMemory(pi.hProcess, (LPVOID)entryPoint, &orgBytes[0], sizeof(jmp), NULL))
	{
		VirtualFreeEx(pi.hProcess, (LPVOID)nameBuffer, 0, MEM_RELEASE);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);

		printf("Could not read from memory\n");
		ExitProcess(-1);
	}

	if (!WriteProcessMemory(pi.hProcess, (LPVOID)entryPoint, &jmp[0], sizeof(jmp), NULL))
	{
		VirtualFreeEx(pi.hProcess, (LPVOID)nameBuffer, 0, MEM_RELEASE);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);

		printf("Could not write to memory\n");
		ExitProcess(-1);
	}

	printf("JMP installed\n");

	/** Let it run a bit */
	ResumeThread(pi.hThread);

	Sleep(1000);

	SuspendThread(pi.hThread);

	printf("Restoring OEP\n");

	if (!WriteProcessMemory(pi.hProcess, (LPVOID)entryPoint, &orgBytes[0], sizeof(jmp), NULL))
	{
		VirtualFreeEx(pi.hProcess, (LPVOID)nameBuffer, 0, MEM_RELEASE);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);

		printf("Could not write to memory\n");
		ExitProcess(-1);
	}

	if (!VirtualProtectEx(pi.hProcess, (LPVOID)entryPoint, sizeof(jmp), oldProtect, &oldProtect))
	{
		VirtualFreeEx(pi.hProcess, (LPVOID)nameBuffer, 0, MEM_RELEASE);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);

		printf("Could not set protection\n");
		ExitProcess(-1);
	}

	printf("OEP restored\n");

	printf("Injecting DLL\n");

	HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)hLoadLibrary, (LPVOID)nameBuffer, 0, NULL);

	if (hThread == NULL)
	{
		VirtualFreeEx(pi.hProcess, (LPVOID)nameBuffer, 0, MEM_RELEASE);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);

		printf("Could not create remote thread\n");
		ExitProcess(-1);
	}

	printf("Remote thread created\n");

	WaitForSingleObject(hThread, INFINITE);

	printf("Injection done\n");

	Sleep(3000);

	ResumeThread(pi.hThread);

	printf("Thread resumed\n");

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	ExitProcess(0);
}