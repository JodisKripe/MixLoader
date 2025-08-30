#pragma once

#include <Windows.h>
#include <WinDNS.h>
#include <stdio.h>

typedef _Return_type_success_(return >= 0) LONG NTSTATUS;
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define ok(strong, ...) (printf("\033[32m[+] " strong "\033[0m\n", ##__VA_ARGS__))
#define info(strong, ...) (printf("\033[36m[*] " strong "\033[0m\n", ##__VA_ARGS__))
#define error(strong, ...) (printf("\033[31m[-] " strong "\nError Code: %ld\n\033[0m", ##__VA_ARGS__, GetLastError()))
#define yolo()                              \
    printf("[*] Now Exiting. T-T See Ya."); \
    return EXIT_FAILURE;

DWORD NtAllocateVirtualMemoryExSSN = 0;
DWORD NtProtectVirtualMemorySSN = 0;

QWORD NtAllocateVirtualMemoryExSyscall = 0;
QWORD NtProtectVirtualMemorySyscall = 0;


// NtAllocateVirtualMemoryEx
EXTERN_C NTSTATUS NtAllocateVirtualMemoryEx(
	_In_ HANDLE ProcessHandle,
	_Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID * BaseAddress,
	_Inout_ PSIZE_T RegionSize,
	_In_ ULONG AllocationType,
	_In_ ULONG PageProtection,
	_Inout_updates_opt_(ExtendedParameterCount) PMEM_EXTENDED_PARAMETER ExtendedParameters,
	_In_ ULONG ExtendedParameterCount
);

// NtProtectvirtualMemory
EXTERN_C NTSTATUS NtProtectVirtualMemory(
	_In_ HANDLE ProcessHandle,
	_Inout_ PVOID * BaseAddress,
	_Inout_ PSIZE_T RegionSize,
	_In_ ULONG NewProtection,
	_Out_ PULONG OldProtection
);


//SystemFunction032
typedef struct ustring {
	DWORD Length;
	DWORD MaximumLength;
	unsigned char* Buffer;
} ustring;

typedef NTSTATUS(NTAPI* SystemFunction032) (
	_In_ ustring* data,
	_In_ ustring* key
	);


