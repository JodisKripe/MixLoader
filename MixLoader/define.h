#pragma once
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

DWORD NtOpenProcessSSN = 0;
DWORD NtAllocateVirtualMemoryExSSN = 0;
DWORD NtProtectVirtualMemorySSN = 0;
DWORD NtWriteVirtualMemorySSN = 0;
DWORD NtCreateThreadExSSN = 0;
DWORD NtCloseSSN = 0;
QWORD NtOpenProcessSyscall = 0;
QWORD NtAllocateVirtualMemoryExSyscall = 0;
QWORD NtProtectVirtualMemorySyscall = 0;
QWORD NtWriteVirtualMemorySyscall = 0;
QWORD NtCreateThreadExSyscall = 0;
QWORD NtCloseSyscall = 0;

// NtOpenProcess
typedef struct _OBJECT_ATTRIBUTES
{
	ULONG Length;                       // 0x0
	VOID* RootDirectory;                // 0x8
	struct _UNICODE_STRING* ObjectName; // 0x10
	ULONG Attributes;                   // 0x18
	VOID* SecurityDescriptor;           // 0x20
	VOID* SecurityQualityOfService;     // 0x28
} OBJECT_ATTRIBUTES, * PCOBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID
{
	VOID* UniqueProcess; // 0x0
	VOID* UniqueThread;  // 0x8
} CLIENTID, * PCLIENT_ID;

EXTERN_C NTSTATUS NtOpenProcess(
	_Out_ PHANDLE ProcessHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ PCOBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PCLIENT_ID ClientId);

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

//NtWriteVirtualMemory
EXTERN_C NTSTATUS NtWriteVirtualMemory(
	_In_ HANDLE ProcessHandle,
	_In_opt_ PVOID BaseAddress,
	_In_reads_bytes_(NumberOfBytesToWrite) PVOID Buffer,
	_In_ SIZE_T NumberOfBytesToWrite,
	_Out_opt_ PSIZE_T NumberOfBytesWritten
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

//unsigned char rc4Key[] = { 0xde,0xad,0xbe,0xef,0xca,0xfe,0xba,0xbe };
//size_t szRc4Key = sizeof(rc4Key);

typedef struct _PS_ATTRIBUTE
{
	ULONG_PTR Attribute;
	SIZE_T Size;
	union
	{
		ULONG_PTR Value;
		PVOID ValuePtr;
	};
	PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
	SIZE_T TotalLength;
	PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

//NtCreateThreadEx
EXTERN_C NTSTATUS NtCreateThreadEx(
	_Out_ PHANDLE ThreadHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ PCOBJECT_ATTRIBUTES ObjectAttributes,
	_In_ HANDLE ProcessHandle,
	_In_ PVOID StartRoutine,
	_In_opt_ PVOID Argument,
	_In_ ULONG CreateFlags, // THREAD_CREATE_FLAGS_*
	_In_ SIZE_T ZeroBits,
	_In_ SIZE_T StackSize,
	_In_ SIZE_T MaximumStackSize,
	_In_opt_ PPS_ATTRIBUTE_LIST AttributeList
);

#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x00000001

//NtClose
EXTERN_C NTSTATUS NtClose(
	_In_ _Post_ptr_invalid_ HANDLE Handle
);
