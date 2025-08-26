.data

; These externs being pulled from the c prog

extern NtAllocateVirtualMemoryExSSN:DWORD
extern NtAllocateVirtualMemoryExSyscall:QWORD
extern NtProtectVirtualMemorySSN:DWORD
extern NtProtectVirtualMemorySyscall:QWORD



.code


NtAllocateVirtualMemoryEx PROC
		mov r10, rcx
		mov eax, NtAllocateVirtualMemoryExSSN
		jmp qword ptr NtAllocateVirtualMemoryExSyscall
		ret
NtAllocateVirtualMemoryEx ENDP

NtProtectVirtualMemory PROC
		mov r10, rcx
		mov eax, NtProtectVirtualMemorySSN
		jmp qword ptr NtProtectVirtualMemorySyscall
		ret
NtProtectVirtualMemory ENDP

end
