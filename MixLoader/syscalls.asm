.data

; These externs being pulled from the c prog
extern NtOpenProcessSSN:DWORD
extern NtOpenProcessSyscall:QWORD
extern NtAllocateVirtualMemoryExSSN:DWORD
extern NtAllocateVirtualMemoryExSyscall:QWORD
extern NtProtectVirtualMemorySSN:DWORD
extern NtProtectVirtualMemorySyscall:QWORD
extern NtWriteVirtualMemorySSN:DWORD
extern NtWriteVirtualMemorySyscall:QWORD
extern NtCreateThreadExSSN:DWORD
extern NtCreateThreadExSyscall:QWORD
extern NtCloseSSN:DWORD
extern NtCloseSyscall:QWORD


.code

NtOpenProcess PROC
		mov r10, rcx
		mov eax, NtOpenProcessSSN
		jmp qword ptr NtOpenProcessSyscall
		ret
NtOpenProcess ENDP

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

NtWriteVirtualMemory PROC
		mov r10, rcx
		mov eax, NtWriteVirtualMemorySSN
		jmp qword ptr NtWriteVirtualMemorySyscall
		ret
NtWriteVirtualMemory ENDP

NtCreateThreadEx PROC
		mov r10, rcx
		mov eax, NtCreateThreadExSSN
		jmp qword ptr NtCreateThreadExSyscall
		ret
NtCreateThreadEx ENDP

NtClose PROC
		mov r10, rcx
		mov eax, NtCloseSSN
		jmp qword ptr NtCloseSyscall
		ret
NtClose ENDP

end
