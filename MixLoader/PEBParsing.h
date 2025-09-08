#pragma once

// PEBParsing for Debugging
// Parsing the Process Environment Block to see if the binary is being debugged or not.

void* get_teb_64() {
	void* teb;
	asm("mov %%gs:0x30, %0" : "=r"(teb));
	return teb;
}

void* get_debuginfo_x64() {
	void* teb = get_teb_64();
	void* debug;
	asm("mov %[teb], %%rax\n\t"
		"mov 0x60(%%rax), %%rax\n\t"
		"mov 0x02(%%rax), %[debug]"
		: [debug] "=r"(debug)
		: [teb] "r" (teb)
		: "rax");
	return debug;
}

BOOL isdebugging_x64() {
	int debug = (BYTE)get_debuginfo_x64();
	if (debug == 0) {
		return FALSE; // Not debugging
	}
	else {
		return TRUE; // Debugging is enabled
	}
}