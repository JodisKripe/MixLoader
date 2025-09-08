# MixLoader
Shellcode Loader With a Cocktail of Techniques

## Current Flavour
- [x] Indirect Syscalls
- [x] Halos Gate for rebuilding ntdll
- [x] RC4 encryption for the shellcode
- [x] OLLVM compilation for Obfuscation
- [x] Fetch shellcode and key from a remote source
- [x] Use Function callback
- [x] PEB Parsing to detect debugging.
- [ ] Dynamic PEB Parsing, without hardcoded call to the PEB, i.e. mov %%gs:0x30,rcx or something.

## Post compilation steps
- Sign the Binary (Legitimate Certificate or LazySign)

## Branch Description
- This will fetch the shellcode and the rc4 key from a remote source.
- The execution will be done by a Function callback. The current function being used for callback is EnumWindows.
- PEB Parsing to detect debugging.

## Overall Goals
- [X] Add Branch for AES Encryption for the shellcode
- [X] Add Branch for PEB Parsing and shutting down if the binary is being debugged (detected by Microsoft Defender Cloud Protection)
- [ ] Add sleep obfuscation 

## Milestones
- [X] Windows Defender + Cloud Delivered Protection [Windows 11] (September 2025)
- [ ] Elastic EDR

## O-LLVM
The current configuration picks the clang-cl.exe binary from a [github repo](https://github.com/wwh1004/ollvm-16/)
- [ ] Compile O-LLVM yourself