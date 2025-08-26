# MixLoader
Shellcode Loader With a Cocktail of Techniques

## Current Flavour
- [x] Indirect Syscalls
- [x] Halos Gate for rebuilding ntdll
- [x] AES encryption for the shellcode
- [x] OLLVM compilation for Obfuscation
- [x] Fetch shellcode and key from a remote source

## Post compilation steps
- Sign the Binary (Legitimate Certificate or LazySign)

## Branch Description
- This will fetch the shellcode and the rc4 key from a remote source, rest is the same as diskload

## O-LLVM
The current configuration picks the clang-cl.exe binary from a [github repo](https://github.com/wwh1004/ollvm-16/)
- [ ] Compile O-LLVM yourself