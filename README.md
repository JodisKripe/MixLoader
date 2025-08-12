# MixLoader
Shellcode Loader With a Cocktail of Techniques

## Current Flavour
- [x] Indirect Syscalls
- [x] Halos Gate for rebuilding ntdll
- [x] RC4 encryption for the shellcode
- [x] OLLVM compilation for Obfuscation
- [ ] Fetch shellcode and key from a remote source

## Post compilation steps
- Sign the Binary (Legitimate Certificate or LazySign)

## Branch Description
- This will fetch the shellcode and the rc4 key from a remote source, rest is the same as diskload
