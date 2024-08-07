nasm -f elf32 shellcode_x86.asm -o shellcode_x86.o
ld -m elf_i386 shellcode_x86.o -o shellcode_x86
