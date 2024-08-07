nasm -f win32 shellcode_x86.asm -o shellcode_x86.o
ld -m i386pe shellcode_x86.o -o shellcode_x86.exe