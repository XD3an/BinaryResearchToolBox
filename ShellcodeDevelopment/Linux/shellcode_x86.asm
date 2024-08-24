;
; arch='x86', os='linux'
;

section .text
global _start

_start:
	; execve("/bin/sh", 0, 0);
	xor ecx,ecx
    mul ecx
    mov al, 11
    push ecx
    push 68732f2fh     ; "/sh"
    push 6e69622fh     ; "/bin"
    mov ebx, esp
    int 0x80
