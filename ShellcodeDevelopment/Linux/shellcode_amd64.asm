;
; arch='amd64', os='linux'
;

section .text
global _start

_start:
	; execve("/bin/sh", 0, 0);
	;         \_rdi     \_rsi ... (rdx, r10, r8, r9, stack)
	xor     rdi, rdi
	xor     rsi, rsi
	xor     rdx, rdx                                              

    push    rdi
	mov     qword rbx, '//bin/sh'
	push    rbx
	mov     rdi, rsp
	mov 	rsi, 0
	mov  	rdx, 0
    mov     al, 0x3b                                              
    syscall	
