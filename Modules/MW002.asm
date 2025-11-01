.DATA

.CODE

ALIGN 16

; https://raw.githubusercontent.com/V-i-x-x/Assembly-Shellcode64/refs/heads/main/Shellcode64/Shellcode.asm

GetKernel32ModuleHandle PROC
	sub rsp, 28h
	; Parse PEB and find kernel32
	find_kernel32:   
		xor rcx, rcx					; RCX = 0
		mov rsi, gs:[rcx + 60h]			; RAX = PEB
		mov rsi, [rsi + 18h]			; RAX = PEB->Ldr
		mov rsi, [rsi + 30h]			; RSI = PEB->Ldr.InMemOrder
		mov dl, 4bh

    next_module:
		mov rbx, [rsi + 10h]			; EBX = InInitOrder[X].base_address
		mov rdi, [rsi + 40h]			; EDI = InInitOrder[X].module_name
		mov rsi, [rsi]					; ESI = InInitOrder[X].flink (next)
		cmp [rdi + 12*2], cx			; (unicode) modulename[12] == 0x00 ?
		jne next_module					; No: try next module
		cmp [rdi], dl					; modulename starts with "K"
		jne next_module					; No: try next module

		mov rax, rbx
		add rsp, 28h
		ret
GetKernel32ModuleHandle ENDP

; RCX - kernel32.dll.base_address
; RDX - GetProcAddressHash
GetAddressOfGetProcAddress PROC
		sub rsp, 28h
		mov r15, rsp
		mov [r15+08h], rdx
    find_function:
		mov rbx, rcx					
		;; dt _IMAGE_DOS_HEADER @rbx
		;push rax
		xor rax, rax
        mov eax, [rbx + 3ch]			; Offset to PE Signature 
		;; dt _IMAGE_NT_HEADERS64 @rbx+@eax
		;; dt _IMAGE_OPTIONAL_HEADER64 @rbx+@eax+18h
		add rax, 88h
		;; dt _IMAGE_DATA_DIRECTORY @rbx+@rax
		xor rdi, rdi
		;; _IMAGE_EXPORT_DIRECTORY -> see win32 documentation 
        mov edi, [rbx + rax]			; Export Table Directory RVA
        add rdi, rbx					; Export Table Directory VMA
        mov ecx, [rdi + 18h]			; NumberOfNames
        mov eax, [rdi + 20h]			; AddressOfNames RVA
        add rax, rbx					; AddressOfNames VMA
        mov [r15 + 10h], rax			; Save AddressOfNames VMA for later

	find_function_loop:
		jecxz find_function_finished    ; Jump to the end if ECX is 0
		dec rcx							; Decrement our names counter
		mov rax, [r15 + 10h]			; Restore AddressOfNames VMA
		xor rsi, rsi
		mov esi, [rax + rcx * 4]		; Get the RVA of the symbol name
		add rsi, rbx					; Set ESI to the VMA of the current symbol name

	compute_hash:
		xor rax , rax					; NULL EAX
		xor r9, r9						; NULL EDX
		cld                             ; Clear direction

	compute_hash_again:
		lodsb                           ; Load the next byte from esi into al
		test al, al						; Check for NULL terminator
		jz compute_hash_finished		; If the ZF is set, we've hit the NULL term
		ror r9d, 0dh					; Rotate edx 13 bits to the right
		add r9, rax						; Add the new byte to the accumulator
		jmp compute_hash_again			; Next iteration

	compute_hash_finished:

	find_function_compare:
		cmp r9, [rsp + 08h]				; Compare the computed hash with the requested hash
		jnz find_function_loop			; If it doesn't match go back to find_function_loop
		xor rdx, rdx
		mov edx, [rdi + 24h]			; AddressOfNameOrdinals RVA
		add rdx, rbx					; AddressOfNameOrdinals VMA
		mov cx,  [rdx + 2 * rcx]		; Extrapolate the function's ordinal
		mov edx, [rdi + 1ch]			; AddressOfFunctions RVA
		add rdx, rbx					; AddressOfFunctions 
		xor eax, eax
		mov eax, [rdx + 4 * rcx]		; Get the function RVA
		add rax, rbx					; Get the function VMA
		;mov [rsp], rax					; Save

	find_function_finished:
		add rsp, 28h
		ret
GetAddressOfGetProcAddress ENDP