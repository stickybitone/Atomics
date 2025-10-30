.DATA

.CODE

ALIGN 16

; https://dennisbabkin.com/blog/?t=how-to-implement-getprocaddress-in-shellcode

GetKernel32ModuleHandle PROC
	mov		rax, gs:[60h]       ; PEB
	mov		rax, [rax + 18h]    ; Ldr
	mov		rax, [rax + 20h]    ; InMemoryOrderModuleList
	mov		rax, [rax]          ; Skip 'this' module and get to ntdll
	mov		rax, [rax]          ; Skip ntdll module and get to kernel32
	mov		rax, [rax + 20h]    ; DllBase for kernel32 --- size_t offset = offsetof(LDR_DATA_TABLE_ENTRY, DllBase) - sizeof(LIST_ENTRY);
	ret
GetKernel32ModuleHandle ENDP

GetAddressOfGetProcAddress PROC
	test	rcx, rcx
	jz		@nothing

	mov		eax, [rcx + 3Ch]    ; e_lfanew
	add		rax, rcx            ; rax = IMAGE_NT_HEADERS64
	lea		rax, [rax + 18h]    ; rax = IMAGE_OPTIONAL_HEADER64  --- size_t offset = offsetof(IMAGE_NT_HEADERS64, OptionalHeader);
	lea		rax, [rax + 70h]    ; rax = IMAGE_DATA_DIRECTORY	 --- size_t offset = offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory);
	lea		rax, [rax + 0h]     ; rax = IMAGE_DATA_DIRECTORY for IMAGE_DIRECTORY_ENTRY_EXPORT

	mov		edx, [rax]          ; rdx = VirtualAddress
	lea		rax, [rcx + rdx]    ; rax = IMAGE_EXPORT_DIRECTORY

	mov		edx, [rax + 18h]    ; rdx = NumberOfNames
	mov		r8d, [rax + 20h]    ; r8 = AddressOfNames
	lea		r8, [rcx + r8]

	mov		r10, 41636f7250746547h   ;	GetProcA
	mov		r11, 0073736572646441h   ;	Address\0

	test	rdx, rdx
	jz		@nothing

@@1:
	mov		r9d, [r8]
	lea		r9, [rcx + r9]      ; function name

	cmp		r10, [r9]
	jnz		@@2
	cmp		r11, [r9 + 7]
	jnz		@@2
	
	; Found our function
	neg		rdx
	mov		r10d, [rax + 18h]   ; r10 = NumberOfNames ---- size_t offset = offsetof(IMAGE_EXPORT_DIRECTORY, NumberOfNames);
	lea		rdx, [r10 + rdx]    ; rdx = function index

	mov		r10d, [rax + 24h]   ; r10 = AddressOfNameOrdinals
	lea		r10, [rcx + r10]
	movzx	rdx, word ptr [r10 + rdx * 2]   ; rdx = index in the function table

	mov		r10d, [rax + 1Ch]   ; r10 = AddressOfFunctions
	lea		r10, [rcx + r10]

	mov		r10d, [r10 + rdx * 4]   ; r10 = offset of possible func addr

	; Check for forwarded function
	mov		edx, [rax + 0]          ; rdx = VirtualAddress
	cmp		r10, rdx
	jb		@nothing

	mov		r11d, [rax + 4]         ; r11 = Size
	add		r11, rdx
	cmp		r10, r11
	jae		@nothing

	lea		rax, [rcx + r10]        ; Got our func addr!

	ret

@@2:
	add		r8, 4
	dec		rdx
	jnz		@@1

@nothing:
	xor		eax, eax
	ret
GetAddressOfGetProcAddress ENDP

END