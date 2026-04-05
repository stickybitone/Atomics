.686p
.model flat, C

.data

.code
ALIGN 8

@GetKernel32ModuleHandle@0 PROC
	ASSUME FS:NOTHING

	mov		eax, fs:[30h]       ; PEB
	mov		eax, [eax + 0Ch]    ; Ldr
	mov		eax, [eax + 14h]    ; InMemoryOrderModuleList
	mov		eax, [eax]          ; Skip 'this' module and get to ntdll
	mov		eax, [eax]          ; Skip ntdll module and get to kernel32
	mov		eax, [eax + 10h]    ; DllBase for kernel32 --- size_t offset = offsetof(LDR_DATA_TABLE_ENTRY, DllBase) - sizeof(LIST_ENTRY);

	ret
@GetKernel32ModuleHandle@0 ENDP

@GetAddressOf_GetProcAddress@4 PROC
	ASSUME FS:NOTHING
	;ecx = base address of kernel32.dll when using __fastcall calling convention

	push	ebx
	push	esi
	test	ecx, ecx
	jz		@nothing
	mov		eax, [ecx + 3Ch]        ; e_lfanew
	lea		eax, [eax + ecx + 78h]  ; eax = IMAGE_DATA_DIRECTORY for IMAGE_DIRECTORY_ENTRY_EXPORT
	mov		edx, [eax]              ; edx = VirtualAddress
	lea		eax, [ecx + edx]        ; eax = IMAGE_EXPORT_DIRECTORY
	mov		edx, [eax + 18h]        ; rdx = NumberOfNames ---- size_t offset = offsetof(IMAGE_EXPORT_DIRECTORY, NumberOfNames);
	test	edx, edx
	jz		@nothing
	mov		ebx, [eax + 20h]        ; ebx = AddressOfNames ---- size_t offset = offsetof(IMAGE_EXPORT_DIRECTORY, AddressOfNames);
	lea		ebx, [ecx + ebx]
@@1:
	mov		esi, [ebx]
	lea		esi, [ecx + esi]        ; function name
	cmp		dword ptr [esi], 50746547h          ; GetP
	jnz		@@2
	cmp		dword ptr [esi + 4], 41636f72h      ; rocA
	jnz		@@2
	cmp		dword ptr [esi + 8], 65726464h      ; ddre
	jnz		@@2
	cmp		dword ptr [esi + 11], 00737365h     ; ress\0
	jnz		@@2
	; Found our function
	neg		edx
	mov		esi, [eax + 18h]        ; esi = NumberOfNames ---- size_t offset = offsetof(IMAGE_EXPORT_DIRECTORY, NumberOfNames);
	lea		edx, [esi + edx]        ; edx = function index
	mov		esi, [eax + 24h]        ; r10 = AddressOfNameOrdinals ---- size_t offset = offsetof(IMAGE_EXPORT_DIRECTORY, AddressOfNameOrdinals);
	lea		esi, [ecx + esi]
	movzx	edx, word ptr [esi + edx * 2]   ; edx = index in the function table
	mov		esi, [eax + 1Ch]        ; esi = AddressOfFunctions ---- size_t offset = offsetof(IMAGE_EXPORT_DIRECTORY, AddressOfFunctions);
	lea		esi, [ecx + esi]
	mov		esi, [esi + edx * 4]    ; esi = offset of possible func addr
	; Check for forwarded function
	mov		edx, [eax]              ; edx = VirtualAddress ---- size_t offset = offsetof(IMAGE_DATA_DIRECTORY, VirtualAddress);
	cmp		esi, edx
	jb		@nothing
	mov		ebx, [eax + 4]          ; ebx = Size ---- size_t offset = offsetof(IMAGE_DATA_DIRECTORY, Size);
	add		ebx, edx
	cmp		esi, ebx
	jae		@nothing
	lea		eax, [ecx + esi]        ; Got our func addr!
	pop		esi
	pop		ebx
	ret
@@2:
	add		ebx, 4
	dec		edx
	jnz		@@1

@nothing:
	xor		eax, eax
	pop		esi
	pop		ebx
	ret
@GetAddressOf_GetProcAddress@4 ENDP

END