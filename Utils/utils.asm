.DATA

.CODE

ALIGN 16

	; RCX - modName
	; RDX - funcName
	; R8  - modName length (unicode)
asmCalculateModuleFunctionHash PROC      
  sub rsp, 28h
  cld
  mov r12, rdx
  mov rsi, rcx	              ; Get pointer to modules name (unicode string)
  mov rcx, r8                 ; Set rcx to the length we want to check
  xor r9, r9                  ; Clear r9 which will store the hash of the module name
loop_modname:                 ;
  xor rax, rax                ; Clear rax
  lodsb                       ; Read in the next byte of the name
  cmp al, 'a'                 ; Some versions of Windows use lower case module names
  jl not_lowercase            ;
  sub al, 20h                 ; If so normalise to uppercase
not_lowercase:                ;
  ror r9d, 0dh                ; Rotate right our hash value
  add r9d, eax                ; Add the next byte of the name
  loop loop_modname           ; Loop untill we have read enough
  ; We now have the module hash computed
  push r9                     ; Save the current module hash for later
  xor r9, r9                  ; Clear r9 which will store the hash of the function name
  mov rsi, r12
loop_funcname:                ;
  xor rax, rax                ; Clear rax
  lodsb                       ; Read in the next byte of the ASCII function name
  ror r9d, 0dh                ; Rotate right our hash value
  add r9d, eax                ; Add the next byte of the name
  cmp al, ah                  ; Compare AL (the next byte from the name) to AH (null)
  jne loop_funcname           ; If we have not reached the null terminator, continue
  add r9, [rsp]               ; Add the current module hash to the function hash
finish:
  mov rax, r9
  add rsp, 30h
  ret
asmCalculateModuleFunctionHash ENDP

	; RCX - funcName
asmCalculateFunctionHash PROC
	sub rsp, 28h
	xor rax, rax
	cdq
	cld

	mov rsi, rcx

compute:
	lodsb
	test al, al
	jz finished
	ror edx, 0dh
	add edx, eax
	jmp compute

finished:
	xor rax, rax
	mov eax, edx
	add rsp, 28h
	ret
asmCalculateFunctionHash ENDP

END