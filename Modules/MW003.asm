.DATA 

.CODE

ALIGN 16

; https://raw.githubusercontent.com/rapid7/metasploit-framework/refs/heads/master/external/source/shellcode/windows/x64/src/block/block_api.asm

; RCX - hash
GetModuleAndFunction PROC
  xor r10, r10
  mov r10, rcx
api_call:
  xor rdx, rdx
  mov rdx, gs:[rdx+60h]       ; Get a pointer to the PEB
  mov rdx, [rdx+18h]          ; Get PEB->Ldr
  mov rdx, [rdx+20h]          ; Get the first module from the InMemoryOrder module list
next_mod:                     ;
  mov rsi, [rdx+50h]          ; Get pointer to modules name (unicode string)
  movzx rcx, byte ptr [rdx+4ah]          ; Set rcx to the length we want to check
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
  push rdx                    ; Save the current position in the module list for later
  push r9                     ; Save the current module hash for later
  ; Proceed to itterate the export address table,
  mov rdx, [rdx+20h]          ; Get this modules base address
  mov eax, [rdx+3ch]          ; Get PE header
  add rax, rdx                ; Add the modules base address
      ;cmp [rax+18h], 020Bh        ; is this module actually a PE64 executable?
      ; this test case covers when running on wow64 but in a native x64 context via nativex64.asm and
      ; their may be a PE32 module present in the PEB's module list, (typicaly the main module).
      ; as we are using the win64 PEB ([gs:96]) we wont see the wow64 modules present in the win32 PEB ([fs:48])
      ;jne get_next_mod1           ; if not, proceed to the next module
  mov eax, [rax+88h]          ; Get export tables RVA
  test rax, rax               ; Test if no export address table is present
  jz get_next_mod1            ; If no EAT present, process the next module
  add rax, rdx                ; Add the modules base address
  push rax                    ; Save the current modules EAT
  mov ecx, [rax+18h]   ; Get the number of function names
  mov r8d, [rax+20h]   ; Get the rva of the function names
  add r8, rdx                 ; Add the modules base address
  ; Computing the module hash + function hash
get_next_func:                ;
  jrcxz get_next_mod          ; When we reach the start of the EAT (we search backwards), process the next module
  dec rcx                     ; Decrement the function name counter
  mov esi, [r8+rcx*04h]       ; Get rva of next module name
  add rsi, rdx                ; Add the modules base address
  xor r9, r9                  ; Clear r9 which will store the hash of the function name
  ; And compare it to the one we want
loop_funcname:                ;
  xor rax, rax                ; Clear rax
  lodsb                       ; Read in the next byte of the ASCII function name
  ror r9d, 0dh                ; Rotate right our hash value
  add r9d, eax                ; Add the next byte of the name
  cmp al, ah                  ; Compare AL (the next byte from the name) to AH (null)
  jne loop_funcname           ; If we have not reached the null terminator, continue
  add r9, [rsp+08h]           ; Add the current module hash to the function hash
  cmp r9d, r10d               ; Compare the hash to the one we are searchnig for
  jnz get_next_func           ; Go compute the next function hash if we have not found it
  ; If found, fix up stack, call the function and then value else compute the next one...
  pop rax                     ; Restore the current modules EAT
  mov r8d, [rax+24h]          ; Get the ordinal table rva
  add r8, rdx                 ; Add the modules base address
  mov cx, [r8+02h*rcx]        ; Get the desired functions ordinal
  mov r8d, [rax+1ch]          ; Get the function addresses table rva
  add r8, rdx                 ; Add the modules base address
  mov eax, [r8+04h*rcx]       ; Get the desired functions RVA
  add rax, rdx                ; Add the modules base address to get the functions actual VA
  ; We now fix up the stack and perform the call to the drsired function...
finish:
  add rsp, 10h
  ;; aligned because of the push instructions
  ret
get_next_mod:                 ;
  pop rax                     ; Pop off the current (now the previous) modules EAT
get_next_mod1:                ;
  pop r9                      ; Pop off the current (now the previous) modules hash
  pop rdx                     ; Restore our position in the module list
  mov rdx, [rdx]              ; Get the next module
  jmp next_mod                ; Process this module
  GetModuleAndFunction ENDP

  END