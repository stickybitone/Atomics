.686p
.model flat, C

.data

.code
ALIGN 8
; https://raw.githubusercontent.com/rapid7/metasploit-framework/refs/heads/master/external/source/shellcode/windows/x86/src/single/single_exec.asm
OPTION LANGUAGE: syscall
@FindFunction@4 PROC
; ECX - function hash
api_call:
  ASSUME FS:NOTHING
  pushad                     ; We preserve all the registers for the caller, bar EAX and ECX.
  mov ebp, esp               ; Create a new stack frame
  push ecx	
  xor edx, edx               ; Zero EDX
  mov edx, fs:[30h]     ; Get a pointer to the PEB
  mov edx, [edx+0ch]         ; Get PEB->Ldr
  mov edx, [edx+14h]         ; Get the first module from the InMemoryOrder module list
next_mod:                    ;
  mov esi, [edx+28h]         ; Get pointer to modules name (unicode string)
  movzx ecx, byte ptr [edx+26h]		 ; Set ECX to the length we want to check
  xor edi, edi               ; Clear EDI which will store the hash of the module name
loop_modname:                ;
  xor eax, eax               ; Clear EAX
  lodsb                      ; Read in the next byte of the name
  cmp al, 'a'                ; Some versions of Windows use lower case module names
  jl not_lowercase           ;
  sub al, 20h               ; If so normalise to uppercase
not_lowercase:               ;
  ror edi, 0dh               ; Rotate right our hash value
  add edi, eax               ; Add the next byte of the name
  dec ecx
  jnz loop_modname           ; Loop until we have read enough
  ; We now have the module hash computed
  push edx                   ; Save the current position in the module list for later
  push edi                   ; Save the current module hash for later
  ; Proceed to iterate the export address table,
  mov edx, [edx+10h]        ; Get this modules base address
  mov eax, [edx+3ch]        ; Get PE header
  add eax, edx               ; Add the modules base address
  mov eax, [eax+78h]        ; Get export tables RVA
  test eax, eax              ; Test if no export address table is present
  jz get_next_mod1           ; If no EAT present, process the next module
  add eax, edx               ; Add the modules base address
  push eax                   ; Save the current modules EAT
  mov ecx, [eax+18h]        ; Get the number of function names
  mov ebx, [eax+20h]        ; Get the rva of the function names
  add ebx, edx               ; Add the modules base address
  ; Computing the module hash + function hash
get_next_func:               ;
  test ecx, ecx              ; Changed from jecxz to accomodate the larger offset produced by random jmps below
  jz get_next_mod            ; When we reach the start of the EAT (we search backwards), process the next module
  dec ecx                    ; Decrement the function name counter
  mov esi, [ebx+ecx*4]       ; Get rva of next module name
  add esi, edx               ; Add the modules base address
  xor edi, edi               ; Clear EDI which will store the hash of the function name
  ; And compare it to the one we want
loop_funcname:               ;
  xor eax, eax               ; Clear EAX
  lodsb                      ; Read in the next byte of the ASCII function name
  ror edi, 0dh               ; Rotate right our hash value
  add edi, eax               ; Add the next byte of the name
  cmp al, ah                 ; Compare AL (the next byte from the name) to AH (null)
  jne loop_funcname          ; If we have not reached the null terminator, continue
  add edi, [ebp-0ch]           ; Add the current module hash to the function hash
  cmp edi, [ebp+18h]        ; Compare the hash to the one we are searchnig for
  jnz get_next_func          ; Go compute the next function hash if we have not found it
  ; If found, fix up stack, call the function and then value else compute the next one...
  pop eax                    ; Restore the current modules EAT
  mov ebx, [eax+24h]        ; Get the ordinal table rva
  add ebx, edx               ; Add the modules base address
  mov cx, [ebx+2*ecx]        ; Get the desired functions ordinal
  mov ebx, [eax+1ch]        ; Get the function addresses table rva
  add ebx, edx               ; Add the modules base address
  mov eax, [ebx+4*ecx]       ; Get the desired functions RVA
  add eax, edx               ; Add the modules base address to get the functions actual VA
  ; We now fix up the stack and perform the call to the desired function...
 finish:
   mov [esp+1ch], eax        ; Overwrite the old EAX value with the desired api address for the upcoming popad
   ;pop ebx                    ; Clear off the current modules hash
   ;pop ebx                    ; Clear off the current position in the module list

   

   popad                      ; Restore all of the callers registers, bar EAX, ECX and EDX which are clobbered
   
   pop ebx
   pop ebx
   pop ebx
   ;push eax
   ret 

   ;pop ecx                    ; Pop off the original return address our caller will have pushed
   ;pop edx                    ; Pop off the hash value our caller will have pushed
   ;push ecx                   ; Push back the correct return value
   ;jmp eax                    ; Jump into the required function
   ;ret 
   ; We now automagically return to the correct caller...
get_next_mod:                ;0078fba4
  pop eax                    ; Pop off the current (now the previous) modules EAT
get_next_mod1:               ;
  pop edi                    ; Pop off the current (now the previous) modules hash
  pop edx                    ; Restore our position in the module list
  mov edx, [edx]             ; Get the next module
  jmp next_mod               ; Process this module
@FindFunction@4 ENDP
OPTION LANGUAGE: C

END