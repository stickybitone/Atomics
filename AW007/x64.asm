.DATA

.CODE
ALIGN 16

	; RCX = lpCmdLine
	; RDX = uCmdShow
	; R8  = WinExec Addr
asmWinExec PROC
	sub rsp, 28h

	call r8

	add rsp, 28h
	ret
asmWinExec  ENDP

INCLUDE ../Modules/MW003.asm

END