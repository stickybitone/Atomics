#include <Windows.h>
#include <stdio.h>
#include <iostream>

extern "C" HMODULE __fastcall GetKernel32ModuleHandle();
extern "C" FARPROC __fastcall GetAddressOf_GetProcAddress(HMODULE kernel32Addr);

FARPROC(WINAPI* pGetProcAddress)(
	HMODULE hModule,
	LPCSTR lpProcName
);

UINT (WINAPI* pWinExec)(
	LPCSTR lpCmdLine,
	UINT   uCmdShow
);

int main(int argc, const char* argv[])
{
	HMODULE kernel32 = GetKernel32ModuleHandle();
	(FARPROC&)pGetProcAddress = GetAddressOf_GetProcAddress(kernel32);
	(FARPROC&)pWinExec = pGetProcAddress(kernel32, "WinExec");
	pWinExec("calc", 1);
	return 0;
}