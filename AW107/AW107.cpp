#include <Windows.h>
#include <stdio.h>

extern "C" FARPROC __fastcall FindFunction(long funcHash);

UINT(WINAPI* pWinExec)(
	LPCSTR lpCmdLine,
	UINT   uCmdShow
	);

int main(int argc, char* argv[])
{
	(FARPROC&) pWinExec = FindFunction(0x876f8b31); // asmCalculateModuleFunctionHash(L"kernel32.dll", "WinExec", 26)
	pWinExec("calc", 1);
	return 1;
}