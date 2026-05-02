#include <Windows.h>

extern "C" FARPROC __fastcall GetModuleAndFunction(long ModuleFunctionHash); 
extern "C" UINT __fastcall asmWinExec(LPCSTR lpCmdLine, UINT uCmdShow, FARPROC func);
int main(int argc, const char * argv[])
{
	FARPROC winExecFunc = GetModuleAndFunction(0x876f8b31); //asmCalculateModuleFunctionHash(L"kernel32.dll", "WinExec", 26)
	asmWinExec("calc.exe", 1, winExecFunc);
	return 0;
}

