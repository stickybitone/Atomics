#include <stdio.h>

extern "C" long long __fastcall asmCalculateModuleFunctionHash(const wchar_t * modName, const char * funcName, int moduleLength); //used by Meterpreter
extern "C" long long __fastcall asmCalculateFunctionHash(const char* funcName); //another collision-free algo

int main()
{
	printf("kernel32.dll!VirtualAlloc: 0x%x\n", asmCalculateModuleFunctionHash(L"kernel32.dll", "VirtualAlloc", 26));
	printf("GetProcAddress: 0x%x\n", asmCalculateFunctionHash("GetProcAddress"));
}