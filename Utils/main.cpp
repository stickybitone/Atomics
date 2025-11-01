#include <stdio.h>

extern "C" long long __fastcall asmCalculateModuleFunctionHash(const wchar_t * modName, const char * funcName, int moduleLength); //used by Meterpreter
extern "C" long long __fastcall asmCalculateFunctionHash(const char* funcName); //another collision-free algo

int main()
{
	printf("kernel32.dll!LoadLibraryA: 0x%x\n", asmCalculateModuleFunctionHash(L"kernel32.dll", "LoadLibraryA", 26));
	printf("ws2_32.dll!WSAStartup: 0x%x\n", asmCalculateModuleFunctionHash(L"ws2_32.dll", "WSAStartup", 22));
	printf("ws2_32.dll!WSASocketA: 0x%x\n", asmCalculateModuleFunctionHash(L"ws2_32.dll", "WSASocketA", 22));
	printf("ws2_32.dll!WSAConnect: 0x%x\n", asmCalculateModuleFunctionHash(L"ws2_32.dll", "WSAConnect", 22));
	printf("ws2_32.dll!recv: 0x%x\n", asmCalculateModuleFunctionHash(L"ws2_32.dll", "recv", 22));
	printf("kernel32.dll!VirtualAlloc: 0x%x\n", asmCalculateModuleFunctionHash(L"kernel32.dll", "VirtualAlloc", 26));
	printf("GetProcAddress: 0x%x\n", asmCalculateFunctionHash("GetProcAddress"));
}