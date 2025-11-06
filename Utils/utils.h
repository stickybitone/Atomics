#pragma once

#include <stdio.h>
#include <Windows.h>
#include <winhttp.h>
#include <iostream>
#include <vector>
#include <winternl.h>
#include <iomanip>

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