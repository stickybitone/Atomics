#pragma once

#include <Windows.h>
#include <iostream>
#include <winternl.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <dbghelp.h>
#include <string>

#pragma comment(lib, "DbgHelp")
#pragma comment(lib, "advapi32")

// https://www.ired.team/offensive-security/defense-evasion/detecting-hooked-syscall-functions

int detectHookedSyscalls()
{
	PDWORD functionAddress = (PDWORD)0;
	HMODULE libraryBase = LoadLibraryA("ntdll");
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)libraryBase;
	PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)libraryBase + dosHeader->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)libraryBase +imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	PDWORD addressOfFunctionsRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfFunctions);
	PDWORD addressOfNamesRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNames);
	PWORD addressOfNameOrdinalsRVA = (PWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNameOrdinals);

	for (DWORD i = 0; i < imageExportDirectory->NumberOfNames; i++)
	{
		DWORD functionNameRVA = addressOfNamesRVA[i];
		DWORD_PTR functionNameVA = (DWORD_PTR)libraryBase + functionNameRVA;
		char* functionName = (char*)functionNameVA;
		DWORD_PTR functionAddressRVA = addressOfFunctionsRVA[addressOfNameOrdinalsRVA[i]];
		functionAddress = (PDWORD)((DWORD_PTR)libraryBase + functionAddressRVA);
		unsigned char syscallPrologue[4] = { 0x4c, 0x8b, 0xd1, 0xb8 };
		if (strncmp(functionName, (char*)"Nt", 2) == 0 || strncmp(functionName, (char*)"Zw", 2) == 0)
		{
			if (memcmp(functionAddress, syscallPrologue, 4) != 0)
			{
				if (*((unsigned char*)functionAddress) == 0xE9)
				{
					DWORD jumpTargetRelative = *((PDWORD)((char*)functionAddress + 1));
					PDWORD jumpTarget = functionAddress + 5 + jumpTargetRelative;
					char moduleNameBuffer[512];
					GetMappedFileNameA(GetCurrentProcess(), jumpTarget, moduleNameBuffer, 512);
					printf("Hooked into module %s -> ", moduleNameBuffer);
				}
				else
				{
					printf("Potentially hooked -> ");
				}
			}
			else
			{
				printf("Function is potentially not hooked -> ");
			}
			printf("%s : ", functionName);
			char syscallStub[5] = {};
			std::memcpy(syscallStub, functionAddress, 4);
			syscallStub[4] = '\0';
			char* cp = syscallStub;
			for (; *cp != '\0'; ++cp)
			{
				printf("%hhx", *cp);
			}
			printf("\n");
		}
	}
	return 0;
}
