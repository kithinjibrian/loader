#ifndef LOADER_H
#define LOADER_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <windows.h>
#include <winternl.h>
#include <stdio.h>

	typedef unsigned short WORD;
	typedef WORD INTERNET_PORT;
	typedef LPVOID HINTERNET;

	typedef FARPROC(WINAPI *m_GetProcAddressPtr)(
		HMODULE hModule,
		LPCSTR lpProcName);

	typedef HMODULE(WINAPI *m_LoadLibraryPtr)(
		LPCSTR lpLibFileName);

	typedef int(WINAPI *m_MessageBoxWPtr)(
		HWND hWnd,
		LPCWSTR lpText,
		LPCWSTR lpCaption,
		UINT uType);

	typedef int(WINAPI *m_showWindowPtr)(
		HWND hWnd,
		int nCmdShow);

	typedef VOID(WINAPI *m_getSystemInfoPtr)(
		LPSYSTEM_INFO lpSystemInfo);

	typedef HANDLE(WINAPI *m_getCurrentProcessPtr)(VOID);

	typedef BOOL(WINAPI *m_CreateProcessAPtr)(
		LPCSTR lpApplicationName,
		LPSTR lpCommandLine,
		LPSECURITY_ATTRIBUTES lpProcessAttributes,
		LPSECURITY_ATTRIBUTES lpThreadAttributes,
		BOOL bInheritHandles,
		DWORD dwCreationFlags,
		LPVOID lpEnvironment,
		LPCSTR lpCurrentDirectory,
		LPSTARTUPINFOA lpStartupInfo,
		LPPROCESS_INFORMATION lpProcessInformation);

	typedef int(WINAPI *m_terminateProcessPtr)(
		HANDLE hProcess,
		UINT uExitCode);

	typedef int(WINAPI *m_getThreadContextPtr)(
		HANDLE hThread,
		LPCONTEXT lpContext);

	typedef int(WINAPI *m_globalMemoryStatusExPtr)(
		LPMEMORYSTATUSEX lpBuffer);

	typedef int(WINAPI *m_isWow64ProcessPtr)(
		HANDLE hProcess,
		PBOOL Wow64Process);

	typedef DWORD(WINAPI *m_resumeThreadPtr)(HANDLE hThread);

	typedef int(WINAPI *m_setThreadContextPtr)(
		HANDLE hThread,
		CONST CONTEXT *lpContext);

	typedef LPVOID(WINAPI *m_VirtualAllocExPtr)(
		HANDLE hProcess,
		LPVOID lpAddress,
		SIZE_T dwSize,
		DWORD flAllocationType,
		DWORD flProtect);

	typedef BOOL(WINAPI *m_WriteProcessMemoryPtr)(
		HANDLE hProcess,
		LPVOID lpBaseAddress,
		LPCVOID lpBuffer,
		SIZE_T nSize,
		SIZE_T *lpNumberOfBytesWritten);

	typedef BOOL(WINAPI *m_ReadProcessMemoryPtr)(
		HANDLE hProcess,
		LPCVOID lpBaseAddress,
		LPVOID lpBuffer,
		SIZE_T nSize,
		SIZE_T *lpNumberOfBytesRead);

	typedef LPVOID(WINAPI *m_VirtualAllocExNumaPtr)(
		HANDLE hProcess,
		LPVOID lpAddress,
		SIZE_T dwSize,
		DWORD flAllocationType,
		DWORD flProtect,
		DWORD nndPreferred);

	typedef HINTERNET(WINAPI *m_internetOpenPtr)(
		LPCTSTR lpszAgent,
		DWORD dwAccessType,
		LPCTSTR lpszProxy,
		LPCTSTR lpszProxyBypass,
		DWORD dwFlags);

	typedef HINTERNET(WINAPI *m_internetOpenUrlPtr)(
		HINTERNET hInternet,
		LPCSTR lpszUrl,
		LPCSTR lpszHeaders,
		DWORD dwHeadersLength,
		DWORD dwFlags,
		DWORD_PTR dwContext);

	typedef HINTERNET(WINAPI *m_internetConnectPtr)(
		HINTERNET hInternet,
		LPCSTR lpszServerName,
		INTERNET_PORT nServerPort,
		LPCSTR lpszUserName,
		LPCSTR lpszPassword,
		DWORD dwService,
		DWORD dwFlags,
		DWORD_PTR dwContext);

	typedef HINTERNET(WINAPI *m_httpOpenRequestPtr)(
		HINTERNET hConnect,
		LPCSTR lpszVerb,
		LPCSTR lpszObjectName,
		LPCSTR lpszVersion,
		LPCSTR lpszReferrer,
		LPCSTR *lplpszAcceptTypes,
		DWORD dwFlags,
		DWORD_PTR dwContext);

	typedef BOOL(WINAPI *m_httpSendRequestPtr)(
		HINTERNET hRequest,
		LPCSTR lpszHeaders,
		DWORD dwHeadersLength,
		LPVOID lpOptional,
		DWORD dwOptionalLength);

	typedef BOOL(WINAPI *m_httpQueryInfoPtr)(
		HINTERNET hRequest,
		DWORD dwInfoLevel,
		LPVOID lpBuffer,
		LPDWORD lpdwBufferLength,
		LPDWORD lpdwIndex);

	typedef BOOL(WINAPI *m_internetReadFilePtr)(
		HINTERNET hFile,
		LPVOID lpBuffer,
		DWORD dwNumberOfBytesToRead,
		LPDWORD lpdwNumberOfBytesRead);

	typedef BOOL(WINAPI *m_internetCloseHandlePtr)(
		HINTERNET hInternet);

	typedef HANDLE(WINAPI *m_createMutexPtr)(
		LPSECURITY_ATTRIBUTES lpMutexAttributes,
		WINBOOL bInitialOwner,
		LPCSTR lpName);

	typedef int(WINAPI *m_wow64GetThreadContextPtr)(
		HANDLE hThread,
		PWOW64_CONTEXT lpContext);

	typedef int(WINAPI *m_wow64SetThreadContextPtr)(
		HANDLE hThread,
		CONST WOW64_CONTEXT *lpContext);

	typedef struct _MY_PEB_LDR_DATA
	{
		ULONG Length;
		BOOL Initialized;
		PVOID SsHandle;
		LIST_ENTRY InLoadOrderModuleList;
		LIST_ENTRY InMemoryOrderModuleList;
		LIST_ENTRY InInitializationOrderModuleList;
	} MY_PEB_LDR_DATA, *PMY_PEB_LDR_DATA;

	typedef struct _MY_LDR_DATA_TABLE_ENTRY
	{
		LIST_ENTRY InLoadOrderLinks;
		LIST_ENTRY InMemoryOrderLinks;
		LIST_ENTRY InInitializationOrderLinks;
		PVOID DllBase;
		PVOID EntryPoint;
		ULONG SizeOfImage;
		UNICODE_STRING FullDllName;
		UNICODE_STRING BaseDllName;
	} MY_LDR_DATA_TABLE_ENTRY, *PMY_LDR_DATA_TABLE_ENTRY;

	HMODULE m_LoadLibrary(LPCSTR lpLibFileName);
	FARPROC m_GetProcAddress(HMODULE hModule, int lpProcName);
	FARPROC m_GetProcAddressEx(LPCSTR lpLibFileName, int lpProcName);

#ifdef __cplusplus
}
#endif

#endif