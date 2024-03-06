#include "loader.h"

int hash(const char *s, const int n)
{
	long long p = 31, m = 1e9 + 7;
	long long hash = 0;
	long long p_pow = 1;
	for (int i = 0; i < n; i++)
	{
		hash = (hash + (s[i] - 'a' + 1) * p_pow) % m;
		p_pow = (p_pow * p) % m;
	}
	return hash;
}

HMODULE m_GetModuleHandle(const wchar_t *moduleName)
{

	PPEB PEB_Address = (PPEB)__readgsqword(0x60);

	PMY_PEB_LDR_DATA P_Ldr = (PMY_PEB_LDR_DATA)PEB_Address->Ldr;

	PLIST_ENTRY P_NextModule = P_Ldr->InLoadOrderModuleList.Flink;

	while (P_NextModule != &P_Ldr->InLoadOrderModuleList)
	{

		PMY_LDR_DATA_TABLE_ENTRY P_DataTableEntry = CONTAINING_RECORD(P_NextModule, MY_LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		if (_wcsicmp(moduleName, P_DataTableEntry->BaseDllName.Buffer) == 0)
		{

			return (HMODULE)P_DataTableEntry->DllBase;
		}

		P_NextModule = P_NextModule->Flink;
	}

	return NULL;
}

FARPROC m_GetProcAddress(HMODULE hModule, int lpProcName)
{

	if (hModule == NULL)
		return NULL;

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;

	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE *)hModule + pDosHeader->e_lfanew);

	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	PIMAGE_DATA_DIRECTORY pExportDirectory = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (pExportDirectory->VirtualAddress == 0 || pExportDirectory->Size == 0)
		return NULL;

	PIMAGE_EXPORT_DIRECTORY pExportDirTable = (PIMAGE_EXPORT_DIRECTORY)((BYTE *)hModule + pExportDirectory->VirtualAddress);

	PDWORD pAddressOfFunctions = (PDWORD)((BYTE *)hModule + pExportDirTable->AddressOfFunctions);
	PDWORD pAddressOfNames = (PDWORD)((BYTE *)hModule + pExportDirTable->AddressOfNames);
	PWORD pAddressOfNameOrdinals = (PWORD)((BYTE *)hModule + pExportDirTable->AddressOfNameOrdinals);

	for (DWORD i = 0; i < pExportDirTable->NumberOfNames; i++)
	{
		LPCSTR functionName = (LPCSTR)((BYTE *)hModule + pAddressOfNames[i]);

		if (hash(functionName, strlen(functionName)) == lpProcName)
		{
			return (FARPROC)((BYTE *)hModule + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
		}
	}

	return NULL;
}

HMODULE m_LoadLibrary(LPCSTR lpLibFileName)
{
	const wchar_t *moduleName = L"kernel32.dll";
	HMODULE kernel32 = m_GetModuleHandle(moduleName);
	// hash LoadLibraryA
	m_LoadLibraryPtr loadLibrary = (m_LoadLibraryPtr)m_GetProcAddress(kernel32, -915862699);
	return loadLibrary(lpLibFileName);
}

FARPROC m_GetProcAddressEx(LPCSTR lpLibFileName, int lpProcName)
{
	HMODULE module = m_LoadLibrary(lpLibFileName);
	return m_GetProcAddress(module, lpProcName);
}

// int main()
// {
// 	// hash MessageBoxW
// 	m_MessageBoxWPtr messageBoxW = (m_MessageBoxWPtr)m_GetProcAddressEx("user32.dll", -977291503);
// 	messageBoxW(NULL, L"Hello no imports", L"Title", MB_OK);
// 	return 0;
// }