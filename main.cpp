#define NOMINMAX

#include "te-sdk.h"
#include "skCrypter.h"
#include <MinHook.h>

#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <winternl.h>
#include <d3d9.h>
#include <vector>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <algorithm>
#include <chrono>
#include <thread>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <atomic>
#include <DbgHelp.h>
#include <cstdio>
#include <cstdarg>
#include <sstream>
#include <new>

// ============================================
// JUNK CODE INJECTION
// ============================================
#define JUNK_NOP() __asm { nop }
#define JUNK_MOV() __asm { mov eax, eax }
#define JUNK_PAUSE() __asm { pause }

#define ADD_JUNK_CODE() \
	do { \
		volatile int x = rand(); \
		if (x > 0x7FFFFFFF) { \
			JUNK_NOP(); JUNK_MOV(); JUNK_PAUSE(); \
		} \
	} while(0)

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xC000000DL)
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif

#ifndef SystemModuleInformation
#define SystemModuleInformation 11
#endif

#ifndef SystemModuleInformationEx
#define SystemModuleInformationEx 77
#endif

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

typedef struct _TE_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} TE_UNICODE_STRING, * PTE_UNICODE_STRING;

typedef struct _TE_LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	TE_UNICODE_STRING FullDllName;
	TE_UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	PVOID SectionPointer;
	ULONG CheckSum;
	ULONG TimeDateStamp;
	PVOID LoadedImports;
	PVOID EntryPointActivationContext;
	PVOID PatchInformation;
} TE_LDR_DATA_TABLE_ENTRY, * PTE_LDR_DATA_TABLE_ENTRY;

typedef struct _TE_PEB_LDR_DATA {
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} TE_PEB_LDR_DATA, * PTE_PEB_LDR_DATA;

typedef struct _TE_PEB {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PTE_PEB_LDR_DATA Ldr;
} TE_PEB, * PTE_PEB;

typedef enum _MEMORY_INFORMATION_CLASS {
	MemoryBasicInformation = 0,
	MemoryWorkingSetInformation = 1,
	MemoryMappedFilenameInformation = 2,
	MemoryRegionInformation = 3,
	MemoryWorkingSetExInformation = 4
} MEMORY_INFORMATION_CLASS;

typedef NTSTATUS(NTAPI* NtQuerySystemInformation_t)(
	SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* NtQueryInformationProcess_t)(
	HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* NtReadVirtualMemory_t)(
	HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(NTAPI* NtWriteVirtualMemory_t)(
	HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

typedef NTSTATUS(NTAPI* NtQueryVirtualMemory_t)(HANDLE, PVOID, MEMORY_INFORMATION_CLASS, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(NTAPI* NtProtectVirtualMemory_t)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory_t)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS(NTAPI* NtFreeVirtualMemory_t)(HANDLE, PVOID*, PSIZE_T, ULONG);


// ============================================
// PROXY SYSTEM
// ============================================
namespace te::winapi::um::ac::bypass::proxy
{
	inline static HMODULE GetKernel32FromPEB()
	{
		ADD_JUNK_CODE();
#ifdef _WIN64
		PTE_PEB pPeb = (PTE_PEB)__readgsqword(0x60);
#else
		PTE_PEB pPeb = (PTE_PEB)__readfsdword(0x30);
#endif

		if (!pPeb || !pPeb->Ldr) return nullptr;

		PTE_PEB_LDR_DATA pLdr = pPeb->Ldr;
		PLIST_ENTRY pListHead = &pLdr->InLoadOrderModuleList;
		PLIST_ENTRY pListEntry = pListHead->Flink;

		while (pListEntry && pListEntry != pListHead) {
			PTE_LDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(
				pListEntry, TE_LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

			if (pEntry->BaseDllName.Buffer) {
				WCHAR* name = pEntry->BaseDllName.Buffer;
				USHORT len = pEntry->BaseDllName.Length / sizeof(WCHAR);

				if (len >= 9) {
					if ((name[0] == L'k' || name[0] == L'K') &&
						(name[1] == L'e' || name[1] == L'E') &&
						(name[8] == L'l' || name[8] == L'L')) {
						ADD_JUNK_CODE();
						return (HMODULE)pEntry->DllBase;
					}
				}
			}
			pListEntry = pListEntry->Flink;
		}

		ADD_JUNK_CODE();
		return nullptr;
	}

	inline static FARPROC GetExportByName(HMODULE hModule, const char* funcName)
	{
		ADD_JUNK_CODE();
		if (!hModule || !funcName) return nullptr;

		PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hModule;
		if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

		PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDos->e_lfanew);
		if (pNt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

		ULONG exportsRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		if (!exportsRva) return nullptr;

		PIMAGE_EXPORT_DIRECTORY pExports = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + exportsRva);

		PDWORD pNames = (PDWORD)((BYTE*)hModule + pExports->AddressOfNames);
		PDWORD pFunctions = (PDWORD)((BYTE*)hModule + pExports->AddressOfFunctions);
		PWORD pOrdinals = (PWORD)((BYTE*)hModule + pExports->AddressOfNameOrdinals);

		for (ULONG i = 0; i < pExports->NumberOfNames; i++) {
			const char* exportName = (const char*)((BYTE*)hModule + pNames[i]);

			const char* s1 = exportName;
			const char* s2 = funcName;
			BOOL match = TRUE;

			while (*s1 && *s2) {
				char c1 = (*s1 >= 'A' && *s1 <= 'Z') ? (*s1 + 32) : *s1;
				char c2 = (*s2 >= 'A' && *s2 <= 'Z') ? (*s2 + 32) : *s2;

				if (c1 != c2) {
					match = FALSE;
					break;
				}
				s1++;
				s2++;
			}

			if (match && *s1 == 0 && *s2 == 0) {
				ULONG funcIndex = pOrdinals[i];
				if (funcIndex < pExports->NumberOfFunctions) {
					FARPROC pFunc = (FARPROC)((BYTE*)hModule + pFunctions[funcIndex]);
					ADD_JUNK_CODE();
					return pFunc;
				}
			}
		}

		ADD_JUNK_CODE();
		return nullptr;
	}

	inline static FARPROC GetAPIUnsafe(const char* dllName, const char* funcName)
	{
		ADD_JUNK_CODE();

		HMODULE hMod = nullptr;

		if (dllName[0] == 'k' || dllName[0] == 'K') {
			hMod = GetKernel32FromPEB();
		}

		if (!hMod) {
			ADD_JUNK_CODE();
			hMod = LoadLibraryA(dllName);
		}

		FARPROC pFunc = GetExportByName(hMod, funcName);

		ADD_JUNK_CODE();
		return pFunc;
	}

	static std::unordered_map<std::string, FARPROC> g_apiCache;
	static std::recursive_mutex g_apiCacheMutex;

	class ProxyAPI {
	private:
		static FARPROC GetAPIInternal(const char* dllName, const char* funcName) {
			ADD_JUNK_CODE();

			std::string key = std::string(dllName) + "::" + funcName;

			{
				std::lock_guard<std::recursive_mutex> lock(g_apiCacheMutex);
				auto it = g_apiCache.find(key);
				if (it != g_apiCache.end()) {
					ADD_JUNK_CODE();
					return it->second;
				}
			}

			FARPROC pFunc = GetAPIUnsafe(dllName, funcName);

			{
				std::lock_guard<std::recursive_mutex> lock(g_apiCacheMutex);
				g_apiCache[key] = pFunc;
			}

			ADD_JUNK_CODE();
			return pFunc;
		}

	public:
		// ============================================
		// KERNEL32.DLL PROXIES
		// ============================================

		static HMODULE GetModuleHandleA(LPCSTR lpModuleName) {
			ADD_JUNK_CODE();
			typedef HMODULE(WINAPI* fn)(LPCSTR);
			fn pFunc = (fn)GetAPIInternal("kernel32.dll", "GetModuleHandleA");
			HMODULE result = pFunc ? pFunc(lpModuleName) : nullptr;
			ADD_JUNK_CODE();
			return result;
		}

		static HMODULE GetModuleHandleW(LPCWSTR lpModuleName) {
			ADD_JUNK_CODE();
			typedef HMODULE(WINAPI* fn)(LPCWSTR);
			fn pFunc = (fn)GetAPIInternal("kernel32.dll", "GetModuleHandleW");
			HMODULE result = pFunc ? pFunc(lpModuleName) : nullptr;
			ADD_JUNK_CODE();
			return result;
		}

		static BOOL GetModuleHandleExA(DWORD dwFlags, LPCSTR lpModuleName, HMODULE* phModule) {
			ADD_JUNK_CODE();
			typedef BOOL(WINAPI* fn)(DWORD, LPCSTR, HMODULE*);
			fn pFunc = (fn)GetAPIInternal("kernel32.dll", "GetModuleHandleExA");
			BOOL result = pFunc ? pFunc(dwFlags, lpModuleName, phModule) : FALSE;
			ADD_JUNK_CODE();
			return result;
		}

		static BOOL GetModuleHandleExW(DWORD dwFlags, LPCWSTR lpModuleName, HMODULE* phModule) {
			ADD_JUNK_CODE();
			typedef BOOL(WINAPI* fn)(DWORD, LPCWSTR, HMODULE*);
			fn pFunc = (fn)GetAPIInternal("kernel32.dll", "GetModuleHandleExW");
			BOOL result = pFunc ? pFunc(dwFlags, lpModuleName, phModule) : FALSE;
			ADD_JUNK_CODE();
			return result;
		}

		static FARPROC GetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
			ADD_JUNK_CODE();
			typedef FARPROC(WINAPI* fn)(HMODULE, LPCSTR);
			fn pFunc = (fn)GetAPIInternal("kernel32.dll", "GetProcAddress");
			FARPROC result = pFunc ? pFunc(hModule, lpProcName) : nullptr;
			ADD_JUNK_CODE();
			return result;
		}

		static HMODULE LoadLibraryA(LPCSTR lpLibFileName) {
			ADD_JUNK_CODE();
			typedef HMODULE(WINAPI* fn)(LPCSTR);
			fn pFunc = (fn)GetAPIInternal("kernel32.dll", "LoadLibraryA");
			HMODULE result = pFunc ? pFunc(lpLibFileName) : nullptr;
			ADD_JUNK_CODE();
			return result;
		}

		static HMODULE LoadLibraryW(LPCWSTR lpLibFileName) {
			ADD_JUNK_CODE();
			typedef HMODULE(WINAPI* fn)(LPCWSTR);
			fn pFunc = (fn)GetAPIInternal("kernel32.dll", "LoadLibraryW");
			HMODULE result = pFunc ? pFunc(lpLibFileName) : nullptr;
			ADD_JUNK_CODE();
			return result;
		}

		static BOOL FreeLibrary(HMODULE hLibModule) {
			ADD_JUNK_CODE();
			typedef BOOL(WINAPI* fn)(HMODULE);
			fn pFunc = (fn)GetAPIInternal("kernel32.dll", "FreeLibrary");
			BOOL result = pFunc ? pFunc(hLibModule) : FALSE;
			ADD_JUNK_CODE();
			return result;
		}

		static DWORD GetCurrentProcessId() {
			ADD_JUNK_CODE();
			typedef DWORD(WINAPI* fn)();
			fn pFunc = (fn)GetAPIInternal("kernel32.dll", "GetCurrentProcessId");
			DWORD result = pFunc ? pFunc() : 0;
			ADD_JUNK_CODE();
			return result;
		}

		static HANDLE GetCurrentProcess() {
			ADD_JUNK_CODE();
			typedef HANDLE(WINAPI* fn)();
			fn pFunc = (fn)GetAPIInternal("kernel32.dll", "GetCurrentProcess");
			HANDLE result = pFunc ? pFunc() : nullptr;
			ADD_JUNK_CODE();
			return result;
		}

		static LPVOID VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
			ADD_JUNK_CODE();
			typedef LPVOID(WINAPI* fn)(LPVOID, SIZE_T, DWORD, DWORD);
			fn pFunc = (fn)GetAPIInternal("kernel32.dll", "VirtualAlloc");
			LPVOID result = pFunc ? pFunc(lpAddress, dwSize, flAllocationType, flProtect) : nullptr;
			ADD_JUNK_CODE();
			return result;
		}

		static BOOL VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
			ADD_JUNK_CODE();
			typedef BOOL(WINAPI* fn)(LPVOID, SIZE_T, DWORD, PDWORD);
			fn pFunc = (fn)GetAPIInternal("kernel32.dll", "VirtualProtect");
			BOOL result = pFunc ? pFunc(lpAddress, dwSize, flNewProtect, lpflOldProtect) : FALSE;
			ADD_JUNK_CODE();
			return result;
		}

		static BOOL VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) {
			ADD_JUNK_CODE();
			typedef BOOL(WINAPI* fn)(LPVOID, SIZE_T, DWORD);
			fn pFunc = (fn)GetAPIInternal("kernel32.dll", "VirtualFree");
			BOOL result = pFunc ? pFunc(lpAddress, dwSize, dwFreeType) : FALSE;
			ADD_JUNK_CODE();
			return result;
		}

		static SIZE_T VirtualQuery(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength) {
			ADD_JUNK_CODE();
			typedef SIZE_T(WINAPI* fn)(LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
			fn pFunc = (fn)GetAPIInternal("kernel32.dll", "VirtualQuery");
			SIZE_T result = pFunc ? pFunc(lpAddress, lpBuffer, dwLength) : 0;
			ADD_JUNK_CODE();
			return result;
		}

		static BOOL TerminateProcess(HANDLE hProcess, UINT uExitCode) {
			ADD_JUNK_CODE();
			typedef BOOL(WINAPI* fn)(HANDLE, UINT);
			fn pFunc = (fn)GetAPIInternal("kernel32.dll", "TerminateProcess");
			BOOL result = pFunc ? pFunc(hProcess, uExitCode) : FALSE;
			ADD_JUNK_CODE();
			return result;
		}

		static HANDLE CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize,
			LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) {
			ADD_JUNK_CODE();
			typedef HANDLE(WINAPI* fn)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
			fn pFunc = (fn)GetAPIInternal("kernel32.dll", "CreateThread");
			HANDLE result = pFunc ? pFunc(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId) : nullptr;
			ADD_JUNK_CODE();
			return result;
		}

		static BOOL GetThreadContext(HANDLE hThread, LPCONTEXT lpContext) {
			ADD_JUNK_CODE();
			typedef BOOL(WINAPI* fn)(HANDLE, LPCONTEXT);
			fn pFunc = (fn)GetAPIInternal("kernel32.dll", "GetThreadContext");
			BOOL result = pFunc ? pFunc(hThread, lpContext) : FALSE;
			ADD_JUNK_CODE();
			return result;
		}

		static BOOL SetThreadContext(HANDLE hThread, const CONTEXT* lpContext) {
			ADD_JUNK_CODE();
			typedef BOOL(WINAPI* fn)(HANDLE, const CONTEXT*);
			fn pFunc = (fn)GetAPIInternal("kernel32.dll", "SetThreadContext");
			BOOL result = pFunc ? pFunc(hThread, lpContext) : FALSE;
			ADD_JUNK_CODE();
			return result;
		}

		static DWORD ResumeThread(HANDLE hThread) {
			ADD_JUNK_CODE();
			typedef DWORD(WINAPI* fn)(HANDLE);
			fn pFunc = (fn)GetAPIInternal("kernel32.dll", "ResumeThread");
			DWORD result = pFunc ? pFunc(hThread) : (DWORD)-1;
			ADD_JUNK_CODE();
			return result;
		}

		static DWORD SuspendThread(HANDLE hThread) {
			ADD_JUNK_CODE();
			typedef DWORD(WINAPI* fn)(HANDLE);
			fn pFunc = (fn)GetAPIInternal("kernel32.dll", "SuspendThread");
			DWORD result = pFunc ? pFunc(hThread) : (DWORD)-1;
			ADD_JUNK_CODE();
			return result;
		}

		static BOOL CloseHandle(HANDLE hObject) {
			ADD_JUNK_CODE();
			typedef BOOL(WINAPI* fn)(HANDLE);
			fn pFunc = (fn)GetAPIInternal("kernel32.dll", "CloseHandle");
			BOOL result = pFunc ? pFunc(hObject) : FALSE;
			ADD_JUNK_CODE();
			return result;
		}

		static void Sleep(DWORD dwMilliseconds) {
			ADD_JUNK_CODE();
			typedef void(WINAPI* fn)(DWORD);
			fn pFunc = (fn)GetAPIInternal("kernel32.dll", "Sleep");
			if (pFunc) pFunc(dwMilliseconds);
			ADD_JUNK_CODE();
		}

		static HANDLE CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID) {
			ADD_JUNK_CODE();
			typedef HANDLE(WINAPI* fn)(DWORD, DWORD);
			fn pFunc = (fn)GetAPIInternal("kernel32.dll", "CreateToolhelp32Snapshot");
			HANDLE result = pFunc ? pFunc(dwFlags, th32ProcessID) : INVALID_HANDLE_VALUE;
			ADD_JUNK_CODE();
			return result;
		}

		static BOOL Module32First(HANDLE hSnapshot, LPMODULEENTRY32 lpme) {
			ADD_JUNK_CODE();
			typedef BOOL(WINAPI* fn)(HANDLE, LPMODULEENTRY32);
			fn pFunc = (fn)GetAPIInternal("kernel32.dll", "Module32First");
			BOOL result = pFunc ? pFunc(hSnapshot, lpme) : FALSE;
			ADD_JUNK_CODE();
			return result;
		}

		static BOOL Module32Next(HANDLE hSnapshot, LPMODULEENTRY32 lpme) {
			ADD_JUNK_CODE();
			typedef BOOL(WINAPI* fn)(HANDLE, LPMODULEENTRY32);
			fn pFunc = (fn)GetAPIInternal("kernel32.dll", "Module32Next");
			BOOL result = pFunc ? pFunc(hSnapshot, lpme) : FALSE;
			ADD_JUNK_CODE();
			return result;
		}

		static BOOL Process32First(HANDLE hSnapshot, LPPROCESSENTRY32 lppe) {
			ADD_JUNK_CODE();
			typedef BOOL(WINAPI* fn)(HANDLE, LPPROCESSENTRY32);
			fn pFunc = (fn)GetAPIInternal("kernel32.dll", "Process32First");
			BOOL result = pFunc ? pFunc(hSnapshot, lppe) : FALSE;
			ADD_JUNK_CODE();
			return result;
		}

		static BOOL Process32Next(HANDLE hSnapshot, LPPROCESSENTRY32 lppe) {
			ADD_JUNK_CODE();
			typedef BOOL(WINAPI* fn)(HANDLE, LPPROCESSENTRY32);
			fn pFunc = (fn)GetAPIInternal("kernel32.dll", "Process32Next");
			BOOL result = pFunc ? pFunc(hSnapshot, lppe) : FALSE;
			ADD_JUNK_CODE();
			return result;
		}

		static HANDLE FindFirstFileA(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData) {
			ADD_JUNK_CODE();
			typedef HANDLE(WINAPI* fn)(LPCSTR, LPWIN32_FIND_DATAA);
			fn pFunc = (fn)GetAPIInternal("kernel32.dll", "FindFirstFileA");
			HANDLE result = pFunc ? pFunc(lpFileName, lpFindFileData) : INVALID_HANDLE_VALUE;
			ADD_JUNK_CODE();
			return result;
		}

		static BOOL FindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData) {
			ADD_JUNK_CODE();
			typedef BOOL(WINAPI* fn)(HANDLE, LPWIN32_FIND_DATAA);
			fn pFunc = (fn)GetAPIInternal("kernel32.dll", "FindNextFileA");
			BOOL result = pFunc ? pFunc(hFindFile, lpFindFileData) : FALSE;
			ADD_JUNK_CODE();
			return result;
		}

		static BOOL FindClose(HANDLE hFindFile) {
			ADD_JUNK_CODE();
			typedef BOOL(WINAPI* fn)(HANDLE);
			fn pFunc = (fn)GetAPIInternal("kernel32.dll", "FindClose");
			BOOL result = pFunc ? pFunc(hFindFile) : FALSE;
			ADD_JUNK_CODE();
			return result;
		}

		static DWORD GetModuleFileNameA(HMODULE hModule, LPSTR lpFilename, DWORD nSize) {
			ADD_JUNK_CODE();
			typedef DWORD(WINAPI* fn)(HMODULE, LPSTR, DWORD);
			fn pFunc = (fn)GetAPIInternal("kernel32.dll", "GetModuleFileNameA");
			DWORD result = pFunc ? pFunc(hModule, lpFilename, nSize) : 0;
			ADD_JUNK_CODE();
			return result;
		}

		static BOOL SetLastError(DWORD dwErrCode) {
			ADD_JUNK_CODE();
			typedef BOOL(WINAPI* fn)(DWORD);
			fn pFunc = (fn)GetAPIInternal("kernel32.dll", "SetLastError");
			BOOL result = pFunc ? pFunc(dwErrCode) : FALSE;
			ADD_JUNK_CODE();
			return result;
		}

		static HANDLE CreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes,
			SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter,
			DWORD dwCreationFlags, LPDWORD lpThreadId) {
			ADD_JUNK_CODE();
			typedef HANDLE(WINAPI* fn)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
			fn pFunc = (fn)GetAPIInternal("kernel32.dll", "CreateRemoteThread");
			HANDLE result = pFunc ? pFunc(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId) : nullptr;
			ADD_JUNK_CODE();
			return result;
		}

		static void ExitThread(DWORD dwExitCode) {
			ADD_JUNK_CODE();
			typedef void(WINAPI* fn)(DWORD);
			fn pFunc = (fn)GetAPIInternal("kernel32.dll", "ExitThread");
			if (pFunc) pFunc(dwExitCode);
			ADD_JUNK_CODE();
		}

		static void DisableThreadLibraryCalls(HMODULE hLibModule) {
			ADD_JUNK_CODE();
			typedef void(WINAPI* fn)(HMODULE);
			fn pFunc = (fn)GetAPIInternal("kernel32.dll", "DisableThreadLibraryCalls");
			if (pFunc) pFunc(hLibModule);
			ADD_JUNK_CODE();
		}

		// ============================================
		// USER32.DLL PROXIES
		// ============================================

		static int MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
			ADD_JUNK_CODE();
			typedef int(WINAPI* fn)(HWND, LPCSTR, LPCSTR, UINT);
			fn pFunc = (fn)GetAPIInternal("user32.dll", "MessageBoxA");
			int result = pFunc ? pFunc(hWnd, lpText, lpCaption, uType) : 0;
			ADD_JUNK_CODE();
			return result;
		}

		static int MessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType) {
			ADD_JUNK_CODE();
			typedef int(WINAPI* fn)(HWND, LPCWSTR, LPCWSTR, UINT);
			fn pFunc = (fn)GetAPIInternal("user32.dll", "MessageBoxW");
			int result = pFunc ? pFunc(hWnd, lpText, lpCaption, uType) : 0;
			ADD_JUNK_CODE();
			return result;
		}

		// ============================================
		// PSAPI.DLL PROXIES
		// ============================================

		static BOOL EnumProcessModules(HANDLE hProcess, HMODULE* lphModule, DWORD cb, LPDWORD lpcbNeeded) {
			ADD_JUNK_CODE();
			typedef BOOL(WINAPI* fn)(HANDLE, HMODULE*, DWORD, LPDWORD);
			fn pFunc = (fn)GetAPIInternal("psapi.dll", "EnumProcessModules");
			BOOL result = pFunc ? pFunc(hProcess, lphModule, cb, lpcbNeeded) : FALSE;
			ADD_JUNK_CODE();
			return result;
		}

		static BOOL GetModuleInformation(HANDLE hProcess, HMODULE hModule, LPMODULEINFO lpmodinfo, DWORD cb) {
			ADD_JUNK_CODE();
			typedef BOOL(WINAPI* fn)(HANDLE, HMODULE, LPMODULEINFO, DWORD);
			fn pFunc = (fn)GetAPIInternal("psapi.dll", "GetModuleInformation");
			BOOL result = pFunc ? pFunc(hProcess, hModule, lpmodinfo, cb) : FALSE;
			ADD_JUNK_CODE();
			return result;
		}

		// ============================================
		// NTDLL.DLL PROXIES
		// ============================================

		static NTSTATUS NtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus) {
			ADD_JUNK_CODE();
			typedef NTSTATUS(NTAPI* fn)(HANDLE, NTSTATUS);
			fn pFunc = (fn)GetAPIInternal("ntdll.dll", "NtTerminateProcess");
			NTSTATUS result = pFunc ? pFunc(ProcessHandle, ExitStatus) : STATUS_UNSUCCESSFUL;
			ADD_JUNK_CODE();
			return result;
		}

		static NTSTATUS NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass,
			PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {
			ADD_JUNK_CODE();
			typedef NTSTATUS(NTAPI* fn)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
			fn pFunc = (fn)GetAPIInternal("ntdll.dll", "NtQuerySystemInformation");
			NTSTATUS result = pFunc ? pFunc(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength) : STATUS_UNSUCCESSFUL;
			ADD_JUNK_CODE();
			return result;
		}

		static NTSTATUS NtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
			SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead) {
			ADD_JUNK_CODE();
			typedef NTSTATUS(NTAPI* fn)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
			fn pFunc = (fn)GetAPIInternal("ntdll.dll", "NtReadVirtualMemory");
			NTSTATUS result = pFunc ? pFunc(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead) : STATUS_UNSUCCESSFUL;
			ADD_JUNK_CODE();
			return result;
		}

		static BOOL ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer,
			SIZE_T nSize, SIZE_T* lpNumberOfBytesRead) {
			ADD_JUNK_CODE();
			typedef BOOL(WINAPI* fn)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
			fn pFunc = (fn)GetAPIInternal("kernel32.dll", "ReadProcessMemory");
			BOOL result = pFunc ? pFunc(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead) : FALSE;
			ADD_JUNK_CODE();
			return result;
		}
	};
}

// ============================================
// DYNAMIC API LOADER
// ============================================
class DynamicAPILoader {
public:
	static HMODULE GetModuleDynamic(const char* moduleName) {
		ADD_JUNK_CODE();
		HMODULE hMod = nullptr;
		__try {
			hMod = te::winapi::um::ac::bypass::proxy::ProxyAPI::LoadLibraryA(moduleName);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {}
		ADD_JUNK_CODE();
		return hMod;
	}

	static FARPROC GetFunctionDynamic(HMODULE hModule, const char* funcName) {
		ADD_JUNK_CODE();
		FARPROC pFunc = nullptr;
		__try {
			if (hModule) {
				pFunc = te::winapi::um::ac::bypass::proxy::ProxyAPI::GetProcAddress(hModule, funcName);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {}
		ADD_JUNK_CODE();
		return pFunc;
	}

	static HMODULE GetModuleFromName(const char* moduleName) {
		ADD_JUNK_CODE();
		HMODULE hMod = nullptr;
		__try {
			hMod = te::winapi::um::ac::bypass::proxy::ProxyAPI::GetModuleHandleA(moduleName);
			if (!hMod) {
				hMod = GetModuleDynamic(moduleName);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {}
		ADD_JUNK_CODE();
		return hMod;
	}
};

namespace te::winapi::um::ac::bypass
{
	// ============================================
	// ENCRYPTED STRINGS
	// ============================================
	inline char* GetStr_asi() { static auto s = skCrypt(".asi"); return s.decrypt(); }
	inline char* GetStr_cs() { static auto s = skCrypt(".cs"); return s.decrypt(); }
	inline char* GetStr_sf() { static auto s = skCrypt(".sf"); return s.decrypt(); }
	inline char* GetStr_lua() { static auto s = skCrypt(".lua"); return s.decrypt(); }
	inline char* GetStr_log() { static auto s = skCrypt(".log"); return s.decrypt(); }
	inline char* GetStr_ws() { static auto s = skCrypt(".ws"); return s.decrypt(); }

	inline char* GetStr_wraith_ac() { static auto s = skCrypt("wraith-ac.asi"); return s.decrypt(); }
	inline char* GetStr_onnxruntime() { static auto s = skCrypt("onnxruntime.dll"); return s.decrypt(); }
	inline char* GetStr_vowac() { static auto s = skCrypt("vowac.asi"); return s.decrypt(); }
	inline char* GetStr_d3d9() { static auto s = skCrypt("d3d9.dll"); return s.decrypt(); }
	inline char* GetStr_d3d11() { static auto s = skCrypt("d3d11.dll"); return s.decrypt(); }
	inline char* GetStr_dxgi() { static auto s = skCrypt("dxgi.dll"); return s.decrypt(); }
	inline char* GetStr_kernel32() { static auto s = skCrypt("kernel32.dll"); return s.decrypt(); }
	inline wchar_t* GetStr_wKernel32() { static auto s = skCrypt(L"kernel32.dll"); return s.decrypt(); }
	inline char* GetStr_ntdll() { static auto s = skCrypt("ntdll.dll"); return s.decrypt(); }
	inline wchar_t* GetStr_wNtdll() { static auto s = skCrypt(L"ntdll.dll"); return s.decrypt(); }
	inline char* GetStr_user32() { static auto s = skCrypt("user32.dll"); return s.decrypt(); }
	inline wchar_t* GetStr_wUser32() { static auto s = skCrypt(L"user32.dll"); return s.decrypt(); }
	inline char* GetStr_gdi32() { static auto s = skCrypt("gdi32.dll"); return s.decrypt(); }

	inline char* GetStr_discordhook() { static auto s = skCrypt("discordhook.dll"); return s.decrypt(); }
	inline char* GetStr_graphics_hook() { static auto s = skCrypt("graphics-hook32.dll"); return s.decrypt(); }
	inline char* GetStr_obs_vulkan() { static auto s = skCrypt("obs-vulkan32.dll"); return s.decrypt(); }
	inline char* GetStr_obs_opengl() { static auto s = skCrypt("obs-opengl32.dll"); return s.decrypt(); }

	inline char* GetStr_cleo() { static auto s = skCrypt("cleo"); return s.decrypt(); }
	inline char* GetStr_sampfuncs() { static auto s = skCrypt("sampfuncs"); return s.decrypt(); }
	inline char* GetStr_modloader() { static auto s = skCrypt("modloader"); return s.decrypt(); }
	inline char* GetStr_moonloader() { static auto s = skCrypt("moonloader"); return s.decrypt(); }
	inline char* GetStr_te_sdk() { static auto s = skCrypt("te_sdk"); return s.decrypt(); }

	inline char* GetStr_GetModuleHandleA() { static auto s = skCrypt("GetModuleHandleA"); return s.decrypt(); }
	inline char* GetStr_GetModuleHandleW() { static auto s = skCrypt("GetModuleHandleW"); return s.decrypt(); }
	inline char* GetStr_GetModuleHandleExA() { static auto s = skCrypt("GetModuleHandleExA"); return s.decrypt(); }
	inline char* GetStr_GetModuleHandleExW() { static auto s = skCrypt("GetModuleHandleExW"); return s.decrypt(); }
	inline char* GetStr_GetProcAddress() { static auto s = skCrypt("GetProcAddress"); return s.decrypt(); }
	inline char* GetStr_LoadLibraryA() { static auto s = skCrypt("LoadLibraryA"); return s.decrypt(); }
	inline char* GetStr_LoadLibraryW() { static auto s = skCrypt("LoadLibraryW"); return s.decrypt(); }
	inline char* GetStr_FindFirstFileA() { static auto s = skCrypt("FindFirstFileA"); return s.decrypt(); }
	inline char* GetStr_FindNextFileA() { static auto s = skCrypt("FindNextFileA"); return s.decrypt(); }
	inline char* GetStr_Module32First() { static auto s = skCrypt("Module32First"); return s.decrypt(); }
	inline char* GetStr_Module32Next() { static auto s = skCrypt("Module32Next"); return s.decrypt(); }
	inline char* GetStr_Process32First() { static auto s = skCrypt("Process32First"); return s.decrypt(); }
	inline char* GetStr_Process32Next() { static auto s = skCrypt("Process32Next"); return s.decrypt(); }
	inline char* GetStr_VirtualQuery() { static auto s = skCrypt("VirtualQuery"); return s.decrypt(); }
	inline char* GetStr_VirtualAlloc() { static auto s = skCrypt("VirtualAlloc"); return s.decrypt(); }
	inline char* GetStr_VirtualProtect() { static auto s = skCrypt("VirtualProtect"); return s.decrypt(); }
	inline char* GetStr_TerminateProcess() { static auto s = skCrypt("TerminateProcess"); return s.decrypt(); }
	inline char* GetStr_ReadProcessMemory() { static auto s = skCrypt("ReadProcessMemory"); return s.decrypt(); }
	inline char* GetStr_VirtualFree() { static auto s = skCrypt("VirtualFree"); return s.decrypt(); }
	inline char* GetStr_CreateRemoteThread() { static auto s = skCrypt("CreateRemoteThread"); return s.decrypt(); }
	inline char* GetStr_CreateThread() { static auto s = skCrypt("CreateThread"); return s.decrypt(); }
	inline char* GetStr_GetThreadContext() { static auto s = skCrypt("GetThreadContext"); return s.decrypt(); }
	inline char* GetStr_MessageBoxA() { static auto s = skCrypt("MessageBoxA"); return s.decrypt(); }
	inline char* GetStr_MessageBoxW() { static auto s = skCrypt("MessageBoxW"); return s.decrypt(); }
	inline char* GetStr_EnumProcessModules() { static auto s = skCrypt("EnumProcessModules"); return s.decrypt(); }
	inline char* GetStr_NtTerminateProcess() { static auto s = skCrypt("NtTerminateProcess"); return s.decrypt(); }
	inline char* GetStr_NtQuerySystemInformation() { static auto s = skCrypt("NtQuerySystemInformation"); return s.decrypt(); }
	inline char* GetStr_NtReadVirtualMemory() { static auto s = skCrypt("NtReadVirtualMemory"); return s.decrypt(); }

	inline char* GetStr_text() { static auto s = skCrypt(".text"); return s.decrypt(); }
	inline char* GetStr_Sleep() { static auto s = skCrypt("Sleep"); return s.decrypt(); }
	inline char* GetStr_psapi() { static auto s = skCrypt("psapi.dll"); return s.decrypt(); }
	inline wchar_t* GetStr_wPsapi() { static auto s = skCrypt(L"psapi.dll"); return s.decrypt(); }
	inline char* GetStr_user32dll() { static auto s = skCrypt("user32.dll"); return s.decrypt(); }
	inline char* GetStr_samp() { static auto s = skCrypt("samp.dll"); return s.decrypt(); }

	inline char* GetStr_HidingLog() { static auto s = skCrypt("[ #TE ] Hiding existing suspicious modules..."); return s.decrypt(); }
	inline char* GetStr_HiddenLog() { static auto s = skCrypt("[ #TE ] Hidden %d modules"); return s.decrypt(); }
	inline char* GetStr_HookLog() { static auto s = skCrypt("[ #TE ] [MH] %ls!%s"); return s.decrypt(); }
	inline char* GetStr_HookFailLog() { static auto s = skCrypt("[ #TE ] [MH] Failed %ls!%s : %s"); return s.decrypt(); }
	inline char* GetStr_InitLog() { static auto s = skCrypt("[ #TE ] Installing hooks via MinHook..."); return s.decrypt(); }
	inline char* GetStr_LoadedMsg() { static auto s = skCrypt("[ #TE ] Usermode AC Bypass by WaterSmoke Loaded!"); return s.decrypt(); }
	inline char* GetStr_WraithConflict() { static auto s = skCrypt("WRAITH AC was loaded before Usermode AC Bypass"); return s.decrypt(); }
	inline char* GetStr_ConflictTitle() { static auto s = skCrypt("Usermode AC Bypass - Conflict Detected"); return s.decrypt(); }
	inline char* GetStr_NtQueryVirtualMemory() { static auto s = skCrypt("NtQueryVirtualMemory"); return s.decrypt(); }
	inline char* GetStr_NtProtectVirtualMemory() { static auto s = skCrypt("NtProtectVirtualMemory"); return s.decrypt(); }

	inline char* GetStr_SetFocus() { static auto s = skCrypt("SetFocus"); return s.decrypt(); }
	inline char* GetStr_SetForegroundWindow() { static auto s = skCrypt("SetForegroundWindow"); return s.decrypt(); }
	inline char* GetStr_ShowWindow() { static auto s = skCrypt("ShowWindow"); return s.decrypt(); }
	inline char* GetStr_GetForegroundWindow() { static auto s = skCrypt("GetForegroundWindow"); return s.decrypt(); }

	inline char* GetStr_socket() { static auto s = skCrypt("socket"); return s.decrypt(); }
	inline char* GetStr_sendto() { static auto s = skCrypt("sendto"); return s.decrypt(); }
	inline char* GetStr_wsasendto() { static auto s = skCrypt("WSASendTo"); return s.decrypt(); }
	inline char* GetStr_send() { static auto s = skCrypt("send"); return s.decrypt(); }
	inline char* GetStr_connect() { static auto s = skCrypt("connect"); return s.decrypt(); }

	// ============================================
	// CONFIGURATION
	// ============================================
	static std::vector<std::string> g_hiddenExtensions;
	static std::vector<std::string> g_whitelistedFiles;
	static std::vector<std::string> g_blacklistedFiles;
	static std::vector<std::string> g_blacklistDirs;

	static void InitializeExtensions() {
		ADD_JUNK_CODE();
		if (!g_hiddenExtensions.empty()) return;
		g_hiddenExtensions = {
			GetStr_asi(), GetStr_cs(), GetStr_sf(), GetStr_lua(), GetStr_log(), GetStr_ws()
		};
		ADD_JUNK_CODE();
	}

	static void InitializeWhitelisted() {
		ADD_JUNK_CODE();
		if (!g_whitelistedFiles.empty()) return;
		g_whitelistedFiles = {
			GetStr_wraith_ac(), GetStr_onnxruntime(), GetStr_vowac(),
			// vowac.asi removed from whitelist - it scans MinHook trampolines directly
			GetStr_d3d9(), GetStr_d3d11(), GetStr_dxgi(), GetStr_kernel32(),
			GetStr_ntdll(), GetStr_user32(), GetStr_gdi32()
		};
		ADD_JUNK_CODE();
	}

	static void InitializeBlacklisted() {
		ADD_JUNK_CODE();
		if (!g_blacklistedFiles.empty()) return;
		g_blacklistedFiles = {
			GetStr_discordhook(), GetStr_graphics_hook(),
			GetStr_obs_vulkan(), GetStr_obs_opengl()
		};
		ADD_JUNK_CODE();
	}

	static void InitializeBlacklistDirs() {
		ADD_JUNK_CODE();
		if (!g_blacklistDirs.empty()) return;
		g_blacklistDirs = {
			GetStr_cleo(), GetStr_sampfuncs(), GetStr_modloader(), GetStr_moonloader(), GetStr_te_sdk()
		};
		ADD_JUNK_CODE();
	}

	// ============================================
	// SOCKET MONITORING & HOOKING
	// ============================================
	namespace SocketMonitor {
		struct SocketInfo {
			SOCKET sock;
			int addressFamily;
			int socketType;
			int protocol;
			bool isMonitored;
		};

		static std::unordered_map<uintptr_t, SocketInfo> g_sockets;
		static std::recursive_mutex g_socketsMutex;

		static bool IsTargetAddress(const sockaddr* addr, int addrlen) {
			if (!addr) return false;

			uint32_t serverIP = htonl(INADDR_LOOPBACK);  // 127.0.0.1 default
			uint16_t serverPort = 7777;

			__try {
				auto& sessionInfo = te::sdk::GetSessionInfo();

				serverIP = inet_addr(sessionInfo.serverIP);

				if (serverIP == INADDR_NONE) {
					serverIP = htonl(INADDR_LOOPBACK);
				}

				serverPort = sessionInfo.serverPort;

				//te::sdk::helper::logging::Log("[ #TE ] SAMP Server configured: IP=%s (%08X), Port=%d",
				//	sessionInfo.serverIP, serverIP, serverPort);
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				return false;
			}

			if (addr->sa_family == AF_INET) {
				sockaddr_in* sin = (sockaddr_in*)addr;
				uint32_t targetIP = sin->sin_addr.S_un.S_addr;
				uint16_t targetPort = sin->sin_port;

				bool isAllowed = (targetIP == serverIP && targetPort == htons(serverPort));

				if (!isAllowed) 
				{
					te::sdk::helper::logging::Log("[ #TE ] SOCKET BLOCKED: IP=%s:%d (not SAMP server)",
						inet_ntoa(sin->sin_addr), ntohs(targetPort));
				}

				return isAllowed;
			}
			else if (addr->sa_family == AF_INET6) {
				te::sdk::helper::logging::Log("[ #TE ] SOCKET BLOCKED: IPv6 connection detected");
				return false;
			}

			return false;
		}
	}

	// ============================================
	// DYNAMIC API HELPERS
	// ============================================
	class APILoader {
	public:
		static HMODULE LoadModule(const char* moduleName) {
			ADD_JUNK_CODE();
			HMODULE hMod = nullptr;

			typedef HMODULE(WINAPI* fnLoadLibraryA)(LPCSTR);
			fnLoadLibraryA pLoadLib = (fnLoadLibraryA)DynamicAPILoader::GetFunctionDynamic(
				proxy::ProxyAPI::GetModuleHandleA("kernel32.dll"), "LoadLibraryA"
			);
			if (pLoadLib) {
				hMod = pLoadLib(moduleName);
			}

			ADD_JUNK_CODE();
			return hMod;
		}

		static HMODULE GetModule(const char* moduleName) {
			ADD_JUNK_CODE();
			HMODULE hMod = nullptr;

			typedef HMODULE(WINAPI* fnGetModuleHandleA)(LPCSTR);
			fnGetModuleHandleA pGetMod = (fnGetModuleHandleA)DynamicAPILoader::GetFunctionDynamic(
				proxy::ProxyAPI::GetModuleHandleA("kernel32.dll"), "GetModuleHandleA"
			);
			if (pGetMod) {
				hMod = pGetMod(moduleName);
			}
			if (!hMod) {
				hMod = LoadModule(moduleName);
			}

			ADD_JUNK_CODE();
			return hMod;
		}

		static FARPROC GetFunction(HMODULE hModule, const char* funcName) {
			ADD_JUNK_CODE();
			FARPROC pFunc = nullptr;

			typedef FARPROC(WINAPI* fnGetProcAddress)(HMODULE, LPCSTR);
			fnGetProcAddress pGetProc = (fnGetProcAddress)DynamicAPILoader::GetFunctionDynamic(
				proxy::ProxyAPI::GetModuleHandleA("kernel32.dll"), "GetProcAddress"
			);
			if (pGetProc && hModule) {
				pFunc = pGetProc(hModule, funcName);
			}

			ADD_JUNK_CODE();
			return pFunc;
		}
	};

	// ============================================
	// GLOBAL STATE
	// ============================================
	static std::unordered_map<std::string, HMODULE> g_hiddenModules;
	static std::recursive_mutex g_hiddenModulesMutex;
	static std::recursive_mutex g_antiDetectionMutex;
	static std::unordered_map<std::string, void*> g_originalFunctions;

	static std::atomic<bool> g_hooksInitialized{ false };
	static std::atomic<bool> g_hooksReady{ false };

	struct MemoryRegion {
		uintptr_t start;
		uintptr_t end;
		DWORD fakeProtect;
		DWORD realProtect;
	};
	static std::vector<MemoryRegion> g_spoofedMemoryRegions;

	// VEH Protection for MinHook trampolines
	struct TrampolineRegion {
		uintptr_t address;
		size_t size;
		std::vector<BYTE> cleanData;  // Original bytes to return on read
	};
	static std::vector<TrampolineRegion> g_protectedTrampolines;
	static std::recursive_mutex g_trampolineMutex;
	static PVOID g_vehHandle = nullptr;

	struct WraithAllocation {
		LPVOID address;
		SIZE_T size;
	};
	static std::vector<WraithAllocation> g_wraithAllocations;
	static std::recursive_mutex g_wraithAllocationsMutex;

	thread_local int g_hookReentrancyCount = 0;

	static std::unordered_set<uintptr_t> g_protectedAddresses;
	static std::recursive_mutex g_protectMutex;

	// ============================================
	// FUNCTION POINTER TYPEDEFS
	// ============================================
	typedef HMODULE(WINAPI* GetModuleHandleA_t)(LPCSTR);
	typedef HMODULE(WINAPI* GetModuleHandleW_t)(LPCWSTR);
	typedef BOOL(WINAPI* GetModuleHandleExA_t)(DWORD, LPCSTR, HMODULE*);
	typedef BOOL(WINAPI* GetModuleHandleExW_t)(DWORD, LPCWSTR, HMODULE*);
	typedef FARPROC(WINAPI* GetProcAddress_t)(HMODULE, LPCSTR);
	typedef HMODULE(WINAPI* LoadLibraryA_t)(LPCSTR);
	typedef HMODULE(WINAPI* LoadLibraryW_t)(LPCWSTR);
	typedef BOOL(WINAPI* Module32First_t)(HANDLE, LPMODULEENTRY32);
	typedef BOOL(WINAPI* Module32Next_t)(HANDLE, LPMODULEENTRY32);
	typedef BOOL(WINAPI* Process32First_t)(HANDLE, LPPROCESSENTRY32);
	typedef BOOL(WINAPI* Process32Next_t)(HANDLE, LPPROCESSENTRY32);
	typedef HANDLE(WINAPI* FindFirstFileA_t)(LPCSTR, LPWIN32_FIND_DATAA);
	typedef BOOL(WINAPI* FindNextFileA_t)(HANDLE, LPWIN32_FIND_DATAA);
	typedef SIZE_T(WINAPI* VirtualQuery_t)(LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
	typedef BOOL(WINAPI* EnumProcessModules_t)(HANDLE, HMODULE*, DWORD, LPDWORD);
	typedef int(WINAPI* MessageBoxA_t)(HWND, LPCSTR, LPCSTR, UINT);
	typedef int(WINAPI* MessageBoxW_t)(HWND, LPCWSTR, LPCWSTR, UINT);
	typedef BOOL(WINAPI* TerminateProcess_t)(HANDLE, UINT);
	typedef BOOL(WINAPI* VirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
	typedef BOOL(WINAPI* VirtualFree_t)(LPVOID, SIZE_T, DWORD);
	typedef HANDLE(WINAPI* CreateThread_t)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
	typedef HANDLE(WINAPI* CreateRemoteThread_t)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
	typedef BOOL(WINAPI* GetThreadContext_t)(HANDLE, LPCONTEXT);
	typedef LPVOID(WINAPI* VirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD);
	typedef BOOL(WINAPI* ReadProcessMemory_t)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
	typedef HWND(WINAPI* SetFocus_t)(HWND);
	typedef HWND(WINAPI* SetForegroundWindow_t)(HWND);
	typedef BOOL(WINAPI* ShowWindow_t)(HWND, int);
	typedef HWND(WINAPI* GetForegroundWindow_t)();

	// ============================================
	// UTILITY FUNCTIONS
	// ============================================
	struct ReentrancyGuard {
		bool wasActive;
		ReentrancyGuard() : wasActive(g_hookReentrancyCount > 0) {
			g_hookReentrancyCount++;
		}
		~ReentrancyGuard() {
			g_hookReentrancyCount--;
		}
		bool IsReentrant() const { return wasActive; }
	};

	template<typename T>
	inline T GetOriginalFunction(const char* name) {
		ADD_JUNK_CODE();
		auto it = g_originalFunctions.find(name);
		ADD_JUNK_CODE();
		return (it != g_originalFunctions.end()) ? reinterpret_cast<T>(it->second) : nullptr;
	}

	static bool HasSuspiciousExtension(const std::string& filename) {
		ADD_JUNK_CODE();
		size_t dotPos = filename.find_last_of('.');
		if (dotPos == std::string::npos) return false;
		std::string ext = filename.substr(dotPos);

		InitializeExtensions();
		for (const auto& hiddenExt : g_hiddenExtensions) {
			if (_stricmp(ext.c_str(), hiddenExt.c_str()) == 0) {
				ADD_JUNK_CODE();
				return true;
			}
		}
		ADD_JUNK_CODE();
		return false;
	}

	static bool IsWhitelistedFile(const std::string& filename) {
		ADD_JUNK_CODE();
		std::string lower = filename;
		std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
		size_t lastSlash = lower.find_last_of("\\/");
		if (lastSlash != std::string::npos) lower = lower.substr(lastSlash + 1);

		InitializeWhitelisted();
		for (const auto& white : g_whitelistedFiles) {
			if (lower == white || lower.find(white) != std::string::npos) {
				ADD_JUNK_CODE();
				return true;
			}
		}
		ADD_JUNK_CODE();
		return false;
	}

	static bool IsBlacklistedFile(const std::string& filename) {
		ADD_JUNK_CODE();
		std::string lower = filename;
		std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
		size_t lastSlash = lower.find_last_of("\\/");
		if (lastSlash != std::string::npos) lower = lower.substr(lastSlash + 1);

		InitializeBlacklisted();
		for (const auto& black : g_blacklistedFiles) {
			if (lower == black) {
				ADD_JUNK_CODE();
				return true;
			}
		}
		ADD_JUNK_CODE();
		return false;
	}

	static bool IsInBlackListDirectory(const std::string& filePath) {
		ADD_JUNK_CODE();
		std::string lower = filePath;
		std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
		std::replace(lower.begin(), lower.end(), '/', '\\');

		InitializeBlacklistDirs();
		for (const auto& dir : g_blacklistDirs) {
			if (lower.find("\\" + dir + "\\") != std::string::npos ||
				lower.find(dir + "\\") == 0) {
				ADD_JUNK_CODE();
				return true;
			}
		}
		ADD_JUNK_CODE();
		return false;
	}

	static bool ShouldHideFile(const std::string& filename, const std::string& fullPath = "") {
		ADD_JUNK_CODE();
		if (IsWhitelistedFile(filename) || (!fullPath.empty() && IsWhitelistedFile(fullPath)))
			return false;
		if (IsBlacklistedFile(filename) || (!fullPath.empty() && IsBlacklistedFile(fullPath)))
			return true;
		if (HasSuspiciousExtension(filename)) return true;
		ADD_JUNK_CODE();
		return !fullPath.empty() && IsInBlackListDirectory(fullPath);
	}

	static bool HasSuspiciousExtensionC(const char* filename) {
		ADD_JUNK_CODE();
		if (!filename) return false;
		const char* dot = strrchr(filename, '.');
		if (!dot) return false;

		InitializeExtensions();
		for (const auto& hiddenExt : g_hiddenExtensions) {
			if (_stricmp(dot, hiddenExt.c_str()) == 0) {
				ADD_JUNK_CODE();
				return true;
			}
		}
		ADD_JUNK_CODE();
		return false;
	}

	static void FilterSystemModulesSafe(
		PRTL_PROCESS_MODULES modules,
		const char* const* hiddenNames,
		size_t hiddenNameCount,
		PULONG returnLength) {

		ADD_JUNK_CODE();
		__try {
			if (!modules || modules->NumberOfModules == 0) return;

			ULONG filteredCount = 0;
			for (ULONG i = 0; i < modules->NumberOfModules; i++) {
				const char* modName = reinterpret_cast<const char*>(modules->Modules[i].FullPathName) +
					modules->Modules[i].OffsetToFileName;

				bool isHidden = false;
				for (size_t h = 0; h < hiddenNameCount; h++) {
					const char* hiddenName = hiddenNames[h];
					if (hiddenName && strstr(modName, hiddenName) != nullptr) {
						isHidden = true;
						break;
					}
				}

				if (!isHidden && !HasSuspiciousExtensionC(modName)) {
					if (filteredCount != i) {
						modules->Modules[filteredCount] = modules->Modules[i];
					}
					filteredCount++;
				}
			}

			modules->NumberOfModules = filteredCount;
			if (returnLength) {
				*returnLength = sizeof(ULONG) + (filteredCount * sizeof(RTL_PROCESS_MODULE_INFORMATION));
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {}
		ADD_JUNK_CODE();
	}

	static bool TryZeroReadFromRegions(
		const MemoryRegion* regions,
		size_t regionCount,
		uintptr_t addr,
		void* buffer,
		SIZE_T size,
		SIZE_T* bytesRead,
		const char* logFormat,
		const void* baseAddress) {

		ADD_JUNK_CODE();
		__try {
			for (size_t i = 0; i < regionCount; i++) {
				const auto& region = regions[i];
				if (addr >= region.start && addr < region.end) {
					if (buffer && size > 0) {
						memset(buffer, 0, size);
					}
					if (bytesRead) *bytesRead = size;

					te::sdk::helper::logging::Log(logFormat, baseAddress);
					ADD_JUNK_CODE();
					return true;
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {}
		ADD_JUNK_CODE();
		return false;
	}

	// ============================================
	// CALL STACK SPOOFING SYSTEM
	// ============================================
	static void* FindLegitimateReturnAddress() {
		ADD_JUNK_CODE();
		auto pOriginal = GetOriginalFunction<GetModuleHandleA_t>(GetStr_GetModuleHandleA());
		if (!pOriginal) {
			pOriginal = (GetModuleHandleA_t)APILoader::GetFunction(
				APILoader::GetModule(GetStr_kernel32()),
				GetStr_GetModuleHandleA()
			);
		}

		HMODULE hKernel32 = pOriginal(GetStr_kernel32());
		if (!hKernel32) {
			ADD_JUNK_CODE();
			return nullptr;
		}

		PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hKernel32;
		PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)hKernel32 + pDos->e_lfanew);
		PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);

		for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
			if (strcmp((char*)pSection[i].Name, GetStr_text()) == 0) {
				ADD_JUNK_CODE();
				return (void*)((uintptr_t)hKernel32 + pSection[i].VirtualAddress + 0x100);
			}
		}
		ADD_JUNK_CODE();
		return (void*)((uintptr_t)hKernel32 + 0x1000);
	}

#ifdef _M_IX86
	extern "C" {
		void* _GetReturnAddressX86();
		void _SetReturnAddressX86(void* newAddress);
		void** _GetStackPointerX86();
	}
#endif

	class CallStackSpoofer {
	private:
		void** pReturnAddress;
		void* originalReturn;
		void* spoofedReturn;
		bool isActive;

	public:
		CallStackSpoofer() : pReturnAddress(nullptr), originalReturn(nullptr),
			spoofedReturn(nullptr), isActive(false) {
			ADD_JUNK_CODE();
#ifdef _WIN64
			pReturnAddress = (void**)_AddressOfReturnAddress();
			originalReturn = *pReturnAddress;
			spoofedReturn = FindLegitimateReturnAddress();
			if (spoofedReturn && pReturnAddress) {
				*pReturnAddress = spoofedReturn;
				isActive = true;
			}
#elif _M_IX86
			originalReturn = _GetReturnAddressX86();
			pReturnAddress = _GetStackPointerX86();
			spoofedReturn = FindLegitimateReturnAddress();

			if (spoofedReturn && pReturnAddress && originalReturn) {
				_SetReturnAddressX86(spoofedReturn);
				isActive = true;
			}
#endif
			ADD_JUNK_CODE();
		}

		~CallStackSpoofer() {
			ADD_JUNK_CODE();
#ifdef _WIN64
			if (isActive && pReturnAddress && originalReturn) {
				*pReturnAddress = originalReturn;
			}
#elif _M_IX86
			if (isActive && pReturnAddress && originalReturn) {
				_SetReturnAddressX86(originalReturn);
			}
#endif
			ADD_JUNK_CODE();
		}

		bool IsActive() const { return isActive; }
	};
	static void RegisterHiddenRegion(void* hiddenPtr, size_t size = 64) {
		ADD_JUNK_CODE();
		if (!hiddenPtr) return;

		std::lock_guard<std::recursive_mutex> lock(g_antiDetectionMutex);

		MemoryRegion region;
		region.start = reinterpret_cast<uintptr_t>(hiddenPtr);
		region.end = region.start + size;
		region.realProtect = PAGE_EXECUTE_READWRITE;
		region.fakeProtect = PAGE_EXECUTE_READ;

		g_spoofedMemoryRegions.push_back(region);

		te::sdk::helper::logging::Log("[ #TE ] Registered hidden region: %p - %p",
			(void*)region.start, (void*)region.end);
		ADD_JUNK_CODE();
	}

	static void RegisterHiddenModuleMemory(HMODULE hModule) {
		ADD_JUNK_CODE();
		if (!hModule) return;

		MODULEINFO modInfo = {};
		if (!te::winapi::um::ac::bypass::proxy::ProxyAPI::GetModuleInformation(te::winapi::um::ac::bypass::proxy::ProxyAPI::GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))) {
			return;
		}

		std::lock_guard<std::recursive_mutex> lock(g_antiDetectionMutex);

		MemoryRegion region;
		region.start = reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll);
		region.end = region.start + modInfo.SizeOfImage;
		region.realProtect = PAGE_EXECUTE_READWRITE;
		region.fakeProtect = PAGE_EXECUTE_READ;

		g_spoofedMemoryRegions.push_back(region);

		te::sdk::helper::logging::Log("[ #TE ] Registered hidden module memory: %p - %p (Size: %u KB)",
			(void*)region.start, (void*)region.end, modInfo.SizeOfImage / 1024);
		ADD_JUNK_CODE();
	}

	static void UnlinkModuleFromPEB(HMODULE hModule) {
		ADD_JUNK_CODE();
		if (!hModule) return;

		__try {
#ifdef _WIN64
			PTE_PEB pPeb = (PTE_PEB)__readgsqword(0x60);
#else
			PTE_PEB pPeb = (PTE_PEB)__readfsdword(0x30);
#endif
			if (!pPeb || !pPeb->Ldr) return;

			PTE_PEB_LDR_DATA pLdr = pPeb->Ldr;
			PLIST_ENTRY pListHead = &pLdr->InLoadOrderModuleList;
			PLIST_ENTRY pListEntry = pListHead->Flink;

			while (pListEntry && pListEntry != pListHead) {
				PTE_LDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(
					pListEntry, TE_LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
				pListEntry = pListEntry->Flink;

				if (pEntry->DllBase == hModule) {
					if (pEntry->InLoadOrderLinks.Flink && pEntry->InLoadOrderLinks.Blink) {
						pEntry->InLoadOrderLinks.Blink->Flink = pEntry->InLoadOrderLinks.Flink;
						pEntry->InLoadOrderLinks.Flink->Blink = pEntry->InLoadOrderLinks.Blink;
					}
					if (pEntry->InMemoryOrderLinks.Flink && pEntry->InMemoryOrderLinks.Blink) {
						pEntry->InMemoryOrderLinks.Blink->Flink = pEntry->InMemoryOrderLinks.Flink;
						pEntry->InMemoryOrderLinks.Flink->Blink = pEntry->InMemoryOrderLinks.Blink;
					}
					if (pEntry->InInitializationOrderLinks.Flink && pEntry->InInitializationOrderLinks.Blink) {
						pEntry->InInitializationOrderLinks.Blink->Flink = pEntry->InInitializationOrderLinks.Flink;
						pEntry->InInitializationOrderLinks.Flink->Blink = pEntry->InInitializationOrderLinks.Blink;
					}
					break;
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {}
		ADD_JUNK_CODE();
	}

	// ============================================
	// HOOKED FUNCTIONS - SIMPLIFIED VERSION
	// ============================================

	HMODULE WINAPI Hooked_GetModuleHandleA(LPCSTR lpModuleName) {
		ADD_JUNK_CODE();
		CallStackSpoofer spoofer;
		auto pOriginal = GetOriginalFunction<GetModuleHandleA_t>(GetStr_GetModuleHandleA());

		ReentrancyGuard guard;
		if (guard.IsReentrant() || !lpModuleName) return pOriginal(lpModuleName);

		if (ShouldHideFile(lpModuleName)) {
			ADD_JUNK_CODE();
			return NULL;
		}
		ADD_JUNK_CODE();
		return pOriginal(lpModuleName);
	}

	HMODULE WINAPI Hooked_GetModuleHandleW(LPCWSTR lpModuleName) {
		ADD_JUNK_CODE();
		CallStackSpoofer spoofer;
		auto pOriginal = GetOriginalFunction<GetModuleHandleW_t>(GetStr_GetModuleHandleW());

		ReentrancyGuard guard;
		if (guard.IsReentrant() || !lpModuleName) return pOriginal(lpModuleName);

		std::wstring wstr(lpModuleName);
		std::string str(wstr.begin(), wstr.end());
		if (ShouldHideFile(str)) {
			ADD_JUNK_CODE();
			return NULL;
		}
		ADD_JUNK_CODE();
		return pOriginal(lpModuleName);
	}

	BOOL WINAPI Hooked_GetModuleHandleExA(DWORD dwFlags, LPCSTR lpModuleName, HMODULE* phModule) {
		ADD_JUNK_CODE();
		CallStackSpoofer spoofer;
		auto pOriginal = GetOriginalFunction<GetModuleHandleExA_t>(GetStr_GetModuleHandleExA());

		ReentrancyGuard guard;
		if (guard.IsReentrant()) return pOriginal(dwFlags, lpModuleName, phModule);

		if (lpModuleName && ShouldHideFile(lpModuleName)) {
			te::winapi::um::ac::bypass::proxy::ProxyAPI::SetLastError(ERROR_MOD_NOT_FOUND);
			ADD_JUNK_CODE();
			return FALSE;
		}
		ADD_JUNK_CODE();
		return pOriginal(dwFlags, lpModuleName, phModule);
	}

	BOOL WINAPI Hooked_GetModuleHandleExW(DWORD dwFlags, LPCWSTR lpModuleName, HMODULE* phModule) {
		ADD_JUNK_CODE();
		CallStackSpoofer spoofer;
		auto pOriginal = GetOriginalFunction<GetModuleHandleExW_t>(GetStr_GetModuleHandleExW());

		ReentrancyGuard guard;
		if (guard.IsReentrant()) return pOriginal(dwFlags, lpModuleName, phModule);

		if (lpModuleName) {
			std::wstring wstr(lpModuleName);
			std::string str(wstr.begin(), wstr.end());
			if (ShouldHideFile(str)) {
				te::winapi::um::ac::bypass::proxy::ProxyAPI::SetLastError(ERROR_MOD_NOT_FOUND);
				ADD_JUNK_CODE();
				return FALSE;
			}
		}
		ADD_JUNK_CODE();
		return pOriginal(dwFlags, lpModuleName, phModule);
	}

	FARPROC WINAPI Hooked_GetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
		ADD_JUNK_CODE();
		CallStackSpoofer spoofer;
		auto pOriginal = GetOriginalFunction<GetProcAddress_t>(GetStr_GetProcAddress());

		ReentrancyGuard guard;
		if (guard.IsReentrant()) return pOriginal(hModule, lpProcName);

		{
			std::lock_guard<std::recursive_mutex> lock(g_hiddenModulesMutex);
			for (const auto& [name, handle] : g_hiddenModules) {
				if (handle == hModule) {
					ADD_JUNK_CODE();
					return NULL;
				}
			}
		}

		ADD_JUNK_CODE();
		return pOriginal(hModule, lpProcName);
	}

	HMODULE WINAPI Hooked_LoadLibraryA(LPCSTR lpLibFileName) {
		ADD_JUNK_CODE();
		CallStackSpoofer spoofer;
		auto pOriginal = GetOriginalFunction<LoadLibraryA_t>(GetStr_LoadLibraryA());

		ReentrancyGuard guard;
		if (guard.IsReentrant()) return pOriginal(lpLibFileName);

		if (lpLibFileName && ShouldHideFile(lpLibFileName)) {
			te::winapi::um::ac::bypass::proxy::ProxyAPI::SetLastError(ERROR_MOD_NOT_FOUND);
			ADD_JUNK_CODE();
			return NULL;
		}

		HMODULE hModule = pOriginal(lpLibFileName);
		if (hModule && lpLibFileName && ShouldHideFile(lpLibFileName, lpLibFileName)) {
			std::string lower = lpLibFileName;
			std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
			std::lock_guard<std::recursive_mutex> lock(g_hiddenModulesMutex);
			g_hiddenModules[lower] = hModule;

			RegisterHiddenModuleMemory(hModule);
		}
		ADD_JUNK_CODE();
		return hModule;
	}

	HMODULE WINAPI Hooked_LoadLibraryW(LPCWSTR lpLibFileName) {
		ADD_JUNK_CODE();
		CallStackSpoofer spoofer;
		auto pOriginal = GetOriginalFunction<LoadLibraryW_t>(GetStr_LoadLibraryW());

		ReentrancyGuard guard;
		if (guard.IsReentrant()) return pOriginal(lpLibFileName);

		if (lpLibFileName) {
			std::wstring wstr(lpLibFileName);
			std::string str(wstr.begin(), wstr.end());
			if (ShouldHideFile(str)) {
				te::winapi::um::ac::bypass::proxy::ProxyAPI::SetLastError(ERROR_MOD_NOT_FOUND);
				ADD_JUNK_CODE();
				return NULL;
			}
		}

		HMODULE hModule = pOriginal(lpLibFileName);
		if (hModule && lpLibFileName) {
			std::wstring wstr(lpLibFileName);
			std::string str(wstr.begin(), wstr.end());
			if (ShouldHideFile(str, str)) {
				std::transform(str.begin(), str.end(), str.begin(), ::tolower);
				std::lock_guard<std::recursive_mutex> lock(g_hiddenModulesMutex);
				g_hiddenModules[str] = hModule;

				RegisterHiddenModuleMemory(hModule);
			}
		}
		ADD_JUNK_CODE();
		return hModule;
	}

	BOOL WINAPI Hooked_Module32First(HANDLE hSnapshot, LPMODULEENTRY32 lpme) {
		ADD_JUNK_CODE();
		CallStackSpoofer spoofer;
		auto pOriginal = GetOriginalFunction<Module32First_t>(GetStr_Module32First());
		if (!pOriginal) return FALSE;

		ReentrancyGuard guard;
		if (guard.IsReentrant()) return pOriginal(hSnapshot, lpme);

		BOOL result;
		do {
			result = pOriginal(hSnapshot, lpme);
			if (!result || !lpme) break;
			if (IsWhitelistedFile(lpme->szModule)) break;
			if (!HasSuspiciousExtension(lpme->szModule)) break;
		} while (result);
		ADD_JUNK_CODE();
		return result;
	}

	BOOL WINAPI Hooked_Module32Next(HANDLE hSnapshot, LPMODULEENTRY32 lpme) {
		ADD_JUNK_CODE();
		CallStackSpoofer spoofer;
		auto pOriginal = GetOriginalFunction<Module32Next_t>(GetStr_Module32Next());
		if (!pOriginal) return FALSE;

		ReentrancyGuard guard;
		if (guard.IsReentrant()) return pOriginal(hSnapshot, lpme);

		BOOL result;
		do {
			result = pOriginal(hSnapshot, lpme);
			if (!result || !lpme) break;
			if (IsWhitelistedFile(lpme->szModule)) break;
			if (!HasSuspiciousExtension(lpme->szModule)) break;
		} while (result);
		ADD_JUNK_CODE();
		return result;
	}

	BOOL WINAPI Hooked_Process32First(HANDLE hSnapshot, LPPROCESSENTRY32 lppe) {
		ADD_JUNK_CODE();
		CallStackSpoofer spoofer;
		auto pOriginal = GetOriginalFunction<Process32First_t>(GetStr_Process32First());
		if (!pOriginal) return FALSE;

		ReentrancyGuard guard;
		if (guard.IsReentrant()) return pOriginal(hSnapshot, lppe);

		DWORD currentPid = GetCurrentProcessId();
		BOOL result;
		do {
			result = pOriginal(hSnapshot, lppe);
			if (!result || !lppe) break;
			if (lppe->th32ProcessID == currentPid) break;
		} while (result);
		ADD_JUNK_CODE();
		return result;
	}

	BOOL WINAPI Hooked_Process32Next(HANDLE hSnapshot, LPPROCESSENTRY32 lppe) {
		ADD_JUNK_CODE();
		CallStackSpoofer spoofer;
		auto pOriginal = GetOriginalFunction<Process32Next_t>(GetStr_Process32Next());
		if (!pOriginal) return FALSE;

		ReentrancyGuard guard;
		if (guard.IsReentrant()) return pOriginal(hSnapshot, lppe);

		DWORD currentPid = GetCurrentProcessId();
		BOOL result;
		do {
			result = pOriginal(hSnapshot, lppe);
			if (!result || !lppe) break;
			if (lppe->th32ProcessID == currentPid) break;
		} while (result);
		ADD_JUNK_CODE();
		return result;
	}

	HANDLE WINAPI Hooked_FindFirstFileA(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData) {
		ADD_JUNK_CODE();
		CallStackSpoofer spoofer;
		auto pOriginal = GetOriginalFunction<FindFirstFileA_t>(GetStr_FindFirstFileA());
		if (!pOriginal) return INVALID_HANDLE_VALUE;

		ReentrancyGuard guard;
		if (guard.IsReentrant()) return pOriginal(lpFileName, lpFindFileData);

		HANDLE result = pOriginal(lpFileName, lpFindFileData);
		if (result != INVALID_HANDLE_VALUE && lpFindFileData) {
			if (ShouldHideFile(lpFindFileData->cFileName, lpFileName ? lpFileName : "")) {
				te::winapi::um::ac::bypass::proxy::ProxyAPI::FindClose(result);
				te::winapi::um::ac::bypass::proxy::ProxyAPI::SetLastError(ERROR_NO_MORE_FILES);
				ADD_JUNK_CODE();
				return INVALID_HANDLE_VALUE;
			}
		}
		ADD_JUNK_CODE();
		return result;
	}

	BOOL WINAPI Hooked_FindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData) {
		ADD_JUNK_CODE();
		CallStackSpoofer spoofer;
		auto pOriginal = GetOriginalFunction<FindNextFileA_t>(GetStr_FindNextFileA());
		if (!pOriginal) return FALSE;

		ReentrancyGuard guard;
		if (guard.IsReentrant()) return pOriginal(hFindFile, lpFindFileData);

		BOOL result;
		do {
			result = pOriginal(hFindFile, lpFindFileData);
			if (!result || !lpFindFileData) break;
			if (!ShouldHideFile(lpFindFileData->cFileName)) break;
		} while (result);
		ADD_JUNK_CODE();
		return result;
	}

	static void MaskRegionAsModule(PMEMORY_BASIC_INFORMATION lpBuffer, const char* maskModule = nullptr) {
		ADD_JUNK_CODE();
		if (!maskModule) maskModule = GetStr_samp();

		HMODULE hMask = APILoader::GetModule(maskModule);
		if (!hMask) hMask = APILoader::GetModule(GetStr_kernel32());
		if (!hMask) return;

		typedef BOOL(WINAPI* fnGetModuleInformation)(HANDLE, HMODULE, LPMODULEINFO, DWORD);
		HMODULE hPsapi = APILoader::GetModule(GetStr_psapi());
		fnGetModuleInformation pGetModInfo = (fnGetModuleInformation)APILoader::GetFunction(hPsapi, "GetModuleInformation");

		if (!pGetModInfo) {
			ADD_JUNK_CODE();
			return;
		}

		MODULEINFO modInfo = {};
		if (pGetModInfo(te::winapi::um::ac::bypass::proxy::ProxyAPI::GetCurrentProcess(), hMask, &modInfo, sizeof(modInfo))) {
			lpBuffer->BaseAddress = modInfo.lpBaseOfDll;
			lpBuffer->RegionSize = modInfo.SizeOfImage;
			lpBuffer->Type = MEM_IMAGE;
			lpBuffer->State = MEM_COMMIT;
			lpBuffer->Protect = PAGE_EXECUTE_READ;
			lpBuffer->AllocationProtect = PAGE_EXECUTE_READ;
		}
		ADD_JUNK_CODE();
	}

	SIZE_T WINAPI Hooked_VirtualQuery(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength) {
		ADD_JUNK_CODE();
		CallStackSpoofer spoofer;
		auto pOriginal = GetOriginalFunction<VirtualQuery_t>(GetStr_VirtualQuery());
		if (!pOriginal) return 0;

		ReentrancyGuard guard;
		if (guard.IsReentrant()) return pOriginal(lpAddress, lpBuffer, dwLength);

		SIZE_T result = pOriginal(lpAddress, lpBuffer, dwLength);
		if (!result || !lpBuffer) return result;

		uintptr_t addr = reinterpret_cast<uintptr_t>(lpAddress);

		/*{
			std::lock_guard<std::recursive_mutex> lock(g_antiDetectionMutex);
			for (const auto& region : g_spoofedMemoryRegions) {
				if (addr >= region.start && addr < region.end) {
					MaskRegionAsModule(lpBuffer, GetStr_samp());
					te::sdk::helper::logging::Log("[ #TE ] VirtualQuery spoofed for hidden region %p", lpAddress);
					ADD_JUNK_CODE();
					return result;
				}
			}
		}*/

		{
			//std::lock_guard<std::recursive_mutex> lock(g_hiddenModulesMutex);
			for (const auto& [name, handle] : g_hiddenModules) {
				MODULEINFO modInfo = {};
				if (te::winapi::um::ac::bypass::proxy::ProxyAPI::GetModuleInformation(te::winapi::um::ac::bypass::proxy::ProxyAPI::GetCurrentProcess(), handle, &modInfo, sizeof(modInfo))) {
					if (addr >= (uintptr_t)modInfo.lpBaseOfDll &&
						addr < (uintptr_t)modInfo.lpBaseOfDll + modInfo.SizeOfImage) {

						MaskRegionAsModule(lpBuffer, GetStr_samp());
						//ADD_JUNK_CODE();
						return result;
					}
				}
			}
		}

		ADD_JUNK_CODE();
		return result;
	}

	BOOL WINAPI Hooked_EnumProcessModules(HANDLE hProcess, HMODULE* lphModule, DWORD cb, LPDWORD lpcbNeeded) {
		ADD_JUNK_CODE();
		CallStackSpoofer spoofer;
		auto pOriginal = GetOriginalFunction<EnumProcessModules_t>(GetStr_EnumProcessModules());
		if (!pOriginal) return FALSE;

		ReentrancyGuard guard;
		if (guard.IsReentrant()) return pOriginal(hProcess, lphModule, cb, lpcbNeeded);
		if (hProcess != te::winapi::um::ac::bypass::proxy::ProxyAPI::GetCurrentProcess() && hProcess != (HANDLE)-1)
			return pOriginal(hProcess, lphModule, cb, lpcbNeeded);

		BOOL result = pOriginal(hProcess, lphModule, cb, lpcbNeeded);
		if (result && lphModule && lpcbNeeded && *lpcbNeeded > 0) {
			DWORD moduleCount = cb / sizeof(HMODULE);
			DWORD filteredCount = 0;

			for (DWORD i = 0; i < moduleCount && i < (*lpcbNeeded / sizeof(HMODULE)); i++) {
				char modulePath[MAX_PATH] = { 0 };
				if (te::winapi::um::ac::bypass::proxy::ProxyAPI::GetModuleFileNameA(lphModule[i], modulePath, MAX_PATH)) {
					std::string modPath(modulePath);
					size_t lastSlash = modPath.find_last_of("\\/");
					std::string modName = (lastSlash != std::string::npos) ?
						modPath.substr(lastSlash + 1) : modPath;

					if (IsWhitelistedFile(modName)) {
						if (filteredCount != i) lphModule[filteredCount] = lphModule[i];
						filteredCount++;
						continue;
					}

					bool shouldHide = false;
					{
						std::lock_guard<std::recursive_mutex> lock(g_hiddenModulesMutex);
						for (const auto& [name, handle] : g_hiddenModules) {
							if (lphModule[i] == handle) {
								shouldHide = true;
								break;
							}
						}
					}

					if (!shouldHide) shouldHide = HasSuspiciousExtension(modName);

					if (!shouldHide) {
						if (filteredCount != i) lphModule[filteredCount] = lphModule[i];
						filteredCount++;
					}
				}
				else {
					if (filteredCount != i) lphModule[filteredCount] = lphModule[i];
					filteredCount++;
				}
			}
			*lpcbNeeded = filteredCount * sizeof(HMODULE);
		}
		ADD_JUNK_CODE();
		return result;
	}

	int WINAPI Hooked_MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
		ADD_JUNK_CODE();
		CallStackSpoofer spoofer;
		auto pOriginal = GetOriginalFunction<MessageBoxA_t>(GetStr_MessageBoxA());

		ReentrancyGuard guard;
		if (guard.IsReentrant()) return pOriginal(hWnd, lpText, lpCaption, uType);

		te::sdk::helper::logging::Log("[ #TE ] ===== MessageBoxA INTERCEPTED =====");
		te::sdk::helper::logging::Log("  Caption: %s", lpCaption ? lpCaption : "(null)");
		te::sdk::helper::logging::Log("  Text: %s", lpText ? lpText : "(null)");
		te::sdk::helper::logging::Log("  Return address: %p", _ReturnAddress());

		if (lpCaption && strstr(lpCaption, "Wraith")) {
			return IDOK;
		}

		ADD_JUNK_CODE();
		return pOriginal(hWnd, lpText, lpCaption, uType);
	}

	int WINAPI Hooked_MessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType) {
		ADD_JUNK_CODE();
		CallStackSpoofer spoofer;
		auto pOriginal = GetOriginalFunction<MessageBoxW_t>(GetStr_MessageBoxW());

		ReentrancyGuard guard;
		if (guard.IsReentrant()) return pOriginal(hWnd, lpText, lpCaption, uType);

		std::wstring wText = lpText ? lpText : L"(null)";
		std::wstring wCaption = lpCaption ? lpCaption : L"(null)";
		std::string text(wText.begin(), wText.end());
		std::string caption(wCaption.begin(), wCaption.end());

		te::sdk::helper::logging::Log("[ #TE ] ===== MessageBoxW INTERCEPTED =====");
		te::sdk::helper::logging::Log("  Caption: %s", caption.c_str());
		te::sdk::helper::logging::Log("  Text: %s", text.c_str());
		te::sdk::helper::logging::Log("  Return address: %p", _ReturnAddress());

		if (lpCaption && wcsstr(lpCaption, L"Wraith")) {
			return IDOK;
		}

		ADD_JUNK_CODE();
		return pOriginal(hWnd, lpText, lpCaption, uType);
	}

	static bool IsCallerFromPrivateMemory(void* returnAddress) {
		ADD_JUNK_CODE();
		if (!returnAddress) return false;

		MEMORY_BASIC_INFORMATION mbi = {};
		if (te::winapi::um::ac::bypass::proxy::ProxyAPI::VirtualQuery(returnAddress, &mbi, sizeof(mbi)) == 0) {
			return true;
		}

		if (mbi.Type == MEM_PRIVATE) {
			return true;
		}

		HMODULE hModule = nullptr;
		if (te::winapi::um::ac::bypass::proxy::ProxyAPI::GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
			GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
			(LPCSTR)returnAddress, &hModule)) {
			char modulePath[MAX_PATH] = { 0 };
			if (te::winapi::um::ac::bypass::proxy::ProxyAPI::GetModuleFileNameA(hModule, modulePath, MAX_PATH)) {
				std::string modPath(modulePath);
				size_t lastSlash = modPath.find_last_of("\\/");
				std::string modName = (lastSlash != std::string::npos) ?
					modPath.substr(lastSlash + 1) : modPath;

				if (ShouldHideFile(modName, modPath)) {
					return true;
				}
				ADD_JUNK_CODE();
				return false;
			}
		}

		ADD_JUNK_CODE();
		return true;
	}

	BOOL WINAPI Hooked_TerminateProcess(HANDLE hProcess, UINT uExitCode) {
		ADD_JUNK_CODE();
		CallStackSpoofer spoofer;
		auto pOriginal = GetOriginalFunction<TerminateProcess_t>(GetStr_TerminateProcess());

		ReentrancyGuard guard;
		if (guard.IsReentrant()) return pOriginal(hProcess, uExitCode);

		void* returnAddress = _ReturnAddress();

		if (hProcess == te::winapi::um::ac::bypass::proxy::ProxyAPI::GetCurrentProcess() || hProcess == (HANDLE)-1) {
			if (IsCallerFromPrivateMemory(returnAddress)) {
				te::winapi::um::ac::bypass::proxy::ProxyAPI::SetLastError(ERROR_SUCCESS);
				ADD_JUNK_CODE();
				return TRUE;
			}
		}

		ADD_JUNK_CODE();
		return pOriginal(hProcess, uExitCode);
	}

	typedef NTSTATUS(NTAPI* NtTerminateProcess_t)(HANDLE, NTSTATUS);

	NTSTATUS NTAPI Hooked_NtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus) {
		ADD_JUNK_CODE();
		CallStackSpoofer spoofer;
		auto pOriginal = GetOriginalFunction<NtTerminateProcess_t>(GetStr_NtTerminateProcess());
		if (!pOriginal) {
			HMODULE hNtdll = DynamicAPILoader::GetModuleFromName(GetStr_ntdll());
			if (hNtdll) {
				pOriginal = (NtTerminateProcess_t)DynamicAPILoader::GetFunctionDynamic(hNtdll, GetStr_NtTerminateProcess());
			}
		}
		if (!pOriginal) return STATUS_UNSUCCESSFUL;

		ReentrancyGuard guard;
		if (guard.IsReentrant()) return pOriginal(ProcessHandle, ExitStatus);

		void* returnAddress = _ReturnAddress();

		if (ProcessHandle == te::winapi::um::ac::bypass::proxy::ProxyAPI::GetCurrentProcess() || ProcessHandle == (HANDLE)-1 || ProcessHandle == nullptr) {
			if (IsCallerFromPrivateMemory(returnAddress)) {
				ADD_JUNK_CODE();
				return STATUS_SUCCESS;
			}
		}

		ADD_JUNK_CODE();
		return pOriginal(ProcessHandle, ExitStatus);
	}

	NTSTATUS NTAPI Hooked_NtQueryVirtualMemory(
		HANDLE ProcessHandle,
		PVOID BaseAddress,
		MEMORY_INFORMATION_CLASS MemoryInformationClass,
		PVOID MemoryInformation,
		SIZE_T MemoryInformationLength,
		PSIZE_T ReturnLength) {

		ADD_JUNK_CODE();
		CallStackSpoofer spoofer;
		auto pOriginal = GetOriginalFunction<NtQueryVirtualMemory_t>(GetStr_NtQueryVirtualMemory());
		if (!pOriginal) {
			HMODULE hNtdll = DynamicAPILoader::GetModuleFromName(GetStr_ntdll());
			if (hNtdll) {
				pOriginal = (NtQueryVirtualMemory_t)DynamicAPILoader::GetFunctionDynamic(hNtdll, "NtQueryVirtualMemory");
			}
		}
		if (!pOriginal) return STATUS_UNSUCCESSFUL;

		ReentrancyGuard guard;
		if (guard.IsReentrant()) return pOriginal(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);

		if (ProcessHandle != proxy::ProxyAPI::GetCurrentProcess() && ProcessHandle != (HANDLE)-1 && ProcessHandle != nullptr)
			return pOriginal(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);

		NTSTATUS status = pOriginal(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);
		if (!NT_SUCCESS(status)) return status;

		if (MemoryInformationClass == MemoryBasicInformation && MemoryInformation) {
			PMEMORY_BASIC_INFORMATION mbi = (PMEMORY_BASIC_INFORMATION)MemoryInformation;
			uintptr_t addr = (uintptr_t)BaseAddress;

			// Check if querying hidden module memory
			std::lock_guard<std::recursive_mutex> lock(g_hiddenModulesMutex);
			for (const auto& [name, handle] : g_hiddenModules) {
				MODULEINFO modInfo = {};
				if (proxy::ProxyAPI::GetModuleInformation(proxy::ProxyAPI::GetCurrentProcess(), handle, &modInfo, sizeof(modInfo))) {
					if (addr >= (uintptr_t)modInfo.lpBaseOfDll && addr < (uintptr_t)modInfo.lpBaseOfDll + modInfo.SizeOfImage) {
						// Spoof as samp.dll memory
						MaskRegionAsModule(mbi, GetStr_samp());
						te::sdk::helper::logging::Log("[ #TE ] NtQueryVirtualMemory spoofed for hidden module: %p", BaseAddress);
						return STATUS_SUCCESS;
					}
				}
			}
		}

		return status;
	}

	NTSTATUS NTAPI Hooked_NtProtectVirtualMemory(
		HANDLE ProcessHandle,
		PVOID* BaseAddress,
		PSIZE_T RegionSize,
		ULONG NewProtect,
		PULONG OldProtect) {

		ADD_JUNK_CODE();
		CallStackSpoofer spoofer;
		auto pOriginal = GetOriginalFunction<NtProtectVirtualMemory_t>(GetStr_NtProtectVirtualMemory());
		if (!pOriginal) {
			HMODULE hNtdll = DynamicAPILoader::GetModuleFromName(GetStr_ntdll());
			if (hNtdll) {
				pOriginal = (NtProtectVirtualMemory_t)DynamicAPILoader::GetFunctionDynamic(hNtdll, "NtProtectVirtualMemory");
			}
		}
		if (!pOriginal) return STATUS_UNSUCCESSFUL;

		ReentrancyGuard guard;
		if (guard.IsReentrant()) return pOriginal(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);

		if (ProcessHandle != proxy::ProxyAPI::GetCurrentProcess() && ProcessHandle != (HANDLE)-1 && ProcessHandle != nullptr)
			return pOriginal(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);

		if (BaseAddress && *BaseAddress) {
			uintptr_t addr = (uintptr_t)*BaseAddress;

			// Check if protecting hidden module memory
			std::lock_guard<std::recursive_mutex> lock(g_hiddenModulesMutex);
			for (const auto& [name, handle] : g_hiddenModules) {
				MODULEINFO modInfo = {};
				if (proxy::ProxyAPI::GetModuleInformation(proxy::ProxyAPI::GetCurrentProcess(), handle, &modInfo, sizeof(modInfo))) {
					if (addr >= (uintptr_t)modInfo.lpBaseOfDll && addr < (uintptr_t)modInfo.lpBaseOfDll + modInfo.SizeOfImage) {
						if (OldProtect) *OldProtect = PAGE_EXECUTE_READ;
						te::sdk::helper::logging::Log("[ #TE ] NtProtectVirtualMemory spoofed on hidden module: %p", *BaseAddress);
						return STATUS_SUCCESS;
					}
				}
			}
		}

		return pOriginal(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
	}

	BOOL WINAPI Hooked_VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
		ADD_JUNK_CODE();
		CallStackSpoofer spoofer;
		auto pOriginal = GetOriginalFunction<VirtualProtect_t>(GetStr_VirtualProtect());

		ReentrancyGuard guard;
		if (guard.IsReentrant()) return pOriginal(lpAddress, dwSize, flNewProtect, lpflOldProtect);

		uintptr_t addr = reinterpret_cast<uintptr_t>(lpAddress);

		{
			std::lock_guard<std::recursive_mutex> lock(g_antiDetectionMutex);
			for (auto& region : g_spoofedMemoryRegions) {
				if (addr >= region.start && addr < region.end) {
					if (lpflOldProtect) *lpflOldProtect = region.fakeProtect;

					DWORD oldProtect;
					BOOL res = pOriginal(lpAddress, dwSize, flNewProtect, &oldProtect);

					if (res) {
						region.realProtect = flNewProtect;
					}

					te::sdk::helper::logging::Log("[ #TE ] VirtualProtect spoofed on hidden region: %p (New: 0x%X)",
						lpAddress, flNewProtect);

					ADD_JUNK_CODE();
					return res;
				}
			}
		}

		{
			std::lock_guard<std::recursive_mutex> lock(g_hiddenModulesMutex);
			for (const auto& [name, handle] : g_hiddenModules) {
				MODULEINFO modInfo = {};
				if (te::winapi::um::ac::bypass::proxy::ProxyAPI::GetModuleInformation(te::winapi::um::ac::bypass::proxy::ProxyAPI::GetCurrentProcess(), handle, &modInfo, sizeof(modInfo))) {
					if (addr >= (uintptr_t)modInfo.lpBaseOfDll &&
						addr < (uintptr_t)modInfo.lpBaseOfDll + modInfo.SizeOfImage) {

						if (lpflOldProtect) *lpflOldProtect = PAGE_EXECUTE_READ;

						DWORD oldProtect;
						pOriginal(lpAddress, dwSize, flNewProtect, &oldProtect);

						ADD_JUNK_CODE();
						return TRUE;
					}
				}
			}
		}

		ADD_JUNK_CODE();
		return pOriginal(lpAddress, dwSize, flNewProtect, lpflOldProtect);
	}

	BOOL WINAPI Hooked_VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) {
		ADD_JUNK_CODE();
		CallStackSpoofer spoofer;
		auto pOriginal = GetOriginalFunction<VirtualFree_t>(GetStr_VirtualFree());

		ReentrancyGuard guard;
		if (guard.IsReentrant()) return pOriginal(lpAddress, dwSize, dwFreeType);

		uintptr_t addr = reinterpret_cast<uintptr_t>(lpAddress);

		{
			std::lock_guard<std::recursive_mutex> lock(g_antiDetectionMutex);
			for (const auto& region : g_spoofedMemoryRegions) {
				if (addr >= region.start && addr < region.end) {
					te::sdk::helper::logging::Log("[ #TE ] Blocked VirtualFree on protected region: %p", lpAddress);
					ADD_JUNK_CODE();
					return TRUE;
				}
			}
		}

		{
			std::lock_guard<std::recursive_mutex> lock(g_hiddenModulesMutex);
			for (const auto& [name, handle] : g_hiddenModules) {
				MODULEINFO modInfo = {};
				if (te::winapi::um::ac::bypass::proxy::ProxyAPI::GetModuleInformation(te::winapi::um::ac::bypass::proxy::ProxyAPI::GetCurrentProcess(), handle, &modInfo, sizeof(modInfo))) {
					if (addr >= (uintptr_t)modInfo.lpBaseOfDll &&
						addr < (uintptr_t)modInfo.lpBaseOfDll + modInfo.SizeOfImage) {

						te::sdk::helper::logging::Log("[ #TE ] Blocked VirtualFree on hidden module memory: %p", lpAddress);
						ADD_JUNK_CODE();
						return TRUE;
					}
				}
			}
		}

		ADD_JUNK_CODE();
		return pOriginal(lpAddress, dwSize, dwFreeType);
	}

	static bool IsAddressInsideHiddenModule(void* address) {
		ADD_JUNK_CODE();
		if (!address) return false;

		std::lock_guard<std::recursive_mutex> lock(g_hiddenModulesMutex);
		for (const auto& [name, handle] : g_hiddenModules) {
			if (!handle) continue;

			MODULEINFO modInfo = {};
			if (!te::winapi::um::ac::bypass::proxy::ProxyAPI::GetModuleInformation(
				te::winapi::um::ac::bypass::proxy::ProxyAPI::GetCurrentProcess(), handle, &modInfo, sizeof(modInfo))) {
				continue;
			}

			uintptr_t start = reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll);
			uintptr_t end = start + modInfo.SizeOfImage;
			uintptr_t target = reinterpret_cast<uintptr_t>(address);

			if (target >= start && target < end) {
				ADD_JUNK_CODE();
				return true;
			}
		}

		ADD_JUNK_CODE();
		return false;
	}

	struct BlockedThreadContext {
		LPTHREAD_START_ROUTINE originalStart;
		LPVOID originalParameter;
		std::string moduleName;

		BlockedThreadContext() :
			originalStart(nullptr),
			originalParameter(nullptr),
			moduleName() {
		}
	};

	static DWORD WINAPI BlockedThreadStub(LPVOID param) {
		ADD_JUNK_CODE();
		BlockedThreadContext local;

		if (param) {
			local = *static_cast<BlockedThreadContext*>(param);
			delete static_cast<BlockedThreadContext*>(param);
		}

		const char* displayName = local.moduleName.empty() ? "unknown" : local.moduleName.c_str();
		te::sdk::helper::logging::Log("[ #TE ] Suppressed hostile thread from '%s' (StartAddress=%p)",
			displayName, local.originalStart);

		if (local.originalStart) {
			RegisterHiddenRegion(local.originalStart, 256);
		}

		ADD_JUNK_CODE();
		return ERROR_ACCESS_DENIED;
	}

	static bool ShouldBlockThreadCreation(
		const std::string& callerModuleName,
		const std::string& callerModulePath,
		LPTHREAD_START_ROUTINE lpStartAddress) {

		ADD_JUNK_CODE();
		if (!callerModuleName.empty()) {
			if (_stricmp(callerModuleName.c_str(), GetStr_wraith_ac()) == 0) {
				return true;
			}
			if (ShouldHideFile(callerModuleName, callerModulePath)) {
				return true;
			}
		}

		return IsAddressInsideHiddenModule(lpStartAddress);
	}

	HANDLE WINAPI Hooked_CreateThread(
		LPSECURITY_ATTRIBUTES lpThreadAttributes,
		SIZE_T dwStackSize,
		LPTHREAD_START_ROUTINE lpStartAddress,
		LPVOID lpParameter,
		DWORD dwCreationFlags,
		LPDWORD lpThreadId
	) {
		ADD_JUNK_CODE();
		CallStackSpoofer spoofer;
		auto pOriginal = GetOriginalFunction<CreateThread_t>(GetStr_CreateThread());

		ReentrancyGuard guard;
		if (guard.IsReentrant()) {
			return pOriginal(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
		}

		void* returnAddress = _ReturnAddress();
		std::string callerModuleName;
		std::string callerModulePath;

		if (returnAddress) {
			HMODULE hCallerModule = nullptr;
			if (te::winapi::um::ac::bypass::proxy::ProxyAPI::GetModuleHandleExA(
				GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
				(LPCSTR)returnAddress, &hCallerModule)) {

				char modulePath[MAX_PATH] = { 0 };
				if (te::winapi::um::ac::bypass::proxy::ProxyAPI::GetModuleFileNameA(hCallerModule, modulePath, MAX_PATH)) {
					callerModulePath = modulePath;
					size_t lastSlash = callerModulePath.find_last_of("\\/");
					callerModuleName = (lastSlash != std::string::npos) ?
						callerModulePath.substr(lastSlash + 1) : callerModulePath;
					std::transform(callerModuleName.begin(), callerModuleName.end(), callerModuleName.begin(), ::tolower);
				}
			}
		}

		bool blockThread = ShouldBlockThreadCreation(callerModuleName, callerModulePath, lpStartAddress);
		if (blockThread) {
			BlockedThreadContext* ctx = new(std::nothrow) BlockedThreadContext();
			if (!ctx) {
				te::sdk::helper::logging::Log("[ #TE ] Failed to allocate BlockedThreadContext");
				te::winapi::um::ac::bypass::proxy::ProxyAPI::SetLastError(ERROR_NOT_ENOUGH_MEMORY);
				return NULL;
			}

			ctx->originalStart = lpStartAddress;
			ctx->originalParameter = lpParameter;
			ctx->moduleName = !callerModuleName.empty() ? callerModuleName : callerModulePath;

			HANDLE hStubThread = pOriginal(
				lpThreadAttributes,
				dwStackSize,
				BlockedThreadStub,
				ctx,
				dwCreationFlags,
				lpThreadId);

			if (!hStubThread || hStubThread == INVALID_HANDLE_VALUE) {
				delete ctx;
				return hStubThread;
			}

			te::sdk::helper::logging::Log("[ #TE ] Replaced thread from '%s' with stub (StartAddress=%p)",
				ctx->moduleName.empty() ? "unknown" : ctx->moduleName.c_str(),
				lpStartAddress);

			ADD_JUNK_CODE();
			return hStubThread;
		}

		HANDLE hThread = pOriginal(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);

		if (lpStartAddress && hThread && hThread != INVALID_HANDLE_VALUE) {
			RegisterHiddenRegion(lpStartAddress, 256);
		}

		ADD_JUNK_CODE();
		return hThread;
	}

	HANDLE WINAPI Hooked_CreateRemoteThread(
		HANDLE hProcess,
		LPSECURITY_ATTRIBUTES lpThreadAttributes,
		SIZE_T dwStackSize,
		LPTHREAD_START_ROUTINE lpStartAddress,
		LPVOID lpParameter,
		DWORD dwCreationFlags,
		LPDWORD lpThreadId
	) {
		ADD_JUNK_CODE();
		CallStackSpoofer spoofer;
		auto pOriginal = GetOriginalFunction<CreateRemoteThread_t>(GetStr_CreateRemoteThread());

		ReentrancyGuard guard;
		if (guard.IsReentrant()) return pOriginal(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);

		void* returnAddress = _ReturnAddress();
		bool callerIsHidden = false;
		std::string callerModuleName;

		if (returnAddress) {
			HMODULE hCallerModule = nullptr;
			if (te::winapi::um::ac::bypass::proxy::ProxyAPI::GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
				GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
				(LPCSTR)returnAddress, &hCallerModule)) {

				char modulePath[MAX_PATH] = { 0 };
				if (te::winapi::um::ac::bypass::proxy::ProxyAPI::GetModuleFileNameA(hCallerModule, modulePath, MAX_PATH)) {
					std::string modPath(modulePath);
					size_t lastSlash = modPath.find_last_of("\\/");
					callerModuleName = (lastSlash != std::string::npos) ?
						modPath.substr(lastSlash + 1) : modPath;

					{
						std::lock_guard<std::recursive_mutex> lock(g_hiddenModulesMutex);
						for (const auto& [name, handle] : g_hiddenModules) {
							if (hCallerModule == handle) {
								callerIsHidden = true;
								break;
							}
						}
					}

					if (!callerIsHidden) {
						callerIsHidden = ShouldHideFile(callerModuleName, modPath);
					}
				}
			}
		}

		HANDLE hThread = pOriginal(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);

		if (callerIsHidden && lpStartAddress && hThread && hThread != INVALID_HANDLE_VALUE) {
			RegisterHiddenRegion(lpStartAddress, 256);
			te::sdk::helper::logging::Log("[ #TE ] CreateRemoteThread from hidden module '%s': registered thread function %p",
				callerModuleName.c_str(), lpStartAddress);
		}

		ADD_JUNK_CODE();
		return hThread;
	}

	BOOL WINAPI Hooked_GetThreadContext(HANDLE hThread, LPCONTEXT lpContext) {
		ADD_JUNK_CODE();
		CallStackSpoofer spoofer;
		auto pOriginal = GetOriginalFunction<GetThreadContext_t>(GetStr_GetThreadContext());

		ReentrancyGuard guard;
		if (guard.IsReentrant()) return pOriginal(hThread, lpContext);

		void* returnAddress = _ReturnAddress();
		bool callerIsHidden = false;

		if (returnAddress) {
			HMODULE hCallerModule = nullptr;
			if (te::winapi::um::ac::bypass::proxy::ProxyAPI::GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
				GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
				(LPCSTR)returnAddress, &hCallerModule)) {

				std::lock_guard<std::recursive_mutex> lock(g_hiddenModulesMutex);
				for (const auto& [name, handle] : g_hiddenModules) {
					if (hCallerModule == handle) {
						callerIsHidden = true;
						break;
					}
				}
			}
		}

		if (!callerIsHidden && lpContext) {
			te::winapi::um::ac::bypass::proxy::ProxyAPI::SetLastError(ERROR_INVALID_PARAMETER);
			ADD_JUNK_CODE();
			return FALSE;
		}

		ADD_JUNK_CODE();
		return pOriginal(hThread, lpContext);
	}

	typedef NTSTATUS(NTAPI* NtQuerySystemInformation_t)(
		SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

	NTSTATUS NTAPI Hooked_NtQuerySystemInformation(
		SYSTEM_INFORMATION_CLASS SystemInformationClass,
		PVOID SystemInformation,
		ULONG SystemInformationLength,
		PULONG ReturnLength) {

		ADD_JUNK_CODE();
		CallStackSpoofer spoofer;
		auto pOriginal = GetOriginalFunction<NtQuerySystemInformation_t>(GetStr_NtQuerySystemInformation());
		if (!pOriginal) {
			HMODULE hNtdll = DynamicAPILoader::GetModuleFromName(GetStr_ntdll());
			if (hNtdll) {
				pOriginal = (NtQuerySystemInformation_t)DynamicAPILoader::GetFunctionDynamic(hNtdll, GetStr_NtQuerySystemInformation());
			}
		}
		if (!pOriginal) return STATUS_UNSUCCESSFUL;

		ReentrancyGuard guard;
		if (guard.IsReentrant()) return pOriginal(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

		NTSTATUS status = pOriginal(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
		if (!NT_SUCCESS(status)) return status;

		if (SystemInformationClass == SystemModuleInformation) {
			if (SystemInformation) {
				std::unordered_map<std::string, HMODULE> hiddenModulesCopy;
				{
					std::lock_guard<std::recursive_mutex> lock(g_hiddenModulesMutex);
					hiddenModulesCopy = g_hiddenModules;
				}

				std::vector<const char*> hiddenNamePtrs;
				hiddenNamePtrs.reserve(hiddenModulesCopy.size());
				for (const auto& [name, handle] : hiddenModulesCopy) {
					hiddenNamePtrs.push_back(name.c_str());
				}

				FilterSystemModulesSafe(
					reinterpret_cast<PRTL_PROCESS_MODULES>(SystemInformation),
					hiddenNamePtrs.data(),
					hiddenNamePtrs.size(),
					ReturnLength);
			}
		}

		ADD_JUNK_CODE();
		return status;
	}

	LPVOID WINAPI Hooked_VirtualAlloc(
		LPVOID lpAddress,
		SIZE_T dwSize,
		DWORD flAllocationType,
		DWORD flProtect) {

		ADD_JUNK_CODE();
		CallStackSpoofer spoofer;
		auto pOriginal = GetOriginalFunction<VirtualAlloc_t>(GetStr_VirtualAlloc());

		ReentrancyGuard guard;
		if (guard.IsReentrant()) return pOriginal(lpAddress, dwSize, flAllocationType, flProtect);

		void* returnAddress = _ReturnAddress();

		bool shouldTrack = false;
		std::string callerInfo = "unknown";

		if (returnAddress) {
			HMODULE hCallerModule = nullptr;

			if (te::winapi::um::ac::bypass::proxy::ProxyAPI::GetModuleHandleExA(
				GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
				(LPCSTR)returnAddress, &hCallerModule)) {

				char modulePath[MAX_PATH] = { 0 };
				if (te::winapi::um::ac::bypass::proxy::ProxyAPI::GetModuleFileNameA(hCallerModule, modulePath, MAX_PATH)) {
					std::string modPath(modulePath);
					size_t lastSlash = modPath.find_last_of("\\/");
					std::string modName = (lastSlash != std::string::npos) ? modPath.substr(lastSlash + 1) : modPath;

					std::transform(modName.begin(), modName.end(), modName.begin(), ::tolower);

					te::sdk::helper::logging::Log("[ #TE ] VirtualAlloc called from module: %s", modName.c_str());

					if (!strcmp(modName.c_str(), GetStr_wraith_ac())) {
						shouldTrack = true;
						callerInfo = "wraith-ac.asi";
					}
				}
			}
			else {
				MEMORY_BASIC_INFORMATION mbi = {};
				if (te::winapi::um::ac::bypass::proxy::ProxyAPI::VirtualQuery(returnAddress, &mbi, sizeof(mbi)) > 0) {
					if (mbi.Type == MEM_PRIVATE) {
						shouldTrack = true;

						char buffer[64];
						sprintf_s(buffer, sizeof(buffer), "private memory (0x%p)", returnAddress);
						callerInfo = buffer;
					}
				}
			}
		}

		LPVOID result = pOriginal(lpAddress, dwSize, flAllocationType, flProtect);

		if (result && dwSize > 0) {
			if (shouldTrack) {
				std::lock_guard<std::recursive_mutex> lock(g_wraithAllocationsMutex);
				WraithAllocation alloc;
				alloc.address = result;
				alloc.size = dwSize;
				g_wraithAllocations.push_back(alloc);

				te::sdk::helper::logging::Log("[ #TE ] Tracked VirtualAlloc from %s: %p (Size: %zu bytes)",
					callerInfo.c_str(), result, dwSize);
			}

			std::lock_guard<std::recursive_mutex> lock(g_antiDetectionMutex);

			MemoryRegion region;
			region.start = reinterpret_cast<uintptr_t>(result);
			region.end = region.start + dwSize;
			region.realProtect = flProtect;
			region.fakeProtect = PAGE_EXECUTE_READ;

			g_spoofedMemoryRegions.push_back(region);

			if (!shouldTrack) {
				te::sdk::helper::logging::Log("[ #TE ] VirtualAlloc registered: %p - %p (Size: %zu)",
					result, (LPVOID)(region.end), dwSize);
			}
		}

		ADD_JUNK_CODE();
		return result;
	}

	typedef NTSTATUS(NTAPI* NtReadVirtualMemory_t)(
		HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

	NTSTATUS NTAPI Hooked_NtReadVirtualMemory(
		HANDLE ProcessHandle,
		PVOID BaseAddress,
		PVOID Buffer,
		SIZE_T NumberOfBytesToRead,
		PSIZE_T NumberOfBytesRead OPTIONAL) {

		ADD_JUNK_CODE();
		CallStackSpoofer spoofer;
		auto pOriginal = GetOriginalFunction<NtReadVirtualMemory_t>(GetStr_NtReadVirtualMemory());
		if (!pOriginal) {
			HMODULE hNtdll = DynamicAPILoader::GetModuleFromName(GetStr_ntdll());
			if (hNtdll) {
				pOriginal = (NtReadVirtualMemory_t)DynamicAPILoader::GetFunctionDynamic(hNtdll, GetStr_NtReadVirtualMemory());
			}
		}
		if (!pOriginal) return STATUS_UNSUCCESSFUL;

		ReentrancyGuard guard;
		if (guard.IsReentrant()) return pOriginal(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);

		if (ProcessHandle == te::winapi::um::ac::bypass::proxy::ProxyAPI::GetCurrentProcess() || ProcessHandle == (HANDLE)-1) {
			uintptr_t addr = reinterpret_cast<uintptr_t>(BaseAddress);

			std::vector<MemoryRegion> localRegions;
			{
				std::lock_guard<std::recursive_mutex> lock(g_antiDetectionMutex);
				localRegions = g_spoofedMemoryRegions;
			}

			if (TryZeroReadFromRegions(
				localRegions.data(),
				localRegions.size(),
				addr,
				Buffer,
				NumberOfBytesToRead,
				NumberOfBytesRead,
				"[ #TE ] Blocked NtReadVirtualMemory from protected region: %p",
				BaseAddress)) {

				ADD_JUNK_CODE();
				return STATUS_SUCCESS;
			}
		}

		ADD_JUNK_CODE();
		return pOriginal(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);
	}

	BOOL WINAPI Hooked_ReadProcessMemory(
		HANDLE hProcess,
		LPCVOID lpBaseAddress,
		LPVOID lpBuffer,
		SIZE_T nSize,
		SIZE_T* lpNumberOfBytesRead) {

		ADD_JUNK_CODE();
		CallStackSpoofer spoofer;
		auto pOriginal = GetOriginalFunction<ReadProcessMemory_t>(GetStr_ReadProcessMemory());
		if (!pOriginal) return;

		ReentrancyGuard guard;
		if (guard.IsReentrant()) return pOriginal(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);

		if (hProcess == te::winapi::um::ac::bypass::proxy::ProxyAPI::GetCurrentProcess() || hProcess == (HANDLE)-1) {
			uintptr_t addr = reinterpret_cast<uintptr_t>(lpBaseAddress);

			std::vector<MemoryRegion> localRegions;
			{
				std::lock_guard<std::recursive_mutex> lock(g_antiDetectionMutex);
				localRegions = g_spoofedMemoryRegions;
			}

			if (TryZeroReadFromRegions(
				localRegions.data(),
				localRegions.size(),
				addr,
				lpBuffer,
				nSize,
				lpNumberOfBytesRead,
				"[ #TE ] Blocked ReadProcessMemory from protected region: %p",
				lpBaseAddress)) {

				ADD_JUNK_CODE();
				return TRUE;
			}
		}

		ADD_JUNK_CODE();
		return pOriginal(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
	}

	HWND WINAPI Hooked_SetFocus(HWND hWnd) {
		ADD_JUNK_CODE();
		CallStackSpoofer spoofer;
		auto pOriginal = GetOriginalFunction<SetFocus_t>(GetStr_SetFocus());

		ReentrancyGuard guard;
		if (guard.IsReentrant()) return pOriginal(hWnd);

		void* returnAddress = _ReturnAddress();
		if (returnAddress && IsCallerFromPrivateMemory(returnAddress)) {
			ADD_JUNK_CODE();
			return nullptr;
		}

		ADD_JUNK_CODE();
		return pOriginal(hWnd);
	}

	HWND WINAPI Hooked_SetForegroundWindow(HWND hWnd) {
		ADD_JUNK_CODE();
		CallStackSpoofer spoofer;
		auto pOriginal = GetOriginalFunction<SetForegroundWindow_t>(GetStr_SetForegroundWindow());

		ReentrancyGuard guard;
		if (guard.IsReentrant()) return pOriginal(hWnd);

		void* returnAddress = _ReturnAddress();
		if (returnAddress && IsCallerFromPrivateMemory(returnAddress)) {
			ADD_JUNK_CODE();
			return nullptr;
		}

		ADD_JUNK_CODE();
		return pOriginal(hWnd);
	}

	BOOL WINAPI Hooked_ShowWindow(HWND hWnd, int nCmdShow) {
		ADD_JUNK_CODE();
		CallStackSpoofer spoofer;
		auto pOriginal = GetOriginalFunction<ShowWindow_t>(GetStr_ShowWindow());

		ReentrancyGuard guard;
		if (guard.IsReentrant()) return pOriginal(hWnd, nCmdShow);

		if (nCmdShow == SW_MINIMIZE || nCmdShow == SW_HIDE) {
			void* returnAddress = _ReturnAddress();
			if (returnAddress && IsCallerFromPrivateMemory(returnAddress)) {
				ADD_JUNK_CODE();
				return FALSE;
			}
		}

		ADD_JUNK_CODE();
		return pOriginal(hWnd, nCmdShow);
	}

	// ============================================
	// WINSOCK2 HOOKS
	// ============================================
	typedef SOCKET(WSAAPI* socket_winsock_t)(int af, int type, int protocol);
	typedef int(WSAAPI* sendto_winsock_t)(SOCKET s, const char* buf, int len, int flags, const sockaddr* to, int tolen);
	typedef int(WSAAPI* wsasendto_winsock_t)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent,
		DWORD dwFlags, const sockaddr* lpTo, int iTolen, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
	typedef int(WSAAPI* send_winsock_t)(SOCKET s, const char* buf, int len, int flags);
	typedef int(WSAAPI* connect_winsock_t)(SOCKET s, const sockaddr* name, int namelen);

	SOCKET WSAAPI Hooked_socket(int af, int type, int protocol) {
		ADD_JUNK_CODE();
		socket_winsock_t pOriginal = GetOriginalFunction<socket_winsock_t>(GetStr_socket());
		if (!pOriginal) return INVALID_SOCKET;

		SOCKET sock = pOriginal(af, type, protocol);

		if (sock != INVALID_SOCKET) {
			std::lock_guard<std::recursive_mutex> lock(SocketMonitor::g_socketsMutex);
			SocketMonitor::SocketInfo info = { sock, af, type, protocol, true };
			SocketMonitor::g_sockets[(uintptr_t)(UINT_PTR)sock] = info;
			te::sdk::helper::logging::Log("[ #TE ] SOCKET CREATED: %p (Family: %d, Type: %d)",
				(void*)(UINT_PTR)sock, af, type);
		}

		ADD_JUNK_CODE();
		return sock;
	}

	int WSAAPI Hooked_sendto(SOCKET s, const char* buf, int len, int flags, const sockaddr* to, int tolen) {
		ADD_JUNK_CODE();
		sendto_winsock_t pOriginal = GetOriginalFunction<sendto_winsock_t>(GetStr_sendto());
		if (!pOriginal) return SOCKET_ERROR;

		if (!SocketMonitor::IsTargetAddress(to, tolen)) {
			WSASetLastError(WSAEHOSTUNREACH);
			te::sdk::helper::logging::Log("[ #TE ] SENDTO BLOCKED: Unauthorized destination");
			ADD_JUNK_CODE();
			return SOCKET_ERROR;
		}

		int result = pOriginal(s, buf, len, flags, to, tolen);
		if (result != SOCKET_ERROR && len > 256) {
			te::sdk::helper::logging::Log("[ #TE ] SENDTO OK: %d bytes", result);
		}

		ADD_JUNK_CODE();
		return result;
	}

	int WSAAPI Hooked_wsasendto(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent,
		DWORD dwFlags, const sockaddr* lpTo, int iTolen, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
		ADD_JUNK_CODE();
		wsasendto_winsock_t pOriginal = GetOriginalFunction<wsasendto_winsock_t>(GetStr_wsasendto());
		if (!pOriginal) return SOCKET_ERROR;

		if (!SocketMonitor::IsTargetAddress(lpTo, iTolen)) {
			WSASetLastError(WSAEHOSTUNREACH);
			te::sdk::helper::logging::Log("[ #TE ] WSASENDTO BLOCKED: Unauthorized destination");
			ADD_JUNK_CODE();
			return SOCKET_ERROR;
		}

		int result = pOriginal(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpTo, iTolen, lpOverlapped, lpCompletionRoutine);
		ADD_JUNK_CODE();
		return result;
	}

	int WSAAPI Hooked_connect(SOCKET s, const sockaddr* name, int namelen) {
		ADD_JUNK_CODE();
		connect_winsock_t pOriginal = GetOriginalFunction<connect_winsock_t>(GetStr_connect());
		if (!pOriginal) return SOCKET_ERROR;

		if (!SocketMonitor::IsTargetAddress(name, namelen)) {
			WSASetLastError(WSAEHOSTUNREACH);
			te::sdk::helper::logging::Log("[ #TE ] CONNECT BLOCKED: Unauthorized destination");
			ADD_JUNK_CODE();
			return SOCKET_ERROR;
		}

		int result = pOriginal(s, name, namelen);
		if (result == 0) {
			te::sdk::helper::logging::Log("[ #TE ] CONNECT OK");
		}

		ADD_JUNK_CODE();
		return result;
	}

	int WSAAPI Hooked_send(SOCKET s, const char* buf, int len, int flags) {
		ADD_JUNK_CODE();
		send_winsock_t pOriginal = GetOriginalFunction<send_winsock_t>(GetStr_send());
		if (!pOriginal) return SOCKET_ERROR;

		{
			std::lock_guard<std::recursive_mutex> lock(SocketMonitor::g_socketsMutex);
			auto it = SocketMonitor::g_sockets.find((uintptr_t)(UINT_PTR)s);
			if (it != SocketMonitor::g_sockets.end()) {
				// PASS
			}
		}

		int result = pOriginal(s, buf, len, flags);
		if (result != SOCKET_ERROR && len > 512) {
			te::sdk::helper::logging::Log("[ #TE ] SEND OK: %d bytes (large packet)", result);
		}

		ADD_JUNK_CODE();
		return result;
	}

	// ============================================
	// HOOK INSTALLATION
	// ============================================
	static void HideExistingModules() {
		ADD_JUNK_CODE();
		te::sdk::helper::logging::Log(GetStr_HidingLog());

		HANDLE hSnapshot = te::winapi::um::ac::bypass::proxy::ProxyAPI::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
		if (hSnapshot == INVALID_HANDLE_VALUE) return;

		MODULEENTRY32 me32;
		me32.dwSize = sizeof(MODULEENTRY32);
		int hiddenCount = 0;

		if (te::winapi::um::ac::bypass::proxy::ProxyAPI::Module32First(hSnapshot, &me32)) {
			do {
				std::string moduleName(me32.szModule);
				std::string modulePath(me32.szExePath);

				if (!IsWhitelistedFile(moduleName) && ShouldHideFile(moduleName, modulePath)) {
					std::string lower = moduleName;
					std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

					std::lock_guard<std::recursive_mutex> lock(g_hiddenModulesMutex);
					if (g_hiddenModules.find(lower) == g_hiddenModules.end()) {
						g_hiddenModules[lower] = me32.hModule;
						UnlinkModuleFromPEB(me32.hModule);
						RegisterHiddenModuleMemory(me32.hModule);
						hiddenCount++;
					}
				}
			} while (te::winapi::um::ac::bypass::proxy::ProxyAPI::Module32Next(hSnapshot, &me32));
		}

		te::winapi::um::ac::bypass::proxy::ProxyAPI::CloseHandle(hSnapshot);
		te::sdk::helper::logging::Log(GetStr_HiddenLog(), hiddenCount);
		ADD_JUNK_CODE();
	}

	bool InstallAntiDetectionHooks() {
		ADD_JUNK_CODE();
		if (g_hooksInitialized.load()) {
			te::sdk::helper::logging::Log("[ #TE ] Hooks already initialized");
			return true;
		}

		te::sdk::helper::logging::Log(GetStr_InitLog());

		MH_STATUS mhInit = MH_Initialize();
		if (mhInit != MH_OK && mhInit != 1) { // MH_ERROR_ALREADY_INITIALIZED = 1
			te::sdk::helper::logging::Log("[ #TE ] MH_Initialize failed");
			return false;
		}

		struct HookSpec {
			LPCWSTR module;
			const char* function;
			void* detour;
			const char* key;
		};

		const HookSpec hooks[] = {
			{ GetStr_wKernel32(), GetStr_CreateThread(), (void*)Hooked_CreateThread, GetStr_CreateThread() },
			{ GetStr_wKernel32(), GetStr_GetThreadContext(), (void*)Hooked_GetThreadContext, GetStr_GetThreadContext() },
			{ GetStr_wKernel32(), GetStr_GetModuleHandleA(), (void*)Hooked_GetModuleHandleA, GetStr_GetModuleHandleA() },
			{ GetStr_wKernel32(), GetStr_GetModuleHandleW(), (void*)Hooked_GetModuleHandleW, GetStr_GetModuleHandleW() },
			{ GetStr_wKernel32(), GetStr_GetModuleHandleExA(), (void*)Hooked_GetModuleHandleExA, GetStr_GetModuleHandleExA() },
			{ GetStr_wKernel32(), GetStr_GetModuleHandleExW(), (void*)Hooked_GetModuleHandleExW, GetStr_GetModuleHandleExW() },
			{ GetStr_wKernel32(), GetStr_GetProcAddress(), (void*)Hooked_GetProcAddress, GetStr_GetProcAddress() },
			{ GetStr_wKernel32(), GetStr_LoadLibraryA(), (void*)Hooked_LoadLibraryA, GetStr_LoadLibraryA() },
			{ GetStr_wKernel32(), GetStr_LoadLibraryW(), (void*)Hooked_LoadLibraryW, GetStr_LoadLibraryW() },
			{ GetStr_wKernel32(), GetStr_FindFirstFileA(), (void*)Hooked_FindFirstFileA, GetStr_FindFirstFileA() },
			{ GetStr_wKernel32(), GetStr_FindNextFileA(), (void*)Hooked_FindNextFileA, GetStr_FindNextFileA() },
			{ GetStr_wKernel32(), GetStr_Module32First(), (void*)Hooked_Module32First, GetStr_Module32First() },
			{ GetStr_wKernel32(), GetStr_Module32Next(), (void*)Hooked_Module32Next, GetStr_Module32Next() },
			{ GetStr_wKernel32(), GetStr_Process32First(), (void*)Hooked_Process32First, GetStr_Process32First() },
			{ GetStr_wKernel32(), GetStr_Process32Next(), (void*)Hooked_Process32Next, GetStr_Process32Next() },
			{ GetStr_wKernel32(), GetStr_VirtualQuery(), (void*)Hooked_VirtualQuery, GetStr_VirtualQuery() },
			//{ GetStr_wKernel32(), GetStr_VirtualAlloc(), (void*)Hooked_VirtualAlloc, GetStr_VirtualAlloc() },
			//{ GetStr_wKernel32(), GetStr_VirtualProtect(), (void*)Hooked_VirtualProtect, GetStr_VirtualProtect() },
			{ GetStr_wKernel32(), GetStr_TerminateProcess(), (void*)Hooked_TerminateProcess, GetStr_TerminateProcess() },
			{ GetStr_wKernel32(), GetStr_ReadProcessMemory(), (void*)Hooked_ReadProcessMemory, GetStr_ReadProcessMemory() },
			{ GetStr_wKernel32(), GetStr_VirtualFree(), (void*)Hooked_VirtualFree, GetStr_VirtualFree() },
			{ GetStr_wKernel32(), GetStr_CreateRemoteThread(), (void*)Hooked_CreateRemoteThread, GetStr_CreateRemoteThread() },

			{ GetStr_wUser32(), GetStr_MessageBoxA(), (void*)Hooked_MessageBoxA, GetStr_MessageBoxA() },
			{ GetStr_wUser32(), GetStr_MessageBoxW(), (void*)Hooked_MessageBoxW, GetStr_MessageBoxW() },
			{ GetStr_wUser32(), GetStr_SetFocus(), (void*)Hooked_SetFocus, GetStr_SetFocus() },
			{ GetStr_wUser32(), GetStr_SetForegroundWindow(), (void*)Hooked_SetForegroundWindow, GetStr_SetForegroundWindow() },
			{ GetStr_wUser32(), GetStr_ShowWindow(), (void*)Hooked_ShowWindow, GetStr_ShowWindow() },

			{ GetStr_wPsapi(), GetStr_EnumProcessModules(), (void*)Hooked_EnumProcessModules, GetStr_EnumProcessModules()},

			{ GetStr_wNtdll(), GetStr_NtTerminateProcess(), (void*)Hooked_NtTerminateProcess, GetStr_NtTerminateProcess() },
			{ GetStr_wNtdll(), GetStr_NtQuerySystemInformation(), (void*)Hooked_NtQuerySystemInformation, GetStr_NtQuerySystemInformation() },
			{ GetStr_wNtdll(), GetStr_NtReadVirtualMemory(), (void*)Hooked_NtReadVirtualMemory, GetStr_NtReadVirtualMemory() },
			
			//{ GetStr_wNtdll(), GetStr_NtQueryVirtualMemory(), (void*)Hooked_NtQueryVirtualMemory, GetStr_NtQueryVirtualMemory() },
			//{ GetStr_wNtdll(), GetStr_NtProtectVirtualMemory(), (void*)Hooked_NtProtectVirtualMemory, GetStr_NtProtectVirtualMemory() },

			{ L"ws2_32.dll", "socket", (void*)Hooked_socket, GetStr_socket() },
			{ L"ws2_32.dll", "sendto", (void*)Hooked_sendto, GetStr_sendto() },
			{ L"ws2_32.dll", "WSASendTo", (void*)Hooked_wsasendto, GetStr_wsasendto() },
			{ L"ws2_32.dll", "send", (void*)Hooked_send, GetStr_send() },
			{ L"ws2_32.dll", "connect", (void*)Hooked_connect, GetStr_connect() }
		};

		int hookedCount = 0;
		const size_t hookCount = sizeof(hooks) / sizeof(hooks[0]);

		for (size_t i = 0; i < hookCount; i++) {
			const auto& h = hooks[i];
			void* original = nullptr;

			MH_STATUS st = MH_CreateHookApi(h.module, h.function, h.detour, &original);
			if (st == MH_OK) {
				g_originalFunctions[h.key] = original;
				
				// NOTE: PAGE_GUARD protection disabled - causes crash on trampoline execution
				// vowac.asi reads trampolines directly via pointers, not API calls
				// ProtectTrampolineRegion(original, 128);

				// Register for VirtualQuery spoofing (won't help if vowac.asi reads directly)
				RegisterHiddenRegion(original, 128);
				
				// Get and register hooked function address (where JMP was placed)
				HMODULE hMod = GetModuleHandleW(h.module);
				if (hMod) {
					void* targetFunc = GetProcAddress(hMod, h.function);
					if (targetFunc) {
						RegisterHiddenRegion(targetFunc, 32);  // MinHook JMP is typically 5-13 bytes
					}
				}
				
				te::sdk::helper::logging::Log(GetStr_HookLog(), h.module, h.function);
				hookedCount++;
			}
			else {
				te::sdk::helper::logging::Log(GetStr_HookFailLog(), h.module, h.function, "error");
			}
		}

		MH_STATUS enableSt = MH_EnableHook(MH_ALL_HOOKS);
		if (enableSt != MH_OK) {
			te::sdk::helper::logging::Log("[ #TE ] MH_EnableHook failed");
			return false;
		}

		g_hooksInitialized.store(true);
		g_hooksReady.store(true);

		te::sdk::helper::logging::Log("[ #TE ] MinHook enabled (%d hooks).", hookedCount);
		ADD_JUNK_CODE();
		return hookedCount > 0;
	}

	static void LoadModsFromDirectory() {
		ADD_JUNK_CODE();
		te::sdk::helper::logging::Log("[ #TE ] Loading .ws mods from game directory...");

		char exePath[MAX_PATH] = { 0 };
		DWORD exeLen = ::GetModuleFileNameA(nullptr, exePath, MAX_PATH);
		if (exeLen == 0) {
			te::sdk::helper::logging::Log("[ #TE ] ERROR: Failed to get executable path");
			ADD_JUNK_CODE();
			return;
		}

		char* lastSlash = strrchr(exePath, '\\');
		if (lastSlash) {
			*lastSlash = '\0';
		}

		te::sdk::helper::logging::Log("[ #TE ] Looking for .ws files in: %s", exePath);

		char searchPath[MAX_PATH] = { 0 };
		sprintf_s(searchPath, sizeof(searchPath), "%s\\*.ws", exePath);

		auto pOrigFindFirst = GetOriginalFunction<FindFirstFileA_t>(GetStr_FindFirstFileA());
		auto pOrigFindNext = GetOriginalFunction<FindNextFileA_t>(GetStr_FindNextFileA());
		auto pOrigLoadLibraryA = GetOriginalFunction<LoadLibraryA_t>(GetStr_LoadLibraryA());

		if (!pOrigFindFirst || !pOrigFindNext || !pOrigLoadLibraryA) {
			te::sdk::helper::logging::Log("[ #TE ] ERROR: Cannot get original FindFile functions");
			ADD_JUNK_CODE();
			return;
		}

		int loadedCount = 0;
		int failedCount = 0;

		WIN32_FIND_DATAA findData = {};
		HANDLE hFindFile = pOrigFindFirst(searchPath, &findData);

		if (hFindFile == INVALID_HANDLE_VALUE) {
			te::sdk::helper::logging::Log("[ #TE ] No .ws files found in game directory");
			ADD_JUNK_CODE();
			return;
		}

		do {
			std::string filename(findData.cFileName);
			if (filename == "." || filename == "..") continue;

			std::string lower = filename;
			std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

			if (lower.length() > 3) {
				std::string ext = lower.substr(lower.length() - 3);
				if (ext == ".ws") {
					te::sdk::helper::logging::Log("[ #TE ] Found .ws file: %s", filename.c_str());
					te::sdk::helper::logging::Log("[ #TE ] Attempting to load: %s", filename.c_str());

					HMODULE hMod = pOrigLoadLibraryA(filename.c_str());

					if (hMod) {
						te::sdk::helper::logging::Log("[ #TE ] Successfully loaded: %s (Handle: %p)",
							filename.c_str(), hMod);
						loadedCount++;

						std::lock_guard<std::recursive_mutex> lock(te::winapi::um::ac::bypass::g_hiddenModulesMutex);
						te::winapi::um::ac::bypass::g_hiddenModules[lower] = hMod;
						te::winapi::um::ac::bypass::RegisterHiddenModuleMemory(hMod);
						te::winapi::um::ac::bypass::UnlinkModuleFromPEB(hMod);
					}
					else {
						DWORD err = ::GetLastError();
						te::sdk::helper::logging::Log("[ #TE ] Failed to load: %s (Error: 0x%08X)",
							filename.c_str(), err);

						if (err == 0x7E) {
							te::sdk::helper::logging::Log("[ #TE ]   Missing dependency - check required DLLs");
						}

						failedCount++;
					}
				}
			}
		} while (pOrigFindNext(hFindFile, &findData));

		te::winapi::um::ac::bypass::proxy::ProxyAPI::FindClose(hFindFile);

		te::sdk::helper::logging::Log("[ #TE ] .ws loading complete - Loaded: %d, Failed: %d",
			loadedCount, failedCount);
		ADD_JUNK_CODE();
	}
}

// ============================================
// MAIN ENTRY POINTS
// ============================================
bool OnOutgoingRPC(const te::sdk::RpcContext& ctx) {
	if (ctx.rpcId == 25) {
		te::sdk::helper::samp::AddChatMessage(
			te::winapi::um::ac::bypass::GetStr_LoadedMsg(),
			D3DCOLOR_XRGB(0, 0xFF, 0)
		);

		//te::sdk::helper::logging::Log("[ #TE ] Returning from OnOutgoingRPC");
		//AddVectoredExceptionHandler(1, te::winapi::um::ac::bypass::AdvancedWraithCrashHandler);
	}
	if (ctx.rpcId == 128) {
		static bool modsLoaded = false;
		if (!modsLoaded) {
			modsLoaded = true;
			te::sdk::helper::logging::Log("[ #TE ] Loading mods...");
			te::winapi::um::ac::bypass::LoadModsFromDirectory();
		}
	}
	return true;
}

void Init() {
	ADD_JUNK_CODE();
	te::sdk::helper::logging::Log("[ #TE ] Initializing...");

	void* rakInterface = te::sdk::helper::GetRakNetInterface();
	while (rakInterface == nullptr) {
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
		rakInterface = te::sdk::helper::GetRakNetInterface();
	}

	if (te::sdk::InitRakNetHooks())
	{
		te::sdk::helper::logging::Log("[ #TE ] RakNet initialized, registering callbacks...");
		te::sdk::RegisterRaknetCallback(HookType::OutgoingRpc, OnOutgoingRPC);
	}

	te::sdk::helper::logging::Log("[ #TE ] Initialization complete");
	ADD_JUNK_CODE();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
	ADD_JUNK_CODE();
	if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
		if (te::winapi::um::ac::bypass::proxy::ProxyAPI::GetModuleHandleA(te::winapi::um::ac::bypass::GetStr_wraith_ac())) {
			te::winapi::um::ac::bypass::proxy::ProxyAPI::MessageBoxA(nullptr,
				te::winapi::um::ac::bypass::GetStr_WraithConflict(),
				te::winapi::um::ac::bypass::GetStr_ConflictTitle(),
				MB_OK | MB_ICONERROR);
			return FALSE;
		}

		te::winapi::um::ac::bypass::proxy::ProxyAPI::DisableThreadLibraryCalls(hModule);

		te::winapi::um::ac::bypass::InitializeExtensions();
		te::winapi::um::ac::bypass::InitializeWhitelisted();
		te::winapi::um::ac::bypass::InitializeBlacklisted();
		te::winapi::um::ac::bypass::InitializeBlacklistDirs();

		te::winapi::um::ac::bypass::HideExistingModules();

		if (!te::winapi::um::ac::bypass::InstallAntiDetectionHooks()) {
			return FALSE;
		}

		std::thread(Init).detach();
	}
	ADD_JUNK_CODE();
	return TRUE;
}