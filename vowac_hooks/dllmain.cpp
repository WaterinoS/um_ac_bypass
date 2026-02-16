// vowac_hooks.cpp - Rewritten with anti-detection fixes
// Fixes: self-integrity spoof, PEB unlinking, silent operation,
//        x64 prologue, NtQueryVirtualMemory hook, selective WinVerifyTrust,
//        NtQuerySystemInformation filtering, no AllocConsole, no log files
//
// #define VOWAC_DEBUG   // Uncomment for debug logging via OutputDebugStringA

#define NOMINMAX

#include <winsock2.h>
#include <windows.h>
#include <minhook.h>
#include <string>
#include <unordered_set>
#include <unordered_map>
#include <mutex>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstdio>
#include <ctime>
#include <tlhelp32.h>
#include <psapi.h>
#include <intrin.h>
#include <vector>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ws2_32.lib")

// ============================================
// NTDLL Function Pointers
// ============================================

typedef NTSTATUS(WINAPI* NtReadVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesRead
    );

typedef NTSTATUS(WINAPI* NtQueryVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    int MemoryInformationClass,
    PVOID MemoryInformation,
    SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength
    );

typedef NTSTATUS(WINAPI* NtQueryInformationProcess_t)(
    HANDLE ProcessHandle,
    int ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS(WINAPI* NtQuerySystemInformation_t)(
    int SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef VOID(NTAPI* PIO_APC_ROUTINE)(
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG Reserved
    );

typedef struct _UNICODE_STRING_NT {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING_NT, * PUNICODE_STRING_NT;

typedef NTSTATUS(WINAPI* NtQueryDirectoryFile_t)(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    int FileInformationClass,
    BOOLEAN ReturnSingleEntry,
    PUNICODE_STRING_NT FileName,
    BOOLEAN RestartScan
    );

typedef NTSTATUS(WINAPI* NtQueryDirectoryFileEx_t)(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    int FileInformationClass,
    ULONG QueryFlags,
    PUNICODE_STRING_NT FileName
    );

typedef SIZE_T(WINAPI* VirtualQueryEx_t)(
    HANDLE hProcess,
    LPCVOID lpAddress,
    PMEMORY_BASIC_INFORMATION lpBuffer,
    SIZE_T dwLength
    );

typedef SIZE_T(WINAPI* VirtualQuery_t)(
    LPCVOID lpAddress,
    PMEMORY_BASIC_INFORMATION lpBuffer,
    SIZE_T dwLength
    );

typedef NTSTATUS(NTAPI* NtWriteFile_t)(
    HANDLE FileHandle,
    HANDLE Event,
    PVOID ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
    );

typedef HANDLE(WINAPI* CreateToolhelp32Snapshot_t)(DWORD dwFlags, DWORD th32ProcessID);
typedef BOOL(WINAPI* Process32FirstW_t)(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);
typedef BOOL(WINAPI* Process32NextW_t)(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);
typedef BOOL(WINAPI* Module32FirstW_t)(HANDLE hSnapshot, LPMODULEENTRY32W lpme);
typedef BOOL(WINAPI* Module32NextW_t)(HANDLE hSnapshot, LPMODULEENTRY32W lpme);

typedef BOOL(WINAPI* QueryFullProcessImageNameA_t)(HANDLE, DWORD, LPSTR, PDWORD);
typedef BOOL(WINAPI* QueryFullProcessImageNameW_t)(HANDLE, DWORD, LPWSTR, PDWORD);
typedef BOOL(WINAPI* GetProcessImageFileNameA_t)(HANDLE, LPSTR, DWORD);
typedef BOOL(WINAPI* GetProcessImageFileNameW_t)(HANDLE, LPWSTR, DWORD);

typedef HANDLE(WINAPI* FindFirstChangeNotificationA_t)(LPCSTR, BOOL, DWORD);
typedef HANDLE(WINAPI* FindFirstChangeNotificationW_t)(LPCWSTR, BOOL, DWORD);
typedef BOOL(WINAPI* ReadDirectoryChangesW_t)(HANDLE, LPVOID, DWORD, BOOL, DWORD, LPDWORD, LPOVERLAPPED, LPOVERLAPPED_COMPLETION_ROUTINE);

typedef BOOL(WINAPI* GetThreadContext_t)(HANDLE hThread, LPCONTEXT lpContext);
typedef BOOL(WINAPI* SetThreadContext_t)(HANDLE hThread, const CONTEXT* lpContext);
typedef DWORD(WINAPI* SuspendThread_t)(HANDLE hThread);
typedef DWORD(WINAPI* ResumeThread_t)(HANDLE hThread);

typedef HANDLE(WINAPI* CreateRemoteThread_t)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef LPVOID(WINAPI* VirtualAllocEx_t)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* VirtualProtectEx_t)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);

typedef BOOL(WINAPI* EnumProcessModules_t)(HANDLE, HMODULE*, DWORD, LPDWORD);
typedef BOOL(WINAPI* EnumProcessModulesEx_t)(HANDLE, HMODULE*, DWORD, LPDWORD, DWORD);
typedef BOOL(WINAPI* GetModuleInformation_t)(HANDLE, HMODULE, LPMODULEINFO, DWORD);
typedef DWORD(WINAPI* GetModuleFileNameExA_t)(HANDLE, HMODULE, LPSTR, DWORD);
typedef DWORD(WINAPI* GetModuleFileNameExW_t)(HANDLE, HMODULE, LPWSTR, DWORD);
typedef LONG(WINAPI* WinVerifyTrust_t)(HWND, GUID*, LPVOID);
typedef BOOL(WINAPI* CryptCATAdminCalcHashFromFileHandle_t)(HANDLE, DWORD*, BYTE*, DWORD);

typedef HANDLE(WINAPI* CreateFileA_t)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef HANDLE(WINAPI* CreateFileW_t)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL(WINAPI* ReadFile_t)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL(WINAPI* WriteFile_t)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef DWORD(WINAPI* GetFileAttributesA_t)(LPCSTR);
typedef DWORD(WINAPI* GetFileAttributesW_t)(LPCWSTR);
typedef HANDLE(WINAPI* FindFirstFileA_t)(LPCSTR, LPWIN32_FIND_DATAA);
typedef HANDLE(WINAPI* FindFirstFileW_t)(LPCWSTR, LPWIN32_FIND_DATAW);
typedef BOOL(WINAPI* FindNextFileA_t)(HANDLE, LPWIN32_FIND_DATAA);
typedef BOOL(WINAPI* FindNextFileW_t)(HANDLE, LPWIN32_FIND_DATAW);
typedef BOOL(WINAPI* FindClose_t)(HANDLE);
typedef HANDLE(WINAPI* OpenProcess_t)(DWORD, BOOL, DWORD);

typedef int (WINAPI* recv_t)(SOCKET, char*, int, int);
typedef int (WINAPI* WSARecv_t)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WINAPI* send_t)(SOCKET, const char*, int, int);
typedef BOOL(WINAPI* PostMessageA_t)(HWND, UINT, WPARAM, LPARAM);
typedef BOOL(WINAPI* PostMessageW_t)(HWND, UINT, WPARAM, LPARAM);
typedef LRESULT(WINAPI* SendMessageW_t)(HWND, UINT, WPARAM, LPARAM);

// ============================================
// PEB Structures (x64) for module unlinking
// ============================================

typedef struct _MY_PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} MY_PEB_LDR_DATA, * PMY_PEB_LDR_DATA;

typedef struct _MY_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING_NT FullDllName;
    UNICODE_STRING_NT BaseDllName;
} MY_LDR_DATA_TABLE_ENTRY, * PMY_LDR_DATA_TABLE_ENTRY;

typedef struct _MY_PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PMY_PEB_LDR_DATA Ldr;
} MY_PEB, * PMY_PEB;

// ============================================
// NtQuerySystemInformation structures
// ============================================

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

// ============================================
// Logger (silent - OutputDebugString only)
// ============================================

#ifdef VOWAC_DEBUG
static void LogMessage(const char* format, ...) {
    char buffer[2048];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    OutputDebugStringA(buffer);
}
#else
#define LogMessage(...) ((void)0)
#endif

// ============================================
// Configuration Reader
// ============================================

class VowacConfigReader {
private:
    std::string vowacDir;
    std::string gtaSADir;
    std::unordered_set<std::string> whitelistExtensions;
    std::unordered_set<std::string> whitelistFolders;

    static std::string ToLower(const std::string& str) {
        std::string result = str;
        std::transform(result.begin(), result.end(), result.begin(), ::tolower);
        return result;
    }

    static std::string Trim(const std::string& str) {
        size_t first = str.find_first_not_of(" \t\r\n");
        if (std::string::npos == first) return str;
        size_t last = str.find_last_not_of(" \t\r\n");
        return str.substr(first, (last - first + 1));
    }

public:
    VowacConfigReader() {
        LoadConfig("vowac_config.ini");
    }

    bool LoadConfig(const std::string& configPath) {
        LogMessage("[CONFIG] Loading configuration from: %s", configPath.c_str());

        std::ifstream configFile(configPath);
        if (!configFile.is_open()) {
            LogMessage("[CONFIG] ERROR: Failed to open config file");
            return false;
        }

        std::string line;
        std::string currentSection;

        while (std::getline(configFile, line)) {
            line = Trim(line);
            if (line.empty() || line[0] == ';') continue;

            if (line[0] == '[' && line[line.length() - 1] == ']') {
                currentSection = line.substr(1, line.length() - 2);
                continue;
            }

            size_t equalPos = line.find('=');
            if (equalPos == std::string::npos) continue;

            std::string key = Trim(line.substr(0, equalPos));
            std::string value = Trim(line.substr(equalPos + 1));

            if (currentSection == "Paths") {
                if (key == "vowac_dir") {
                    vowacDir = value;
                    LogMessage("[CONFIG] Vowac Dir: %s", vowacDir.c_str());
                }
                else if (key == "gtasa_dir") {
                    gtaSADir = value;
                    LogMessage("[CONFIG] GTA SA Dir: %s", gtaSADir.c_str());
                }
            }
            else if (currentSection == "Whitelist.Extensions") {
                whitelistExtensions.insert(ToLower(value));
            }
            else if (currentSection == "Whitelist.Folders") {
                whitelistFolders.insert(ToLower(value));
            }
        }

        configFile.close();
        LogMessage("[CONFIG] Configuration loaded - Extensions: %u, Folders: %u",
            (unsigned)whitelistExtensions.size(), (unsigned)whitelistFolders.size());
        return true;
    }

    bool IsInMonitoredDirectory(const std::string& filePath) const {
        std::string lowerPath = ToLower(filePath);
        std::string lowerGtaSADir = ToLower(gtaSADir);
        if (lowerGtaSADir.empty()) return false;
        if (lowerGtaSADir.back() != '\\' && lowerGtaSADir.back() != '/') {
            lowerGtaSADir += '\\';
        }
        return lowerPath.find(lowerGtaSADir) == 0;
    }

    bool IsExtensionBlacklisted(const std::string& filename) const {
        size_t dotPos = filename.find_last_of('.');
        if (dotPos == std::string::npos) return false;
        std::string ext = ToLower(filename.substr(dotPos));
        return whitelistExtensions.find(ext) != whitelistExtensions.end();
    }

    bool IsFolderBlacklisted(const std::string& folderPath) const {
        std::string lowerPath = ToLower(folderPath);
        for (const auto& folder : whitelistFolders) {
            if (lowerPath.find(folder) != std::string::npos) {
                return true;
            }
        }
        return false;
    }

    bool IsFileForHide(const std::string& filePath) const {
        if (!IsInMonitoredDirectory(filePath)) return false;

        std::string lowerPath = ToLower(filePath);
        if (lowerPath.find("vowac.asi") != std::string::npos) return false;

        size_t lastSlash = filePath.find_last_of("\\/");
        std::string filename = (lastSlash != std::string::npos)
            ? ToLower(filePath.substr(lastSlash + 1))
            : lowerPath;

        return IsExtensionBlacklisted(filename) || IsFolderBlacklisted(lowerPath);
    }

    std::string GetBlockReason(const std::string& filePath) const {
        if (!IsInMonitoredDirectory(filePath)) return "NOT_IN_MONITORED_DIR";
        if (IsExtensionBlacklisted(filePath)) return "EXT_BLACKLISTED";
        if (IsFolderBlacklisted(filePath)) return "FOLDER_BLACKLISTED";
        size_t dotPos = filePath.find_last_of('.');
        std::string ext = (dotPos != std::string::npos) ? filePath.substr(dotPos) : "NO_EXT";
        return "BLOCKED_EXT:" + ext;
    }

    const std::string& GetVowacDir() const { return vowacDir; }
    const std::string& GetGTASADir() const { return gtaSADir; }
};

// ============================================
// Original Bytes Store (for integrity spoofing)
// ============================================

struct HookedFunctionEntry {
    LPVOID address;
    BYTE originalBytes[64];
    SIZE_T savedSize;
};

static std::vector<HookedFunctionEntry> g_hookedFunctions;
static std::mutex g_hookedFunctionsMutex;

// Save original bytes BEFORE MH_CreateHook modifies them
static void SaveOriginalBytes(LPVOID funcAddr, SIZE_T size = 64) {
    if (!funcAddr || size == 0) return;

    HookedFunctionEntry entry = {};
    entry.address = funcAddr;
    entry.savedSize = std::min(size, (SIZE_T)64);
    memcpy(entry.originalBytes, funcAddr, entry.savedSize);
    g_hookedFunctions.push_back(entry);
}

// Restore original bytes in a read buffer (for self-integrity spoof)
static void SpoofOriginalBytes(PVOID baseAddress, PVOID buffer, SIZE_T bytesRead) {
    if (!buffer || bytesRead == 0) return;

    DWORD_PTR readStart = (DWORD_PTR)baseAddress;
    DWORD_PTR readEnd = readStart + bytesRead;

    for (const auto& hf : g_hookedFunctions) {
        DWORD_PTR hookAddr = (DWORD_PTR)hf.address;
        DWORD_PTR hookEnd = hookAddr + hf.savedSize;

        // Check for overlap
        if (hookAddr < readEnd && hookEnd > readStart) {
            DWORD_PTR overlapStart = std::max(readStart, hookAddr);
            DWORD_PTR overlapEnd = std::min(readEnd, hookEnd);

            SIZE_T srcOffset = (SIZE_T)(overlapStart - hookAddr);
            SIZE_T dstOffset = (SIZE_T)(overlapStart - readStart);
            SIZE_T copySize = (SIZE_T)(overlapEnd - overlapStart);

            memcpy((BYTE*)buffer + dstOffset, hf.originalBytes + srcOffset, copySize);
        }
    }
}

// ============================================
// DLL Self-Info (for hiding own regions)
// ============================================

static HMODULE g_ourDllModule = NULL;
static DWORD_PTR g_ourDllBase = 0;
static DWORD g_ourDllSize = 0;

static bool IsInOurDllRegion(PVOID address) {
    DWORD_PTR addr = (DWORD_PTR)address;
    return (addr >= g_ourDllBase && addr < g_ourDllBase + g_ourDllSize);
}

// ============================================
// PEB Unlinking
// ============================================

static void UnlinkModuleFromPEB(HMODULE hModule) {
    // Get PEB on x64
    PMY_PEB pPeb = (PMY_PEB)__readgsqword(0x60);
    if (!pPeb || !pPeb->Ldr) return;

    PMY_PEB_LDR_DATA pLdr = pPeb->Ldr;

    // Walk InLoadOrderModuleList
    PLIST_ENTRY head = &pLdr->InLoadOrderModuleList;
    PLIST_ENTRY current = head->Flink;

    while (current != head) {
        PMY_LDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(current, MY_LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        if (entry->DllBase == (PVOID)hModule) {
            // Unlink from InLoadOrderModuleList
            entry->InLoadOrderLinks.Flink->Blink = entry->InLoadOrderLinks.Blink;
            entry->InLoadOrderLinks.Blink->Flink = entry->InLoadOrderLinks.Flink;

            // Unlink from InMemoryOrderModuleList
            entry->InMemoryOrderLinks.Flink->Blink = entry->InMemoryOrderLinks.Blink;
            entry->InMemoryOrderLinks.Blink->Flink = entry->InMemoryOrderLinks.Flink;

            // Unlink from InInitializationOrderModuleList
            entry->InInitializationOrderLinks.Flink->Blink = entry->InInitializationOrderLinks.Blink;
            entry->InInitializationOrderLinks.Blink->Flink = entry->InInitializationOrderLinks.Flink;

            // Zero the DLL name strings so cached references don't reveal us
            if (entry->BaseDllName.Buffer) {
                memset(entry->BaseDllName.Buffer, 0, entry->BaseDllName.MaximumLength);
            }
            if (entry->FullDllName.Buffer) {
                memset(entry->FullDllName.Buffer, 0, entry->FullDllName.MaximumLength);
            }

            LogMessage("[PEB] Module unlinked from PEB");
            break;
        }

        current = current->Flink;
    }
}

// ============================================
// Context Structures
// ============================================

struct FindFileContext {
    std::string searchPath;
    bool isMonitored;
};

struct DirectoryWatchContext {
    std::string directoryPath;
    bool isMonitored;
};

// ============================================
// Global Variables
// ============================================

VowacConfigReader* g_pConfig = nullptr;
std::mutex g_mutex;
std::unordered_map<HANDLE, FindFileContext> g_findFileContexts;
std::unordered_map<HANDLE, DirectoryWatchContext> g_directoryWatchContexts;
std::unordered_map<DWORD, bool> g_gtaSaProcessCache;
std::mutex g_cacheMutex;

std::vector<BYTE> g_cleanGtaSaImage;
DWORD_PTR g_gtaSaBaseAddress = 0;
std::unordered_map<DWORD, DWORD_PTR> g_processBaseAddresses;
std::mutex g_cleanImageMutex;

// ============================================
// Original Function Pointers
// ============================================

CreateFileA_t pOriginalCreateFileA = nullptr;
CreateFileW_t pOriginalCreateFileW = nullptr;
ReadFile_t pOriginalReadFile = nullptr;
WriteFile_t pOriginalWriteFile = nullptr;
GetFileAttributesA_t pOriginalGetFileAttributesA = nullptr;
GetFileAttributesW_t pOriginalGetFileAttributesW = nullptr;
FindFirstFileA_t pOriginalFindFirstFileA = nullptr;
FindFirstFileW_t pOriginalFindFirstFileW = nullptr;
FindNextFileA_t pOriginalFindNextFileA = nullptr;
FindNextFileW_t pOriginalFindNextFileW = nullptr;
FindClose_t pOriginalFindClose = nullptr;
OpenProcess_t pOriginalOpenProcess = nullptr;
VirtualQueryEx_t pOriginalVirtualQueryEx = nullptr;
VirtualQuery_t pOriginalVirtualQuery = nullptr;
NtWriteFile_t pOriginalNtWriteFile = nullptr;

recv_t pOriginal_recv = nullptr;
WSARecv_t pOriginal_WSARecv = nullptr;
PostMessageA_t pOriginal_PostMessageA = nullptr;
PostMessageW_t pOriginal_PostMessageW = nullptr;
SendMessageW_t pOriginal_SendMessageW = nullptr;
send_t pOriginal_send = nullptr;

NtReadVirtualMemory_t pOriginalNtReadVirtualMemory = nullptr;
NtQueryVirtualMemory_t pOriginalNtQueryVirtualMemory = nullptr;
NtQueryInformationProcess_t pOriginalNtQueryInformationProcess = nullptr;
NtQuerySystemInformation_t pOriginalNtQuerySystemInformation = nullptr;
NtQueryDirectoryFile_t pOriginalNtQueryDirectoryFile = nullptr;
NtQueryDirectoryFileEx_t pOriginalNtQueryDirectoryFileEx = nullptr;
CreateToolhelp32Snapshot_t pOriginalCreateToolhelp32Snapshot = nullptr;
Process32FirstW_t pOriginalProcess32FirstW = nullptr;
Process32NextW_t pOriginalProcess32NextW = nullptr;
Module32FirstW_t pOriginalModule32FirstW = nullptr;
Module32NextW_t pOriginalModule32NextW = nullptr;
QueryFullProcessImageNameA_t pOriginalQueryFullProcessImageNameA = nullptr;
QueryFullProcessImageNameW_t pOriginalQueryFullProcessImageNameW = nullptr;
GetProcessImageFileNameA_t pOriginalGetProcessImageFileNameA = nullptr;
GetProcessImageFileNameW_t pOriginalGetProcessImageFileNameW = nullptr;
FindFirstChangeNotificationA_t pOriginalFindFirstChangeNotificationA = nullptr;
FindFirstChangeNotificationW_t pOriginalFindFirstChangeNotificationW = nullptr;
ReadDirectoryChangesW_t pOriginalReadDirectoryChangesW = nullptr;
GetThreadContext_t pOriginalGetThreadContext = nullptr;
SetThreadContext_t pOriginalSetThreadContext = nullptr;
SuspendThread_t pOriginalSuspendThread = nullptr;
ResumeThread_t pOriginalResumeThread = nullptr;
CreateRemoteThread_t pOriginalCreateRemoteThread = nullptr;
VirtualAllocEx_t pOriginalVirtualAllocEx = nullptr;
VirtualProtectEx_t pOriginalVirtualProtectEx = nullptr;

EnumProcessModules_t pOriginalEnumProcessModules = nullptr;
EnumProcessModulesEx_t pOriginalEnumProcessModulesEx = nullptr;
GetModuleInformation_t pOriginalGetModuleInformation = nullptr;
GetModuleFileNameExA_t pOriginalGetModuleFileNameExA = nullptr;
GetModuleFileNameExW_t pOriginalGetModuleFileNameExW = nullptr;
WinVerifyTrust_t pOriginalWinVerifyTrust = nullptr;
CryptCATAdminCalcHashFromFileHandle_t pOriginalCryptCATAdminCalcHashFromFileHandle = nullptr;

// ============================================
// Helper Functions
// ============================================

static std::string ExtractDirectoryFromSearchPath(const std::string& searchPath) {
    size_t lastSlash = searchPath.find_last_of("\\/");
    if (lastSlash == std::string::npos) return "";
    return searchPath.substr(0, lastSlash);
}

static std::string ToLower(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

static std::string WideStringToAnsi(const wchar_t* wideStr) {
    if (!wideStr) return "";
    int sizeNeeded = WideCharToMultiByte(CP_ACP, 0, wideStr, -1, nullptr, 0, nullptr, nullptr);
    if (sizeNeeded <= 0) return "";
    std::string ansiStr(sizeNeeded, 0);
    WideCharToMultiByte(CP_ACP, 0, wideStr, -1, &ansiStr[0], sizeNeeded, nullptr, nullptr);
    if (!ansiStr.empty() && ansiStr.back() == '\0') ansiStr.pop_back();
    return ansiStr;
}

// Check if handle refers to our own process
static bool IsOwnProcess(HANDLE hProcess) {
    if (hProcess == GetCurrentProcess() || hProcess == (HANDLE)-1) return true;
    DWORD pid = GetProcessId(hProcess);
    return (pid != 0 && pid == GetCurrentProcessId());
}

// Forward declarations
bool LoadCleanGtaSaImage(const std::wstring& gtaSaPath);
bool IsModuleBlacklisted(const std::string& modulePath);

// Check if process handle points to gta_sa.exe
static bool IsGtaSaProcess(HANDLE hProcess) {
    if (hProcess == nullptr || hProcess == INVALID_HANDLE_VALUE) return false;
    if (hProcess == GetCurrentProcess() || hProcess == (HANDLE)-1) return false;

    DWORD pid = GetProcessId(hProcess);
    if (pid == 0) return false;
    if (pid == GetCurrentProcessId()) return false;

    {
        std::lock_guard<std::mutex> lock(g_cacheMutex);
        auto it = g_gtaSaProcessCache.find(pid);
        if (it != g_gtaSaProcessCache.end()) {
            return it->second;
        }
    }

    wchar_t processName[MAX_PATH] = {};
    DWORD size = MAX_PATH;
    BOOL result = FALSE;

    if (pOriginalQueryFullProcessImageNameW) {
        result = pOriginalQueryFullProcessImageNameW(hProcess, 0, processName, &size);
    }
    else {
        result = QueryFullProcessImageNameW(hProcess, 0, processName, &size);
    }

    if (result) {
        _wcslwr_s(processName, MAX_PATH);
        bool isGtaSa = wcsstr(processName, L"gta_sa.exe") != nullptr;

        {
            std::lock_guard<std::mutex> lock(g_cacheMutex);
            g_gtaSaProcessCache[pid] = isGtaSa;
        }

        if (isGtaSa) {
            LogMessage("[HOOK] Detected GTA SA process: PID=%u", pid);
            LoadCleanGtaSaImage(processName);

            HMODULE hMods[1024];
            DWORD cbNeeded;
            if (pOriginalEnumProcessModules &&
                pOriginalEnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded) && cbNeeded > 0) {
                DWORD_PTR baseAddr = (DWORD_PTR)hMods[0];
                std::lock_guard<std::mutex> lock(g_cleanImageMutex);
                g_processBaseAddresses[pid] = baseAddr;
            }
        }

        return isGtaSa;
    }

    return false;
}

static bool IsAddressInKnownModule(LPVOID address, HANDLE hProcess) {
    if (!address) return false;

    DWORD_PTR addr = (DWORD_PTR)address;
    HMODULE hMods[1024];
    DWORD cbNeeded;

    if (!pOriginalEnumProcessModules ||
        !pOriginalEnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        return false;
    }

    DWORD moduleCount = cbNeeded / sizeof(HMODULE);

    for (DWORD i = 0; i < moduleCount; i++) {
        MODULEINFO modInfo = {};
        if (pOriginalGetModuleInformation &&
            pOriginalGetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo))) {
            DWORD_PTR moduleStart = (DWORD_PTR)modInfo.lpBaseOfDll;
            DWORD_PTR moduleEnd = moduleStart + modInfo.SizeOfImage;

            if (addr >= moduleStart && addr < moduleEnd) {
                char moduleName[MAX_PATH] = {};
                if (pOriginalGetModuleFileNameExA &&
                    pOriginalGetModuleFileNameExA(hProcess, hMods[i], moduleName, MAX_PATH)) {
                    for (char* p = moduleName; *p; p++) *p = (char)tolower(*p);

                    if (strstr(moduleName, "gta_sa.exe") ||
                        strstr(moduleName, "ntdll.dll") ||
                        strstr(moduleName, "kernel32.dll") ||
                        strstr(moduleName, "samp.dll") ||
                        strstr(moduleName, "vowac.asi")) {
                        return true;
                    }
                }
                return false;
            }
        }
    }

    return false;
}

bool IsModuleBlacklisted(const std::string& modulePath) {
    if (!g_pConfig) return false;

    std::string lowerPath = ToLower(modulePath);
    if (lowerPath.find("vowac.asi") != std::string::npos) return false;

    // Also hide our own DLL
    if (lowerPath.find("vowac_hooks") != std::string::npos) return true;

    size_t lastSlash = modulePath.find_last_of("\\/");
    std::string filename = (lastSlash != std::string::npos)
        ? lowerPath.substr(lastSlash + 1)
        : lowerPath;

    return g_pConfig->IsExtensionBlacklisted(filename) ||
        g_pConfig->IsFolderBlacklisted(lowerPath);
}

static bool ShouldHideModule(const wchar_t* moduleName) {
    if (!moduleName || !g_pConfig) return false;

    wchar_t lower[MAX_PATH] = {};
    wcsncpy_s(lower, moduleName, MAX_PATH - 1);
    _wcslwr_s(lower, MAX_PATH);

    // Always hide our DLL from module enumeration
    if (wcsstr(lower, L"vowac_hooks") != nullptr) return true;

    std::string modulePath = WideStringToAnsi(lower);
    if (modulePath.empty()) return false;
    return IsModuleBlacklisted(modulePath);
}

// ============================================
// Clean Image Support (for gta_sa integrity)
// ============================================

bool LoadCleanGtaSaImage(const std::wstring& gtaSaPath) {
    std::lock_guard<std::mutex> lock(g_cleanImageMutex);
    if (!g_cleanGtaSaImage.empty()) return true;

    HANDLE hFile = CreateFileW(gtaSaPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    DWORD fileSize = GetFileSize(hFile, NULL);
    g_cleanGtaSaImage.resize(fileSize);

    DWORD bytesRead = 0;
    if (!ReadFile(hFile, g_cleanGtaSaImage.data(), fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        CloseHandle(hFile);
        g_cleanGtaSaImage.clear();
        return false;
    }

    CloseHandle(hFile);
    LogMessage("[INTEGRITY] Loaded clean gta_sa.exe (%u bytes)", fileSize);
    return true;
}

static bool GetCleanMemoryData(HANDLE processHandle, DWORD_PTR addr, SIZE_T size, PVOID buffer) {
    std::lock_guard<std::mutex> lock(g_cleanImageMutex);
    if (g_cleanGtaSaImage.empty()) return false;

    DWORD pid = GetProcessId(processHandle);
    auto it = g_processBaseAddresses.find(pid);
    if (it == g_processBaseAddresses.end()) return false;

    DWORD_PTR baseAddr = it->second;
    DWORD_PTR rva = addr - baseAddr;

    if (g_cleanGtaSaImage.size() < sizeof(IMAGE_DOS_HEADER)) return false;

    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)g_cleanGtaSaImage.data();
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;
    if (g_cleanGtaSaImage.size() < dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS)) return false;

    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(g_cleanGtaSaImage.data() + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return false;

    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(ntHeaders);
    WORD numSections = ntHeaders->FileHeader.NumberOfSections;

    for (WORD i = 0; i < numSections; i++) {
        DWORD sectionStart = sections[i].VirtualAddress;
        DWORD sectionEnd = sectionStart + sections[i].Misc.VirtualSize;

        if (rva >= sectionStart && rva < sectionEnd) {
            DWORD fileOffset = (DWORD)(rva - sectionStart) + sections[i].PointerToRawData;
            if (fileOffset + size > g_cleanGtaSaImage.size()) return false;
            memcpy(buffer, g_cleanGtaSaImage.data() + fileOffset, size);
            return true;
        }
    }

    return false;
}

// ============================================
// Hook Implementations - File I/O
// ============================================

HANDLE WINAPI HookedCreateFileA(
    LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile
) {
    if (g_pConfig && lpFileName) {
        std::string filename(lpFileName);
        if (g_pConfig->IsFileForHide(filename)) {
            LogMessage("[HOOK] BLOCKED CreateFileA: %s", filename.c_str());
            SetLastError(ERROR_FILE_NOT_FOUND);
            return INVALID_HANDLE_VALUE;
        }
    }
    return pOriginalCreateFileA(lpFileName, dwDesiredAccess, dwShareMode,
        lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

HANDLE WINAPI HookedCreateFileW(
    LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile
) {
    if (g_pConfig && lpFileName) {
        char filename[MAX_PATH] = {};
        WideCharToMultiByte(CP_ACP, 0, lpFileName, -1, filename, MAX_PATH, nullptr, nullptr);
        if (g_pConfig->IsFileForHide(filename)) {
            LogMessage("[HOOK] BLOCKED CreateFileW: %s", filename);
            SetLastError(ERROR_FILE_NOT_FOUND);
            return INVALID_HANDLE_VALUE;
        }
    }
    return pOriginalCreateFileW(lpFileName, dwDesiredAccess, dwShareMode,
        lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

DWORD WINAPI HookedGetFileAttributesA(LPCSTR lpFileName) {
    if (g_pConfig && lpFileName && g_pConfig->IsFileForHide(lpFileName)) {
        SetLastError(ERROR_FILE_NOT_FOUND);
        return INVALID_FILE_ATTRIBUTES;
    }
    return pOriginalGetFileAttributesA(lpFileName);
}

DWORD WINAPI HookedGetFileAttributesW(LPCWSTR lpFileName) {
    if (g_pConfig && lpFileName) {
        char filename[MAX_PATH] = {};
        WideCharToMultiByte(CP_ACP, 0, lpFileName, -1, filename, MAX_PATH, nullptr, nullptr);
        if (g_pConfig->IsFileForHide(filename)) {
            SetLastError(ERROR_FILE_NOT_FOUND);
            return INVALID_FILE_ATTRIBUTES;
        }
    }
    return pOriginalGetFileAttributesW(lpFileName);
}

BOOL WINAPI HookedReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead,
    LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) {
    return pOriginalReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
}

BOOL WINAPI HookedWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
    LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {
    return pOriginalWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}

NTSTATUS NTAPI HookedNtWriteFile(HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine,
    PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length,
    PLARGE_INTEGER ByteOffset, PULONG Key) {
    return pOriginalNtWriteFile(FileHandle, Event, ApcRoutine, ApcContext,
        IoStatusBlock, Buffer, Length, ByteOffset, Key);
}

// ============================================
// Hook Implementations - Module Enumeration
// ============================================

BOOL WINAPI HookedEnumProcessModules(HANDLE hProcess, HMODULE* lphModule, DWORD cb, LPDWORD lpcbNeeded) {
    BOOL result = pOriginalEnumProcessModules(hProcess, lphModule, cb, lpcbNeeded);
    if (!result || !lphModule || !lpcbNeeded) return result;

    bool isOwn = IsOwnProcess(hProcess);
    bool isGtaSa = !isOwn && IsGtaSaProcess(hProcess);

    if (isOwn || isGtaSa) {
        DWORD moduleCount = *lpcbNeeded / sizeof(HMODULE);
        DWORD filteredCount = 0;

        for (DWORD i = 0; i < moduleCount; i++) {
            wchar_t moduleName[MAX_PATH] = {};
            if (pOriginalGetModuleFileNameExW &&
                pOriginalGetModuleFileNameExW(hProcess, lphModule[i], moduleName, MAX_PATH)) {
                _wcslwr_s(moduleName, MAX_PATH);

                // Own process: hide vowac_hooks
                if (isOwn && wcsstr(moduleName, L"vowac_hooks") != nullptr) continue;

                // GTA SA: hide blacklisted modules (consistent with file hiding)
                if (isGtaSa && ShouldHideModule(moduleName)) continue;
            }
            if (filteredCount != i) lphModule[filteredCount] = lphModule[i];
            filteredCount++;
        }

        *lpcbNeeded = filteredCount * sizeof(HMODULE);
    }

    return result;
}

BOOL WINAPI HookedEnumProcessModulesEx(HANDLE hProcess, HMODULE* lphModule, DWORD cb,
    LPDWORD lpcbNeeded, DWORD dwFilterFlag) {
    BOOL result = pOriginalEnumProcessModulesEx(hProcess, lphModule, cb, lpcbNeeded, dwFilterFlag);
    if (!result || !lphModule || !lpcbNeeded) return result;

    bool isOwn = IsOwnProcess(hProcess);
    bool isGtaSa = !isOwn && IsGtaSaProcess(hProcess);

    if (isOwn || isGtaSa) {
        DWORD moduleCount = *lpcbNeeded / sizeof(HMODULE);
        DWORD filteredCount = 0;

        for (DWORD i = 0; i < moduleCount; i++) {
            wchar_t moduleName[MAX_PATH] = {};
            if (pOriginalGetModuleFileNameExW &&
                pOriginalGetModuleFileNameExW(hProcess, lphModule[i], moduleName, MAX_PATH)) {
                _wcslwr_s(moduleName, MAX_PATH);

                // Own process: hide vowac_hooks
                if (isOwn && wcsstr(moduleName, L"vowac_hooks") != nullptr) continue;

                // GTA SA: hide blacklisted modules (consistent with file hiding)
                if (isGtaSa && ShouldHideModule(moduleName)) continue;
            }
            if (filteredCount != i) lphModule[filteredCount] = lphModule[i];
            filteredCount++;
        }

        *lpcbNeeded = filteredCount * sizeof(HMODULE);
    }

    return result;
}

BOOL WINAPI HookedGetModuleInformation(HANDLE hProcess, HMODULE hModule, LPMODULEINFO lpmodinfo, DWORD cb) {
    bool isOwn = IsOwnProcess(hProcess);
    bool isGtaSa = !isOwn && IsGtaSaProcess(hProcess);

    if (isOwn || isGtaSa) {
        wchar_t moduleName[MAX_PATH] = {};
        if (pOriginalGetModuleFileNameExW &&
            pOriginalGetModuleFileNameExW(hProcess, hModule, moduleName, MAX_PATH)) {
            _wcslwr_s(moduleName, MAX_PATH);

            if (isOwn && wcsstr(moduleName, L"vowac_hooks") != nullptr) {
                SetLastError(ERROR_MOD_NOT_FOUND);
                return FALSE;
            }
            if (isGtaSa && ShouldHideModule(moduleName)) {
                SetLastError(ERROR_MOD_NOT_FOUND);
                return FALSE;
            }
        }
    }
    return pOriginalGetModuleInformation(hProcess, hModule, lpmodinfo, cb);
}

DWORD WINAPI HookedGetModuleFileNameExA(HANDLE hProcess, HMODULE hModule, LPSTR lpFilename, DWORD nSize) {
    DWORD result = pOriginalGetModuleFileNameExA(hProcess, hModule, lpFilename, nSize);
    if (result > 0 && lpFilename) {
        char lowerName[MAX_PATH] = {};
        strncpy_s(lowerName, lpFilename, MAX_PATH - 1);
        _strlwr_s(lowerName, MAX_PATH);

        // Own process: spoof vowac_hooks name
        if (strstr(lowerName, "vowac_hooks") != nullptr) {
            strncpy_s(lpFilename, nSize, "C:\\Windows\\System32\\kernel32.dll", _TRUNCATE);
            return (DWORD)strlen(lpFilename);
        }

        // GTA SA process: hide blacklisted modules by returning error
        if (IsGtaSaProcess(hProcess)) {
            wchar_t wLowerName[MAX_PATH] = {};
            MultiByteToWideChar(CP_ACP, 0, lowerName, -1, wLowerName, MAX_PATH);
            if (ShouldHideModule(wLowerName)) {
                SetLastError(ERROR_MOD_NOT_FOUND);
                return 0;
            }
        }
    }
    return result;
}

DWORD WINAPI HookedGetModuleFileNameExW(HANDLE hProcess, HMODULE hModule, LPWSTR lpFilename, DWORD nSize) {
    DWORD result = pOriginalGetModuleFileNameExW(hProcess, hModule, lpFilename, nSize);
    if (result > 0 && lpFilename) {
        wchar_t lowerName[MAX_PATH] = {};
        wcsncpy_s(lowerName, lpFilename, MAX_PATH - 1);
        _wcslwr_s(lowerName, MAX_PATH);

        // Own process: spoof vowac_hooks name
        if (wcsstr(lowerName, L"vowac_hooks") != nullptr) {
            wcsncpy_s(lpFilename, nSize, L"C:\\Windows\\System32\\kernel32.dll", _TRUNCATE);
            return (DWORD)wcslen(lpFilename);
        }

        // GTA SA process: hide blacklisted modules by returning error
        if (IsGtaSaProcess(hProcess)) {
            if (ShouldHideModule(lowerName)) {
                SetLastError(ERROR_MOD_NOT_FOUND);
                return 0;
            }
        }
    }
    return result;
}

// ============================================
// Hook Implementations - WinVerifyTrust (selective)
// ============================================

LONG WINAPI HookedWinVerifyTrust(HWND hwnd, GUID* pgActionID, LPVOID pWVTData) {
    // Only spoof for our own DLL, pass through everything else
    // We can't easily check which file is being verified from pWVTData
    // so pass through - our DLL is hidden from enumeration anyway
    return pOriginalWinVerifyTrust(hwnd, pgActionID, pWVTData);
}

BOOL WINAPI HookedCryptCATAdminCalcHashFromFileHandle(HANDLE hFile, DWORD* pcbHash, BYTE* pbHash, DWORD dwFlags) {
    char fileName[MAX_PATH] = {};
    DWORD size = GetFinalPathNameByHandleA(hFile, fileName, MAX_PATH, FILE_NAME_NORMALIZED);
    if (size > 0) {
        _strlwr_s(fileName, MAX_PATH);
        if (strstr(fileName, "vowac_hooks") != nullptr) {
            if (pcbHash && pbHash) {
                *pcbHash = 20;
                memset(pbHash, 0, 20);
                return TRUE;
            }
        }
    }
    return pOriginalCryptCATAdminCalcHashFromFileHandle(hFile, pcbHash, pbHash, dwFlags);
}

// ============================================
// Hook Implementations - FindFile
// ============================================

HANDLE WINAPI HookedFindFirstFileA(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData) {
    if (!g_pConfig || !lpFileName)
        return pOriginalFindFirstFileA(lpFileName, lpFindFileData);

    std::string searchPath(lpFileName);
    std::string directory = ExtractDirectoryFromSearchPath(searchPath);
    bool isMonitored = g_pConfig->IsInMonitoredDirectory(directory);

    HANDLE hFind = pOriginalFindFirstFileA(lpFileName, lpFindFileData);

    if (hFind != INVALID_HANDLE_VALUE) {
        FindFileContext context;
        context.searchPath = searchPath;
        context.isMonitored = isMonitored;

        {
            std::lock_guard<std::mutex> lock(g_mutex);
            g_findFileContexts[hFind] = context;
        }

        if (isMonitored) {
            std::string fullPath = directory + "\\" + lpFindFileData->cFileName;
            while (hFind != INVALID_HANDLE_VALUE) {
                if (!g_pConfig->IsFileForHide(fullPath)) return hFind;
                if (!pOriginalFindNextFileA(hFind, lpFindFileData)) {
                    FindClose(hFind);
                    return INVALID_HANDLE_VALUE;
                }
                fullPath = directory + "\\" + lpFindFileData->cFileName;
            }
        }
    }

    return hFind;
}

HANDLE WINAPI HookedFindFirstFileW(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData) {
    if (!g_pConfig || !lpFileName)
        return pOriginalFindFirstFileW(lpFileName, lpFindFileData);

    char searchPathA[MAX_PATH] = {};
    WideCharToMultiByte(CP_ACP, 0, lpFileName, -1, searchPathA, MAX_PATH, nullptr, nullptr);
    std::string searchPath(searchPathA);
    std::string directory = ExtractDirectoryFromSearchPath(searchPath);
    bool isMonitored = g_pConfig->IsInMonitoredDirectory(directory);

    HANDLE hFind = pOriginalFindFirstFileW(lpFileName, lpFindFileData);

    if (hFind != INVALID_HANDLE_VALUE) {
        FindFileContext context;
        context.searchPath = searchPath;
        context.isMonitored = isMonitored;

        {
            std::lock_guard<std::mutex> lock(g_mutex);
            g_findFileContexts[hFind] = context;
        }

        if (isMonitored) {
            char filenameA[MAX_PATH] = {};
            WideCharToMultiByte(CP_ACP, 0, lpFindFileData->cFileName, -1, filenameA, MAX_PATH, nullptr, nullptr);
            std::string fullPath = directory + "\\" + filenameA;

            while (hFind != INVALID_HANDLE_VALUE) {
                if (!g_pConfig->IsFileForHide(fullPath)) return hFind;
                if (!pOriginalFindNextFileW(hFind, lpFindFileData)) {
                    FindClose(hFind);
                    return INVALID_HANDLE_VALUE;
                }
                WideCharToMultiByte(CP_ACP, 0, lpFindFileData->cFileName, -1, filenameA, MAX_PATH, nullptr, nullptr);
                fullPath = directory + "\\" + filenameA;
            }
        }
    }

    return hFind;
}

BOOL WINAPI HookedFindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData) {
    if (!g_pConfig) return pOriginalFindNextFileA(hFindFile, lpFindFileData);

    std::string directory;
    bool isMonitored = false;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto it = g_findFileContexts.find(hFindFile);
        if (it != g_findFileContexts.end()) {
            isMonitored = it->second.isMonitored;
            directory = ExtractDirectoryFromSearchPath(it->second.searchPath);
        }
    }

    if (!isMonitored) return pOriginalFindNextFileA(hFindFile, lpFindFileData);

    while (pOriginalFindNextFileA(hFindFile, lpFindFileData)) {
        std::string fullPath = directory + "\\" + lpFindFileData->cFileName;
        if (!g_pConfig->IsFileForHide(fullPath)) return TRUE;
    }
    return FALSE;
}

BOOL WINAPI HookedFindNextFileW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData) {
    if (!g_pConfig) return pOriginalFindNextFileW(hFindFile, lpFindFileData);

    std::string directory;
    bool isMonitored = false;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto it = g_findFileContexts.find(hFindFile);
        if (it != g_findFileContexts.end()) {
            isMonitored = it->second.isMonitored;
            directory = ExtractDirectoryFromSearchPath(it->second.searchPath);
        }
    }

    if (!isMonitored) return pOriginalFindNextFileW(hFindFile, lpFindFileData);

    while (pOriginalFindNextFileW(hFindFile, lpFindFileData)) {
        char filenameA[MAX_PATH] = {};
        WideCharToMultiByte(CP_ACP, 0, lpFindFileData->cFileName, -1, filenameA, MAX_PATH, nullptr, nullptr);
        std::string fullPath = directory + "\\" + filenameA;
        if (!g_pConfig->IsFileForHide(fullPath)) return TRUE;
    }
    return FALSE;
}

BOOL WINAPI HookedFindClose(HANDLE hFindFile) {
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_findFileContexts.erase(hFindFile);
    }
    return pOriginalFindClose(hFindFile);
}

// ============================================
// Hook Implementations - NTDLL Memory (FIXED)
// ============================================

NTSTATUS WINAPI HookedNtReadVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesRead
) {
    // SELF-PROCESS: Spoof hooked function prologues back to original bytes
    if (IsOwnProcess(ProcessHandle)) {
        NTSTATUS status = pOriginalNtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer,
            NumberOfBytesToRead, NumberOfBytesRead);

        if (status == 0 && Buffer && NumberOfBytesRead && *NumberOfBytesRead > 0) {
            // Check if read overlaps our DLL region - return zeros/free
            if (IsInOurDllRegion(BaseAddress)) {
                memset(Buffer, 0, *NumberOfBytesRead);
                if (NumberOfBytesRead) *NumberOfBytesRead = NumberOfBytesToRead;
                return 0;
            }

            // Restore original bytes for any hooked functions in the read range
            SpoofOriginalBytes(BaseAddress, Buffer, *NumberOfBytesRead);
        }
        return status;
    }

    // GTA SA PROCESS: Existing integrity protection
    bool isGtaSa = IsGtaSaProcess(ProcessHandle);

    if (!isGtaSa) {
        return pOriginalNtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer,
            NumberOfBytesToRead, NumberOfBytesRead);
    }

    DWORD_PTR addr = (DWORD_PTR)BaseAddress;

    // Block reads from unknown RWX regions (injected code detection)
    MEMORY_BASIC_INFORMATION mbi;
    if (pOriginalVirtualQueryEx &&
        pOriginalVirtualQueryEx(ProcessHandle, BaseAddress, &mbi, sizeof(mbi)) > 0) {
        if (mbi.State == MEM_COMMIT && mbi.Protect == PAGE_EXECUTE_READWRITE) {
            if (!IsAddressInKnownModule(BaseAddress, ProcessHandle)) {
                LogMessage("[BLOCK] Blocking read from unknown RWX region at 0x%p", BaseAddress);
                if (NumberOfBytesRead) *NumberOfBytesRead = 0;
                return 0xC0000005; // STATUS_ACCESS_VIOLATION
            }
        }
    }

    // Serve clean data for integrity checks
    if (GetCleanMemoryData(ProcessHandle, addr, NumberOfBytesToRead, Buffer)) {
        if (NumberOfBytesRead) *NumberOfBytesRead = NumberOfBytesToRead;
        return 0;
    }

    // Pass through to original
    NTSTATUS status = pOriginalNtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer,
        NumberOfBytesToRead, NumberOfBytesRead);

    // Post-process: spoof hook signatures in gta_sa memory
    if (status == 0 && Buffer && NumberOfBytesRead && *NumberOfBytesRead > 0) {
        SIZE_T bytesRead = *NumberOfBytesRead;
        BYTE* pBuffer = (BYTE*)Buffer;

        // E9 = JMP rel32 (MinHook inline hook signature)
        if (bytesRead >= 5 && pBuffer[0] == 0xE9) {
            // x86 standard prologue for 32-bit gta_sa.exe
            pBuffer[0] = 0x8B; // MOV EDI, EDI
            pBuffer[1] = 0xFF;
            pBuffer[2] = 0x55; // PUSH EBP
            pBuffer[3] = 0x8B; // MOV EBP, ESP
            pBuffer[4] = 0xEC;
        }
        // FF 25 = JMP [addr] (absolute indirect jump)
        else if (bytesRead >= 6 && pBuffer[0] == 0xFF && pBuffer[1] == 0x25) {
            pBuffer[0] = 0x8B;
            pBuffer[1] = 0xFF;
            pBuffer[2] = 0x55;
            pBuffer[3] = 0x8B;
            pBuffer[4] = 0xEC;
        }
    }

    return status;
}

// ============================================
// Hook Implementations - NtQueryVirtualMemory (NEW - was unhooked!)
// ============================================

#define MemoryBasicInformation_Class    0
#define MemorySectionName_Class         2

NTSTATUS WINAPI HookedNtQueryVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    int MemoryInformationClass,
    PVOID MemoryInformation,
    SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength
) {
    NTSTATUS status = pOriginalNtQueryVirtualMemory(ProcessHandle, BaseAddress,
        MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);

    if (status != 0) return status;

    // Only spoof for own process
    if (!IsOwnProcess(ProcessHandle)) return status;

    // Hide our DLL's memory regions
    if (MemoryInformationClass == MemoryBasicInformation_Class && MemoryInformation) {
        PMEMORY_BASIC_INFORMATION mbi = (PMEMORY_BASIC_INFORMATION)MemoryInformation;

        // Check if this region's allocation base matches our DLL
        DWORD_PTR allocBase = (DWORD_PTR)mbi->AllocationBase;
        if (allocBase >= g_ourDllBase && allocBase < g_ourDllBase + g_ourDllSize) {
            mbi->State = MEM_FREE;
            mbi->Protect = PAGE_NOACCESS;
            mbi->Type = 0;
            mbi->AllocationProtect = 0;
            mbi->AllocationBase = nullptr;
            mbi->RegionSize = 0x10000; // Fake reasonable size
            LogMessage("[NtQVM] Hidden our DLL region at 0x%p", BaseAddress);
        }
    }

    // Hide our DLL path from MemorySectionName queries
    if (MemoryInformationClass == MemorySectionName_Class && MemoryInformation) {
        DWORD_PTR addr = (DWORD_PTR)BaseAddress;
        if (addr >= g_ourDllBase && addr < g_ourDllBase + g_ourDllSize) {
            // Return error - "no section name for this address"
            return 0xC0000141; // STATUS_INVALID_ADDRESS
        }
    }

    return status;
}

NTSTATUS WINAPI HookedNtQueryInformationProcess(
    HANDLE ProcessHandle, int ProcessInformationClass,
    PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength
) {
    return pOriginalNtQueryInformationProcess(ProcessHandle, ProcessInformationClass,
        ProcessInformation, ProcessInformationLength, ReturnLength);
}

// ============================================
// Hook Implementations - NtQuerySystemInformation (FIXED: filter, don't error)
// ============================================

#define SystemModuleInformation 11

NTSTATUS WINAPI HookedNtQuerySystemInformation(
    int SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
) {
    NTSTATUS status = pOriginalNtQuerySystemInformation(
        SystemInformationClass, SystemInformation,
        SystemInformationLength, ReturnLength);

    // Filter SystemModuleInformation - remove our DLL from the list instead of blocking
    if (status == 0 && SystemInformationClass == SystemModuleInformation && SystemInformation) {
        PRTL_PROCESS_MODULES pModules = (PRTL_PROCESS_MODULES)SystemInformation;

        ULONG writeIdx = 0;
        for (ULONG i = 0; i < pModules->NumberOfModules; i++) {
            char* fullPath = (char*)pModules->Modules[i].FullPathName;
            char* fileName = fullPath + pModules->Modules[i].OffsetToFileName;

            // Check if this is our DLL
            char lowerName[256] = {};
            strncpy_s(lowerName, fileName, sizeof(lowerName) - 1);
            _strlwr_s(lowerName, sizeof(lowerName));

            if (strstr(lowerName, "vowac_hooks") != nullptr) {
                LogMessage("[NTQSI] Filtering our DLL from SystemModuleInformation");
                continue; // Skip our module
            }

            // Keep this entry
            if (writeIdx != i) {
                memcpy(&pModules->Modules[writeIdx], &pModules->Modules[i],
                    sizeof(RTL_PROCESS_MODULE_INFORMATION));
            }
            writeIdx++;
        }

        pModules->NumberOfModules = writeIdx;
    }

    return status;
}

// ============================================
// Hook Implementations - VirtualQuery/Ex
// ============================================

SIZE_T WINAPI HookedVirtualQueryEx(
    HANDLE hProcess, LPCVOID lpAddress,
    PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength
) {
    SIZE_T result = pOriginalVirtualQueryEx(hProcess, lpAddress, lpBuffer, dwLength);
    if (result == 0 || !lpBuffer) return result;

    // For own process - hide our DLL regions
    if (IsOwnProcess(hProcess)) {
        DWORD_PTR allocBase = (DWORD_PTR)lpBuffer->AllocationBase;
        if (allocBase >= g_ourDllBase && allocBase < g_ourDllBase + g_ourDllSize) {
            lpBuffer->State = MEM_FREE;
            lpBuffer->Protect = PAGE_NOACCESS;
            lpBuffer->Type = 0;
            lpBuffer->AllocationProtect = 0;
            return result;
        }
    }

    bool isGtaSa = !IsOwnProcess(hProcess) && IsGtaSaProcess(hProcess);

    if (!isGtaSa) {
        // For own process, also downgrade RWX to RX
        if (IsOwnProcess(hProcess) && lpBuffer->Protect == PAGE_EXECUTE_READWRITE) {
            lpBuffer->Protect = PAGE_EXECUTE_READ;
        }
        return result;
    }

    // GTA SA process filtering
    if (lpBuffer->Type == MEM_IMAGE) {
        char devicePath[MAX_PATH] = { 0 };
        if (GetMappedFileNameA(hProcess, (LPVOID)lpBuffer->BaseAddress, devicePath, MAX_PATH)) {
            _strlwr_s(devicePath, MAX_PATH);
            if (g_pConfig && IsModuleBlacklisted(devicePath)) {
                LogMessage("[SPOOF] Hiding suspicious MEM_IMAGE in GTA SA");
                lpBuffer->State = MEM_FREE;
                lpBuffer->Protect = PAGE_NOACCESS;
                lpBuffer->Type = 0;
                lpBuffer->AllocationProtect = 0;
                return result;
            }
        }
        return result;
    }

    if (lpBuffer->State == MEM_COMMIT &&
        lpBuffer->Protect == PAGE_EXECUTE_READWRITE &&
        lpBuffer->Type == MEM_PRIVATE) {

        BYTE buffer[16];
        SIZE_T bytesRead = 0;

        if (pOriginalNtReadVirtualMemory) {
            NTSTATUS readStatus = pOriginalNtReadVirtualMemory(
                hProcess, (PVOID)lpAddress, buffer, sizeof(buffer), &bytesRead);

            if (readStatus == 0 && bytesRead >= 4) {
                if (buffer[0] == 'M' && buffer[1] == 'Z') {
                    lpBuffer->State = MEM_FREE;
                    lpBuffer->Protect = PAGE_NOACCESS;
                    lpBuffer->Type = 0;
                    lpBuffer->AllocationProtect = 0;
                    return result;
                }

                DWORD_PTR ptr = *(DWORD_PTR*)buffer;
                if (ptr >= 0x00400000 && ptr <= 0x7FFFFFFF) {
                    if (!IsAddressInKnownModule((LPVOID)ptr, hProcess)) {
                        lpBuffer->State = MEM_FREE;
                        lpBuffer->Protect = PAGE_NOACCESS;
                        lpBuffer->Type = 0;
                        lpBuffer->AllocationProtect = 0;
                        return result;
                    }
                }
            }
        }
    }

    if (lpBuffer->Protect == PAGE_EXECUTE_READWRITE) {
        lpBuffer->Protect = PAGE_EXECUTE_READ;
    }

    return result;
}

SIZE_T WINAPI HookedVirtualQuery(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength) {
    SIZE_T result = pOriginalVirtualQuery(lpAddress, lpBuffer, dwLength);
    if (result == 0 || !lpBuffer) return result;

    // Hide our DLL regions
    DWORD_PTR allocBase = (DWORD_PTR)lpBuffer->AllocationBase;
    if (allocBase >= g_ourDllBase && allocBase < g_ourDllBase + g_ourDllSize) {
        lpBuffer->State = MEM_FREE;
        lpBuffer->Protect = PAGE_NOACCESS;
        lpBuffer->Type = 0;
        lpBuffer->AllocationProtect = 0;
        return result;
    }

    // Hide blacklisted modules
    if (lpBuffer->Type == MEM_IMAGE) {
        char devicePath[MAX_PATH] = { 0 };
        if (GetMappedFileNameA(GetCurrentProcess(), (LPVOID)lpBuffer->BaseAddress, devicePath, MAX_PATH)) {
            _strlwr_s(devicePath, MAX_PATH);
            if (g_pConfig && IsModuleBlacklisted(devicePath)) {
                lpBuffer->State = MEM_FREE;
                lpBuffer->Protect = PAGE_NOACCESS;
                lpBuffer->Type = 0;
                lpBuffer->AllocationProtect = 0;
                return result;
            }
        }
    }

    // Hide suspicious RWX private memory
    if (lpBuffer->State == MEM_COMMIT &&
        lpBuffer->Protect == PAGE_EXECUTE_READWRITE &&
        lpBuffer->Type == MEM_PRIVATE) {
        lpBuffer->State = MEM_FREE;
        lpBuffer->Protect = PAGE_NOACCESS;
        lpBuffer->Type = 0;
        lpBuffer->AllocationProtect = 0;
    }

    if (lpBuffer->Protect == PAGE_EXECUTE_READWRITE) {
        lpBuffer->Protect = PAGE_EXECUTE_READ;
    }

    return result;
}

// ============================================
// Hook Implementations - Process/Module Enumeration
// ============================================

HANDLE WINAPI HookedCreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID) {
    return pOriginalCreateToolhelp32Snapshot(dwFlags, th32ProcessID);
}

BOOL WINAPI HookedProcess32FirstW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe) {
    return pOriginalProcess32FirstW(hSnapshot, lppe);
}

BOOL WINAPI HookedProcess32NextW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe) {
    return pOriginalProcess32NextW(hSnapshot, lppe);
}

BOOL WINAPI HookedModule32FirstW(HANDLE hSnapshot, LPMODULEENTRY32W lpme) {
    if (!lpme) return pOriginalModule32FirstW(hSnapshot, lpme);

    BOOL result = pOriginalModule32FirstW(hSnapshot, lpme);
    if (!result) return result;

    int skipCount = 0;
    while (result && lpme && ShouldHideModule(lpme->szModule) && skipCount < 100) {
        result = pOriginalModule32NextW(hSnapshot, lpme);
        skipCount++;
    }

    return result;
}

BOOL WINAPI HookedModule32NextW(HANDLE hSnapshot, LPMODULEENTRY32W lpme) {
    if (!lpme) return pOriginalModule32NextW(hSnapshot, lpme);

    BOOL result = pOriginalModule32NextW(hSnapshot, lpme);

    int skipCount = 0;
    while (result && lpme && ShouldHideModule(lpme->szModule) && skipCount < 100) {
        result = pOriginalModule32NextW(hSnapshot, lpme);
        skipCount++;
    }

    return result;
}

BOOL WINAPI HookedQueryFullProcessImageNameA(HANDLE hProcess, DWORD dwFlags, LPSTR lpExeName, PDWORD lpdwSize) {
    return pOriginalQueryFullProcessImageNameA(hProcess, dwFlags, lpExeName, lpdwSize);
}

BOOL WINAPI HookedQueryFullProcessImageNameW(HANDLE hProcess, DWORD dwFlags, LPWSTR lpExeName, PDWORD lpdwSize) {
    return pOriginalQueryFullProcessImageNameW(hProcess, dwFlags, lpExeName, lpdwSize);
}

BOOL WINAPI HookedGetProcessImageFileNameA(HANDLE hProcess, LPSTR lpImageFileName, DWORD nSize) {
    return pOriginalGetProcessImageFileNameA(hProcess, lpImageFileName, nSize);
}

BOOL WINAPI HookedGetProcessImageFileNameW(HANDLE hProcess, LPWSTR lpImageFileName, DWORD nSize) {
    return pOriginalGetProcessImageFileNameW(hProcess, lpImageFileName, nSize);
}

// ============================================
// Hook Implementations - Directory Changes
// ============================================

HANDLE WINAPI HookedFindFirstChangeNotificationA(LPCSTR lpPathName, BOOL bWatchSubtree, DWORD dwNotifyFilter) {
    return pOriginalFindFirstChangeNotificationA(lpPathName, bWatchSubtree, dwNotifyFilter);
}

HANDLE WINAPI HookedFindFirstChangeNotificationW(LPCWSTR lpPathName, BOOL bWatchSubtree, DWORD dwNotifyFilter) {
    return pOriginalFindFirstChangeNotificationW(lpPathName, bWatchSubtree, dwNotifyFilter);
}

BOOL WINAPI HookedReadDirectoryChangesW(
    HANDLE hDirectory, LPVOID lpBuffer, DWORD nBufferLength, BOOL bWatchSubtree,
    DWORD dwNotifyFilter, LPDWORD lpBytesReturned, LPOVERLAPPED lpOverlapped,
    LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
) {
    return pOriginalReadDirectoryChangesW(hDirectory, lpBuffer, nBufferLength, bWatchSubtree,
        dwNotifyFilter, lpBytesReturned, lpOverlapped, lpCompletionRoutine);
}

// ============================================
// Hook Implementations - NtQueryDirectoryFile
// ============================================

typedef struct _FILE_DIRECTORY_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_DIRECTORY_INFORMATION, * PFILE_DIRECTORY_INFORMATION;

typedef struct _FILE_FULL_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    WCHAR FileName[1];
} FILE_FULL_DIR_INFORMATION, * PFILE_FULL_DIR_INFORMATION;

typedef struct _FILE_BOTH_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    CCHAR ShortNameLength;
    WCHAR ShortName[12];
    WCHAR FileName[1];
} FILE_BOTH_DIR_INFORMATION, * PFILE_BOTH_DIR_INFORMATION;

typedef struct _FILE_DIR_ENTRY_GENERIC {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    ULONG Data[100];
} FILE_DIR_ENTRY_GENERIC, * PFILE_DIR_ENTRY_GENERIC;

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define STATUS_NO_MORE_FILES ((NTSTATUS)0x80000006L)
#define FileDirectoryInformation 1
#define FileFullDirectoryInformation 2
#define FileBothDirectoryInformation 3

static void FilterDirectoryEntries(PVOID FileInformation, int FileInformationClass, const std::string& directoryPath) {
    if (FileInformationClass != FileDirectoryInformation &&
        FileInformationClass != FileFullDirectoryInformation &&
        FileInformationClass != FileBothDirectoryInformation) {
        return;
    }

    PFILE_DIR_ENTRY_GENERIC pCurrent = (PFILE_DIR_ENTRY_GENERIC)FileInformation;
    PFILE_DIR_ENTRY_GENERIC pPrevious = nullptr;
    bool isFirstEntry = true;
    int totalEntries = 0;

    while (true) {
        PWSTR pFileName = nullptr;
        ULONG fileNameLen = 0;

        if (FileInformationClass == FileDirectoryInformation) {
            PFILE_DIRECTORY_INFORMATION pDir = (PFILE_DIRECTORY_INFORMATION)pCurrent;
            pFileName = pDir->FileName;
            fileNameLen = pDir->FileNameLength;
        }
        else if (FileInformationClass == FileFullDirectoryInformation) {
            PFILE_FULL_DIR_INFORMATION pFull = (PFILE_FULL_DIR_INFORMATION)pCurrent;
            pFileName = pFull->FileName;
            fileNameLen = pFull->FileNameLength;
        }
        else if (FileInformationClass == FileBothDirectoryInformation) {
            PFILE_BOTH_DIR_INFORMATION pBoth = (PFILE_BOTH_DIR_INFORMATION)pCurrent;
            pFileName = pBoth->FileName;
            fileNameLen = pBoth->FileNameLength;
        }

        char filename[MAX_PATH] = {};
        if (pFileName && fileNameLen > 0 && fileNameLen < (MAX_PATH * sizeof(WCHAR))) {
            WideCharToMultiByte(CP_ACP, 0, pFileName, fileNameLen / sizeof(WCHAR),
                filename, MAX_PATH, nullptr, nullptr);
        }

        totalEntries++;

        bool isDotEntry = (strcmp(filename, ".") == 0 || strcmp(filename, "..") == 0);
        std::string fullPath = directoryPath + "\\" + filename;
        bool shouldHide = !isDotEntry && !isFirstEntry && g_pConfig && g_pConfig->IsFileForHide(fullPath);

        // Also hide vowac_hooks files from directory listing
        if (!isDotEntry) {
            char lowerFn[MAX_PATH] = {};
            strncpy_s(lowerFn, filename, MAX_PATH - 1);
            _strlwr_s(lowerFn, MAX_PATH);
            if (strstr(lowerFn, "vowac_hooks") != nullptr) shouldHide = true;
        }

        if (shouldHide && pPrevious != nullptr) {
            if (pCurrent->NextEntryOffset != 0) {
                pPrevious->NextEntryOffset += pCurrent->NextEntryOffset;
            }
            else {
                pPrevious->NextEntryOffset = 0;
            }
        }
        else {
            pPrevious = pCurrent;
        }

        isFirstEntry = false;

        if (pCurrent->NextEntryOffset == 0) break;
        pCurrent = (PFILE_DIR_ENTRY_GENERIC)((LPBYTE)pCurrent + pCurrent->NextEntryOffset);

        if (totalEntries > 10000) break;
    }
}

NTSTATUS WINAPI HookedNtQueryDirectoryFile(
    HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length,
    int FileInformationClass, BOOLEAN ReturnSingleEntry, PUNICODE_STRING_NT FileName,
    BOOLEAN RestartScan
) {
    NTSTATUS status = pOriginalNtQueryDirectoryFile(
        FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
        FileInformation, Length, FileInformationClass,
        ReturnSingleEntry, FileName, RestartScan);

    if (status != STATUS_SUCCESS || FileInformation == nullptr ||
        Event != nullptr || ApcRoutine != nullptr) {
        return status;
    }

    char dirPath[MAX_PATH] = {};
    DWORD pathLen = GetFinalPathNameByHandleA(FileHandle, dirPath, MAX_PATH, FILE_NAME_NORMALIZED);
    std::string directoryPath;
    if (pathLen > 0 && pathLen < MAX_PATH) {
        directoryPath = dirPath;
        if (directoryPath.find("\\\\?\\") == 0) directoryPath = directoryPath.substr(4);
    }

    FilterDirectoryEntries(FileInformation, FileInformationClass, directoryPath);
    return status;
}

NTSTATUS WINAPI HookedNtQueryDirectoryFileEx(
    HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length,
    int FileInformationClass, ULONG QueryFlags, PUNICODE_STRING_NT FileName
) {
    NTSTATUS status = pOriginalNtQueryDirectoryFileEx(
        FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
        FileInformation, Length, FileInformationClass, QueryFlags, FileName);

    if (status != STATUS_SUCCESS || FileInformation == nullptr ||
        Event != nullptr || ApcRoutine != nullptr) {
        return status;
    }

    char dirPath[MAX_PATH] = {};
    DWORD pathLen = GetFinalPathNameByHandleA(FileHandle, dirPath, MAX_PATH, FILE_NAME_NORMALIZED);
    std::string directoryPath;
    if (pathLen > 0 && pathLen < MAX_PATH) {
        directoryPath = dirPath;
        if (directoryPath.find("\\\\?\\") == 0) directoryPath = directoryPath.substr(4);
    }

    FilterDirectoryEntries(FileInformation, FileInformationClass, directoryPath);
    return status;
}

// ============================================
// Hook Implementations - IPC (silent, no file I/O)
// ============================================

int WINAPI Hooked_recv(SOCKET s, char* buf, int len, int flags) {
    return pOriginal_recv(s, buf, len, flags);
}

int WINAPI Hooked_send(SOCKET s, const char* buf, int len, int flags) {
    return pOriginal_send(s, buf, len, flags);
}

BOOL WINAPI Hooked_PostMessageA(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
    return pOriginal_PostMessageA(hWnd, Msg, wParam, lParam);
}

BOOL WINAPI Hooked_PostMessageW(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
    return pOriginal_PostMessageW(hWnd, Msg, wParam, lParam);
}

LRESULT WINAPI Hooked_SendMessageW(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
    return pOriginal_SendMessageW(hWnd, Msg, wParam, lParam);
}

// ============================================
// Hook Implementations - Process/Thread/Remote
// ============================================

HANDLE WINAPI HookedOpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) {
    return pOriginalOpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
}

BOOL WINAPI HookedGetThreadContext(HANDLE hThread, LPCONTEXT lpContext) {
    BOOL result = pOriginalGetThreadContext(hThread, lpContext);
    // Clean debug registers to hide hardware breakpoints
    if (result && lpContext && (lpContext->ContextFlags & CONTEXT_DEBUG_REGISTERS)) {
        lpContext->Dr0 = 0;
        lpContext->Dr1 = 0;
        lpContext->Dr2 = 0;
        lpContext->Dr3 = 0;
        lpContext->Dr6 = 0;
        lpContext->Dr7 = 0;
    }
    return result;
}

BOOL WINAPI HookedSetThreadContext(HANDLE hThread, const CONTEXT* lpContext) {
    return pOriginalSetThreadContext(hThread, lpContext);
}

DWORD WINAPI HookedSuspendThread(HANDLE hThread) {
    return pOriginalSuspendThread(hThread);
}

DWORD WINAPI HookedResumeThread(HANDLE hThread) {
    return pOriginalResumeThread(hThread);
}

HANDLE WINAPI HookedCreateRemoteThread(
    HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags,
    LPDWORD lpThreadId
) {
    return pOriginalCreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize,
        lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
}

LPVOID WINAPI HookedVirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize,
    DWORD flAllocationType, DWORD flProtect) {
    return pOriginalVirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
}

BOOL WINAPI HookedVirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize,
    DWORD flNewProtect, PDWORD lpflOldProtect) {
    return pOriginalVirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

// ============================================
// Helper: Save bytes + Create hook
// ============================================

static MH_STATUS CreateHookWithSave(LPVOID pTarget, LPVOID pDetour, LPVOID* ppOriginal) {
    SaveOriginalBytes(pTarget);
    return MH_CreateHook(pTarget, pDetour, ppOriginal);
}

// ============================================
// Hook Initialization
// ============================================

BOOL InitializeHooks() {
    LogMessage("[HOOKS] Initializing MinHook...");

    if (MH_Initialize() != MH_OK) {
        LogMessage("[HOOKS] ERROR: MH_Initialize failed");
        return FALSE;
    }

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) hNtdll = LoadLibraryA("ntdll.dll");

    // ---- File I/O hooks ----
    if (CreateHookWithSave(&CreateFileA, &HookedCreateFileA, (LPVOID*)&pOriginalCreateFileA) != MH_OK ||
        CreateHookWithSave(&CreateFileW, &HookedCreateFileW, (LPVOID*)&pOriginalCreateFileW) != MH_OK ||
        CreateHookWithSave(&ReadFile, &HookedReadFile, (LPVOID*)&pOriginalReadFile) != MH_OK ||
        CreateHookWithSave(&WriteFile, &HookedWriteFile, (LPVOID*)&pOriginalWriteFile) != MH_OK ||
        CreateHookWithSave(&GetFileAttributesA, &HookedGetFileAttributesA, (LPVOID*)&pOriginalGetFileAttributesA) != MH_OK ||
        CreateHookWithSave(&GetFileAttributesW, &HookedGetFileAttributesW, (LPVOID*)&pOriginalGetFileAttributesW) != MH_OK ||
        CreateHookWithSave(&FindFirstFileA, &HookedFindFirstFileA, (LPVOID*)&pOriginalFindFirstFileA) != MH_OK ||
        CreateHookWithSave(&FindFirstFileW, &HookedFindFirstFileW, (LPVOID*)&pOriginalFindFirstFileW) != MH_OK ||
        CreateHookWithSave(&FindNextFileA, &HookedFindNextFileA, (LPVOID*)&pOriginalFindNextFileA) != MH_OK ||
        CreateHookWithSave(&FindNextFileW, &HookedFindNextFileW, (LPVOID*)&pOriginalFindNextFileW) != MH_OK ||
        CreateHookWithSave(&FindClose, &HookedFindClose, (LPVOID*)&pOriginalFindClose) != MH_OK) {
        LogMessage("[HOOKS] ERROR: File I/O hooks creation failed");
        MH_Uninitialize();
        return FALSE;
    }

    // ---- Process/Module enumeration hooks ----
    if (CreateHookWithSave(&OpenProcess, &HookedOpenProcess, (LPVOID*)&pOriginalOpenProcess) != MH_OK ||
        CreateHookWithSave(&VirtualQueryEx, &HookedVirtualQueryEx, (LPVOID*)&pOriginalVirtualQueryEx) != MH_OK ||
        CreateHookWithSave(&VirtualQuery, &HookedVirtualQuery, (LPVOID*)&pOriginalVirtualQuery) != MH_OK ||
        CreateHookWithSave(&CreateToolhelp32Snapshot, &HookedCreateToolhelp32Snapshot, (LPVOID*)&pOriginalCreateToolhelp32Snapshot) != MH_OK ||
        CreateHookWithSave(&Process32FirstW, &HookedProcess32FirstW, (LPVOID*)&pOriginalProcess32FirstW) != MH_OK ||
        CreateHookWithSave(&Process32NextW, &HookedProcess32NextW, (LPVOID*)&pOriginalProcess32NextW) != MH_OK ||
        CreateHookWithSave(&Module32FirstW, &HookedModule32FirstW, (LPVOID*)&pOriginalModule32FirstW) != MH_OK ||
        CreateHookWithSave(&Module32NextW, &HookedModule32NextW, (LPVOID*)&pOriginalModule32NextW) != MH_OK) {
        LogMessage("[HOOKS] ERROR: Process/Module hooks creation failed");
        MH_Uninitialize();
        return FALSE;
    }

    // ---- Process info hooks ----
    if (CreateHookWithSave(&QueryFullProcessImageNameA, &HookedQueryFullProcessImageNameA, (LPVOID*)&pOriginalQueryFullProcessImageNameA) != MH_OK ||
        CreateHookWithSave(&QueryFullProcessImageNameW, &HookedQueryFullProcessImageNameW, (LPVOID*)&pOriginalQueryFullProcessImageNameW) != MH_OK ||
        CreateHookWithSave(&GetProcessImageFileNameA, &HookedGetProcessImageFileNameA, (LPVOID*)&pOriginalGetProcessImageFileNameA) != MH_OK ||
        CreateHookWithSave(&GetProcessImageFileNameW, &HookedGetProcessImageFileNameW, (LPVOID*)&pOriginalGetProcessImageFileNameW) != MH_OK) {
        LogMessage("[HOOKS] ERROR: Process info hooks creation failed");
        MH_Uninitialize();
        return FALSE;
    }

    // ---- Directory change hooks ----
    if (CreateHookWithSave(&FindFirstChangeNotificationA, &HookedFindFirstChangeNotificationA, (LPVOID*)&pOriginalFindFirstChangeNotificationA) != MH_OK ||
        CreateHookWithSave(&FindFirstChangeNotificationW, &HookedFindFirstChangeNotificationW, (LPVOID*)&pOriginalFindFirstChangeNotificationW) != MH_OK ||
        CreateHookWithSave(&ReadDirectoryChangesW, &HookedReadDirectoryChangesW, (LPVOID*)&pOriginalReadDirectoryChangesW) != MH_OK) {
        LogMessage("[HOOKS] ERROR: Directory change hooks creation failed");
        MH_Uninitialize();
        return FALSE;
    }

    // ---- PSAPI hooks ----
    HMODULE hPsapi = GetModuleHandleA("psapi.dll");
    if (!hPsapi) hPsapi = LoadLibraryA("psapi.dll");

    if (hPsapi) {
        FARPROC p;
        if ((p = GetProcAddress(hPsapi, "EnumProcessModules")) != nullptr)
            CreateHookWithSave(p, &HookedEnumProcessModules, (LPVOID*)&pOriginalEnumProcessModules);
        if ((p = GetProcAddress(hPsapi, "EnumProcessModulesEx")) != nullptr)
            CreateHookWithSave(p, &HookedEnumProcessModulesEx, (LPVOID*)&pOriginalEnumProcessModulesEx);
        if ((p = GetProcAddress(hPsapi, "GetModuleInformation")) != nullptr)
            CreateHookWithSave(p, &HookedGetModuleInformation, (LPVOID*)&pOriginalGetModuleInformation);
        if ((p = GetProcAddress(hPsapi, "GetModuleFileNameExA")) != nullptr)
            CreateHookWithSave(p, &HookedGetModuleFileNameExA, (LPVOID*)&pOriginalGetModuleFileNameExA);
        if ((p = GetProcAddress(hPsapi, "GetModuleFileNameExW")) != nullptr)
            CreateHookWithSave(p, &HookedGetModuleFileNameExW, (LPVOID*)&pOriginalGetModuleFileNameExW);
    }

    // ---- WinTrust hooks ----
    HMODULE hWintrust = GetModuleHandleA("wintrust.dll");
    if (!hWintrust) hWintrust = LoadLibraryA("wintrust.dll");

    if (hWintrust) {
        FARPROC p;
        if ((p = GetProcAddress(hWintrust, "WinVerifyTrust")) != nullptr)
            CreateHookWithSave(p, &HookedWinVerifyTrust, (LPVOID*)&pOriginalWinVerifyTrust);
        if ((p = GetProcAddress(hWintrust, "CryptCATAdminCalcHashFromFileHandle")) != nullptr)
            CreateHookWithSave(p, &HookedCryptCATAdminCalcHashFromFileHandle, (LPVOID*)&pOriginalCryptCATAdminCalcHashFromFileHandle);
    }

    // ---- NTDLL hooks ----
    if (hNtdll) {
        FARPROC p;

        if ((p = GetProcAddress(hNtdll, "NtQuerySystemInformation")) != nullptr)
            CreateHookWithSave(p, &HookedNtQuerySystemInformation, (LPVOID*)&pOriginalNtQuerySystemInformation);

        if ((p = GetProcAddress(hNtdll, "NtQueryInformationProcess")) != nullptr)
            CreateHookWithSave(p, &HookedNtQueryInformationProcess, (LPVOID*)&pOriginalNtQueryInformationProcess);

        if ((p = GetProcAddress(hNtdll, "NtQueryDirectoryFile")) != nullptr)
            CreateHookWithSave(p, &HookedNtQueryDirectoryFile, (LPVOID*)&pOriginalNtQueryDirectoryFile);

        if ((p = GetProcAddress(hNtdll, "NtQueryDirectoryFileEx")) != nullptr)
            CreateHookWithSave(p, &HookedNtQueryDirectoryFileEx, (LPVOID*)&pOriginalNtQueryDirectoryFileEx);

        if ((p = GetProcAddress(hNtdll, "NtReadVirtualMemory")) != nullptr)
            CreateHookWithSave(p, &HookedNtReadVirtualMemory, (LPVOID*)&pOriginalNtReadVirtualMemory);

        if ((p = GetProcAddress(hNtdll, "NtWriteFile")) != nullptr)
            CreateHookWithSave(p, &HookedNtWriteFile, (LPVOID*)&pOriginalNtWriteFile);

        // NEW: NtQueryVirtualMemory - was missing in original!
        if ((p = GetProcAddress(hNtdll, "NtQueryVirtualMemory")) != nullptr)
            CreateHookWithSave(p, &HookedNtQueryVirtualMemory, (LPVOID*)&pOriginalNtQueryVirtualMemory);
    }

    // ---- IPC hooks ----
    HMODULE hWs2_32 = GetModuleHandleA("ws2_32.dll");
    if (!hWs2_32) hWs2_32 = LoadLibraryA("ws2_32.dll");

    HMODULE hUser32 = GetModuleHandleA("user32.dll");
    if (!hUser32) hUser32 = LoadLibraryA("user32.dll");

    if (hWs2_32) {
        FARPROC p;
        if ((p = GetProcAddress(hWs2_32, "recv")) != nullptr)
            CreateHookWithSave(p, &Hooked_recv, (LPVOID*)&pOriginal_recv);
        if ((p = GetProcAddress(hWs2_32, "send")) != nullptr)
            CreateHookWithSave(p, &Hooked_send, (LPVOID*)&pOriginal_send);
    }

    if (hUser32) {
        FARPROC p;
        if ((p = GetProcAddress(hUser32, "PostMessageA")) != nullptr)
            CreateHookWithSave(p, &Hooked_PostMessageA, (LPVOID*)&pOriginal_PostMessageA);
        if ((p = GetProcAddress(hUser32, "PostMessageW")) != nullptr)
            CreateHookWithSave(p, &Hooked_PostMessageW, (LPVOID*)&pOriginal_PostMessageW);
        if ((p = GetProcAddress(hUser32, "SendMessageW")) != nullptr)
            CreateHookWithSave(p, &Hooked_SendMessageW, (LPVOID*)&pOriginal_SendMessageW);
    }

    // ---- Thread/Remote hooks ----
    CreateHookWithSave(&GetThreadContext, &HookedGetThreadContext, (LPVOID*)&pOriginalGetThreadContext);
    CreateHookWithSave(&SetThreadContext, &HookedSetThreadContext, (LPVOID*)&pOriginalSetThreadContext);
    CreateHookWithSave(&SuspendThread, &HookedSuspendThread, (LPVOID*)&pOriginalSuspendThread);
    CreateHookWithSave(&ResumeThread, &HookedResumeThread, (LPVOID*)&pOriginalResumeThread);
    CreateHookWithSave(&CreateRemoteThread, &HookedCreateRemoteThread, (LPVOID*)&pOriginalCreateRemoteThread);
    CreateHookWithSave(&VirtualAllocEx, &HookedVirtualAllocEx, (LPVOID*)&pOriginalVirtualAllocEx);
    CreateHookWithSave(&VirtualProtectEx, &HookedVirtualProtectEx, (LPVOID*)&pOriginalVirtualProtectEx);

    // ---- Enable all hooks ----
    LogMessage("[HOOKS] Enabling all hooks...");
    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
        LogMessage("[HOOKS] ERROR: MH_EnableHook failed");
        MH_Uninitialize();
        return FALSE;
    }

    LogMessage("[HOOKS] All hooks initialized and enabled");
    return TRUE;
}

void CleanupHooks() {
    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();

    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_findFileContexts.clear();
        g_directoryWatchContexts.clear();
    }
    {
        std::lock_guard<std::mutex> lock(g_cacheMutex);
        g_gtaSaProcessCache.clear();
    }
}

// ============================================
// DLL Entry Point
// ============================================

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
    {
        // Disable thread attach/detach notifications (performance + avoid loader lock issues)
        DisableThreadLibraryCalls(hModule);

        // Save our DLL info BEFORE touching PE headers
        g_ourDllModule = hModule;
        g_ourDllBase = (DWORD_PTR)hModule;

        // Read SizeOfImage from PE header before we erase it
        IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)hModule;
        if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE) {
            IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)hModule + dosHeader->e_lfanew);
            if (ntHeaders->Signature == IMAGE_NT_SIGNATURE) {
                g_ourDllSize = ntHeaders->OptionalHeader.SizeOfImage;
            }
        }

        // Erase PE headers from memory
        DWORD oldProtect;
        if (VirtualProtect(hModule, 0x1000, PAGE_READWRITE, &oldProtect)) {
            // Zero MZ signature
            memset(hModule, 0, 2);
            // Zero PE signature
            DWORD e_lfanew = dosHeader->e_lfanew;
            if (e_lfanew > 0 && e_lfanew < 0x1000) {
                memset((BYTE*)hModule + e_lfanew, 0, 4);
            }
            VirtualProtect(hModule, 0x1000, oldProtect, &oldProtect);
        }

        // Load config (silently - no console, no log file)
        g_pConfig = new VowacConfigReader();

        // Initialize all hooks (saves original bytes before patching)
        if (!InitializeHooks()) {
            delete g_pConfig;
            g_pConfig = nullptr;
            return FALSE;
        }

        // Unlink from PEB AFTER hooks are active (so the unlinking itself is protected)
        UnlinkModuleFromPEB(hModule);

        LogMessage("[DLL] Initialization complete - PEB unlinked, hooks active");
        break;
    }

    case DLL_PROCESS_DETACH:
        CleanupHooks();
        if (g_pConfig) {
            delete g_pConfig;
            g_pConfig = nullptr;
        }
        break;
    }

    return TRUE;
}
