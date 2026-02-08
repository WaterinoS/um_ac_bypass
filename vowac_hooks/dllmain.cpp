// vowac_hooks.cpp - File I/O hooks for VOWAC file monitoring
//
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
#include <iostream>
#include <cstdio>
#include <ctime>
#include <tlhelp32.h>
#include <psapi.h>

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

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

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
    PUNICODE_STRING FileName,
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
    PUNICODE_STRING FileName
    );

typedef SIZE_T(WINAPI* VirtualQueryEx_t)(
    HANDLE hProcess,
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

typedef HANDLE(WINAPI* CreateToolhelp32Snapshot_t)(
    DWORD dwFlags,
    DWORD th32ProcessID
    );

typedef BOOL(WINAPI* Process32FirstA_t)(
    HANDLE hSnapshot,
    LPPROCESSENTRY32 lppe
    );

typedef BOOL(WINAPI* Process32NextA_t)(
    HANDLE hSnapshot,
    LPPROCESSENTRY32 lppe
    );

typedef BOOL(WINAPI* Process32FirstW_t)(
    HANDLE hSnapshot,
    LPPROCESSENTRY32W lppe
    );

typedef BOOL(WINAPI* Process32NextW_t)(
    HANDLE hSnapshot,
    LPPROCESSENTRY32W lppe
    );

typedef BOOL(WINAPI* Module32FirstA_t)(
    HANDLE hSnapshot,
    LPMODULEENTRY32 lpme
    );

typedef BOOL(WINAPI* Module32NextA_t)(
    HANDLE hSnapshot,
    LPMODULEENTRY32 lpme
    );

typedef BOOL(WINAPI* Module32FirstW_t)(
    HANDLE hSnapshot,
    LPMODULEENTRY32W lpme
    );

typedef BOOL(WINAPI* Module32NextW_t)(
    HANDLE hSnapshot,
    LPMODULEENTRY32W lpme
    );

typedef BOOL(WINAPI* QueryFullProcessImageNameA_t)(
    HANDLE hProcess,
    DWORD dwFlags,
    LPSTR lpExeName,
    PDWORD lpdwSize
    );

typedef BOOL(WINAPI* QueryFullProcessImageNameW_t)(
    HANDLE hProcess,
    DWORD dwFlags,
    LPWSTR lpExeName,
    PDWORD lpdwSize
    );

typedef BOOL(WINAPI* GetProcessImageFileNameA_t)(
    HANDLE hProcess,
    LPSTR lpImageFileName,
    DWORD nSize
    );

typedef BOOL(WINAPI* GetProcessImageFileNameW_t)(
    HANDLE hProcess,
    LPWSTR lpImageFileName,
    DWORD nSize
    );

typedef HANDLE(WINAPI* FindFirstChangeNotificationA_t)(
    LPCSTR lpPathName,
    BOOL bWatchSubtree,
    DWORD dwNotifyFilter
    );

typedef HANDLE(WINAPI* FindFirstChangeNotificationW_t)(
    LPCWSTR lpPathName,
    BOOL bWatchSubtree,
    DWORD dwNotifyFilter
    );

typedef BOOL(WINAPI* ReadDirectoryChangesW_t)(
    HANDLE hDirectory,
    LPVOID lpBuffer,
    DWORD nBufferLength,
    BOOL bWatchSubtree,
    DWORD dwNotifyFilter,
    LPDWORD lpBytesReturned,
    LPOVERLAPPED lpOverlapped,
    LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
    );

typedef BOOL(WINAPI* GetThreadContext_t)(
    HANDLE hThread,
    LPCONTEXT lpContext
    );

typedef BOOL(WINAPI* SetThreadContext_t)(
    HANDLE hThread,
    const CONTEXT* lpContext
    );

typedef DWORD(WINAPI* SuspendThread_t)(HANDLE hThread);
typedef DWORD(WINAPI* ResumeThread_t)(HANDLE hThread);

typedef HANDLE(WINAPI* CreateRemoteThread_t)(
    HANDLE hProcess,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPDWORD lpThreadId
    );

typedef LPVOID(WINAPI* VirtualAllocEx_t)(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flAllocationType,
    DWORD flProtect
    );

typedef BOOL(WINAPI* VirtualProtectEx_t)(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flNewProtect,
    PDWORD lpflOldProtect
    );


// ============================================
// Global Log File Handle
// ============================================

FILE* g_logFile = nullptr;
std::mutex g_logMutex;

void InitializeLogger() {
    g_logFile = fopen("vowac_hooks.log", "w");
    if (g_logFile) {
        fprintf(g_logFile, "========================================\n");
        fprintf(g_logFile, "VOWAC Hooks Logger Initialized\n");
        fprintf(g_logFile, "========================================\n\n");
        fflush(g_logFile);
    }
}

void LogMessage(const char* format, ...) {
    std::lock_guard<std::mutex> lock(g_logMutex);

    if (!g_logFile) return;

    // Get current time
    time_t now = time(nullptr);
    struct tm timeinfo;
    localtime_s(&timeinfo, &now);

    fprintf(g_logFile, "[%02d:%02d:%02d] ",
        timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);

    va_list args;
    va_start(args, format);
    vfprintf(g_logFile, format, args);
    va_end(args);

    fprintf(g_logFile, "\n");
    fflush(g_logFile);
}

void CloseLogger() {
    std::lock_guard<std::mutex> lock(g_logMutex);

    if (g_logFile) {
        fprintf(g_logFile, "\nLogger closed\n");
        fclose(g_logFile);
        g_logFile = nullptr;
    }
}

// ============================================
// Debug Console Setup
// ============================================

void SetupDebugConsole() {
    // Allocate console for this process
    if (AllocConsole()) {
        // Redirect stdout to console
        FILE* fp = nullptr;
        freopen_s(&fp, "CONOUT$", "w", stdout);
        freopen_s(&fp, "CONOUT$", "w", stderr);
        freopen_s(&fp, "CONIN$", "r", stdin);

        // Set console window title
        SetConsoleTitleA("VOWAC Hooks - Debug Console");

        // Enable UTF-8 output
        SetConsoleCP(65001);
        SetConsoleOutputCP(65001);

        std::cout << "====================================================\n";
        std::cout << "   VOWAC DLL Hooks - Injected Successfully!\n";
        std::cout << "====================================================\n\n";
    }

    InitializeLogger();
    LogMessage("[INIT] Debug console and logger initialized");
}

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
        if (std::string::npos == first) {
            return str;
        }
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

            if (line.empty() || line[0] == ';') {
                continue;
            }

            if (line[0] == '[' && line[line.length() - 1] == ']') {
                currentSection = line.substr(1, line.length() - 2);
                continue;
            }

            size_t equalPos = line.find('=');
            if (equalPos == std::string::npos) {
                continue;
            }

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
                LogMessage("[CONFIG] Added extension: %s", value.c_str());
            }
            else if (currentSection == "Whitelist.Folders") {
                whitelistFolders.insert(ToLower(value));
                LogMessage("[CONFIG] Added folder: %s", value.c_str());
            }
        }

        configFile.close();

        LogMessage("[CONFIG] Configuration loaded - Extensions: %u, Folders: %u",
            whitelistExtensions.size(), whitelistFolders.size());
        return true;
    }

    bool IsInMonitoredDirectory(const std::string& filePath) const {
        std::string lowerPath = ToLower(filePath);
        std::string lowerGtaSADir = ToLower(gtaSADir);

        if (lowerGtaSADir.empty()) return false;
        if (lowerGtaSADir.back() != '\\' && lowerGtaSADir.back() != '/') {
            lowerGtaSADir += '\\';
        }

        if (lowerPath.find(lowerGtaSADir) != 0) {
            return false;
        }

        return true;
    }

private:
    static std::string ExtractFilenameFromPath(const std::string& filePath) {
        size_t lastSlash = filePath.find_last_of("\\/");
        if (lastSlash != std::string::npos) {
            return filePath.substr(lastSlash + 1);
        }
        return filePath;
    }

 public:
     bool IsExtensionBlacklisted(const std::string& filename) const {
         size_t dotPos = filename.find_last_of('.');
         if (dotPos == std::string::npos) {
             return false;  // No extension = not blacklisted
         }

         std::string ext = ToLower(filename.substr(dotPos));
         // Returns TRUE if extension IS in the blacklist (should be hidden)
         return whitelistExtensions.find(ext) != whitelistExtensions.end();
     }

     bool IsFolderBlacklisted(const std::string& folderPath) const {
         std::string lowerPath = ToLower(folderPath);

         // Check if any blacklisted folder is in the path
         for (const auto& folder : whitelistFolders) {
             if (lowerPath.find(folder) != std::string::npos) {
                 return true;  // Found blacklisted folder
             }
         }

         return false;
     }

     bool IsFileForHide(const std::string& filePath) const {
         if (!IsInMonitoredDirectory(filePath)) {
             return false;
         }

         std::string lowerPath = ToLower(filePath);

         if (lowerPath.find("vowac.asi") != std::string::npos) {
             return false;
         }

         size_t lastSlash = filePath.find_last_of("\\/");
         std::string filename = (lastSlash != std::string::npos)
             ? ToLower(filePath.substr(lastSlash + 1))
             : lowerPath;

         // Hide if extension OR folder is blacklisted
         return IsExtensionBlacklisted(filename) || IsFolderBlacklisted(lowerPath);
     }

    std::string GetBlockReason(const std::string& filePath) const {
        if (!IsInMonitoredDirectory(filePath)) {
            return "NOT_IN_MONITORED_DIR";
        }

        if (IsExtensionBlacklisted(filePath)) {
            return "EXT_BLACKLISTED";
        }

        if (IsFolderBlacklisted(filePath)) {
            return "FOLDER_BLACKLISTED";
        }

        size_t dotPos = filePath.find_last_of('.');
        std::string ext = (dotPos != std::string::npos) ? filePath.substr(dotPos) : "NO_EXT";

        return "BLOCKED_EXT:" + ext;
    }

    const std::string& GetVowacDir() const { return vowacDir; }
    const std::string& GetGTASADir() const { return gtaSADir; }
};

// ============================================
// Context Structure for FindFile Hooks
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
std::unordered_map<DWORD, bool> g_gtaSaProcessCache;  // Cache of known gta_sa.exe PIDs
std::mutex g_cacheMutex;

// Clean memory snapshot for integrity checks
std::vector<BYTE> g_cleanGtaSaImage;
DWORD_PTR g_gtaSaBaseAddress = 0;
std::unordered_map<DWORD, DWORD_PTR> g_processBaseAddresses; // PID -> base address
std::mutex g_cleanImageMutex;

// Forward declaration
typedef BOOL(WINAPI* QueryFullProcessImageNameW_t)(HANDLE, DWORD, LPWSTR, PDWORD);
extern QueryFullProcessImageNameW_t pOriginalQueryFullProcessImageNameW;
bool LoadCleanGtaSaImage(const std::wstring& gtaSaPath);

// Helper to check if process handle points to gta_sa.exe
bool IsGtaSaProcess(HANDLE hProcess) {
    if (hProcess == nullptr || hProcess == INVALID_HANDLE_VALUE) return false;
    if (hProcess == GetCurrentProcess() || hProcess == (HANDLE)-1) return false;

    DWORD pid = GetProcessId(hProcess);
    if (pid == 0) return false;

    // Check cache first (thread-safe)
    {
        std::lock_guard<std::mutex> lock(g_cacheMutex);
        auto it = g_gtaSaProcessCache.find(pid);
        if (it != g_gtaSaProcessCache.end()) {
            return it->second;
        }
    }

    // Query process name - use original function to avoid recursion
    wchar_t processName[MAX_PATH] = {};
    DWORD size = MAX_PATH;
    BOOL result = FALSE;

    if (pOriginalQueryFullProcessImageNameW) {
        result = pOriginalQueryFullProcessImageNameW(hProcess, 0, processName, &size);
    } else {
        result = QueryFullProcessImageNameW(hProcess, 0, processName, &size);
    }

    if (result) {
        _wcslwr_s(processName, MAX_PATH);

        bool isGtaSa = wcsstr(processName, L"gta_sa.exe") != nullptr;

        // Update cache (thread-safe)
        {
            std::lock_guard<std::mutex> lock(g_cacheMutex);
            g_gtaSaProcessCache[pid] = isGtaSa;
        }

        if (isGtaSa) {
            LogMessage("[HOOK] Detected GTA SA process: PID=%u, Path=%ws", pid, processName);
            
            // Load clean image for integrity checks (only once)
            LoadCleanGtaSaImage(processName);
            
            // Get base address - the main executable is always the first module
            HMODULE hMods[1024];
            DWORD cbNeeded;
            if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded) && cbNeeded > 0) {
                DWORD_PTR baseAddr = (DWORD_PTR)hMods[0]; // First module is always main executable
                std::lock_guard<std::mutex> lock(g_cleanImageMutex);
                g_processBaseAddresses[pid] = baseAddr;
                LogMessage("[INTEGRITY] Process base address for PID %u: 0x%p (path: %ws)", pid, baseAddr, processName);
            } else {
                LogMessage("[INTEGRITY] Failed to get base address for PID %u", pid);
            }
        }

        return isGtaSa;
    }

    return false;
}

bool IsAddressInKnownModule(LPVOID address, HANDLE hProcess) {
    if (!address) {
        LogMessage("[MODULE-CHECK] Address is NULL!");
        return false;
    }

    DWORD_PTR addr = (DWORD_PTR)address;

    HMODULE hMods[1024];
    DWORD cbNeeded;

    if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        LogMessage("[MODULE-CHECK] EnumProcessModules failed!");
        return false;
    }

    DWORD moduleCount = cbNeeded / sizeof(HMODULE);

    for (DWORD i = 0; i < moduleCount; i++) {
        MODULEINFO modInfo = {};
        if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo))) {
            DWORD_PTR moduleStart = (DWORD_PTR)modInfo.lpBaseOfDll;
            DWORD_PTR moduleEnd = moduleStart + modInfo.SizeOfImage;

            if (addr >= moduleStart && addr < moduleEnd) {
                char moduleName[MAX_PATH] = {};
                if (GetModuleFileNameExA(hProcess, hMods[i], moduleName, MAX_PATH)) {
                    for (char* p = moduleName; *p; p++) *p = tolower(*p);

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

// Original function pointers
typedef HANDLE(WINAPI* CreateFileA_t)(
    LPCSTR                 lpFileName,
    DWORD                  dwDesiredAccess,
    DWORD                  dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                  dwCreationDisposition,
    DWORD                  dwFlagsAndAttributes,
    HANDLE                 hTemplateFile
    );

typedef HANDLE(WINAPI* CreateFileW_t)(
    LPCWSTR                lpFileName,
    DWORD                  dwDesiredAccess,
    DWORD                  dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                  dwCreationDisposition,
    DWORD                  dwFlagsAndAttributes,
    HANDLE                 hTemplateFile
    );

typedef BOOL(WINAPI* ReadFile_t)(
    HANDLE       hFile,
    LPVOID       lpBuffer,
    DWORD        nNumberOfBytesToRead,
    LPDWORD      lpNumberOfBytesRead,
    LPOVERLAPPED lpOverlapped
    );

typedef BOOL(WINAPI* WriteFile_t)(
    HANDLE       hFile,
    LPCVOID      lpBuffer,
    DWORD        nNumberOfBytesToWrite,
    LPDWORD      lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped
    );

typedef DWORD(WINAPI* GetFileAttributesA_t)(LPCSTR lpFileName);
typedef DWORD(WINAPI* GetFileAttributesW_t)(LPCWSTR lpFileName);

typedef HANDLE(WINAPI* FindFirstFileA_t)(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData);
typedef HANDLE(WINAPI* FindFirstFileW_t)(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData);

typedef BOOL(WINAPI* FindNextFileA_t)(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData);
typedef BOOL(WINAPI* FindNextFileW_t)(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData);

typedef BOOL(WINAPI* FindClose_t)(HANDLE hFindFile);

// Original function addresses
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

typedef HANDLE(WINAPI* OpenProcess_t)(DWORD, BOOL, DWORD);
OpenProcess_t pOriginalOpenProcess = nullptr;
VirtualQueryEx_t pOriginalVirtualQueryEx = nullptr;
NtWriteFile_t pOriginalNtWriteFile = nullptr;

// WebView2/IPC communication hooks
typedef int (WINAPI* recv_t)(SOCKET s, char* buf, int len, int flags);
typedef int (WINAPI* WSARecv_t)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
typedef BOOL (WINAPI* PostMessageA_t)(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
typedef BOOL (WINAPI* PostMessageW_t)(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
typedef LRESULT (WINAPI* SendMessageW_t)(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
typedef int (WINAPI* send_t)(SOCKET s, const char* buf, int len, int flags);
typedef int (WINAPI* WSASend_t)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);


recv_t pOriginal_recv = nullptr;
WSARecv_t pOriginal_WSARecv = nullptr;
PostMessageA_t pOriginal_PostMessageA = nullptr;
PostMessageW_t pOriginal_PostMessageW = nullptr;
SendMessageW_t pOriginal_SendMessageW = nullptr;
send_t pOriginal_send = nullptr;
WSASend_t pOriginal_WSASend = nullptr;

NtReadVirtualMemory_t pOriginalNtReadVirtualMemory = nullptr;
NtQueryVirtualMemory_t pOriginalNtQueryVirtualMemory = nullptr;
NtQueryInformationProcess_t pOriginalNtQueryInformationProcess = nullptr;
NtQuerySystemInformation_t pOriginalNtQuerySystemInformation = nullptr;
NtQueryDirectoryFile_t pOriginalNtQueryDirectoryFile = nullptr;
NtQueryDirectoryFileEx_t pOriginalNtQueryDirectoryFileEx = nullptr;
CreateToolhelp32Snapshot_t pOriginalCreateToolhelp32Snapshot = nullptr;
Process32FirstA_t pOriginalProcess32FirstA = nullptr;
Process32NextA_t pOriginalProcess32NextA = nullptr;
Process32FirstW_t pOriginalProcess32FirstW = nullptr;
Process32NextW_t pOriginalProcess32NextW = nullptr;
Module32FirstA_t pOriginalModule32FirstA = nullptr;
Module32NextA_t pOriginalModule32NextA = nullptr;
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

// ============================================
// Helper Functions
// ============================================

std::string ExtractDirectoryFromSearchPath(const std::string& searchPath) {
    size_t lastSlash = searchPath.find_last_of("\\/");
    if (lastSlash == std::string::npos) {
        return "";
    }
    return searchPath.substr(0, lastSlash);
}

std::string ToLower(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

// ============================================
// Hook Implementations
// ============================================

HANDLE WINAPI HookedCreateFileA(
    LPCSTR                 lpFileName,
    DWORD                  dwDesiredAccess,
    DWORD                  dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                  dwCreationDisposition,
    DWORD                  dwFlagsAndAttributes,
    HANDLE                 hTemplateFile
) {
    std::lock_guard<std::mutex> lock(g_mutex);

    if (g_pConfig && lpFileName) {
        std::string filename(lpFileName);

        if (g_pConfig->IsFileForHide(filename)) {
            std::string reason = g_pConfig->GetBlockReason(filename);
            LogMessage("[HOOK] BLOCKED CreateFileA: %s (Reason: %s, Access=0x%X, Disposition=0x%X)",
                filename.c_str(), reason.c_str(), dwDesiredAccess, dwCreationDisposition);
            SetLastError(ERROR_ACCESS_DENIED);
            return INVALID_HANDLE_VALUE;
        }

        //LogMessage("[HOOK] ALLOWED CreateFileA: %s", filename.c_str());
    }

    return pOriginalCreateFileA(
        lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
        dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile
    );
}

HANDLE WINAPI HookedCreateFileW(
    LPCWSTR                lpFileName,
    DWORD                  dwDesiredAccess,
    DWORD                  dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                  dwCreationDisposition,
    DWORD                  dwFlagsAndAttributes,
    HANDLE                 hTemplateFile
) {
    std::lock_guard<std::mutex> lock(g_mutex);

    if (g_pConfig && lpFileName) {
        char filename[MAX_PATH] = {};
        WideCharToMultiByte(CP_ACP, 0, lpFileName, -1, filename, MAX_PATH, nullptr, nullptr);

        if (g_pConfig->IsFileForHide(filename)) {
            std::string reason = g_pConfig->GetBlockReason(filename);
            LogMessage("[HOOK] BLOCKED CreateFileW: %s (Reason: %s, Access=0x%X, Disposition=0x%X)",
                filename, reason.c_str(), dwDesiredAccess, dwCreationDisposition);
            SetLastError(ERROR_ACCESS_DENIED);
            return INVALID_HANDLE_VALUE;
        }

        //LogMessage("[HOOK] ALLOWED CreateFileW: %s", filename);
    }

    return pOriginalCreateFileW(
        lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
        dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile
    );
}

DWORD WINAPI HookedGetFileAttributesA(LPCSTR lpFileName) {
    std::lock_guard<std::mutex> lock(g_mutex);

    if (g_pConfig && lpFileName) {
        if (g_pConfig->IsFileForHide(lpFileName)) {
            std::string reason = g_pConfig->GetBlockReason(lpFileName);
            LogMessage("[HOOK] BLOCKED GetFileAttributesA: %s (Reason: %s)", lpFileName, reason.c_str());
            return INVALID_FILE_ATTRIBUTES;
        }

        //LogMessage("[HOOK] ALLOWED GetFileAttributesA: %s", lpFileName);
    }

    return pOriginalGetFileAttributesA(lpFileName);
}

DWORD WINAPI HookedGetFileAttributesW(LPCWSTR lpFileName) {
    std::lock_guard<std::mutex> lock(g_mutex);

    if (g_pConfig && lpFileName) {
        char filename[MAX_PATH] = {};
        WideCharToMultiByte(CP_ACP, 0, lpFileName, -1, filename, MAX_PATH, nullptr, nullptr);

        if (g_pConfig->IsFileForHide(filename)) {
            std::string reason = g_pConfig->GetBlockReason(filename);
            LogMessage("[HOOK] BLOCKED GetFileAttributesW: %s (Reason: %s)", filename, reason.c_str());
            return INVALID_FILE_ATTRIBUTES;
        }

        //LogMessage("[HOOK] ALLOWED GetFileAttributesW: %s", filename);
    }

    return pOriginalGetFileAttributesW(lpFileName);
}

// FindFirstFileA hook
HANDLE WINAPI HookedFindFirstFileA(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData) {
    if (!g_pConfig || !lpFileName) {
        return pOriginalFindFirstFileA(lpFileName, lpFindFileData);
    }

    std::lock_guard<std::mutex> lock(g_mutex);

    std::string searchPath(lpFileName);
    std::string directory = ExtractDirectoryFromSearchPath(searchPath);
    bool isMonitored = g_pConfig->IsInMonitoredDirectory(directory);

    //LogMessage("[HOOK] FindFirstFileA: %s (Monitored: %s)", searchPath.c_str(), isMonitored ? "YES" : "NO");

    // Call original function
    HANDLE hFind = pOriginalFindFirstFileA(lpFileName, lpFindFileData);

    if (hFind != INVALID_HANDLE_VALUE) {
        // Store context
        FindFileContext context;
        context.searchPath = searchPath;
        context.isMonitored = isMonitored;
        g_findFileContexts[hFind] = context;

        // Filter files if in monitored directory
        if (isMonitored) {
            std::string fullPath = directory + "\\" + lpFindFileData->cFileName;

            while (hFind != INVALID_HANDLE_VALUE) {
                if (!g_pConfig->IsFileForHide(fullPath)) {
                    //LogMessage("[HOOK] FindFirstFileA - ALLOWED: %s", lpFindFileData->cFileName);
                    return hFind;
                }

                LogMessage("[HOOK] FindFirstFileA - FILTERED: %s", lpFindFileData->cFileName);

                // Try next file
                if (!pOriginalFindNextFileA(hFind, lpFindFileData)) {
                    FindClose(hFind);
                    LogMessage("[HOOK] FindFirstFileA - NO MORE FILES");
                    return INVALID_HANDLE_VALUE;
                }

                fullPath = directory + "\\" + lpFindFileData->cFileName;
            }
        }
    }

    return hFind;
}

// FindFirstFileW hook
HANDLE WINAPI HookedFindFirstFileW(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData) {
    if (!g_pConfig || !lpFileName) {
        return pOriginalFindFirstFileW(lpFileName, lpFindFileData);
    }

    std::lock_guard<std::mutex> lock(g_mutex);

    char searchPathA[MAX_PATH] = {};
    WideCharToMultiByte(CP_ACP, 0, lpFileName, -1, searchPathA, MAX_PATH, nullptr, nullptr);
    std::string searchPath(searchPathA);
    std::string directory = ExtractDirectoryFromSearchPath(searchPath);
    bool isMonitored = g_pConfig->IsInMonitoredDirectory(directory);

    LogMessage("[HOOK] FindFirstFileW: %s (Monitored: %s)", searchPath.c_str(), isMonitored ? "YES" : "NO");

    // Call original function
    HANDLE hFind = pOriginalFindFirstFileW(lpFileName, lpFindFileData);

    if (hFind != INVALID_HANDLE_VALUE) {
        // Store context
        FindFileContext context;
        context.searchPath = searchPath;
        context.isMonitored = isMonitored;
        g_findFileContexts[hFind] = context;

        // Filter files if in monitored directory
        if (isMonitored) {
            char filenameA[MAX_PATH] = {};
            WideCharToMultiByte(CP_ACP, 0, lpFindFileData->cFileName, -1, filenameA, MAX_PATH, nullptr, nullptr);
            std::string fullPath = directory + "\\" + filenameA;

            while (hFind != INVALID_HANDLE_VALUE) {
                if (!g_pConfig->IsFileForHide(fullPath)) {
                    //LogMessage("[HOOK] FindFirstFileW - ALLOWED: %s", filenameA);
                    return hFind;
                }

                LogMessage("[HOOK] FindFirstFileW - FILTERED: %s", filenameA);

                // Try next file
                if (!pOriginalFindNextFileW(hFind, lpFindFileData)) {
                    FindClose(hFind);
                    LogMessage("[HOOK] FindFirstFileW - NO MORE FILES");
                    return INVALID_HANDLE_VALUE;
                }

                WideCharToMultiByte(CP_ACP, 0, lpFindFileData->cFileName, -1, filenameA, MAX_PATH, nullptr, nullptr);
                fullPath = directory + "\\" + filenameA;
            }
        }
    }

    return hFind;
}

// FindNextFileA hook
BOOL WINAPI HookedFindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData) {
    if (!g_pConfig) {
        return pOriginalFindNextFileA(hFindFile, lpFindFileData);
    }

    std::lock_guard<std::mutex> lock(g_mutex);

    auto it = g_findFileContexts.find(hFindFile);
    bool isMonitored = (it != g_findFileContexts.end()) ? it->second.isMonitored : false;

    if (!isMonitored) {
        return pOriginalFindNextFileA(hFindFile, lpFindFileData);
    }

    // Get directory from stored context
    std::string directory;
    if (it != g_findFileContexts.end()) {
        directory = ExtractDirectoryFromSearchPath(it->second.searchPath);
    }

    // Iterate until we find a whitelisted file
    while (pOriginalFindNextFileA(hFindFile, lpFindFileData)) {
        std::string fullPath = directory + "\\" + lpFindFileData->cFileName;

        if (!g_pConfig->IsFileForHide(fullPath)) {
            //LogMessage("[HOOK] FindNextFileA - ALLOWED: %s", lpFindFileData->cFileName);
            return TRUE;
        }

        LogMessage("[HOOK] FindNextFileA - FILTERED: %s", lpFindFileData->cFileName);
    }

    LogMessage("[HOOK] FindNextFileA - NO MORE FILES");
    return FALSE;
}

// FindNextFileW hook
BOOL WINAPI HookedFindNextFileW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData) {
    if (!g_pConfig) {
        return pOriginalFindNextFileW(hFindFile, lpFindFileData);
    }

    std::lock_guard<std::mutex> lock(g_mutex);

    auto it = g_findFileContexts.find(hFindFile);
    bool isMonitored = (it != g_findFileContexts.end()) ? it->second.isMonitored : false;

    if (!isMonitored) {
        return pOriginalFindNextFileW(hFindFile, lpFindFileData);
    }

    // Get directory from stored context
    std::string directory;
    if (it != g_findFileContexts.end()) {
        directory = ExtractDirectoryFromSearchPath(it->second.searchPath);
    }

    // Iterate until we find a whitelisted file
    while (pOriginalFindNextFileW(hFindFile, lpFindFileData)) {
        char filenameA[MAX_PATH] = {};
        WideCharToMultiByte(CP_ACP, 0, lpFindFileData->cFileName, -1, filenameA, MAX_PATH, nullptr, nullptr);
        std::string fullPath = directory + "\\" + filenameA;

        if (!g_pConfig->IsFileForHide(fullPath)) {
            //LogMessage("[HOOK] FindNextFileW - ALLOWED: %s", filenameA);
            return TRUE;
        }

        LogMessage("[HOOK] FindNextFileW - FILTERED: %s", filenameA);
    }

    LogMessage("[HOOK] FindNextFileW - NO MORE FILES");
    return FALSE;
}

// FindClose hook
BOOL WINAPI HookedFindClose(HANDLE hFindFile) {
    std::lock_guard<std::mutex> lock(g_mutex);

    // Clean up context
    auto it = g_findFileContexts.find(hFindFile);
    if (it != g_findFileContexts.end()) {
        g_findFileContexts.erase(it);
    }

    return pOriginalFindClose(hFindFile);
}

BOOL WINAPI HookedReadFile(
    HANDLE       hFile,
    LPVOID       lpBuffer,
    DWORD        nNumberOfBytesToRead,
    LPDWORD      lpNumberOfBytesRead,
    LPOVERLAPPED lpOverlapped
) {
    //LogMessage("[HOOK] ReadFile called (Handle=0x%p, Bytes=%u)", hFile, nNumberOfBytesToRead);

    BOOL result = pOriginalReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);

    return result;
}

// ============================================
// NtWriteFile Hook (Low-level file writing)
// ============================================

NTSTATUS NTAPI HookedNtWriteFile(
    HANDLE FileHandle,
    HANDLE Event,
    PVOID ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
) {
    
    return pOriginalNtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, 
                                IoStatusBlock, Buffer, Length, ByteOffset, Key);
}

BOOL WINAPI HookedWriteFile(
    HANDLE       hFile,
    LPCVOID      lpBuffer,
    DWORD        nNumberOfBytesToWrite,
    LPDWORD      lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped
) {
    BOOL result = pOriginalWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);

    return result;
}

// ============================================
// NTDLL Hook Implementations
// ============================================

struct CachedMemoryData {
    std::vector<BYTE> data;
    DWORD timestamp;
};

std::unordered_map<DWORD_PTR, CachedMemoryData> g_memoryDataCache;
std::mutex g_memoryDataCacheMutex;


bool LoadCleanGtaSaImage(const std::wstring& gtaSaPath) {
    std::lock_guard<std::mutex> lock(g_cleanImageMutex);
    
    // Only load once
    if (!g_cleanGtaSaImage.empty()) {
        return true;
    }
    
    HANDLE hFile = CreateFileW(gtaSaPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        LogMessage("[INTEGRITY] Failed to open clean gta_sa.exe: %s", gtaSaPath.c_str());
        return false;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    g_cleanGtaSaImage.resize(fileSize);

    DWORD bytesRead = 0;
    if (!ReadFile(hFile, g_cleanGtaSaImage.data(), fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        LogMessage("[INTEGRITY] Failed to read clean gta_sa.exe");
        CloseHandle(hFile);
        g_cleanGtaSaImage.clear();
        return false;
    }

    CloseHandle(hFile);
    LogMessage("[INTEGRITY] Loaded clean gta_sa.exe (%u bytes)", fileSize);
    return true;
}

bool GetCleanMemoryData(HANDLE processHandle, DWORD_PTR addr, SIZE_T size, PVOID buffer) {
    std::lock_guard<std::mutex> lock(g_cleanImageMutex);
    
    if (g_cleanGtaSaImage.empty()) {
        return false;
    }

    // Get base address for this specific process
    DWORD pid = GetProcessId(processHandle);
    auto it = g_processBaseAddresses.find(pid);
    if (it == g_processBaseAddresses.end()) {
        LogMessage("[INTEGRITY] No base address found for PID %u", pid);
        return false;
    }
    
    DWORD_PTR baseAddr = it->second;

    // Convert runtime address to RVA
    DWORD_PTR rva = addr - baseAddr;
    
    // Read PE headers to convert RVA to file offset
    if (g_cleanGtaSaImage.size() < sizeof(IMAGE_DOS_HEADER)) {
        return false;
    }

    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)g_cleanGtaSaImage.data();
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }

    if (g_cleanGtaSaImage.size() < dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS)) {
        return false;
    }

    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(g_cleanGtaSaImage.data() + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }

    // Find section containing this RVA
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(ntHeaders);
    WORD numSections = ntHeaders->FileHeader.NumberOfSections;

    for (WORD i = 0; i < numSections; i++) {
        DWORD sectionStart = sections[i].VirtualAddress;
        DWORD sectionEnd = sectionStart + sections[i].Misc.VirtualSize;

        if (rva >= sectionStart && rva < sectionEnd) {
            // Convert RVA to file offset
            DWORD fileOffset = (DWORD)(rva - sectionStart) + sections[i].PointerToRawData;
            
            if (fileOffset + size > g_cleanGtaSaImage.size()) {
                LogMessage("[INTEGRITY] File offset out of bounds: 0x%X + %zu", fileOffset, size);
                return false;
            }

            memcpy(buffer, g_cleanGtaSaImage.data() + fileOffset, size);
            return true;
        }
    }

    return false;
}

bool GetCachedMemoryData(DWORD_PTR addr, SIZE_T size, PVOID buffer) 
{
    {
        std::lock_guard<std::mutex> lock(g_memoryDataCacheMutex);

        auto it = g_memoryDataCache.find(addr);
        if (it != g_memoryDataCache.end()) {
            LogMessage("[CACHE] Memory data FOUND at 0x%p (%zu bytes)", addr, size);

            if (it->second.data.size() >= size) {
                memcpy(buffer, it->second.data.data(), size);
                return true;
            }
        }
    }

    return false; // Not in cache
}

void CacheMemoryData(DWORD_PTR addr, SIZE_T size, LPVOID buffer)
{
    {
        std::lock_guard<std::mutex> lock(g_memoryDataCacheMutex);

        CachedMemoryData cached;
        cached.data.resize(size);
        memcpy(cached.data.data(), buffer, size);
        cached.timestamp = GetTickCount();

        g_memoryDataCache[addr] = cached;
        LogMessage("[CACHE] Memory data STORED at 0x%p (%zu bytes)", addr, size);
    }
}


NTSTATUS WINAPI HookedNtReadVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesRead
) 
{
    bool isGtaSa = IsGtaSaProcess(ProcessHandle);

    if (!isGtaSa) {
        return pOriginalNtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);
    }

    DWORD_PTR addr = (DWORD_PTR)BaseAddress;
    
    MEMORY_BASIC_INFORMATION mbi;
    if (pOriginalVirtualQueryEx(ProcessHandle, BaseAddress, &mbi, sizeof(mbi)) > 0) {
        if (mbi.State == MEM_COMMIT && mbi.Protect == PAGE_EXECUTE_READWRITE) {
            if (!IsAddressInKnownModule(BaseAddress, ProcessHandle)) {

                LogMessage("[BLOCK] Blocking read from unknown RWX region at 0x%p", BaseAddress);
				//memcpy_s(Buffer, NumberOfBytesToRead, 0, NumberOfBytesToRead); // NULL response
				//return 0;

                if (NumberOfBytesRead) *NumberOfBytesRead = 0;
                return 0xC0000005; // STATUS_ACCESS_VIOLATION
            }
        }
    }

    // Try to serve clean data if this is a known integrity check
    if (GetCleanMemoryData(ProcessHandle, addr, NumberOfBytesToRead, Buffer)) {
        if (NumberOfBytesRead) *NumberOfBytesRead = NumberOfBytesToRead;
        return 0;
    }

    // Pass through to original
    NTSTATUS status = pOriginalNtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);
    
    if (status == 0 && Buffer && NumberOfBytesRead && *NumberOfBytesRead > 0) {
        SIZE_T bytesRead = *NumberOfBytesRead;
        BYTE* pBuffer = (BYTE*)Buffer;
        
        // Check if buffer starts with E9 (JMP rel32) - MinHook signature
        if (bytesRead >= 5 && pBuffer[0] == 0xE9) {
           /* LogMessage("[HOOK-SPOOF] Detected JMP (E9) at 0x%p - buffer: %02X %02X %02X %02X %02X", 
                BaseAddress, pBuffer[0], pBuffer[1], pBuffer[2], pBuffer[3], pBuffer[4]);
            */
            if (bytesRead >= 5) {
                pBuffer[0] = 0x8B; // MOV EDI, EDI
                pBuffer[1] = 0xFF;
                pBuffer[2] = 0x55; // PUSH EBP
                pBuffer[3] = 0x8B; // MOV EBP, ESP
                pBuffer[4] = 0xEC;
                LogMessage("[HOOK-SPOOF] Replaced JMP with legitimate prologue at 0x%p", BaseAddress);
            }
        }
        // Check for other hook patterns: 0xFF 0x25 (JMP [addr]) - common in x64
        else if (bytesRead >= 6 && pBuffer[0] == 0xFF && pBuffer[1] == 0x25) {
 /*           LogMessage("[HOOK-SPOOF] Detected JMP [mem] (FF 25) at 0x%p - buffer: %02X %02X %02X %02X %02X %02X", 
                BaseAddress, pBuffer[0], pBuffer[1], pBuffer[2], pBuffer[3], pBuffer[4], pBuffer[5]);
 */           
            // Replace with standard prologue
            if (bytesRead >= 5) {
                pBuffer[0] = 0x8B;
                pBuffer[1] = 0xFF;
                pBuffer[2] = 0x55;
                pBuffer[3] = 0x8B;
                pBuffer[4] = 0xEC;
                LogMessage("[HOOK-SPOOF] Replaced JMP [mem] with legitimate prologue at 0x%p", BaseAddress);
            }
        }
    }

    return status;
}

NTSTATUS WINAPI HookedNtQueryVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    int MemoryInformationClass,
    PVOID MemoryInformation,
    SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength
) {
    // Allow all queries - VOWAC needs to verify gta_sa.exe integrity
    // Just pass through, no blocking
    return pOriginalNtQueryVirtualMemory(ProcessHandle, BaseAddress, MemoryInformationClass,
        MemoryInformation, MemoryInformationLength, ReturnLength);
}

NTSTATUS WINAPI HookedNtQueryInformationProcess(
    HANDLE ProcessHandle,
    int ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
) {
    LogMessage("[NTDLL] NtQueryInformationProcess: Process=0x%p, Class=%d",
        ProcessHandle, ProcessInformationClass);
    return pOriginalNtQueryInformationProcess(ProcessHandle, ProcessInformationClass,
        ProcessInformation, ProcessInformationLength, ReturnLength);
}

// ============================================
// Additional NTDLL Hooks
// ============================================

NTSTATUS WINAPI HookedNtQuerySystemInformation(
    int SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
) {
    LogMessage("[NTDLL] NtQuerySystemInformation: Class=%d", SystemInformationClass);
    return pOriginalNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
}

// ============================================
// IPC Communication Hooks (vowac.asi -> VOWAC.exe)
// ============================================

int WINAPI Hooked_recv(SOCKET s, char* buf, int len, int flags) {
    int result = pOriginal_recv(s, buf, len, flags);
    
    if (result > 0 && buf) {
        // Log to file
        FILE* fp = fopen("network_traffic.bin", "ab");
        if (fp) {
            fprintf(fp, "\n[RECV] %d bytes from socket 0x%X:\n", result, s);

            // Hex dump
            for (int i = 0; i < result && i < 1024; i++) {
                if (i % 16 == 0) fprintf(fp, "\n%04X: ", i);
                fprintf(fp, "%02X ", (unsigned char)buf[i]);
            }

            // ASCII dump
            fprintf(fp, "\n\nASCII:\n");
            for (int i = 0; i < result && i < 1024; i++) {
                unsigned char c = buf[i];
                fprintf(fp, "%c", (c >= 32 && c <= 126) ? c : '.');
            }
            fprintf(fp, "\n");
            fflush(fp);
            fclose(fp);
        }

        // Check for detection keywords
        std::string data(buf, result);
        if (data.find("externalHandlesCount") != std::string::npos ||
            data.find("suspiciousScore") != std::string::npos) {

            FILE* detect = fopen("detection_attempts.txt", "a");
            if (detect) {
                fprintf(detect, "[DETECTION ATTEMPT] recv: %.200s\n", buf);
                fclose(detect);
            }
        }
    }
    
    return result;
}

int WINAPI Hooked_WSARecv(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    int result = pOriginal_WSARecv(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine);
    
    if (result == 0 && lpBuffers && dwBufferCount > 0 && lpNumberOfBytesRecvd && *lpNumberOfBytesRecvd > 0) {
        FILE* fp = fopen("network_traffic.bin", "ab");
        if (fp) {
            fprintf(fp, "\n[WSARecv] %u bytes from socket 0x%X (%u buffers):\n",
                *lpNumberOfBytesRecvd, s, dwBufferCount);

            // Dump all buffers
            for (DWORD i = 0; i < dwBufferCount; i++) {
                if (lpBuffers[i].buf && lpBuffers[i].len > 0) {
                    fprintf(fp, "\nBuffer %u (%u bytes):\n", i, lpBuffers[i].len);

                    for (DWORD j = 0; j < lpBuffers[i].len && j < 1024; j++) {
                        if (j % 16 == 0) fprintf(fp, "\n%04X: ", j);
                        fprintf(fp, "%02X ", (unsigned char)lpBuffers[i].buf[j]);
                    }

                    fprintf(fp, "\n\nASCII:\n");
                    for (DWORD j = 0; j < lpBuffers[i].len && j < 1024; j++) {
                        unsigned char c = lpBuffers[i].buf[j];
                        fprintf(fp, "%c", (c >= 32 && c <= 126) ? c : '.');
                    }
                }
            }
            fprintf(fp, "\n");
            fflush(fp);
            fclose(fp);
        }
    }
    
    return result;
}

int WINAPI Hooked_send(SOCKET s, const char* buf, int len, int flags) {
    int result = pOriginal_send(s, buf, len, flags);

    if (result > 0 && buf) {
        FILE* fp = fopen("network_traffic.bin", "ab");
        if (fp) {
            fprintf(fp, "\n[SEND] %d bytes TO socket 0x%X:\n", result, s);

            for (int i = 0; i < result && i < 1024; i++) {
                if (i % 16 == 0) fprintf(fp, "\n%04X: ", i);
                fprintf(fp, "%02X ", (unsigned char)buf[i]);
            }

            fprintf(fp, "\n\nASCII:\n");
            for (int i = 0; i < result && i < 1024; i++) {
                unsigned char c = buf[i];
                fprintf(fp, "%c", (c >= 32 && c <= 126) ? c : '.');
            }
            fprintf(fp, "\n");
            fflush(fp);
            fclose(fp);
        }
    }

    return result;
}

BOOL WINAPI Hooked_PostMessageA(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
    return pOriginal_PostMessageA(hWnd, Msg, wParam, lParam);
}

BOOL WINAPI Hooked_PostMessageW(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {

    return pOriginal_PostMessageW(hWnd, Msg, wParam, lParam);
}

// ============================================
// SendMessageW Hook (Tauri synchronous IPC)
// ============================================

LRESULT WINAPI Hooked_SendMessageW(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
    if (Msg >= WM_USER && Msg < 0xC000) {
        LogMessage("[USER32] SendMessageW: HWND=0x%p, Msg=0x%X (WM_USER+%d), wParam=0x%p, lParam=0x%p", 
            hWnd, Msg, Msg - WM_USER, wParam, lParam);
    }
    return pOriginal_SendMessageW(hWnd, Msg, wParam, lParam);
}

// ============================================
// Process Opening Hook
// ============================================

HANDLE WINAPI HookedOpenProcess(
    DWORD dwDesiredAccess,
    BOOL bInheritHandle,
    DWORD dwProcessId
) {
    // Get process name of target PID
    //HANDLE hProcess = pOriginalOpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwProcessId);
    //if (hProcess) {
    //    wchar_t processName[MAX_PATH] = {};
    //    DWORD size = MAX_PATH;
    //    if (QueryFullProcessImageNameW(hProcess, 0, processName, &size)) {
    //        _wcslwr_s(processName, MAX_PATH);
    //        
    //        // Block opening VOWAC process from GTA SA
    //        if (wcsstr(processName, L"vowac.exe") != nullptr) {
    //            CloseHandle(hProcess);
    //            LogMessage("[KERNEL32] BLOCKED OpenProcess to VOWAC.exe (PID=%u, Access=0x%X)", dwProcessId, dwDesiredAccess);
    //            SetLastError(ERROR_ACCESS_DENIED);
    //            return NULL;
    //        }
    //    }
    //    CloseHandle(hProcess);
    //}
    
    return pOriginalOpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
}

bool IsModuleBlacklisted(const std::string& modulePath);

SIZE_T WINAPI HookedVirtualQueryEx(
    HANDLE hProcess,
    LPCVOID lpAddress,
    PMEMORY_BASIC_INFORMATION lpBuffer,
    SIZE_T dwLength
) {
    bool isGtaSa = IsGtaSaProcess(hProcess);
    
    if (!isGtaSa) {
        return pOriginalVirtualQueryEx(hProcess, lpAddress, lpBuffer, dwLength);
    }

    // Call original first
    SIZE_T result = pOriginalVirtualQueryEx(hProcess, lpAddress, lpBuffer, dwLength);
    
    if (lpBuffer->Type == MEM_IMAGE)
    {
        char devicePath[MAX_PATH] = { 0 };
        if (GetMappedFileNameA(hProcess, (LPVOID)lpBuffer->BaseAddress, devicePath, MAX_PATH))
        {
            _strlwr_s(devicePath, MAX_PATH);

            char* pFilename = strrchr(devicePath, '\\');
            if (!pFilename) {
                pFilename = devicePath;
            }
            else {
                pFilename++;
            }

			//LogMessage("[VQE] MEM_IMAGE at 0x%p mapped to file: %s", lpBuffer->BaseAddress, devicePath);

            if (g_pConfig && IsModuleBlacklisted(devicePath))
            {
                LogMessage("[SPOOF] Hiding suspicious MEM_IMAGE: %s (device: %s)", pFilename, devicePath);

                lpBuffer->State = MEM_FREE;
                lpBuffer->Protect = PAGE_NOACCESS;
                lpBuffer->Type = 0;
                lpBuffer->AllocationProtect = 0;

                return result;
            }
        }
        return result;
    }

    /*LogMessage("[HOOK] VirtualQueryEx called for 0x%p - Result=%zu, Base=0x%p, RegionSize=0x%zX, State=0x%X, Protect=0x%X, Type=0x%X",
        lpAddress, result, lpBuffer ? lpBuffer->BaseAddress : nullptr, lpBuffer ? lpBuffer->RegionSize : 0,
        lpBuffer ? lpBuffer->State : 0, lpBuffer ? lpBuffer->Protect : 0, lpBuffer ? lpBuffer->Type : 0);*/

    if (result > 0 && lpBuffer)
    {
        if (lpBuffer->State == MEM_COMMIT &&
            lpBuffer->Protect == PAGE_EXECUTE_READWRITE &&
            lpBuffer->Type == MEM_PRIVATE) {

            LogMessage("[VQE] Found suspicious MEM_PRIVATE RWX at 0x%p", lpAddress);

            BYTE buffer[16];
            SIZE_T bytesRead = 0;

            NTSTATUS status = pOriginalNtReadVirtualMemory(
                hProcess,
                (PVOID)lpAddress,
                buffer,
                sizeof(buffer),
                &bytesRead
            );

            if (status == 0 && bytesRead >= 4) {
                if (buffer[0] == 'M' && buffer[1] == 'Z') {
                    LogMessage("[VQE] Region contains PE header (MZ) - manual mapped DLL!");

                    // Spoof as MEM_FREE:
                    lpBuffer->State = MEM_FREE;
                    lpBuffer->Protect = PAGE_NOACCESS;
                    lpBuffer->Type = 0;
                    lpBuffer->AllocationProtect = 0;

                    LogMessage("[SPOOF] Hidden manual mapped DLL at 0x%p", lpAddress);
                    return result;
                }

                DWORD_PTR ptr = *(DWORD_PTR*)buffer;

                if (ptr >= 0x00400000 && ptr <= 0x7FFFFFFF) {
                    if (!IsAddressInKnownModule((LPVOID)ptr, hProcess)) {

                        LogMessage("[SPOOF] RWX region at 0x%p points to unknown module (ptr=0x%p) - hiding!",
                            lpAddress, ptr);

                        lpBuffer->State = MEM_FREE;
                        lpBuffer->Protect = PAGE_NOACCESS;
                        lpBuffer->Type = 0;
                        lpBuffer->AllocationProtect = 0;

                        return result;
                    }
                }
            }
        }

        if (lpBuffer->Protect == PAGE_EXECUTE_READWRITE) {
            lpBuffer->Protect = PAGE_EXECUTE_READ;
        }
    }
    
    return result;
}

// ============================================
// Process/Module Enumeration Hooks
// ============================================

HANDLE WINAPI HookedCreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID) {
   // LogMessage("[KERNEL32] CreateToolhelp32Snapshot: Flags=0x%X, PID=%u", dwFlags, th32ProcessID);
    return pOriginalCreateToolhelp32Snapshot(dwFlags, th32ProcessID);
}

BOOL WINAPI HookedProcess32FirstW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe) {
   // LogMessage("[KERNEL32] Process32FirstW: Snapshot=0x%p", hSnapshot);
    return pOriginalProcess32FirstW(hSnapshot, lppe);
}

BOOL WINAPI HookedProcess32NextW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe) {
   // LogMessage("[KERNEL32] Process32NextW: Snapshot=0x%p", hSnapshot);
    return pOriginalProcess32NextW(hSnapshot, lppe);
}

BOOL WINAPI HookedModule32FirstA(HANDLE hSnapshot, LPMODULEENTRY32 lpme) {
    //LogMessage("[KERNEL32] Module32FirstA: Snapshot=0x%p", hSnapshot);
    return pOriginalModule32FirstA(hSnapshot, lpme);
}

BOOL WINAPI HookedModule32NextA(HANDLE hSnapshot, LPMODULEENTRY32 lpme) {
    //LogMessage("[KERNEL32] Module32NextA: Snapshot=0x%p", hSnapshot);
    return pOriginalModule32NextA(hSnapshot, lpme);
}

std::string WideStringToAnsi(const wchar_t* wideStr) {
    if (!wideStr) return "";
    int sizeNeeded = WideCharToMultiByte(CP_ACP, 0, wideStr, -1, nullptr, 0, nullptr, nullptr);
    if (sizeNeeded <= 0) return "";
    std::string ansiStr(sizeNeeded, 0);
    WideCharToMultiByte(CP_ACP, 0, wideStr, -1, &ansiStr[0], sizeNeeded, nullptr, nullptr);
    
    // Remove the null terminator added by WideCharToMultiByte
    if (!ansiStr.empty() && ansiStr.back() == '\0') {
        ansiStr.pop_back();
    }
    return ansiStr;
}

// Helper to check if module should be hidden
bool IsModuleBlacklisted(const std::string& modulePath) {
    if (!g_pConfig) return false;

    std::string lowerPath = ToLower(modulePath);

    // Never hide vowac.asi
    if (lowerPath.find("vowac.asi") != std::string::npos) {
        return false;
    }

    size_t lastSlash = modulePath.find_last_of("\\/");
    std::string filename = (lastSlash != std::string::npos)
        ? lowerPath.substr(lastSlash + 1)
        : lowerPath;

    // Check extension and folder blacklist (no monitored directory check)
    return g_pConfig->IsExtensionBlacklisted(filename) ||
        g_pConfig->IsFolderBlacklisted(lowerPath);
}

// Helper to check if module should be hidden
bool ShouldHideModule(const wchar_t* moduleName) {
    if (!moduleName || !g_pConfig) return false;

    wchar_t lower[MAX_PATH] = {};
    wcsncpy_s(lower, moduleName, MAX_PATH - 1);
    _wcslwr_s(lower, MAX_PATH);

    std::string modulePath = WideStringToAnsi(lower);

    if (modulePath.empty()) {
        return false;
    }

    // Use module-specific blacklist check (without monitored directory requirement)
    bool shouldHide = IsModuleBlacklisted(modulePath);
    return shouldHide;
}

BOOL WINAPI HookedModule32FirstW(HANDLE hSnapshot, LPMODULEENTRY32W lpme) {
    if (!lpme) {
        LogMessage("[KERNEL32] Module32FirstW - ERROR: lpme is NULL");
        return pOriginalModule32FirstW(hSnapshot, lpme);
    }

    BOOL result = pOriginalModule32FirstW(hSnapshot, lpme);

    if (!result) {
        LogMessage("[KERNEL32] Module32FirstW - Original returned FALSE (Error=%u)", GetLastError());
        return result;
    }

    //LogMessage("[KERNEL32] Module32FirstW - Got module: %ws", lpme->szModule);

    // If first module should be hidden, skip to next (with safety limit)
    int skipCount = 0;
    const int maxSkips = 100;

    while (result && lpme && ShouldHideModule(lpme->szModule) && skipCount < maxSkips) {
        LogMessage("[KERNEL32] Module32FirstW - HIDING module: %ws", lpme->szModule);
        result = pOriginalModule32NextW(hSnapshot, lpme);
        skipCount++;
    }

    if (skipCount >= maxSkips) {
        LogMessage("[KERNEL32] Module32FirstW - WARNING: Hit max skip limit!");
    }

    //LogMessage("[KERNEL32] Module32FirstW - Returning %d, module: %ws", result, result && lpme ? lpme->szModule : L"<none>");
    return result;
}

BOOL WINAPI HookedModule32NextW(HANDLE hSnapshot, LPMODULEENTRY32W lpme) {
   // LogMessage("[KERNEL32] Module32NextW - CALLED (Snapshot=0x%p, lpme=0x%p)", hSnapshot, lpme);

    if (!lpme) {
        LogMessage("[KERNEL32] Module32NextW - ERROR: lpme is NULL");
        return pOriginalModule32NextW(hSnapshot, lpme);
    }

    BOOL result = pOriginalModule32NextW(hSnapshot, lpme);

    //LogMessage("[KERNEL32] Module32NextW - Got module: %ws", lpme->szModule);

    // Skip hidden modules (with safety limit)
    int skipCount = 0;
    const int maxSkips = 100;

    while (result && lpme && ShouldHideModule(lpme->szModule) && skipCount < maxSkips) {
        LogMessage("[KERNEL32] Module32NextW - HIDING module: %ws", lpme->szModule);
        result = pOriginalModule32NextW(hSnapshot, lpme);
        skipCount++;

        if (result && lpme) {
            LogMessage("[KERNEL32] Module32NextW - After skip, got module: %ws", lpme->szModule);
        }
    }

    if (skipCount >= maxSkips) {
        LogMessage("[KERNEL32] Module32NextW - WARNING: Hit max skip limit!");
    }

    //LogMessage("[KERNEL32] Module32NextW - Returning %d, module: %ws", result, result && lpme ? lpme->szModule : L"<none>");
    return result;
}

BOOL WINAPI HookedQueryFullProcessImageNameA(HANDLE hProcess, DWORD dwFlags, LPSTR lpExeName, PDWORD lpdwSize) {
    //LogMessage("[KERNEL32] QueryFullProcessImageNameA: Process=0x%p, Flags=0x%X", hProcess, dwFlags);
    return pOriginalQueryFullProcessImageNameA(hProcess, dwFlags, lpExeName, lpdwSize);
}

BOOL WINAPI HookedQueryFullProcessImageNameW(HANDLE hProcess, DWORD dwFlags, LPWSTR lpExeName, PDWORD lpdwSize) {
    //LogMessage("[KERNEL32] QueryFullProcessImageNameW: Process=0x%p, Flags=0x%X", hProcess, dwFlags);
    return pOriginalQueryFullProcessImageNameW(hProcess, dwFlags, lpExeName, lpdwSize);
}

BOOL WINAPI HookedGetProcessImageFileNameA(HANDLE hProcess, LPSTR lpImageFileName, DWORD nSize) {
    //LogMessage("[PSAPI] GetProcessImageFileNameA: Process=0x%p", hProcess);
    return pOriginalGetProcessImageFileNameA(hProcess, lpImageFileName, nSize);
}

BOOL WINAPI HookedGetProcessImageFileNameW(HANDLE hProcess, LPWSTR lpImageFileName, DWORD nSize) {
   // LogMessage("[PSAPI] GetProcessImageFileNameW: Process=0x%p", hProcess);
    return pOriginalGetProcessImageFileNameW(hProcess, lpImageFileName, nSize);
}

// ============================================
// Directory Change Notification Hooks
// ============================================

HANDLE WINAPI HookedFindFirstChangeNotificationA(LPCSTR lpPathName, BOOL bWatchSubtree, DWORD dwNotifyFilter) {
    // Pass through without blocking to avoid crashes
    return pOriginalFindFirstChangeNotificationA(lpPathName, bWatchSubtree, dwNotifyFilter);
}

HANDLE WINAPI HookedFindFirstChangeNotificationW(LPCWSTR lpPathName, BOOL bWatchSubtree, DWORD dwNotifyFilter) {
    // Pass through without blocking to avoid crashes
    return pOriginalFindFirstChangeNotificationW(lpPathName, bWatchSubtree, dwNotifyFilter);
}

BOOL WINAPI HookedReadDirectoryChangesW(
    HANDLE hDirectory,
    LPVOID lpBuffer,
    DWORD nBufferLength,
    BOOL bWatchSubtree,
    DWORD dwNotifyFilter,
    LPDWORD lpBytesReturned,
    LPOVERLAPPED lpOverlapped,
    LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
) {
    // Pass through without filtering to avoid crashes
    // File hiding via FindFirstFile/NtQueryDirectoryFile should be sufficient
    return pOriginalReadDirectoryChangesW(
        hDirectory, lpBuffer, nBufferLength, bWatchSubtree,
        dwNotifyFilter, lpBytesReturned, lpOverlapped, lpCompletionRoutine
    );
}

// ============================================
// NtQueryDirectoryFile Hooks
// ============================================

// Directory information structures - all have same layout for first 3 fields
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

// Generic structure - works for all types since they have same first 2 fields
typedef struct _FILE_DIR_ENTRY_GENERIC {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    ULONG Data[100]; // Rest of data, we don't care about layout
} FILE_DIR_ENTRY_GENERIC, * PFILE_DIR_ENTRY_GENERIC;

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define STATUS_NO_MORE_FILES ((NTSTATUS)0x80000006L)

// FileInformationClass values
#define FileDirectoryInformation 1
#define FileFullDirectoryInformation 2
#define FileBothDirectoryInformation 3
#define FileNamesInformation 12
#define FileIdBothDirectoryInformation 37
#define FileIdFullDirectoryInformation 38
#define FileIdExtdDirectoryInformation 60

NTSTATUS WINAPI HookedNtQueryDirectoryFile(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    int FileInformationClass,
    BOOLEAN ReturnSingleEntry,
    PUNICODE_STRING FileName,
    BOOLEAN RestartScan
) {
    NTSTATUS status = pOriginalNtQueryDirectoryFile(
        FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
        FileInformation, Length, FileInformationClass,
        ReturnSingleEntry, FileName, RestartScan
    );

    // Only filter synchronous successful results
    if (status != STATUS_SUCCESS || FileInformation == nullptr || Event != nullptr || ApcRoutine != nullptr) {
        return status;
    }

    // Get directory path from handle
    char dirPath[MAX_PATH] = {};
    DWORD pathLen = GetFinalPathNameByHandleA(FileHandle, dirPath, MAX_PATH, FILE_NAME_NORMALIZED);

    std::string directoryPath;
    if (pathLen > 0 && pathLen < MAX_PATH) {
        directoryPath = dirPath;
        if (directoryPath.find("\\\\?\\") == 0) {
            directoryPath = directoryPath.substr(4);
        }
    }

    // All structures have same layout for first fields, we can use generic approach
    if (FileInformationClass == FileDirectoryInformation ||
        FileInformationClass == FileFullDirectoryInformation ||
        FileInformationClass == FileBothDirectoryInformation) {

        PFILE_DIR_ENTRY_GENERIC pCurrent = (PFILE_DIR_ENTRY_GENERIC)FileInformation;
        PFILE_DIR_ENTRY_GENERIC pPrevious = nullptr;
        bool isFirstEntry = true;
        int totalEntries = 0;
        int hiddenEntries = 0;

        while (true) {
            // Extract filename based on structure type
            PWSTR pFileName = nullptr;
            ULONG fileNameLen = 0;

            if (FileInformationClass == FileDirectoryInformation) {
                PFILE_DIRECTORY_INFORMATION pDir = (PFILE_DIRECTORY_INFORMATION)pCurrent;
                pFileName = pDir->FileName;
                fileNameLen = pDir->FileNameLength;
            } else if (FileInformationClass == FileFullDirectoryInformation) {
                PFILE_FULL_DIR_INFORMATION pFull = (PFILE_FULL_DIR_INFORMATION)pCurrent;
                pFileName = pFull->FileName;
                fileNameLen = pFull->FileNameLength;
            } else if (FileInformationClass == FileBothDirectoryInformation) {
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

            // Never hide ".", ".." or first entry (safety)
            bool isDotEntry = (strcmp(filename, ".") == 0 || strcmp(filename, "..") == 0);
            std::string fullPath = directoryPath + "\\" + filename;
            bool shouldHide = !isDotEntry && !isFirstEntry && g_pConfig->IsFileForHide(fullPath);

            if (shouldHide && pPrevious != nullptr) {
                LogMessage("[NTDLL] NtQueryDirectoryFile - HIDING: %s", filename);
                hiddenEntries++;

                // Skip this entry by adjusting previous entry's NextEntryOffset
                if (pCurrent->NextEntryOffset != 0) {
                    pPrevious->NextEntryOffset += pCurrent->NextEntryOffset;
                } else {
                    pPrevious->NextEntryOffset = 0;
                }
            } else {
                if (shouldHide) {
                    LogMessage("[NTDLL] NtQueryDirectoryFile - Would hide %s but it's first entry, keeping", filename);
                }
                pPrevious = pCurrent;
            }

            isFirstEntry = false;

            if (pCurrent->NextEntryOffset == 0) {
                break;
            }

            pCurrent = (PFILE_DIR_ENTRY_GENERIC)((LPBYTE)pCurrent + pCurrent->NextEntryOffset);

            // Safety limit
            if (totalEntries > 10000) {
                LogMessage("[NTDLL] NtQueryDirectoryFile - ERROR: Too many entries!");
                break;
            }
        }

        LogMessage("[NTDLL] NtQueryDirectoryFile - Processed %d entries, hidden %d", totalEntries, hiddenEntries);
    }

    return status;
}

NTSTATUS WINAPI HookedNtQueryDirectoryFileEx(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    int FileInformationClass,
    ULONG QueryFlags,
    PUNICODE_STRING FileName
) {
    NTSTATUS status = pOriginalNtQueryDirectoryFileEx(
        FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
        FileInformation, Length, FileInformationClass, QueryFlags, FileName
    );

    // Only filter synchronous successful results
    if (status != STATUS_SUCCESS || FileInformation == nullptr || Event != nullptr || ApcRoutine != nullptr) {
        /*LogMessage("[NTDLL] NtQueryDirectoryFileEx - Skipping filter (status=0x%X, async=%d)",
            status, (Event != nullptr || ApcRoutine != nullptr) ? 1 : 0);*/
        return status;
    }

    // Get directory path from handle
    char dirPath[MAX_PATH] = {};
    DWORD pathLen = GetFinalPathNameByHandleA(FileHandle, dirPath, MAX_PATH, FILE_NAME_NORMALIZED);

    std::string directoryPath;
    if (pathLen > 0 && pathLen < MAX_PATH) {
        directoryPath = dirPath;
        if (directoryPath.find("\\\\?\\") == 0) {
            directoryPath = directoryPath.substr(4);
        }
    }

    //LogMessage("[NTDLL] NtQueryDirectoryFileEx - Directory: %s, Class=%d", directoryPath.c_str(), FileInformationClass);

    // All structures have same layout for first fields, we can use generic approach
    if (FileInformationClass == FileDirectoryInformation ||
        FileInformationClass == FileFullDirectoryInformation ||
        FileInformationClass == FileBothDirectoryInformation) {

        PFILE_DIR_ENTRY_GENERIC pCurrent = (PFILE_DIR_ENTRY_GENERIC)FileInformation;
        PFILE_DIR_ENTRY_GENERIC pPrevious = nullptr;
        bool isFirstEntry = true;
        int totalEntries = 0;
        int hiddenEntries = 0;

        while (true) {
            // Extract filename based on structure type
            PWSTR pFileName = nullptr;
            ULONG fileNameLen = 0;

            if (FileInformationClass == FileDirectoryInformation) {
                PFILE_DIRECTORY_INFORMATION pDir = (PFILE_DIRECTORY_INFORMATION)pCurrent;
                pFileName = pDir->FileName;
                fileNameLen = pDir->FileNameLength;
            } else if (FileInformationClass == FileFullDirectoryInformation) {
                PFILE_FULL_DIR_INFORMATION pFull = (PFILE_FULL_DIR_INFORMATION)pCurrent;
                pFileName = pFull->FileName;
                fileNameLen = pFull->FileNameLength;
            } else if (FileInformationClass == FileBothDirectoryInformation) {
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

            // Never hide ".", ".." or first entry (safety)
            bool isDotEntry = (strcmp(filename, ".") == 0 || strcmp(filename, "..") == 0);
            std::string fullPath = directoryPath + "\\" + filename;
            bool shouldHide = !isDotEntry && !isFirstEntry && g_pConfig->IsFileForHide(fullPath);

            if (shouldHide && pPrevious != nullptr) {
                hiddenEntries++;

                // Skip this entry by adjusting previous entry's NextEntryOffset
                if (pCurrent->NextEntryOffset != 0) {
                    pPrevious->NextEntryOffset += pCurrent->NextEntryOffset;
                } else {
                    pPrevious->NextEntryOffset = 0;
                }
            } else {
                pPrevious = pCurrent;
            }

            isFirstEntry = false;

            if (pCurrent->NextEntryOffset == 0) {
                break;
            }

            pCurrent = (PFILE_DIR_ENTRY_GENERIC)((LPBYTE)pCurrent + pCurrent->NextEntryOffset);

            // Safety limit
            if (totalEntries > 10000) {
                LogMessage("[NTDLL] NtQueryDirectoryFileEx - ERROR: Too many entries!");
                break;
            }
        }

        if (hiddenEntries > 0) {
            LogMessage("[NTDLL] NtQueryDirectoryFileEx - Hidden %d files from %s", hiddenEntries, directoryPath.c_str());
        }
    }

    return status;
}

// ============================================
// Thread Manipulation Hooks
// ============================================

BOOL WINAPI HookedGetThreadContext(HANDLE hThread, LPCONTEXT lpContext) {
    LogMessage("[KERNEL32] GetThreadContext: Thread=0x%p", hThread);
    return pOriginalGetThreadContext(hThread, lpContext);
}

BOOL WINAPI HookedSetThreadContext(HANDLE hThread, const CONTEXT* lpContext) {
    LogMessage("[KERNEL32] SetThreadContext: Thread=0x%p", hThread);
    return pOriginalSetThreadContext(hThread, lpContext);
}

DWORD WINAPI HookedSuspendThread(HANDLE hThread) {
    LogMessage("[KERNEL32] SuspendThread: Thread=0x%p", hThread);
    return pOriginalSuspendThread(hThread);
}

DWORD WINAPI HookedResumeThread(HANDLE hThread) {
    LogMessage("[KERNEL32] ResumeThread: Thread=0x%p", hThread);
    return pOriginalResumeThread(hThread);
}

// ============================================
// Remote Code Execution Hooks
// ============================================

HANDLE WINAPI HookedCreateRemoteThread(
    HANDLE hProcess,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPDWORD lpThreadId
) {
    LogMessage("[KERNEL32] CreateRemoteThread: Process=0x%p, StartAddr=0x%p, Param=0x%p, Flags=0x%X",
        hProcess, lpStartAddress, lpParameter, dwCreationFlags);
    return pOriginalCreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
}

LPVOID WINAPI HookedVirtualAllocEx(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flAllocationType,
    DWORD flProtect
) {
    LogMessage("[KERNEL32] VirtualAllocEx: Process=0x%p, Addr=0x%p, Size=%u, AllocType=0x%X, Protect=0x%X",
        hProcess, lpAddress, dwSize, flAllocationType, flProtect);
    return pOriginalVirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
}

BOOL WINAPI HookedVirtualProtectEx(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flNewProtect,
    PDWORD lpflOldProtect
) {
    LogMessage("[KERNEL32] VirtualProtectEx: Process=0x%p, Addr=0x%p, Size=%u, NewProtect=0x%X",
        hProcess, lpAddress, dwSize, flNewProtect);
    return pOriginalVirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

// ============================================
// Initialization and Cleanup
// ============================================

BOOL InitializeHooks() {
    LogMessage("[HOOKS] Initializing MinHook...");

    if (MH_Initialize() != MH_OK) {
        LogMessage("[HOOKS] ERROR: MH_Initialize failed");
        return FALSE;
    }

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");

    if (!hNtdll) {
        hNtdll = LoadLibraryA("ntdll.dll");
    }

    // Kernel32 File I/O hooks
    LogMessage("[HOOKS] Creating File I/O hooks...");
    if (MH_CreateHook(&CreateFileA, &HookedCreateFileA, (LPVOID*)&pOriginalCreateFileA) != MH_OK ||
        MH_CreateHook(&CreateFileW, &HookedCreateFileW, (LPVOID*)&pOriginalCreateFileW) != MH_OK ||
        MH_CreateHook(&ReadFile, &HookedReadFile, (LPVOID*)&pOriginalReadFile) != MH_OK ||
        MH_CreateHook(&WriteFile, &HookedWriteFile, (LPVOID*)&pOriginalWriteFile) != MH_OK ||
        MH_CreateHook(&GetFileAttributesA, &HookedGetFileAttributesA, (LPVOID*)&pOriginalGetFileAttributesA) != MH_OK ||
        MH_CreateHook(&GetFileAttributesW, &HookedGetFileAttributesW, (LPVOID*)&pOriginalGetFileAttributesW) != MH_OK ||
        MH_CreateHook(&FindFirstFileA, &HookedFindFirstFileA, (LPVOID*)&pOriginalFindFirstFileA) != MH_OK ||
        MH_CreateHook(&FindFirstFileW, &HookedFindFirstFileW, (LPVOID*)&pOriginalFindFirstFileW) != MH_OK ||
        MH_CreateHook(&FindNextFileA, &HookedFindNextFileA, (LPVOID*)&pOriginalFindNextFileA) != MH_OK ||
        MH_CreateHook(&FindNextFileW, &HookedFindNextFileW, (LPVOID*)&pOriginalFindNextFileW) != MH_OK ||
        MH_CreateHook(&FindClose, &HookedFindClose, (LPVOID*)&pOriginalFindClose) != MH_OK) {
        LogMessage("[HOOKS] ERROR: File I/O hooks creation failed");
        MH_Uninitialize();
        return FALSE;
    }

    // Process/Module enumeration hooks
    LogMessage("[HOOKS] Creating Process/Module enumeration hooks...");
    if (MH_CreateHook(&OpenProcess, &HookedOpenProcess, (LPVOID*)&pOriginalOpenProcess) != MH_OK) {
        LogMessage("[HOOKS] ERROR: OpenProcess hook failed");
        MH_Uninitialize();
        return FALSE;
    }
    LogMessage("[HOOKS] Successfully hooked OpenProcess");
    
    if (MH_CreateHook(&VirtualQueryEx, &HookedVirtualQueryEx, (LPVOID*)&pOriginalVirtualQueryEx) != MH_OK) {
        LogMessage("[HOOKS] ERROR: VirtualQueryEx hook failed");
        MH_Uninitialize();
        return FALSE;
    }
    LogMessage("[HOOKS] Successfully hooked VirtualQueryEx");
    
    if (MH_CreateHook(&CreateToolhelp32Snapshot, &HookedCreateToolhelp32Snapshot, (LPVOID*)&pOriginalCreateToolhelp32Snapshot) != MH_OK ||
        MH_CreateHook(&Process32FirstW, &HookedProcess32FirstW, (LPVOID*)&pOriginalProcess32FirstW) != MH_OK ||
        MH_CreateHook(&Process32NextW, &HookedProcess32NextW, (LPVOID*)&pOriginalProcess32NextW) != MH_OK ||
        MH_CreateHook(&Module32FirstW, &HookedModule32FirstW, (LPVOID*)&pOriginalModule32FirstW) != MH_OK ||
        MH_CreateHook(&Module32NextW, &HookedModule32NextW, (LPVOID*)&pOriginalModule32NextW) != MH_OK) {
        LogMessage("[HOOKS] ERROR: Process/Module hooks creation failed");
        MH_Uninitialize();
        return FALSE;
    }

    // Process info hooks
    LogMessage("[HOOKS] Creating Process info hooks...");
    if (MH_CreateHook(&QueryFullProcessImageNameA, &HookedQueryFullProcessImageNameA, (LPVOID*)&pOriginalQueryFullProcessImageNameA) != MH_OK ||
        MH_CreateHook(&QueryFullProcessImageNameW, &HookedQueryFullProcessImageNameW, (LPVOID*)&pOriginalQueryFullProcessImageNameW) != MH_OK ||
        MH_CreateHook(&GetProcessImageFileNameA, &HookedGetProcessImageFileNameA, (LPVOID*)&pOriginalGetProcessImageFileNameA) != MH_OK ||
        MH_CreateHook(&GetProcessImageFileNameW, &HookedGetProcessImageFileNameW, (LPVOID*)&pOriginalGetProcessImageFileNameW) != MH_OK) {
        LogMessage("[HOOKS] ERROR: Process info hooks creation failed");
        MH_Uninitialize();
        return FALSE;
    }

    // Directory change notification hooks
    LogMessage("[HOOKS] Creating Directory change notification hooks...");
    if (MH_CreateHook(&FindFirstChangeNotificationA, &HookedFindFirstChangeNotificationA, (LPVOID*)&pOriginalFindFirstChangeNotificationA) != MH_OK ||
        MH_CreateHook(&FindFirstChangeNotificationW, &HookedFindFirstChangeNotificationW, (LPVOID*)&pOriginalFindFirstChangeNotificationW) != MH_OK ||
        MH_CreateHook(&ReadDirectoryChangesW, &HookedReadDirectoryChangesW, (LPVOID*)&pOriginalReadDirectoryChangesW) != MH_OK) {
        LogMessage("[HOOKS] ERROR: Directory change hooks creation failed");
        MH_Uninitialize();
        return FALSE;
    }

    // Thread manipulation hooks - DISABLED (suspicious to anti-cheat)
    LogMessage("[HOOKS] Thread manipulation hooks DISABLED (anti-detection)");

    // Remote code execution hooks - DISABLED (suspicious to anti-cheat)
    LogMessage("[HOOKS] RCE hooks DISABLED (anti-detection)");

    // IPC Communication hooks (vowac.asi -> VOWAC.exe)
    LogMessage("[HOOKS] Creating IPC communication hooks...");
    HMODULE hWs2_32 = GetModuleHandleA("ws2_32.dll");
    if (!hWs2_32) {
        hWs2_32 = LoadLibraryA("ws2_32.dll");
    }
    HMODULE hUser32 = GetModuleHandleA("user32.dll");
    if (!hUser32) {
        hUser32 = LoadLibraryA("user32.dll");
    }
    
    if (hWs2_32) {
        FARPROC pRecv = GetProcAddress(hWs2_32, "recv");
        FARPROC pWSARecv = GetProcAddress(hWs2_32, "WSARecv");
        FARPROC pSend = GetProcAddress(hWs2_32, "send");

        if (pRecv && MH_CreateHook(pRecv, &Hooked_recv, (LPVOID*)&pOriginal_recv) == MH_OK) {
            LogMessage("[HOOKS] Successfully hooked recv");
        }
        if (pWSARecv && MH_CreateHook(pWSARecv, &Hooked_WSARecv, (LPVOID*)&pOriginal_WSARecv) == MH_OK) {
            LogMessage("[HOOKS] Successfully hooked WSARecv");
        }
        if (pSend && MH_CreateHook(pSend, &Hooked_send, (LPVOID*)&pOriginal_send) == MH_OK) {
            LogMessage("[HOOKS] Successfully hooked send");
        }
    }
    
    if (hUser32) {
        FARPROC pPostMessageA = GetProcAddress(hUser32, "PostMessageA");
        FARPROC pPostMessageW = GetProcAddress(hUser32, "PostMessageW");
        
        if (pPostMessageA && MH_CreateHook(pPostMessageA, &Hooked_PostMessageA, (LPVOID*)&pOriginal_PostMessageA) == MH_OK) {
            LogMessage("[HOOKS] Successfully hooked PostMessageA");
        }
        if (pPostMessageW && MH_CreateHook(pPostMessageW, &Hooked_PostMessageW, (LPVOID*)&pOriginal_PostMessageW) == MH_OK) {
            LogMessage("[HOOKS] Successfully hooked PostMessageW");
        }
        
        FARPROC pSendMessageW = GetProcAddress(hUser32, "SendMessageW");
        if (pSendMessageW && MH_CreateHook(pSendMessageW, &Hooked_SendMessageW, (LPVOID*)&pOriginal_SendMessageW) == MH_OK) {
            LogMessage("[HOOKS] Successfully hooked SendMessageW");
        }
    }

    // NTDLL hooks - directory enumeration for file hiding and memory protection
    LogMessage("[HOOKS] Creating NTDLL hooks...");
    if (hNtdll) {
        FARPROC pNtQueryDirectoryFile = GetProcAddress(hNtdll, "NtQueryDirectoryFile");
        FARPROC pNtQueryDirectoryFileEx = GetProcAddress(hNtdll, "NtQueryDirectoryFileEx");
        FARPROC pNtReadVirtualMemory = GetProcAddress(hNtdll, "NtReadVirtualMemory");
        FARPROC pNtWriteFile = GetProcAddress(hNtdll, "NtWriteFile");

        if (pNtQueryDirectoryFile && MH_CreateHook(pNtQueryDirectoryFile, &HookedNtQueryDirectoryFile, (LPVOID*)&pOriginalNtQueryDirectoryFile) == MH_OK) {
            LogMessage("[HOOKS] Successfully hooked NtQueryDirectoryFile");
        }
        if (pNtQueryDirectoryFileEx && MH_CreateHook(pNtQueryDirectoryFileEx, &HookedNtQueryDirectoryFileEx, (LPVOID*)&pOriginalNtQueryDirectoryFileEx) == MH_OK) {
            LogMessage("[HOOKS] Successfully hooked NtQueryDirectoryFileEx");
        }
        if (pNtReadVirtualMemory && MH_CreateHook(pNtReadVirtualMemory, &HookedNtReadVirtualMemory, (LPVOID*)&pOriginalNtReadVirtualMemory) == MH_OK) {
            LogMessage("[HOOKS] Successfully hooked NtReadVirtualMemory");
        }
        if (pNtWriteFile && MH_CreateHook(pNtWriteFile, &HookedNtWriteFile, (LPVOID*)&pOriginalNtWriteFile) == MH_OK) {
            LogMessage("[HOOKS] Successfully hooked NtWriteFile");
        }
    }

    LogMessage("[HOOKS] Enabling all hooks...");
    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
        LogMessage("[HOOKS] ERROR: MH_EnableHook failed");
        MH_Uninitialize();
        return FALSE;
    }

    LogMessage("[HOOKS] All hooks initialized successfully!");
    return TRUE;
}

void CleanupHooks() {
    LogMessage("[HOOKS] Cleaning up hooks...");

    if (MH_DisableHook(MH_ALL_HOOKS) == MH_OK) {
        MH_Uninitialize();
    }

    // Clear contexts
    g_findFileContexts.clear();
    g_directoryWatchContexts.clear();
    g_gtaSaProcessCache.clear();

    LogMessage("[HOOKS] Cleanup complete");
}

// ============================================
// DLL Entry Point
// ============================================

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        SetupDebugConsole();
        LogMessage("[DLL] DLL_PROCESS_ATTACH - Process attached");
        LogMessage("[DLL] Creating config reader...");

        g_pConfig = new VowacConfigReader();

        if (!InitializeHooks()) {
            LogMessage("[DLL] ERROR: Failed to initialize hooks");
            delete g_pConfig;
            g_pConfig = nullptr;
            return FALSE;
        }

        LogMessage("[DLL] DLL attachment complete!");
        break;

    case DLL_PROCESS_DETACH:
        LogMessage("[DLL] DLL_PROCESS_DETACH - Process detached");
        CleanupHooks();
        if (g_pConfig) {
            delete g_pConfig;
            g_pConfig = nullptr;
        }
        LogMessage("[DLL] DLL detachment complete");
        CloseLogger();
        break;

    case DLL_THREAD_ATTACH:
        LogMessage("[DLL] DLL_THREAD_ATTACH - Thread %u attached", GetCurrentThreadId());
        break;

    case DLL_THREAD_DETACH:
        LogMessage("[DLL] DLL_THREAD_DETACH - Thread %u detached", GetCurrentThreadId());
        break;
    }

    return TRUE;
}