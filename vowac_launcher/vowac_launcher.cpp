// vowac_launcher.cpp - Configuration and setup console application for VOWAC monitoring
//

#include <iostream>
#include <windows.h>
#include <string>
#include <fstream>
#include <shlobj.h>
#include <sstream>
#include <vector>
#include <algorithm>
#include <tlhelp32.h>
#include <cctype>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")

#include <psapi.h>
#pragma comment(lib, "psapi.lib")

// ============================================
// String Extractor Functionality
// ============================================

class StringExtractor {
public:
    static bool ExtractStringsFromFile(const std::string& filePath, const std::string& outputFile) {
        FILE* inputFile = fopen(filePath.c_str(), "rb");
        if (!inputFile) {
            std::cerr << "[ERROR] Failed to open file: " << filePath << "\n";
            return false;
        }

        FILE* outputFp = fopen(outputFile.c_str(), "w");
        if (!outputFp) {
            std::cerr << "[ERROR] Failed to create output file: " << outputFile << "\n";
            fclose(inputFile);
            return false;
        }

        fprintf(outputFp, "Extracted Strings from: %s\n", filePath.c_str());
        fprintf(outputFp, "=====================================\n\n");

        const int MIN_STRING_LENGTH = 4;
        std::string currentString;
        int stringCount = 0;

        unsigned char byte;
        while (fread(&byte, 1, 1, inputFile) == 1) {
            if ((byte >= 32 && byte <= 126) || byte == '\t' || byte == '\n' || byte == '\r') {
                currentString += (char)byte;
            }
            else {
                if (currentString.length() >= MIN_STRING_LENGTH) {
                    if (IsValidString(currentString)) {
                        fprintf(outputFp, "[%d] %s\n", stringCount++, currentString.c_str());
                    }
                }
                currentString.clear();
            }
        }

        if (currentString.length() >= MIN_STRING_LENGTH && IsValidString(currentString)) {
            fprintf(outputFp, "[%d] %s\n", stringCount++, currentString.c_str());
        }

        fprintf(outputFp, "\n=====================================\n");
        fprintf(outputFp, "Total strings found: %d\n", stringCount);

        fclose(inputFile);
        fclose(outputFp);

        std::cout << "[OK] Strings extracted: " << outputFile << " (" << stringCount << " strings)\n";
        return true;
    }

    static bool ExtractStringsFromProcess(DWORD processId, const std::string& outputFile) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
        if (!hProcess) {
            std::cerr << "[ERROR] Could not open process\n";
            return false;
        }

        FILE* outputFp = fopen(outputFile.c_str(), "w");
        if (!outputFp) {
            std::cerr << "[ERROR] Failed to create output file\n";
            CloseHandle(hProcess);
            return false;
        }

        fprintf(outputFp, "Extracted Strings from Process %lu\n", processId);
        fprintf(outputFp, "=====================================\n\n");

        const int MIN_STRING_LENGTH = 4;
        std::string currentString;
        int stringCount = 0;

        // Enumerate loaded modules
        HMODULE modules[256] = {};
        DWORD cbNeeded = 0;
        if (EnumProcessModules(hProcess, modules, sizeof(modules), &cbNeeded)) {
            int moduleCount = cbNeeded / sizeof(HMODULE);

            for (int i = 0; i < moduleCount && i < 256; i++) {
                MODULEINFO modInfo = {};
                if (GetModuleInformation(hProcess, modules[i], &modInfo, sizeof(modInfo))) {
                    char moduleName[MAX_PATH] = {};
                    GetModuleFileNameExA(hProcess, modules[i], moduleName, MAX_PATH);

                    fprintf(outputFp, "\n=== Module: %s ===\n", moduleName);
                    fprintf(outputFp, "Base: 0x%p, Size: 0x%X\n\n", modInfo.lpBaseOfDll, modInfo.SizeOfImage);

                    // Read module memory
                    unsigned char* buffer = new unsigned char[4096];
                    DWORD bytesRead = 0;
                    DWORD_PTR currentAddr = (DWORD_PTR)modInfo.lpBaseOfDll;
                    DWORD_PTR endAddr = currentAddr + modInfo.SizeOfImage;

                    while (currentAddr < endAddr) {
                        DWORD toRead = min(4096UL, (DWORD)(endAddr - currentAddr));

                        if (ReadProcessMemory(hProcess, (LPCVOID)currentAddr, buffer, toRead, nullptr)) {
                            for (DWORD j = 0; j < toRead; j++) {
                                unsigned char byte = buffer[j];

                                if ((byte >= 32 && byte <= 126) || byte == '\t') {
                                    currentString += (char)byte;
                                }
                                else {
                                    if (currentString.length() >= MIN_STRING_LENGTH && IsValidString(currentString)) {
                                        fprintf(outputFp, "[%d] %s\n", stringCount++, currentString.c_str());
                                    }
                                    currentString.clear();
                                }
                            }
                        }

                        currentAddr += toRead;
                    }

                    delete[] buffer;
                }
            }
        }

        fprintf(outputFp, "\n=====================================\n");
        fprintf(outputFp, "Total strings found: %d\n", stringCount);

        fclose(outputFp);
        CloseHandle(hProcess);

        std::cout << "[OK] Process strings extracted: " << outputFile << " (" << stringCount << " strings)\n";
        return true;
    }

private:
    static bool IsValidString(const std::string& str) {
        if (str.find("\\x") != std::string::npos ||
            str.find("..") != std::string::npos ||
            str.length() > 512) {
            return false;
        }

        for (char c : str) {
            if (std::isalpha(c)) {
                return true;
            }
        }

        return false;
    }
};

// Configuration file structure
class VowacConfig {
private:
    std::string vowacDir;
    std::string gtaSADir;
    std::vector<std::string> whitelistExtensions;
    std::vector<std::string> whitelistFolders;
    std::string configFilePath;
    bool isConfigLoaded;

    static constexpr const char* REGISTRY_KEY = "Software\\VOWAC";
    static constexpr const char* REGISTRY_CONFIG_PATH_VALUE = "ConfigPath";

    // Save config file path to registry
    bool SaveConfigPathToRegistry(const std::string& fullPath) {
        HKEY hKey = nullptr;
        LONG result = RegCreateKeyExA(
            HKEY_CURRENT_USER,
            REGISTRY_KEY,
            0,
            nullptr,
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            nullptr,
            &hKey,
            nullptr
        );

        if (result != ERROR_SUCCESS) {
            std::cerr << "[ERROR] Failed to create registry key. Error code: " << result << "\n";
            return false;
        }

        result = RegSetValueExA(
            hKey,
            REGISTRY_CONFIG_PATH_VALUE,
            0,
            REG_SZ,
            (const BYTE*)fullPath.c_str(),
            (DWORD)(fullPath.length() + 1)
        );

        RegCloseKey(hKey);

        if (result != ERROR_SUCCESS) {
            std::cerr << "[ERROR] Failed to save config path to registry. Error code: " << result << "\n";
            return false;
        }

        std::cout << "[OK] Config path saved to registry: " << fullPath << "\n";
        return true;
    }

    // Load config file path from registry
    bool LoadConfigPathFromRegistry(std::string& outPath) {
        HKEY hKey = nullptr;
        LONG result = RegOpenKeyExA(
            HKEY_CURRENT_USER,
            REGISTRY_KEY,
            0,
            KEY_READ,
            &hKey
        );

        if (result != ERROR_SUCCESS) {
            return false; // Registry key doesn't exist yet
        }

        char path[MAX_PATH] = {};
        DWORD size = sizeof(path);
        DWORD type = REG_SZ;

        result = RegQueryValueExA(
            hKey,
            REGISTRY_CONFIG_PATH_VALUE,
            nullptr,
            &type,
            (LPBYTE)path,
            &size
        );

        RegCloseKey(hKey);

        if (result != ERROR_SUCCESS || type != REG_SZ) {
            return false;
        }

        outPath = path;
        std::cout << "[OK] Config path loaded from registry: " << outPath << "\n";
        return true;
    }

public:
    VowacConfig(const std::string& configPath = "vowac_config.ini")
        : configFilePath(configPath) {
        // Default whitelisted extensions
        whitelistExtensions = { ".asi", ".ws", ".log", ".cfg" };
        // Default whitelisted folders
        whitelistFolders = { "sampfuncs", "cleo", "te_sdk", "te_mod" };
    }

    // Read GTA SA executable path from Windows registry
    bool ReadGTASAPathFromRegistry() {
        HKEY hKey = nullptr;
        LONG result = RegOpenKeyExA(
            HKEY_CURRENT_USER,
            "Software\\SAMP",
            0,
            KEY_READ,
            &hKey
        );

        if (result != ERROR_SUCCESS) {
            std::cerr << "Error: Failed to open registry key. Error code: " << result << "\n";
            return false;
        }

        char path[MAX_PATH] = {};
        DWORD size = sizeof(path);

        result = RegQueryValueExA(hKey, "gta_sa_exe", nullptr, nullptr, (LPBYTE)path, &size);
        RegCloseKey(hKey);

        if (result != ERROR_SUCCESS) {
            std::cerr << "Error: Failed to read gta_sa_exe value. Error code: " << result << "\n";
            return false;
        }

        // Extract directory from full path
        std::string fullPath(path);
        size_t lastSlash = fullPath.find_last_of("\\/");

        if (lastSlash != std::string::npos) {
            gtaSADir = fullPath.substr(0, lastSlash);
            std::cout << "[OK] GTA SA directory detected: " << gtaSADir << "\n";
            return true;
        }

        return false;
    }

    bool LoadConfig() {
        std::vector<std::string> paths;

        std::string registryPath;
        if (LoadConfigPathFromRegistry(registryPath)) {
            paths.push_back(registryPath);
        }

        if (!vowacDir.empty()) {
            paths.push_back(vowacDir + "\\" + configFilePath);
        }

        paths.push_back(configFilePath);

        for (const auto& path : paths) {
            std::ifstream configFile(path);
            if (!configFile.is_open()) {
                continue;
            }

            std::string line;
            std::string currentSection;

            while (std::getline(configFile, line)) {
                // Trim line
                line.erase(0, line.find_first_not_of(" \t\r\n"));
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

                std::string key = line.substr(0, equalPos);
                std::string value = line.substr(equalPos + 1);

                // Trim key and value
                key.erase(key.find_last_not_of(" \t") + 1);
                value.erase(0, value.find_first_not_of(" \t"));

                if (currentSection == "Paths") {
                    if (key == "vowac_dir") {
                        vowacDir = value;
                    }
                    else if (key == "gtasa_dir") {
                        gtaSADir = value;
                    }
                }
            }

            configFile.close();

            if (!vowacDir.empty() && !gtaSADir.empty()) {
                isConfigLoaded = true;
                return true;
            }
        }
        return false;
    }

    // Prompt user for VOWAC directory
    bool PromptForVowacDir() {
        std::cout << "\nEnter VOWAC.exe directory path:\n";
        std::cout << "(Leave empty to skip): ";

        std::string input;
        std::getline(std::cin, input);

        if (input.empty()) {
            std::cout << "[WARNING] VOWAC directory not set\n";
            return false;
        }

        // Validate directory exists
        DWORD attributes = GetFileAttributesA(input.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY)) {
            std::cerr << "[ERROR] Directory does not exist: " << input << "\n";
            return false;
        }

        vowacDir = input;
        std::cout << "[OK] VOWAC directory set: " << vowacDir << "\n";
        return true;
    }

    // Add custom extensions to whitelist
    void PromptForCustomExtensions() {
        std::cout << "\nCurrent whitelisted extensions: ";
        for (const auto& ext : whitelistExtensions) {
            std::cout << ext << " ";
        }
        std::cout << "\n";

        std::cout << "Add additional extensions? (comma-separated, e.g., .exe,.dll): ";
        std::string input;
        std::getline(std::cin, input);

        if (input.empty()) {
            return;
        }

        // Parse comma-separated extensions
        std::stringstream ss(input);
        std::string ext;
        while (std::getline(ss, ext, ',')) {
            // Trim whitespace
            ext.erase(0, ext.find_first_not_of(" \t"));
            ext.erase(ext.find_last_not_of(" \t") + 1);

            if (!ext.empty()) {
                if (ext[0] != '.') {
                    ext = "." + ext;
                }
                whitelistExtensions.push_back(ext);
            }
        }

        std::cout << "[OK] Extensions updated\n";
    }

    // Add custom folders to whitelist
    void PromptForCustomFolders() {
        std::cout << "\nCurrent whitelisted folders: ";
        for (const auto& folder : whitelistFolders) {
            std::cout << folder << " ";
        }
        std::cout << "\n";

        std::cout << "Add additional folders? (comma-separated, e.g., custom,temp): ";
        std::string input;
        std::getline(std::cin, input);

        if (input.empty()) {
            return;
        }

        // Parse comma-separated folders
        std::stringstream ss(input);
        std::string folder;
        while (std::getline(ss, folder, ',')) {
            // Trim whitespace
            folder.erase(0, folder.find_first_not_of(" \t"));
            folder.erase(folder.find_last_not_of(" \t") + 1);

            if (!folder.empty()) {
                whitelistFolders.push_back(folder);
            }
        }

        std::cout << "[OK] Folders updated\n";
    }

    // Save configuration to INI file
    bool SaveToFile() {
        std::string fullConfigPath = vowacDir;
        if (!vowacDir.empty() && vowacDir.back() != '\\' && vowacDir.back() != '/') {
            fullConfigPath += "\\";
        }
        fullConfigPath += configFilePath;

        std::ofstream iniFile(fullConfigPath);
        if (!iniFile.is_open()) {
            std::cerr << "[ERROR] Failed to create config file: " << configFilePath << "\n";
            return false;
        }

        // [Paths] section
        iniFile << "[Paths]\n";
        iniFile << "vowac_dir=" << vowacDir << "\n";
        iniFile << "gtasa_dir=" << gtaSADir << "\n";
        iniFile << "\n";

        // [Whitelist.Extensions] section
        iniFile << "[Whitelist.Extensions]\n";
        for (size_t i = 0; i < whitelistExtensions.size(); ++i) {
            iniFile << "extension" << (i + 1) << "=" << whitelistExtensions[i] << "\n";
        }
        iniFile << "\n";

        // [Whitelist.Folders] section
        iniFile << "[Whitelist.Folders]\n";
        for (size_t i = 0; i < whitelistFolders.size(); ++i) {
            iniFile << "folder" << (i + 1) << "=" << whitelistFolders[i] << "\n";
        }

        iniFile.close();
        std::cout << "\n[OK] Configuration saved to: " << configFilePath << "\n";

        // Save config path to registry for future loads
        SaveConfigPathToRegistry(fullConfigPath);

        return true;
    }

    // Validate configuration completeness
    bool IsValid() const {
        return !vowacDir.empty() && !gtaSADir.empty();
    }

    const std::string& GetVowacDir() const { return vowacDir; }
    const std::string& GetGTASADir() const { return gtaSADir; }
};

// DLL Injection functionality
class DLLInjector {
private:
    std::string dllPath;
    std::string targetExecutable;

public:
    DLLInjector(const std::string& dllToInject, const std::string& targetExe)
        : dllPath(dllToInject), targetExecutable(targetExe) {
    }

    HANDLE WaitForProcessByName(const std::string& processName, DWORD timeoutMs = 30000) {
        std::cout << "[*] Waiting for process: " << processName << " (timeout: " << timeoutMs << "ms)\n";

        DWORD startTime = GetTickCount();

        while ((GetTickCount() - startTime) < timeoutMs) {
            // Vytvoř snapshot procesů
            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnapshot == INVALID_HANDLE_VALUE) {
                Sleep(100);
                continue;
            }

            PROCESSENTRY32 pe32 = {};
            pe32.dwSize = sizeof(PROCESSENTRY32);

            if (Process32First(hSnapshot, &pe32)) {
                do {
                    std::string currentProcessName(pe32.szExeFile);

                    std::transform(currentProcessName.begin(), currentProcessName.end(),
                        currentProcessName.begin(), ::tolower);
                    std::string targetName = processName;
                    std::transform(targetName.begin(), targetName.end(),
                        targetName.begin(), ::tolower);

                    if (currentProcessName == targetName) {
                        std::cout << "[OK] Found process: " << processName << " (PID: " << pe32.th32ProcessID << ")\n";

                        HANDLE hProcess = OpenProcess(
                            PROCESS_ALL_ACCESS,
                            FALSE,
                            pe32.th32ProcessID
                        );

                        if (hProcess) {
                            std::cout << "[OK] Got handle to: " << processName << "\n";
                            CloseHandle(hSnapshot);
                            return hProcess;
                        }
                    }
                } while (Process32Next(hSnapshot, &pe32));
            }

            CloseHandle(hSnapshot);
            Sleep(500);
        }

        std::cerr << "[ERROR] Process not found after " << timeoutMs << "ms: " << processName << "\n";
        return INVALID_HANDLE_VALUE;
    }

    // Inject DLL into target process using CreateRemoteThread
    bool InjectDLL(HANDLE hProcess) {
        // Get absolute path to DLL
        char fullDLLPath[MAX_PATH] = {};
        if (!GetFullPathNameA(dllPath.c_str(), MAX_PATH, fullDLLPath, nullptr)) {
            std::cerr << "[ERROR] Failed to get full DLL path\n";
            return false;
        }

        std::cout << "[DEBUG] Full DLL path: " << fullDLLPath << "\n";

        // Allocate memory in target process
        SIZE_T dllPathSize = strlen(fullDLLPath) + 1;
        LPVOID pDLLPath = VirtualAllocEx(hProcess, nullptr, dllPathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (!pDLLPath) {
            std::cerr << "[ERROR] Failed to allocate memory in target process\n";
            return false;
        }

        std::cout << "[DEBUG] Allocated memory at: " << pDLLPath << "\n";

        // Write DLL path into target process memory
        if (!WriteProcessMemory(hProcess, pDLLPath, fullDLLPath, dllPathSize, nullptr)) {
            std::cerr << "[ERROR] Failed to write DLL path to target process memory\n";
            VirtualFreeEx(hProcess, pDLLPath, 0, MEM_RELEASE);
            return false;
        }

        std::cout << "[DEBUG] DLL path written to process memory\n";

        // Get LoadLibraryA function address from kernel32.dll
        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        if (!hKernel32) {
            std::cerr << "[ERROR] Failed to get kernel32.dll handle\n";
            VirtualFreeEx(hProcess, pDLLPath, 0, MEM_RELEASE);
            return false;
        }

        FARPROC pLoadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA");
        if (!pLoadLibraryA) {
            std::cerr << "[ERROR] Failed to get LoadLibraryA address\n";
            VirtualFreeEx(hProcess, pDLLPath, 0, MEM_RELEASE);
            return false;
        }

        std::cout << "[DEBUG] LoadLibraryA address: " << pLoadLibraryA << "\n";

        // Create remote thread to load DLL
        HANDLE hThread = CreateRemoteThread(
            hProcess,
            nullptr,
            0,
            (LPTHREAD_START_ROUTINE)pLoadLibraryA,
            pDLLPath,
            0,
            nullptr
        );

        if (!hThread) {
            DWORD lastError = GetLastError();
            std::cerr << "[ERROR] Failed to create remote thread. Error code: " << lastError << "\n";
            VirtualFreeEx(hProcess, pDLLPath, 0, MEM_RELEASE);
            return false;
        }

        std::cout << "[DEBUG] Remote thread created: " << hThread << "\n";

        // Wait for thread completion
        DWORD waitResult = WaitForSingleObject(hThread, 5000); // 5 second timeout
        if (waitResult == WAIT_TIMEOUT) {
            std::cerr << "[ERROR] Remote thread execution timed out\n";
        }

        DWORD threadExitCode = 0;
        if (GetExitCodeThread(hThread, &threadExitCode)) {
            std::cout << "[DEBUG] Remote thread exit code: " << threadExitCode << "\n";
        }

        // Cleanup
        CloseHandle(hThread);
        VirtualFreeEx(hProcess, pDLLPath, 0, MEM_RELEASE);

        std::cout << "[OK] DLL injected successfully\n";
        return true;
    }

    std::string GetDirectoryFromPath(const std::string& fullPath) {
        size_t lastSlash = fullPath.find_last_of("\\/");
        if (lastSlash != std::string::npos) {
            return fullPath.substr(0, lastSlash + 1);
        }
        return ".\\";
    }

    // Launch VOWAC process and inject DLL
    HANDLE LaunchAndInject() {
        std::string vowacDir = GetDirectoryFromPath(targetExecutable);
        std::wstring wideVowacDir(vowacDir.begin(), vowacDir.end());

        int len = MultiByteToWideChar(CP_ACP, 0, targetExecutable.c_str(), -1, nullptr, 0);
        wchar_t* wideExePath = new wchar_t[len];
        MultiByteToWideChar(CP_ACP, 0, targetExecutable.c_str(), -1, wideExePath, len);

        HINSTANCE hResult = ShellExecuteW(
            nullptr,
            L"open",
            wideExePath,
            nullptr,
            wideVowacDir.c_str(),
            SW_SHOW
        );

        delete[] wideExePath;

        if ((intptr_t)hResult <= 32) {
            std::cerr << "[ERROR] ShellExecute failed with error: " << (intptr_t)hResult << "\n";
            return INVALID_HANDLE_VALUE;
        }

		HANDLE hProcess = WaitForProcessByName("vowac.exe", 5000); 
		if (hProcess == INVALID_HANDLE_VALUE) {
            std::cerr << "[ERROR] Failed to find VOWAC process after launch\n";
            return INVALID_HANDLE_VALUE;
        }

        std::cout << "[OK] Process created ..\n";

        // Inject DLL
        bool injectionSuccess = InjectDLL(hProcess);
        if (!injectionSuccess) {
            std::cout << "[ERROR] Injection failed, terminating process...\n";
            TerminateProcess(hProcess, 1);
			return INVALID_HANDLE_VALUE;
        }

        // Cleanup
        CloseHandle(hProcess);

       //  StringExtractor::ExtractStringsFromProcess(pi.dwProcessId, "vowac_process_strings.txt");

		return hProcess;
    }

    bool InjectOnlyDLL(HANDLE hProcess)
    {
	    return InjectDLL(hProcess);
    }
};

int main() {
    // Enable UTF-8 console output for better compatibility
    SetConsoleCP(65001);
    SetConsoleOutputCP(65001);

    std::cout << "====================================================================\n";
    std::cout << "   VOWAC Launcher - Bypass Loader & Configuration Utility   \n";
    std::cout << "====================================================================\n\n";

    VowacConfig config;

    if (config.LoadConfig()) {
        std::cout << "[OK] Configuration already exists\n";
        std::cout << "[OK] VOWAC directory: " << config.GetVowacDir() << "\n";
        std::cout << "[OK] GTA SA directory: " << config.GetGTASADir() << "\n\n";
    }
    else {
        // Step 1: Read GTA SA path from registry
        std::cout << "[Step 1/4] Reading GTA SA configuration from registry...\n";
        if (!config.ReadGTASAPathFromRegistry()) {
            std::cout << "[WARNING] Could not read GTA SA path from registry.\n";
            std::cout << "Please enter it manually.\n";
            std::string manualPath;
            std::cout << "GTA SA directory: ";
            std::getline(std::cin, manualPath);

            if (manualPath.empty()) {
                std::cerr << "[ERROR] GTA SA directory is required!\n";
                return 1;
            }
        }

        // Step 2: Prompt for VOWAC directory
        std::cout << "\n[Step 2/4] Configuring VOWAC.exe directory...\n";
        if (!config.PromptForVowacDir()) {
            std::cerr << "[ERROR] VOWAC directory is required!\n";
            return 1;
        }

        // Step 3: Configure whitelist extensions
        std::cout << "\n[Step 3/4] Configuring whitelisted file extensions...\n";
        config.PromptForCustomExtensions();

        // Step 4: Configure whitelist folders
        std::cout << "\n[Step 4/4] Configuring whitelisted folders...\n";
        config.PromptForCustomFolders();

        // Validate and save
        if (!config.IsValid()) {
            std::cerr << "\n[ERROR] Configuration is incomplete!\n";
            return 1;
        }

        if (!config.SaveToFile()) {
            return 1;
        }

        std::cout << "\n============================================\n";
        std::cout << "        Configuration Complete!             \n";
        std::cout << "============================================\n\n";
    }

    // Step 5: Launch VOWAC and inject hook DLL
    std::cout << "[Step 5/5] Launching VOWAC with file monitoring hooks...\n";

    std::string vowacExecutable = config.GetVowacDir() + "\\vowac.exe";
    std::string hookDLL = "vowac_hooks.dll";
    std::string bypassASI = "um_ac_bypass.asi";

    // Validate VOWAC executable exists
    DWORD attributes = GetFileAttributesA(vowacExecutable.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        std::cerr << "[ERROR] VOWAC executable not found: " << vowacExecutable << "\n";
        std::cout << "Press Enter to exit...\n";
        std::cin.get();
        return 1;
    }

    // Validate hook DLL exists
    attributes = GetFileAttributesA(hookDLL.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        std::cerr << "[ERROR] Hook DLL not found: " << hookDLL << "\n";
        std::cout << "Make sure vowac_hooks.dll is in the current directory.\n";
        std::cout << "Press Enter to exit...\n";
        std::cin.get();
        return 1;
    }

	attributes = GetFileAttributesA(bypassASI.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        std::cerr << "[ERROR] Bypass ASI not found: " << bypassASI << "\n";
        std::cout << "Make sure um_ac_bypass.asi is in the current directory.\n";
        std::cout << "Press Enter to exit...\n";
        std::cin.get();
        return 1;
	}

    // Perform DLL injection
    DLLInjector injector(hookDLL, vowacExecutable);
	HANDLE hVowac = injector.LaunchAndInject();
    if (hVowac == INVALID_HANDLE_VALUE) {
        std::cerr << "\n[ERROR] Failed to inject DLL into VOWAC process\n";
        std::cout << "Press Enter to exit...\n";
        std::cin.get();
        return 1;
    }

 //   std::cout << "\n[*] Waiting for gta_sa.exe to start...\n";
 //   DLLInjector gtaInjector(bypassASI, "gta_sa.exe");
 //   HANDLE hGTA = gtaInjector.WaitForProcessByName("gta_sa.exe", 120000);
 //   if (hGTA == INVALID_HANDLE_VALUE) {
 //       std::cerr << "\n[ERROR] GTA SA process not found!\n";
 //       std::cout << "Press Enter to exit...\n";
 //       std::cin.get();
 //       return 1;
 //   }

	//std::cout << "\n[*] GTA SA process detected, waiting for it to initialize... (10s)\n";
 //   Sleep(10000);

 //   std::cout << "\n[*] Injecting bypass ASI into gta_sa.exe...\n";
 //   if (!gtaInjector.InjectOnlyDLL(hGTA)) {
 //       std::cerr << "\n[ERROR] Failed to inject bypass ASI into GTA SA process\n";
 //       std::cout << "Press Enter to exit...\n";
 //       std::cin.get();
 //       return 1;
 //   }

 //   CloseHandle(hGTA);

    std::cout << "\n============================================\n";
    std::cout << " VOWAC launched with active file monitoring\n";
    std::cout << "============================================\n";
    std::cout << "Press Enter to exit...\n";
    std::cin.get();

    return 0;
}