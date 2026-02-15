// vowac_emulator.cpp : VOWAC Protocol Emulator
//

#include <iostream>
#include <string>
#include <sstream>
#include <random>
#include <chrono>
#include <thread>
#include <vector>
#include <iomanip>
#include <fstream>
#include <regex>
#include <atomic>
#include <Windows.h>
#include <ShlObj.h>
#include <TlHelp32.h> 
#include <curl/curl.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <nlohmann/json.hpp>

#pragma comment(lib, "Shell32.lib")

using json = nlohmann::json;

// Console color codes
enum ConsoleColor {
    COLOR_DEFAULT = 7,
    COLOR_RED = 12,
    COLOR_GREEN = 10,
    COLOR_YELLOW = 14,
    COLOR_CYAN = 11,
    COLOR_MAGENTA = 13,
    COLOR_BLUE = 9,
    COLOR_GRAY = 8
};

HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

void setColor(ConsoleColor color) {
    SetConsoleTextAttribute(hConsole, color);
}

void printHeader(const std::string& text) {
    setColor(COLOR_CYAN);
    std::cout << "+============================================================+" << std::endl;
    std::cout << "|  " << text;
    // Pad to align
    int padding = 58 - text.length();
    for (int i = 0; i < padding; i++) std::cout << " ";
    std::cout << "|" << std::endl;
    std::cout << "+============================================================+" << std::endl;
    setColor(COLOR_DEFAULT);
}

void printInfo(const std::string& text) {
    setColor(COLOR_CYAN);
    std::cout << "[INFO] ";
    setColor(COLOR_DEFAULT);
    std::cout << text << std::endl;
}

void printSuccess(const std::string& text) {
    setColor(COLOR_GREEN);
    std::cout << "[OK] ";
    setColor(COLOR_DEFAULT);
    std::cout << text << std::endl;
}

void printError(const std::string& text) {
    setColor(COLOR_RED);
    std::cout << "[ERROR] ";
    setColor(COLOR_DEFAULT);
    std::cout << text << std::endl;
}

void printWarning(const std::string& text) {
    setColor(COLOR_YELLOW);
    std::cout << "[WARN] ";
    setColor(COLOR_DEFAULT);
    std::cout << text << std::endl;
}

void printDebug(const std::string& text) {
    setColor(COLOR_GRAY);
    std::cout << "[DEBUG] " << text;
    setColor(COLOR_DEFAULT);
    std::cout << std::endl;
}

void printPrompt(const std::string& text) {
    setColor(COLOR_MAGENTA);
    std::cout << "> " << text;
    setColor(COLOR_DEFAULT);
}

// Constants
const std::string API_BASE = "https://cwtglagshot.xyz/api";
const std::string INITIAL_SECRET = "rklbgifMCYwUdiqbIoHwEPpddSwiXW3YovpUKDpQQqPmVg3E";
const std::string SK1_PREFIX = "SK1|";
const std::string CLIENT_VERSION = "vowac-1.2.4";
const int DEFAULT_INTERVAL = 10;

// Global session variables
std::string g_sessionId;
std::string g_playerId;
std::string g_currentChallenge;
std::string g_machineId;
std::string g_deviceName;
std::string g_userName;
int g_gtaPid = 0;

std::atomic<bool> g_pinFound(false);
std::atomic<bool> g_userCancelled(false);
std::string g_detectedPin;

// Random number generator
std::random_device rd;
std::mt19937 gen(rd());

// Forward declarations
DWORD WINAPI MonitorChatlogThread(LPVOID lpParam);
std::string get_pin_from_user();

// Callback for curl - stores response into string
size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* userp) {
    size_t totalSize = size * nmemb;
    userp->append((char*)contents, totalSize);
    return totalSize;
}

// Base64 encoding
std::string base64_encode(const unsigned char* input, size_t length) {
    static const char encoding_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string encoded;
    encoded.reserve(((length + 2) / 3) * 4);

    for (size_t i = 0; i < length; i += 3) {
        uint32_t b = (input[i] << 16) | ((i + 1 < length ? input[i + 1] : 0) << 8) | (i + 2 < length ? input[i + 2] : 0);
        encoded.push_back(encoding_table[(b >> 18) & 0x3F]);
        encoded.push_back(encoding_table[(b >> 12) & 0x3F]);
        encoded.push_back(i + 1 < length ? encoding_table[(b >> 6) & 0x3F] : '=');
        encoded.push_back(i + 2 < length ? encoding_table[b & 0x3F] : '=');
    }
    return encoded;
}

// Generate random hex string
std::string generate_random_hex(size_t length) {
    std::uniform_int_distribution<> dis(0, 15);
    std::ostringstream oss;
    for (size_t i = 0; i < length; i++) {
        oss << std::hex << dis(gen);
    }
    return oss.str();
}

// Generate randomized machine ID (hardware fingerprint simulation)
std::string generate_machine_id() {
    // Generate random bytes
    std::uniform_int_distribution<> dis(0, 255);
    unsigned char random_bytes[32];
    for (int i = 0; i < 32; i++) {
        random_bytes[i] = dis(gen);
    }

    // SHA256 hash
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(random_bytes, 32, hash);

    // Convert to hex string
    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return oss.str();
}

// Generate random nonce
std::string generate_nonce() {
    std::uniform_int_distribution<> dis(0, 255);

    unsigned char bytes[16];
    for (int i = 0; i < 16; i++) {
        bytes[i] = dis(gen);
    }
    return base64_encode(bytes, 16);
}

// Get Unix timestamp as string
std::string get_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto epoch = now.time_since_epoch();
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(epoch);
    return std::to_string(seconds.count());
}

// Get Unix timestamp as integer
int64_t get_timestamp_int() {
    auto now = std::chrono::system_clock::now();
    auto epoch = now.time_since_epoch();
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(epoch);
    return seconds.count();
}

// Generate random nonce as integer
int64_t generate_nonce_int() {
    std::uniform_int_distribution<int64_t> dis(INT64_MIN, INT64_MAX);
    return dis(gen);
}

// Get formatted time for reports (DD/MM/YYYY HH:MM:SS)
std::string get_formatted_time() {
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    struct tm local_tm;
    localtime_s(&local_tm, &time_t_now);

    std::ostringstream oss;
    oss << std::setfill('0') << std::setw(2) << local_tm.tm_mday << "/"
        << std::setfill('0') << std::setw(2) << (local_tm.tm_mon + 1) << "/"
        << (local_tm.tm_year + 1900) << " "
        << std::setfill('0') << std::setw(2) << local_tm.tm_hour << ":"
        << std::setfill('0') << std::setw(2) << local_tm.tm_min << ":"
        << std::setfill('0') << std::setw(2) << local_tm.tm_sec;
    return oss.str();
}

// HMAC-SHA256 signing function - returns raw bytes
std::vector<unsigned char> hmac_sha256_raw(const std::string& key, const std::string& message) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    HMAC(EVP_sha256(), key.c_str(), key.length(),
        (unsigned char*)message.c_str(), message.length(),
        hash, nullptr);
    return std::vector<unsigned char>(hash, hash + SHA256_DIGEST_LENGTH);
}

// HMAC-SHA256 signing function - returns raw bytes from raw key
std::vector<unsigned char> hmac_sha256_raw_key(const std::vector<unsigned char>& key, const std::string& message) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    HMAC(EVP_sha256(), key.data(), key.size(),
        (unsigned char*)message.c_str(), message.length(),
        hash, nullptr);
    return std::vector<unsigned char>(hash, hash + SHA256_DIGEST_LENGTH);
}

std::string base64_decode(const std::string& encoded) {
    static const std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string decoded;
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T[base64_chars[i]] = i;

    int val = 0, valb = -8;
    for (unsigned char c : encoded) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            decoded.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return decoded;
}
std::string sha256_hex(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)input.c_str(), input.length(), hash);

    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return oss.str();
}

// VOWAC HMAC Signature Scheme
std::string create_signature(const std::string& body_json, int64_t ts, int64_t nonce) {
    // Step 1: Key Derivation
    // dk = HMAC-SHA256(SECRET, "SK1|" + base64_decode(challenge) + "|" + machineId + "|" + playerId)
    std::string decoded_challenge = base64_decode(g_currentChallenge);
    std::string kdf_message = "SK1|" + decoded_challenge + "|" + g_machineId + "|" + g_playerId;

    //printDebug("Key Derivation - Message: SK1|[challenge]|" + g_machineId + "|" + g_playerId);

    // Derive key (RAW bytes)
    std::vector<unsigned char> derived_key = hmac_sha256_raw(INITIAL_SECRET, kdf_message);

    printDebug("Derived key length: " + std::to_string(derived_key.size()) + " bytes");

    // Step 2: Create Canonical String
    // v1|POST|/report|{sessionToken}|{ts}|{nonce}|{sha256_hex_lower(body_json)}
    std::string body_hash = sha256_hex(body_json);

    std::string canonical_string = "v1|POST|/report|" + g_sessionId + "|" +
        std::to_string(ts) + "|" +
        std::to_string(nonce) + "|" +
        body_hash;

    printDebug("Canonical String: " + canonical_string);
    printDebug("Body SHA256: " + body_hash.substr(0, 16) + "...");

    // Step 3: Sign canonical string with derived key
    // sig = base64(HMAC-SHA256(dk, canonical_string))
    std::vector<unsigned char> signature_raw = hmac_sha256_raw_key(derived_key, canonical_string);

    std::string signature_b64 = base64_encode(signature_raw.data(), signature_raw.size());

    printDebug("Final signature: " + signature_b64.substr(0, 20) + "...");

    return signature_b64;
}

// HTTP POST request using curl
bool http_post(const std::string& url, const json& payload, json& response) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        printError("Failed to initialize curl");
        return false;
    }

    std::string response_str;
    std::string payload_str = payload.dump();

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload_str.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_str);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    CURLcode res = curl_easy_perform(curl);

    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        printError(std::string("curl_easy_perform() failed: ") + curl_easy_strerror(res));
        return false;
    }

    printDebug("HTTP Status Code: " + std::to_string(http_code));
    printDebug("Response (first 200 chars): " + response_str.substr(0, 200));

    if (http_code != 200) {
        printError("HTTP error " + std::to_string(http_code));
        printError("Full response: " + response_str);
        return false;
    }

    try {
        response = json::parse(response_str);
        return true;
    }
    catch (const json::parse_error& e) {
        printError(std::string("JSON parse error: ") + e.what());
        printError("Raw response: " + response_str);
        return false;
    }
}

// Get SA-MP chatlog path dynamically
std::string get_samp_chatlog_path() {
    char documentsPath[MAX_PATH];

    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_PERSONAL, NULL, 0, documentsPath))) {
        std::string chatlogPath = std::string(documentsPath) + "\\GTA San Andreas User Files\\SAMP\\chatlog.txt";
        return chatlogPath;
    }

    printWarning("Failed to get Documents folder, using fallback path");
    return "chatlog.txt";
}

// Extract PIN from chatlog line
bool extract_pin_from_line(const std::string& line, std::string& pin) {
    std::regex pin_regex1(R"(\[VOWAC\].*?PIN:\s*(\d{6}))");
    std::regex pin_regex2(R"(PIN:\s*(\d{6}))");

    std::smatch match;

    // Try first pattern
    if (std::regex_search(line, match, pin_regex1)) {
        if (match.size() > 1) {
            pin = match[1].str();
            return true;
        }
    }

    // Try fallback pattern
    if (std::regex_search(line, match, pin_regex2)) {
        if (match.size() > 1) {
            pin = match[1].str();
            return true;
        }
    }

    return false;
}

DWORD WINAPI KeyboardListenerThread(LPVOID lpParam) {
    while (!g_pinFound.load() && !g_userCancelled.load()) {
        // Check if ESC is pressed
        if (GetAsyncKeyState(VK_ESCAPE) & 0x8000) {
            g_userCancelled.store(true);

            setColor(COLOR_YELLOW);
            std::cout << "\n[USER INPUT] ";
            setColor(COLOR_DEFAULT);
            std::cout << "ESC pressed - switching to manual input" << std::endl;

            break;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    return 0;
}

bool is_gta_running() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    bool found = false;
    if (Process32First(hSnapshot, &pe32)) {
        do {
            // Case-insensitive comparison
            std::string exeFile(pe32.szExeFile);
            std::transform(exeFile.begin(), exeFile.end(), exeFile.begin(), ::tolower);

            if (exeFile == "gta_sa.exe") {
                found = true;

                // Update global PID with actual PID
                g_gtaPid = pe32.th32ProcessID;

                printDebug("Found gta_sa.exe process (PID: " + std::to_string(g_gtaPid) + ")");
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return found;
}


// Enhanced PIN retrieval with auto-detection
std::string get_pin_with_auto_detect() {
    // Check if GTA is running FIRST
    if (!is_gta_running()) {
        std::cout << std::endl;
        setColor(COLOR_YELLOW);
        std::cout << "+============================================================+" << std::endl;
        std::cout << "|  GTA:SA Process Not Detected                             |" << std::endl;
        std::cout << "+============================================================+" << std::endl;
        setColor(COLOR_DEFAULT);
        std::cout << std::endl;

        printWarning("gta_sa.exe is not running!");
        printInfo("Auto-detection requires GTA:SA to be active");
        printInfo("Please start the game before using this emulator");
        std::cout << std::endl;

        setColor(COLOR_CYAN);
        std::cout << "Options:" << std::endl;
        std::cout << "  1. Start GTA:SA and restart this emulator" << std::endl;
        std::cout << "  2. Enter PIN manually (game not required)" << std::endl;
        setColor(COLOR_DEFAULT);
        std::cout << std::endl;

        // Skip auto-detection, go straight to manual input
        return get_pin_from_user();
    }

    std::cout << std::endl;
    setColor(COLOR_YELLOW);
    std::cout << "+============================================================+" << std::endl;
    std::cout << "|  PIN Auto-Detection Active                               |" << std::endl;
    std::cout << "+============================================================+" << std::endl;
    setColor(COLOR_DEFAULT);
    std::cout << std::endl;

    printInfo("Scanning SA-MP chatlog for VOWAC PIN...");
    printInfo("Timeout: 5 minutes | Press ESC for manual input");

    std::cout << std::endl;
    setColor(COLOR_CYAN);
    std::cout << "  Waiting for PIN in chatlog";
    setColor(COLOR_DEFAULT);
    std::cout << std::flush;

    // Reset atomic flags
    g_pinFound.store(false);
    g_userCancelled.store(false);
    g_detectedPin.clear();

    // Start monitoring threads
    HANDLE hChatlogThread = CreateThread(NULL, 0, MonitorChatlogThread, NULL, 0, NULL);
    HANDLE hKeyboardThread = CreateThread(NULL, 0, KeyboardListenerThread, NULL, 0, NULL);

    if (!hChatlogThread || !hKeyboardThread) {
        printError("Failed to create monitoring threads");
        if (hChatlogThread) CloseHandle(hChatlogThread);
        if (hKeyboardThread) CloseHandle(hKeyboardThread);
        return get_pin_from_user();
    }

    // Animated waiting indicator
    const char* spinChars = "|/-\\";
    int spinIndex = 0;
    auto startTime = std::chrono::steady_clock::now();

    while (!g_pinFound.load() && !g_userCancelled.load()) {
        auto elapsed = std::chrono::steady_clock::now() - startTime;
        int secondsElapsed = std::chrono::duration_cast<std::chrono::seconds>(elapsed).count();
        int secondsRemaining = 300 - secondsElapsed; // 5 minutes = 300 seconds

        if (secondsRemaining <= 0) {
            break;
        }

        // Update spinner
        std::cout << "\r";
        setColor(COLOR_CYAN);
        std::cout << "  Waiting for PIN in chatlog " << spinChars[spinIndex % 4] << " ";
        setColor(COLOR_GRAY);
        std::cout << "(" << (secondsRemaining / 60) << "m " << (secondsRemaining % 60) << "s remaining)";
        setColor(COLOR_DEFAULT);
        std::cout << "          " << std::flush;

        spinIndex++;
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }

    // Wait for threads to finish
    WaitForSingleObject(hChatlogThread, 1000);
    WaitForSingleObject(hKeyboardThread, 1000);

    CloseHandle(hChatlogThread);
    CloseHandle(hKeyboardThread);

    std::cout << "\r" << std::string(80, ' ') << "\r"; // Clear line

    // Check results
    if (g_pinFound.load() && !g_detectedPin.empty()) {
        printSuccess("Auto-detected PIN: " + g_detectedPin);
        return g_detectedPin;
    }

    if (g_userCancelled.load()) {
        printInfo("Falling back to manual PIN entry");
    }
    else {
        printWarning("No PIN detected in chatlog");
    }

    // Fallback to manual input
    return get_pin_from_user();
}

// Original manual PIN input function (kept as fallback)
std::string get_pin_from_user() {
    std::string pin;
    while (true) {
        std::cout << std::endl;
        setColor(COLOR_YELLOW);
        std::cout << "+----------------------------------------------+" << std::endl;
        std::cout << "|  The server requires a 6-digit PIN          |" << std::endl;
        std::cout << "|  This PIN might be sent via in-game chat    |" << std::endl;
        std::cout << "+----------------------------------------------+" << std::endl;
        setColor(COLOR_DEFAULT);
        std::cout << std::endl;

        printPrompt("Enter 6-digit PIN (or 'skip' to use 000000): ");
        std::getline(std::cin, pin);

        // Trim whitespace
        pin.erase(0, pin.find_first_not_of(" \t\r\n"));
        pin.erase(pin.find_last_not_of(" \t\r\n") + 1);

        if (pin == "skip") {
            printWarning("Using default PIN: 000000");
            return "000000";
        }

        if (pin.length() == 6 && std::all_of(pin.begin(), pin.end(), ::isdigit)) {
            printSuccess("PIN accepted: " + pin);
            return pin;
        }

        printError("Invalid PIN! Must be exactly 6 digits.");
    }
}

DWORD WINAPI MonitorChatlogThread(LPVOID lpParam) {
    std::string chatlogPath = get_samp_chatlog_path();

    // Get initial file size (to skip old content)
    std::ifstream initialCheck(chatlogPath, std::ios::ate | std::ios::binary);
    std::streampos initialSize = initialCheck.tellg();
    initialCheck.close();

    if (initialSize == -1) {
        printWarning("Could not determine initial chatlog size");
        initialSize = 0;
    }

    auto startTime = std::chrono::steady_clock::now();
    const auto timeout = std::chrono::minutes(5);

    while (!g_userCancelled.load() && !g_pinFound.load()) {
        // Check timeout
        auto elapsed = std::chrono::steady_clock::now() - startTime;
        if (elapsed >= timeout) {
            printWarning("Timeout: No PIN detected in 5 minutes");
            break;
        }

        // REOPEN file each time for fresh read
        std::ifstream chatlog(chatlogPath, std::ios::in);
        if (!chatlog.is_open()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            continue;
        }

        // Get current file size
        chatlog.seekg(0, std::ios::end);
        std::streampos currentSize = chatlog.tellg();

        if (currentSize > initialSize) {
            // New content available - read only NEW lines
            chatlog.seekg(initialSize);

            std::string newLine;
            while (std::getline(chatlog, newLine)) {
                std::string pin;
                if (extract_pin_from_line(newLine, pin)) {
                    g_detectedPin = pin;
                    g_pinFound.store(true);

                    setColor(COLOR_GREEN);
                    std::cout << "\n[AUTO-DETECT] ";
                    setColor(COLOR_DEFAULT);
                    std::cout << "PIN detected: ";
                    setColor(COLOR_CYAN);
                    std::cout << pin << std::endl;
                    setColor(COLOR_DEFAULT);

                    chatlog.close();
                    return 0;
                }
            }

            // Update last known position
            initialSize = currentSize;
        }

        chatlog.close();
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    return 0;
}

// /ac/attach - session initialization
bool attach_session() {
    printInfo("Connecting to /ac/attach...");

    std::string pin = get_pin_with_auto_detect();

    json attach_payload = {
        {"pin", pin},
        {"machineId", g_machineId},
        {"clientLabel", g_userName}
    };

    printDebug("Sending attach payload...");

    json response;
    if (!http_post(API_BASE + "/ac/attach", attach_payload, response)) {
        return false;
    }

    if (response.value("ok", false)) {
        g_sessionId = response.value("sessionToken", "");
        g_playerId = response.value("playerId", "");
        g_currentChallenge = response.value("challenge", "");

        std::cout << std::endl;
        printSuccess("Session attached successfully!");
        setColor(COLOR_GREEN);
        std::cout << "  +- Player ID: ";
        setColor(COLOR_CYAN);
        std::cout << g_playerId << std::endl;
        setColor(COLOR_GREEN);
        std::cout << "  +- Session Token: ";
        setColor(COLOR_CYAN);
        std::cout << g_sessionId << std::endl;
        setColor(COLOR_GREEN);
        std::cout << "  +- Challenge: ";
        setColor(COLOR_CYAN);
        std::cout << g_currentChallenge.substr(0, 20) << "..." << std::endl;
        setColor(COLOR_GREEN);
        std::cout << "  +- Interval: ";
        setColor(COLOR_CYAN);
        std::cout << response.value("interval", DEFAULT_INTERVAL) << "s" << std::endl;
        setColor(COLOR_DEFAULT);
        return true;
    }

    printError("Attach failed: " + response.dump(2));
    return false;
}
json create_report_body();

// /report - send periodic report with signature
bool send_report() {
    printInfo("Sending report...");

    int64_t ts_int = get_timestamp_int();
    int64_t nonce_int = generate_nonce_int();

    json body = create_report_body();
    std::string body_json = body.dump();

    std::string sig = create_signature(body_json, ts_int, nonce_int);

    printDebug("Signature components:");
    printDebug("  Challenge (base64): " + g_currentChallenge.substr(0, 20) + "...");
    printDebug("  MachineId: " + g_machineId);
    printDebug("  PlayerId: " + g_playerId);
    printDebug("  SessionToken: " + g_sessionId);
    printDebug("  TS: " + std::to_string(ts_int));
    printDebug("  Nonce: " + std::to_string(nonce_int));
    printDebug("  Sig: " + sig.substr(0, 20) + "...");

    json signed_payload = {
        {"ts", ts_int},
        {"nonce", nonce_int},
        {"body", body},
        {"sig", sig}
    };

    json response;
    if (!http_post(API_BASE + "/report", signed_payload, response)) {
        return false;
    }

    if (response.contains("status")) {
        std::string status = response.value("status", "unknown");
        int riskScore = response.value("riskScore", -1);
        std::string reason = response.value("reason", "");

        // Update challenge if present
        if (response.contains("newChallenge") && !response["newChallenge"].is_null()) {
            g_currentChallenge = response.value("newChallenge", "");
            printSuccess("Challenge rotated");
        }
        else if (response.contains("challenge") && !response["challenge"].is_null()) {
            g_currentChallenge = response.value("challenge", "");
            printSuccess("Challenge rotated");
        }

        // Display status
        std::cout << std::endl;
        setColor(COLOR_CYAN);
        std::cout << "  +- Status: ";

        if (status == "ok" || status == "trusted" || status == "clean") {
            setColor(COLOR_GREEN);
        }
        else if (status == "warning" || status == "suspicious") {
            setColor(COLOR_YELLOW);
        }
        else if (status == "critical" || status == "banned") {
            setColor(COLOR_RED);
        }
        else {
            setColor(COLOR_DEFAULT);
        }

        std::cout << status << std::endl;

        setColor(COLOR_CYAN);
        std::cout << "  +- Risk Score: ";
        setColor(riskScore == 0 ? COLOR_GREEN : (riskScore < 50 ? COLOR_YELLOW : COLOR_RED));
        std::cout << riskScore << std::endl;

        if (!reason.empty()) {
            setColor(COLOR_CYAN);
            std::cout << "  +- Reason: ";
            setColor(COLOR_DEFAULT);
            std::cout << reason << std::endl;
        }

        setColor(COLOR_DEFAULT);

        if (status != "critical" && status != "banned") {
            printSuccess("Report accepted");
            return true;
        }
        else {
            printWarning("Report marked as " + status);
            return true;
        }
    }

    printError("Report failed: invalid response structure");
    printError("Response: " + response.dump(2));
    return false;
}

// Create report body with all required fields
json create_report_body() {
    static int sessionUptime = 0;
    static int tick_counter = 0;
    sessionUptime += DEFAULT_INTERVAL;
    tick_counter++;

    std::string currentTime = get_formatted_time();
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();

    // Use consistent "clean" SHA256 hashes (these would ideally be real file hashes)
    // For real usage, you'd compute actual SHA256 of legitimate GTA files
    std::string sha256_bass = "3f04620d6627abe5c3b4747faf26603ab7a006c81b2021ab4689bdd7033bb4cd";
    std::string sha256_samp = "b72b5dbe725f81864ca3f78bc7063bda56cc05fc7188af822fa7a754432553a2";
    std::string sha256_gta = "f01a00ce950fa40ca1ed59df0e789848c6edcf6405456274965885d0929343ac";
    std::string sha256_eax = "b2da4f1e47ef8054c8390ead0b97d1fbb0c547245b79b8861cfa92ce9ef153fb";
    std::string sha256_ogg = "4a4f65427e016b3c5ae0d2517a69db5f1cdc7a43d2c0a7957e8da5d6f378f063";
    std::string sha256_vorbis = "fefda850b69e007fceba644483c7616bc07e9f177fc634fb74e114f0d15b0db0";
    std::string sha256_vorbisfile = "bdcf32fc3961eebffb4104327ca1396daf1cbd5e736930ed247836035148dafc";
    std::string sha256_vorbishooked = "a08923479000cec366967fb8259e0920b7aa18859722c7dda1415726bed4774f";
    std::string sha256_vowac = "584467271f4ad658e3e5c82bc464ce1ff246184553a1ee3b95d83ce406d5a8f9";
    std::string sha256_winmm = "c79ac9445b514ada6245ce12051f4aa57b421d221b91973058ee2abdc259059d";

    // Use legitimate looking paths
    std::string gtaPath = "C:\\Program Files (x86)\\Rockstar Games\\GTA San Andreas";

    json report = {
        {"clientLabel", g_userName},
        {"machineId", g_machineId},
        {"playerId", g_playerId},
        {"sessionToken", g_sessionId},

        {"conn", {
            {"connected", true},
            {"hasGtaProcess", true},
            {"pid", g_gtaPid},
            {"reason", "udp activity present for gta process"},
            {"udpEndpointsCount", 1},
            {"udpEndpointsSample", json::array({
                {
                    {"localIp", "0.0.0.0"},
                    {"localPort", 60570}
                }
            })}
        }},

        {"envPosture", {
            {"score", 0},
            {"level", "trusted"},
            {"testSigningEnabled", false},
            {"kernelDebuggerEnabled", false},
            {"codeIntegrityRelaxed", false}
        }},

        {"deterministicIntegrity", {
            {"gtaPid", g_gtaPid},
            {"timestampMs", ms},
            {"probes", json::array({
                {
                    {"id", "gta_sa_bytes_probe_01"},
                    {"bytesTotal", 32},
                    {"currentHex", "00 18 2B 87 00 33 33 73 3F 9A 99 19 3E C3 B8 B2 BE 00 00 40 3F 00 00 A0 40 2E E3 CD 3B CD CC 4C"},
                    {"expectedHex", "00 18 2B 87 00 33 33 73 3F 9A 99 19 3E C3 B8 B2 BE 00 00 40 3F 00 00 A0 40 2E E3 CD 3B CD CC 4C"},
                    {"diffIndexes", json::array()},
                    {"module", {
                        {"base", 4194304},
                        {"name", "gta_sa.exe"},
                        {"path", gtaPath + "\\gta_sa.exe"},
                        {"sizeBytes", 18313216}
                    }},
                    {"offsetOrVa", 5071119},
                    {"pageInfo", {
                        {"pageType", 16777216},
                        {"protect", 64},
                        {"state", 4096}
                    }},
                    {"readStartAddress", 9265407},
                    {"resolvedAddress", 9265423},
                    {"status", "baselineOk"}
                },
                {
                    {"id", "samp_bytes_probe_01"},
                    {"bytesTotal", 20},
                    {"currentHex", "75 42 40 83 F8 0C 72 F4 8D 47 10 50 6A 0A 6A 0A 8D 4C 24 3C"},
                    {"expectedHex", "75 42 40 83 F8 0C 72 F4 8D 47 10 50 6A 0A 6A 0A 8D 4C 24 3C"},
                    {"diffIndexes", json::array()},
                    {"module", {
                        {"base", 67371008},
                        {"name", "samp.dll"},
                        {"path", gtaPath + "\\samp.dll"},
                        {"sizeBytes", 2613248}
                    }},
                    {"offsetOrVa", 380716},
                    {"pageInfo", {
                        {"pageType", 16777216},
                        {"protect", 32},
                        {"state", 4096}
                    }},
                    {"readStartAddress", 67751716},
                    {"resolvedAddress", 67751724},
                    {"status", "baselineOk"}
                }
            })}
        }},

        // FIXED: Legitimate parent chain (no cmd.exe)
        {"shield", {
            {"hasExecRegionsOutsideModules", false},
            {"parentChain", json::array({
                {
                    {"childPid", g_gtaPid},
                    {"parentImagePath", "C:\\Windows\\explorer.exe"},
                    {"parentPid", 5128}
                }/*,
                {
                    {"childPid", 892},
                    {"parentImagePath", nullptr},
                    {"parentPid", 4}
                }*/
            })},
            {"selfInvalidSignedModules", json::array()},
            {"tick", tick_counter},
            {"tsUnixSeconds", std::chrono::system_clock::to_time_t(now)},
            {"violatingModulesCount", 0},
            {"violatingModulesSample", json::array()}
        }},

        // FIXED: Clean memory scan (no suspicious regions)
        {"memoryScan", {
            {"execRangesTotal", 8},
            {"memImageExecNoOwner", 0},
            {"pid", g_gtaPid},
            {"suspiciousRegionCount", 0},
            {"suspiciousRegions", json::array()},
            {"threadHits", json::array()},
            {"threadHitsCount", 0}
        }},

        // Empty externalFiles (no Discord hooks etc)
        {"externalFiles", json::array()},

        {"files", json::array({
            {{"relativePath", "bass.dll"}, {"sha256", sha256_bass}},
            {{"relativePath", "eax.dll"}, {"sha256", sha256_eax}},
            {{"relativePath", "gta_sa.exe"}, {"sha256", sha256_gta}},
            {{"relativePath", "ogg.dll"}, {"sha256", sha256_ogg}},
            {{"relativePath", "samp.dll"}, {"sha256", sha256_samp}},
            {{"relativePath", "vorbis.dll"}, {"sha256", sha256_vorbis}},
            {{"relativePath", "vorbisfile.dll"}, {"sha256", sha256_vorbisfile}},
            {{"relativePath", "vorbishooked.dll"}, {"sha256", sha256_vorbishooked}},
            {{"relativePath", "vowac.asi"}, {"sha256", sha256_vowac}},
            {{"relativePath", "winmm.dll"}, {"sha256", sha256_winmm}}
        })},

        {"filesInside", json::array({
            {{"relativePath", "gta_sa.exe"}, {"sha256", sha256_gta}},
            {{"relativePath", "winmm.dll"}, {"sha256", sha256_winmm}},
            {{"relativePath", "vorbisfile.dll"}, {"sha256", sha256_vorbisfile}},
            {{"relativePath", "eax.dll"}, {"sha256", sha256_eax}},
            {{"relativePath", "samp.dll"}, {"sha256", sha256_samp}},
            {{"relativePath", "bass.dll"}, {"sha256", sha256_bass}},
            {{"relativePath", "vorbishooked.dll"}, {"sha256", sha256_vorbishooked}},
            {{"relativePath", "vorbis.dll"}, {"sha256", sha256_vorbis}},
            {{"relativePath", "ogg.dll"}, {"sha256", sha256_ogg}},
            {{"relativePath", "vowac.asi"}, {"sha256", sha256_vowac}}
        })},

        // FIXED: Legitimate module paths
        {"loadedModules", json::array({
            {
                {"allowedThirdpartyHook", false},
                {"allowlistMatch", true},
                {"inGameRoot", true},
                {"lateLoad", false},
                {"loadedSinceStartSeconds", 0},
                {"name", "bass.dll"},
                {"onDiskPresent", true},
                {"path", gtaPath + "\\BASS.dll"},
                {"relativePath", "bass.dll"},
                {"sha256", sha256_bass},
                {"sizeBytes", 348160},
                {"suspiciousScore", 0}
            },
            {
                {"allowedThirdpartyHook", false},
                {"allowlistMatch", true},
                {"inGameRoot", true},
                {"lateLoad", false},
                {"loadedSinceStartSeconds", 0},
                {"name", "eax.dll"},
                {"onDiskPresent", true},
                {"path", gtaPath + "\\EAX.DLL"},
                {"relativePath", "eax.dll"},
                {"sha256", sha256_eax},
                {"sizeBytes", 196608},
                {"suspiciousScore", 0}
            },
            {
                {"allowedThirdpartyHook", false},
                {"allowlistMatch", true},
                {"inGameRoot", true},
                {"lateLoad", false},
                {"loadedSinceStartSeconds", 0},
                {"name", "gta_sa.exe"},
                {"onDiskPresent", true},
                {"path", gtaPath + "\\gta_sa.exe"},
                {"relativePath", "gta_sa.exe"},
                {"sha256", sha256_gta},
                {"sizeBytes", 18313216},
                {"suspiciousScore", 0}
            },
            {
                {"allowedThirdpartyHook", false},
                {"allowlistMatch", true},
                {"inGameRoot", true},
                {"lateLoad", false},
                {"loadedSinceStartSeconds", 0},
                {"name", "ogg.dll"},
                {"onDiskPresent", true},
                {"path", gtaPath + "\\ogg.dll"},
                {"relativePath", "ogg.dll"},
                {"sha256", sha256_ogg},
                {"sizeBytes", 36864},
                {"suspiciousScore", 0}
            },
            {
                {"allowedThirdpartyHook", false},
                {"allowlistMatch", true},
                {"inGameRoot", true},
                {"lateLoad", false},
                {"loadedSinceStartSeconds", 0},
                {"name", "samp.dll"},
                {"onDiskPresent", true},
                {"path", gtaPath + "\\samp.dll"},
                {"relativePath", "samp.dll"},
                {"sha256", sha256_samp},
                {"sizeBytes", 2613248},
                {"suspiciousScore", 0}
            },
            {
                {"allowedThirdpartyHook", false},
                {"allowlistMatch", true},
                {"inGameRoot", true},
                {"lateLoad", false},
                {"loadedSinceStartSeconds", 0},
                {"name", "vorbis.dll"},
                {"onDiskPresent", true},
                {"path", gtaPath + "\\vorbis.dll"},
                {"relativePath", "vorbis.dll"},
                {"sha256", sha256_vorbis},
                {"sizeBytes", 1081344},
                {"suspiciousScore", 0}
            },
            {
                {"allowedThirdpartyHook", false},
                {"allowlistMatch", true},
                {"inGameRoot", true},
                {"lateLoad", false},
                {"loadedSinceStartSeconds", 0},
                {"name", "vorbisfile.dll"},
                {"onDiskPresent", true},
                {"path", gtaPath + "\\vorbisfile.dll"},
                {"relativePath", "vorbisfile.dll"},
                {"sha256", sha256_vorbisfile},
                {"sizeBytes", 36864},
                {"suspiciousScore", 0}
            },
            {
                {"allowedThirdpartyHook", false},
                {"allowlistMatch", true},
                {"inGameRoot", true},
                {"lateLoad", false},
                {"loadedSinceStartSeconds", 0},
                {"name", "vorbishooked.dll"},
                {"onDiskPresent", true},
                {"path", gtaPath + "\\vorbishooked.DLL"},
                {"relativePath", "vorbishooked.dll"},
                {"sha256", sha256_vorbishooked},
                {"sizeBytes", 69632},
                {"suspiciousScore", 0}
            },
            {
                {"allowedThirdpartyHook", false},
                {"allowlistMatch", true},
                {"inGameRoot", true},
                {"lateLoad", false},
                {"loadedSinceStartSeconds", 0},
                {"name", "vowac.asi"},
                {"onDiskPresent", true},
                {"path", gtaPath + "\\vowac.asi"},
                {"relativePath", "vowac.asi"},
                {"sha256", sha256_vowac},
                {"sizeBytes", 274432},
                {"suspiciousScore", 0}
            },
            {
                {"allowedThirdpartyHook", false},
                {"allowlistMatch", true},
                {"inGameRoot", true},
                {"lateLoad", false},
                {"loadedSinceStartSeconds", 0},
                {"name", "winmm.dll"},
                {"onDiskPresent", true},
                {"path", gtaPath + "\\WINMM.dll"},
                {"relativePath", "winmm.dll"},
                {"sha256", sha256_winmm},
                {"sizeBytes", 262144},
                {"suspiciousScore", 0}
            }
        })}
    };

    return report;
}

int main() {
    // Set console title
    SetConsoleTitleA("VOWAC Protocol Emulator v1.0.0 | Coded by WaterSmoke");

    std::cout << std::endl;
    printHeader("VOWAC Protocol Emulator v1.0.0");
    std::cout << std::endl;

    curl_global_init(CURL_GLOBAL_DEFAULT);

    // Get real system information
    char computerName[256];
    DWORD size = sizeof(computerName);
    GetComputerNameA(computerName, &size);
    g_deviceName = computerName;

    char userName[256];
    DWORD userSize = sizeof(userName);
    GetUserNameA(userName, &userSize);
    g_userName = userName;

    // Generate randomized identifiers
    g_machineId = generate_machine_id();

    // Generate realistic PID
    std::uniform_int_distribution<> pid_dis(5000, 65000);
    g_gtaPid = pid_dis(gen);

    // Display system information
    setColor(COLOR_CYAN);
    std::cout << "+-------------------------------------------------------+" << std::endl;
    std::cout << "|  System Information                                   |" << std::endl;
    std::cout << "+-------------------------------------------------------+" << std::endl;
    setColor(COLOR_DEFAULT);

    setColor(COLOR_YELLOW);
    std::cout << "  Machine ID:     ";
    setColor(COLOR_DEFAULT);
    std::cout << g_machineId << std::endl;

    setColor(COLOR_YELLOW);
    std::cout << "  Client Version: ";
    setColor(COLOR_DEFAULT);
    std::cout << CLIENT_VERSION << std::endl;

    setColor(COLOR_YELLOW);
    std::cout << "  Device Name:    ";
    setColor(COLOR_DEFAULT);
    std::cout << g_deviceName << std::endl;

    setColor(COLOR_YELLOW);
    std::cout << "  User Name:      ";
    setColor(COLOR_DEFAULT);
    std::cout << g_userName << std::endl;

    setColor(COLOR_YELLOW);
    std::cout << "  GTA PID:        ";
    setColor(COLOR_DEFAULT);
    std::cout << g_gtaPid << std::endl;
    std::cout << std::endl;

    // Initialize session
    if (!attach_session()) {
        printError("Failed to attach session, exiting...");
        curl_global_cleanup();
        system("pause");
        return 1;
    }

    std::cout << std::endl;
    setColor(COLOR_GREEN);
    std::cout << "+============================================================+" << std::endl;
    std::cout << "|  Periodic reporting loop started (interval: 10s)         |" << std::endl;
    std::cout << "|  Press Ctrl+C to stop                                    |" << std::endl;
    std::cout << "+============================================================+" << std::endl;
    setColor(COLOR_DEFAULT);
    std::cout << std::endl;

    // Main reporting loop
    int report_count = 0;
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(DEFAULT_INTERVAL));

        report_count++;
        setColor(COLOR_MAGENTA);
        std::cout << "+----------------------------------------+" << std::endl;
        std::cout << "|  Report #" << std::setw(4) << report_count << "                          |" << std::endl;
        std::cout << "+----------------------------------------+" << std::endl;
        setColor(COLOR_DEFAULT);

        if (!send_report()) {
            printWarning("Report failed, attempting to reattach...");

            g_machineId = generate_machine_id();
            g_gtaPid = pid_dis(gen);

            printInfo("New Machine ID: " + g_machineId);
            printInfo("New GTA PID: " + std::to_string(g_gtaPid));

            if (!attach_session()) {
                printError("Reattach failed, exiting...");
                break;
            }
        }

        std::cout << std::endl;
    }

    curl_global_cleanup();
    return 0;
}