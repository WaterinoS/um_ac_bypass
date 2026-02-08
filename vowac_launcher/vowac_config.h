// vowac_config.h - Configuration reader for VOWAC whitelist
//

#ifndef VOWAC_CONFIG_H
#define VOWAC_CONFIG_H

#include <string>
#include <vector>
#include <unordered_set>
#include <fstream>
#include <sstream>

class VowacConfigReader {
private:
    std::string vowacDir;
    std::string gtaSADir;
    std::unordered_set<std::string> whitelistExtensions;
    std::unordered_set<std::string> whitelistFolders;

    // Convert string to lowercase
    static std::string ToLower(const std::string& str) {
        std::string result = str;
        std::transform(result.begin(), result.end(), result.begin(), ::tolower);
        return result;
    }

    // Trim whitespace
    static std::string Trim(const std::string& str) {
        size_t first = str.find_first_not_of(" \t\r\n");
        if (std::string::npos == first) {
            return str;
        }
        size_t last = str.find_last_not_of(" \t\r\n");
        return str.substr(first, (last - first + 1));
    }

public:
    VowacConfigReader(const std::string& configPath = "vowac_config.ini") {
        LoadConfig(configPath);
    }

    // Load configuration from INI file
    bool LoadConfig(const std::string& configPath) {
        std::ifstream configFile(configPath);
        
        if (!configFile.is_open()) {
            return false;
        }

        std::string line;
        std::string currentSection;

        while (std::getline(configFile, line)) {
            line = Trim(line);

            // Skip empty lines and comments
            if (line.empty() || line[0] == ';') {
                continue;
            }

            // Check for section headers
            if (line[0] == '[' && line[line.length() - 1] == ']') {
                currentSection = line.substr(1, line.length() - 2);
                continue;
            }

            // Parse key-value pairs
            size_t equalPos = line.find('=');
            if (equalPos == std::string::npos) {
                continue;
            }

            std::string key = Trim(line.substr(0, equalPos));
            std::string value = Trim(line.substr(equalPos + 1));

            if (currentSection == "Paths") {
                if (key == "vowac_dir") {
                    vowacDir = value;
                } else if (key == "gtasa_dir") {
                    gtaSADir = value;
                }
            } else if (currentSection == "Whitelist.Extensions") {
                whitelistExtensions.insert(ToLower(value));
            } else if (currentSection == "Whitelist.Folders") {
                whitelistFolders.insert(ToLower(value));
            }
        }

        configFile.close();
        return true;
    }

    // Check if file extension is whitelisted
    bool IsExtensionWhitelisted(const std::string& filename) const {
        size_t dotPos = filename.find_last_of('.');
        if (dotPos == std::string::npos) {
            return false;
        }

        std::string ext = ToLower(filename.substr(dotPos));
        return whitelistExtensions.find(ext) != whitelistExtensions.end();
    }

    // Check if folder is whitelisted
    bool IsFolderWhitelisted(const std::string& folderPath) const {
        std::string lowerPath = ToLower(folderPath);
        
        for (const auto& folder : whitelistFolders) {
            if (lowerPath.find(folder) != std::string::npos) {
                return true;
            }
        }

        return false;
    }

    const std::string& GetVowacDir() const { return vowacDir; }
    const std::string& GetGTASADir() const { return gtaSADir; }
};

#endif // VOWAC_CONFIG_H