#include <iostream>
#include <windows.h>
#include <string>
#include <vector>
#include <fstream>
#include <random>
#include "json.hpp"

using json = nlohmann::json;
std::wstring string_to_wstring(const std::string& s) {
    return std::wstring(s.begin(), s.end());
}
std::vector<std::string> load_cpu_names(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Error: Could not open JSON file: " << filename << std::endl;
        return {};
    }

    json data;
    try {
        file >> data;
        return data.at("processors").get<std::vector<std::string>>();
    } catch (json::exception& e) {
        std::cerr << "Error: JSON parsing failed: " << e.what() << std::endl;
        return {};
    }
}
bool SetRegistryString(HKEY rootKey, const std::string& subKeyPath_s, const std::string& valueName_s, const std::string& data_s) {
    std::wstring subKeyPath_w = string_to_wstring(subKeyPath_s);
    std::wstring valueName_w = string_to_wstring(valueName_s);
    std::wstring data_w = string_to_wstring(data_s);

    HKEY hKey;
    LONG openRes = RegOpenKeyExW(rootKey, subKeyPath_w.c_str(), 0, KEY_SET_VALUE, &hKey);
    if (openRes != ERROR_SUCCESS) {
        std::cerr << "Error: Could not open registry key. Code: " << openRes << std::endl;
        return false;
    }

    LONG setRes = RegSetValueExW(hKey, valueName_w.c_str(), 0, REG_SZ, (const BYTE*)data_w.c_str(), (data_w.length() + 1) * sizeof(wchar_t));
    if (setRes != ERROR_SUCCESS) {
        std::cerr << "Error: Could not set registry value. Code: " << setRes << std::endl;
        RegCloseKey(hKey);
        return false;
    }

    RegCloseKey(hKey);
    std::cout << "[+] Spoofed: " << subKeyPath_s << "\\" << valueName_s << std::endl;
    return true;
}
void Spooffatherboard(const std::string& newSerial) {
    std::cout << "[*] Applying deep fatherboard spoof with serial: " << newSerial << std::endl;
    const std::string regPath = "SYSTEM\\CurrentControlSet\\Control\\SystemInformation";
    SetRegistryString(HKEY_LOCAL_MACHINE, regPath, "SystemSerialNumber", newSerial);
    SetRegistryString(HKEY_LOCAL_MACHINE, regPath, "BaseBoardSerialNumber", newSerial);
}
void SpoofCPU(const std::string& newIdentifier) {
    std::cout << "[*] Applying deep CPU spoof with identifier: " << newIdentifier << std::endl;

    std::vector<std::string> cpuNames = load_cpu_names("processors.json");
    if (cpuNames.empty()) {
        std::cerr << "Error: No CPU names loaded. Aborting CPU spoof." << std::endl;
        return;
    }
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(0, cpuNames.size() - 1);
    const std::string randomCpuName = cpuNames[distrib(gen)];
    
    std::cout << "[+] Selected random CPU: " << randomCpuName << std::endl;
    const std::string regPathVolatile = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0";
    const std::string regPathPersistent = "SYSTEM\\CurrentControlSet\\Control\\SystemInformation";
    SetRegistryString(HKEY_LOCAL_MACHINE, regPathVolatile, "ProcessorNameString", randomCpuName);
    SetRegistryString(HKEY_LOCAL_MACHINE, regPathVolatile, "Identifier", newIdentifier);
    SetRegistryString(HKEY_LOCAL_MACHINE, regPathPersistent, "ProcessorIdentifier", newIdentifier);
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage:\n"
                  << "  spoofer_core.exe --fatherboard <new_serial>\n"
                  << "  spoofer_core.exe --cpu <new_identifier>\n";
        return 1;
    }

    std::string mode = argv[1];
    std::string value = argv[2];

    if (mode == "--fatherboard") {
        Spooffatherboard(value);
    } else if (mode == "--cpu") {
        SpoofCPU(value);
    } else {
        std::cerr << "Invalid mode specified." << std::endl;
        return 1;
    }

    return 0;
}