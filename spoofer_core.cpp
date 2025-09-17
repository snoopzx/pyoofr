#include <iostream>
#include <windows.h>
#include <string>
#include <vector>

std::wstring string_to_wstring(const std::string& s) {
    return std::wstring(s.begin(), s.end());
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

void SpoofMotherboard(const std::string& newSerial) {
    std::cout << "[*] Applying deep motherboard spoof with serial: " << newSerial << std::endl;
    const std::string regPath = "SYSTEM\\CurrentControlSet\\Control\\SystemInformation";
    SetRegistryString(HKEY_LOCAL_MACHINE, regPath, "SystemSerialNumber", newSerial);
    SetRegistryString(HKEY_LOCAL_MACHINE, regPath, "BaseBoardSerialNumber", newSerial);
}

void SpoofCPU(const std::string& newIdentifier) {
    std::cout << "[*] Applying deep CPU spoof with identifier: " << newIdentifier << std::endl;
    const std::string regPathVolatile = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0";
    const std::string regPathPersistent = "SYSTEM\\CurrentControlSet\\Control\\SystemInformation";
    
    const std::string cpuName = "Intel(R) Core(TM) i9-10900K CPU @ 3.70GHz";

    SetRegistryString(HKEY_LOCAL_MACHINE, regPathVolatile, "ProcessorNameString", cpuName);
    SetRegistryString(HKEY_LOCAL_MACHINE, regPathVolatile, "Identifier", newIdentifier);
    SetRegistryString(HKEY_LOCAL_MACHINE, regPathPersistent, "ProcessorIdentifier", newIdentifier);
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage:\n"
                  << "  spoofer_core.exe --motherboard <new_serial>\n"
                  << "  spoofer_core.exe --cpu <new_identifier>\n";
        return 1;
    }

    std::string mode = argv[1];
    std::string value = argv[2];

    if (mode == "--motherboard") {
        SpoofMotherboard(value);
    } else if (mode == "--cpu") {
        SpoofCPU(value);
    } else {
        std::cerr << "Invalid mode specified." << std::endl;
        return 1;
    }

    return 0;
}