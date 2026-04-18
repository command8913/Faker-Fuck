#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <winsock2.h>
#include <winternl.h>
#include <vector>
#include <string>
#include <iostream>
#include <cstdio>
#include <algorithm>
#include <regex>
#include <sstream>
#include <fstream>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "urlmon.lib")

constexpr const char* DNS = "mshome.net";
constexpr const char* IP = "192.168.137.1";
constexpr const wchar_t* TARGET_PROC = L"javaw.exe";
constexpr const wchar_t* DLL = L"win_redirect.dll";

constexpr const char* WNW_DOWNLOAD_URL = "https://www.nirsoft.net/utils/wnetwatcher.zip";
constexpr const char* WNW_ZIP_FILE = "wnetwatcher.zip";
constexpr const char* WNW_EXE_FILE = "WNetWatcher.exe";
constexpr const char* WNW_CFG_FILE = "WNetWatcher.cfg";

inline std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}

inline bool containsIgnoreCase(const std::string& haystack, const std::string& needle) {
    return lower(haystack).find(lower(needle)) != std::string::npos;
}

std::string execCommand(const char* cmd) {
    std::string out;
    if (FILE* p = _popen(cmd, "r")) {
        char b[256];
        while (fgets(b, sizeof(b), p)) out += b;
        _pclose(p);
    }
    return out;
}

bool downloadFile(const char* url, const char* outputPath) {
    HRESULT hr = URLDownloadToFileA(NULL, url, outputPath, 0, NULL);
    return (hr == S_OK);
}

bool extractZip(const char* zipPath, const char* destPath) {
    std::string cmd = "powershell -command \"Expand-Archive -Force -Path '" +
                      std::string(zipPath) + "' -DestinationPath '" +
                      std::string(destPath) + "'\"";
    int result = system(cmd.c_str());
    return (result == 0);
}

bool ensureWNetWatcher() {
    if (GetFileAttributesA(WNW_EXE_FILE) != INVALID_FILE_ATTRIBUTES) {
        return true;
    }

    if (!downloadFile(WNW_DOWNLOAD_URL, WNW_ZIP_FILE)) {
        return false;
    }

    if (!extractZip(WNW_ZIP_FILE, ".")) {
        return false;
    }

    DeleteFileA(WNW_ZIP_FILE);

    return (GetFileAttributesA(WNW_EXE_FILE) != INVALID_FILE_ATTRIBUTES);
}

struct NetworkDevice {
    std::string macAddress;
    std::string ipAddress;
    std::string deviceName;
    std::string deviceInfo;
    std::string lastDetectTime;
    std::string firstDetectTime;
    int detectCount;
    std::string userText;
};

std::vector<NetworkDevice> scanWithWNetWatcher() {
    std::vector<NetworkDevice> devices;

    if (!ensureWNetWatcher()) {
        return devices;
    }

    std::string cmd = std::string(WNW_EXE_FILE) + " /stab temp.txt";
    system(cmd.c_str());


    Sleep(3000);
    std::ifstream cfg(WNW_CFG_FILE);
    if (!cfg.is_open()) {
        return devices;
    }

    std::string line;
    NetworkDevice currentDevice;
    bool inDevice = false;

    while (std::getline(cfg, line)) {
        if (line.find("[Device_") == 0) {
            if (inDevice && !currentDevice.macAddress.empty()) {
                devices.push_back(currentDevice);
            }
            currentDevice = NetworkDevice();
            inDevice = true;

            std::regex macRe(R"(Device_([0-9A-Fa-f\-]+))");
            std::smatch match;
            if (std::regex_search(line, match, macRe)) {
                currentDevice.macAddress = match[1].str();
            }
        }
        else if (inDevice) {
            if (line.find("LastDetectTime=") == 0) {
                currentDevice.lastDetectTime = line.substr(16);
            }
            else if (line.find("FirstDetectTime=") == 0) {
                currentDevice.firstDetectTime = line.substr(17);
            }
            else if (line.find("DetectCount=") == 0) {
                currentDevice.detectCount = std::stoi(line.substr(12));
            }
            else if (line.find("UserText=") == 0) {
                currentDevice.userText = line.substr(9);
            }
            else if (line.find("IPAddress=") == 0) {
                unsigned long ipRaw = std::stoul(line.substr(10));
                struct in_addr addr;
                addr.S_un.S_addr = ipRaw;
                currentDevice.ipAddress = inet_ntoa(addr);
            }
            else if (line.find("Name=") == 0) {
                currentDevice.deviceName = line.substr(5);
            }
            else if (line.find("HostType=") == 0) {
                int hostType = std::stoi(line.substr(9));
                switch(hostType) {
                    case 0: currentDevice.deviceInfo = "Your Router"; break;
                    case 1: currentDevice.deviceInfo = "Your Computer"; break;
                    default: currentDevice.deviceInfo = ""; break;
                }
            }
        }
    }

    if (inDevice && !currentDevice.macAddress.empty()) {
        devices.push_back(currentDevice);
    }

    cfg.close();

    DeleteFileA("temp.txt");

    return devices;
}

void displayNetworkDevices() {
    std::vector<NetworkDevice> devices = scanWithWNetWatcher();

    if (devices.empty()) {
        return;
    }

    std::cout << "\n[=] Devices in network:\n\n";

    printf("%-18s %-22s %-18s %-16s %-12s %-20s\n",
           "MAC Address", "Device Name", "IP Address", "Device Info", "Count", "Last Seen");
    printf("%-18s %-22s %-18s %-16s %-12s %-20s\n",
           "-----------", "-----------", "-----------", "-----------", "-----", "----------");

    for (const auto& dev : devices) {
        std::string devName = dev.deviceName.empty() ? "" : dev.deviceName;
        if (devName.length() > 22) devName = devName.substr(0, 19) + "...";

        std::string devInfo = dev.deviceInfo.empty() ? "" : dev.deviceInfo;
        if (devInfo.length() > 16) devInfo = devInfo.substr(0, 13) + "...";

        std::string macUpper = dev.macAddress;
        std::transform(macUpper.begin(), macUpper.end(), macUpper.begin(), ::toupper);

        printf("%-18s %-22s %-18s %-16s %-12d %-20s\n",
               macUpper.c_str(),
               devName.c_str(),
               dev.ipAddress.c_str(),
               devInfo.c_str(),
               dev.detectCount,
               dev.lastDetectTime.c_str());
    }

    std::cout << "\n";
}

void checkNetwork(bool& dns, bool& ip) {
    std::string out = execCommand("ipconfig /all");
    std::string l = lower(out);
    dns = l.find(lower(DNS)) != std::string::npos;
    ip = l.find(lower(IP)) != std::string::npos;
}

bool checkModule() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe = { sizeof(PROCESSENTRY32W) };
    bool found = false;

    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, TARGET_PROC) == 0) {
                HANDLE hModSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pe.th32ProcessID);
                if (hModSnap != INVALID_HANDLE_VALUE) {
                    MODULEENTRY32W me = { sizeof(MODULEENTRY32W) };
                    if (Module32FirstW(hModSnap, &me)) {
                        do {
                            if (_wcsicmp(me.szModule, DLL) == 0) {
                                found = true;
                                break;
                            }
                        } while (Module32NextW(hModSnap, &me));
                    }
                    CloseHandle(hModSnap);
                }
                if (found) break;
            }
        } while (Process32NextW(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return found;
}

bool checkPortOnly(const char* port) {
    std::string netstat = execCommand("netstat -ano");
    if (netstat.empty()) return false;

    std::stringstream ss(netstat);
    std::string line;
    DWORD foundPid = 0;

    while (std::getline(ss, line)) {
        if (line.find(port) != std::string::npos) {
            std::regex pidRe(R"((\d+)\s*$)");
            std::smatch match;
            if (std::regex_search(line, match, pidRe)) {
                foundPid = std::stoul(match[1].str());
                break;
            }
        }
    }

    if (foundPid == 0) return false;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe = { sizeof(PROCESSENTRY32W) };
    bool isJavaw = false;

    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, TARGET_PROC) == 0 && pe.th32ProcessID == foundPid) {
                isJavaw = true;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);

    return isJavaw;
}

bool checkSpecificJavawPortOnly() {
    return checkPortOnly("0.0.0.0:25565");
}

bool checkSpecificJavawLocalhostPortOnly() {
    return checkPortOnly("127.0.0.1:25565");
}

bool checkHostedNetwork() {
    std::string out = execCommand("netsh wlan show hostednetwork");
    std::regex statusRe(R"(Status\s*:\s*(.+))", std::regex::icase);
    std::smatch match;

    if (std::regex_search(out, match, statusRe)) {
        std::string status = match[1].str();
        status.erase(0, status.find_first_not_of(" \t"));
        return (_stricmp(status.c_str(), "Started") == 0);
    }
    return false;
}

bool checkMobileHotspot() {
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;

    SC_HANDLE svc = OpenServiceA(scm, "icssvc", SERVICE_QUERY_STATUS);
    if (!svc) {
        CloseServiceHandle(scm);
        return false;
    }

    SERVICE_STATUS_PROCESS status;
    DWORD bytesNeeded;
    bool running = false;

    if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO,
                             (LPBYTE)&status, sizeof(status), &bytesNeeded)) {
        running = (status.dwCurrentState == SERVICE_RUNNING);
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return running;
}

bool checkVirtualAdapters() {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}",
        0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return false;
    }

    const char* virtualPatterns[] = {
       "Microsoft Wi-Fi Direct Virtual Adapter"
    };

    char subKeyName[256];
    DWORD index = 0;
    bool found = false;

    while (!found && RegEnumKeyA(hKey, index++, subKeyName, sizeof(subKeyName)) == ERROR_SUCCESS) {
        HKEY hSubKey;
        if (RegOpenKeyExA(hKey, subKeyName, 0, KEY_READ, &hSubKey) == ERROR_SUCCESS) {
            char desc[512] = {0};
            DWORD size = sizeof(desc);

            if (RegQueryValueExA(hSubKey, "DriverDesc", nullptr, nullptr,
                                (LPBYTE)desc, &size) == ERROR_SUCCESS) {
                for (const auto& pattern : virtualPatterns) {
                    if (containsIgnoreCase(desc, pattern)) {
                        found = true;
                        break;
                    }
                }
            }
            RegCloseKey(hSubKey);
        }
    }

    RegCloseKey(hKey);
    return found;
}

bool checkMdnsDisabled() {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD enable = 1;
        DWORD size = sizeof(enable);
        if (RegQueryValueExA(hKey, "EnableMulticast", nullptr, nullptr,
                             (LPBYTE)&enable, &size) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return enable == 0;
        }
        RegCloseKey(hKey);
    }
    return false;
}

bool checkHttpHostSpoofing() {
    std::string curl = execCommand("curl -s -m 2 http://mshome.net -D - 2>nul");
    if (curl.find("Host:") != std::string::npos && !curl.empty()) {
        return true;
    }
    return false;
}

bool checkFakerProxy() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) return false;

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return false;
    }

    int timeout = 2000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));

    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(25565);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(sock);
        WSACleanup();
        return false;
    }

    unsigned char handshake[] = {
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03
    };

    send(sock, (char*)handshake, sizeof(handshake), 0);

    char buffer[1024] = {0};
    int received = recv(sock, buffer, sizeof(buffer) - 1, 0);
    closesocket(sock);
    WSACleanup();

    return (received == 0);
}

int main() {
    std::cout << "Scan:";
    std::cout << "\n";
    displayNetworkDevices();
    std::vector<std::pair<std::string, bool>> checks;

    bool dns = false, ip = false;
    checkNetwork(dns, ip);
    checks.push_back({"#1", dns});
    checks.push_back({"#2", ip});
    checks.push_back({"#3", checkModule()});
    checks.push_back({"#4", checkHostedNetwork()});
    checks.push_back({"#5", checkMobileHotspot()});
    checks.push_back({"#6", checkVirtualAdapters()});
    checks.push_back({"#7", checkSpecificJavawPortOnly()});
    checks.push_back({"#8", checkSpecificJavawLocalhostPortOnly()});
    checks.push_back({"#9", checkMdnsDisabled()});
    checks.push_back({"#10", checkHttpHostSpoofing()});
    checks.push_back({"#11", checkFakerProxy()});

    std::vector<std::string> found;
    for (const auto& check : checks) {
        if (check.second) found.push_back(check.first);
    }

    if (!found.empty()) {
        std::cout << "[+] Faker Fuck ";
        for (size_t i = 0; i < found.size(); ++i)
            std::cout << (i ? " + " : "") << found[i];
        std::cout << "\n";
    } else {
        std::cout << "[-] Faker not found\n";
    }

    return 0;
}