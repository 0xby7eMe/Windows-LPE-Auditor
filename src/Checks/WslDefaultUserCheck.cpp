#include "Checks/WslDefaultUserCheck.h"
#include "Core/Severity.h"
#include <windows.h>
#include <vector>
#include <string>

namespace WinLpeAuditor
{
    namespace Checks
    {
        CheckResult WslDefaultUserCheck::Run() {
            CheckResult result;
            result.checkName = Name();

            const std::wstring lxssPath = L"Software\\Microsoft\\Windows\\CurrentVersion\\Lxss";
            HKEY hLxssKey = NULL;

            if (RegOpenKeyExW(HKEY_CURRENT_USER, lxssPath.c_str(), 0, KEY_READ, &hLxssKey) != ERROR_SUCCESS) {
                return result;
            }

            DWORD subKeyCount = 0;
            DWORD maxSubKeyLen = 0;
            
            if (RegQueryInfoKeyW(hLxssKey, NULL, NULL, NULL, &subKeyCount, &maxSubKeyLen, NULL, NULL, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) {
                RegCloseKey(hLxssKey);
                return result;
            }

            std::vector<wchar_t> subKeyNameBuffer(maxSubKeyLen + 1);

            for (DWORD i = 0; i < subKeyCount; i++) {
                DWORD nameSize = static_cast<DWORD>(subKeyNameBuffer.size());
                
                if (RegEnumKeyExW(hLxssKey, i, subKeyNameBuffer.data(), &nameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                    std::wstring distGuid(subKeyNameBuffer.data());
                    std::wstring distSubKeyPath = lxssPath + L"\\" + distGuid;
                    
                    HKEY hDistKey = NULL;
                    if (RegOpenKeyExW(HKEY_CURRENT_USER, distSubKeyPath.c_str(), 0, KEY_READ, &hDistKey) == ERROR_SUCCESS) {
                        
                        wchar_t distName[256] = { 0 };
                        DWORD distNameSize = sizeof(distName);
                        
                        DWORD defaultUid = 0;
                        DWORD defaultUidSize = sizeof(DWORD);

                        LONG nameRes = RegQueryValueExW(hDistKey, L"DistributionName", NULL, NULL, reinterpret_cast<LPBYTE>(distName), &distNameSize);
                        LONG uidRes = RegQueryValueExW(hDistKey, L"DefaultUid", NULL, NULL, reinterpret_cast<LPBYTE>(&defaultUid), &defaultUidSize);

                        if (nameRes == ERROR_SUCCESS && uidRes == ERROR_SUCCESS) {
                            if (defaultUid == 0) {
                                std::string sDistName(distName, distName + wcslen(distName));
                                
                                Finding finding;
                                finding.severity = Severity::Medium; // Lokales Konfigurationsrisiko
                                finding.title = "WSL Distribution defaults to root user: " + sDistName;
                                finding.details.push_back({
                                    "Impact", "The Linux environment automatically logs in as root (UID 0). "
                                              "Malicious scripts or compromised software packages inside WSL can manipulate "
                                              "mounted host files with root privileges."
                                });
                                finding.details.push_back({"Distribution Name", sDistName});
                                finding.details.push_back({"Default UID", std::to_string(defaultUid) + " (root)"});
                                
                                result.findings.push_back(std::move(finding));
                            }
                        }
                        RegCloseKey(hDistKey);
                    }
                }
            }

            RegCloseKey(hLxssKey);
            return result;
        }
    }
}
