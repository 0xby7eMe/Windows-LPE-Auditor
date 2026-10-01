#include "Checks/ModifiableServiceBinariesCheck.h"
#include "Core/Severity.h"
#include <windows.h>
#include <tlhelp32.h>
#include <aclapi.h>
#include <vector>
#include <string>

namespace WinLpeAuditor
{
    namespace Checks
    {
        std::wstring ExtractFilePath(const std::wstring& rawPath) {
            if (rawPath.empty()) return L"";
            std::wstring cleanPath = rawPath;
            
            if (cleanPath[0] == L'"') {
                size_t nextQuote = cleanPath.find(L'"', 1);
                if (nextQuote != std::wstring::npos) {
                    return cleanPath.substr(1, nextQuote - 1);
                }
            }
            
            size_t exePos = cleanPath.find(L".exe");
            if (exePos != std::wstring::npos) {
                return cleanPath.substr(0, exePos + 4);
            }
            
            return cleanPath;
        }
        
         bool HasGroupWriteAccess(const std::wstring& filePath, const std::wstring& groupName) {
            PSECURITY_DESCRIPTOR pSD = NULL;
            PACL pDacl = NULL;
            
            if (GetNamedSecurityInfoW(filePath.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, 
                                      NULL, NULL, &pDacl, NULL, &pSD) != ERROR_SUCCESS) {
                return false;
            }

            TRUSTEE_W trustee;
            trustee.pMultipleTrustee = NULL;
            trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
            trustee.TrusteeForm = TRUSTEE_IS_NAME;
            trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
            trustee.ptstrName = const_cast<LPWSTR>(groupName.c_str());

            ACCESS_MASK accessRights = 0;
            if (GetEffectiveRightsFromAclW(pDacl, &trustee, &accessRights) == ERROR_SUCCESS) {
                ACCESS_MASK writeMask = GENERIC_WRITE | FILE_WRITE_DATA | FILE_APPEND_DATA | KEY_WRITE;
                if ((accessRights & writeMask) != 0) {
                    LocalFree(pSD);
                    return true;
                }
            }

            if (pSD) LocalFree(pSD);
            return false;
        }

        CheckResult ModifiableServiceBinariesCheck::Run() {
            CheckResult result;
            result.checkName = Name();

            SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
            if (hSCM == NULL) {
                Finding errorFinding;
                errorFinding.severity = Severity::Low;
                errorFinding.title = "Failed to open SCM";
                errorFinding.details.push_back({"Error Code", std::to_string(GetLastError())});
                result.findings.push_back(std::move(errorFinding));
                return result;
            }

            DWORD bytesNeeded = 0;
            DWORD servicesReturned = 0;
            DWORD resumeHandle = 0;

            EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, 
                                  NULL, 0, &bytesNeeded, &servicesReturned, &resumeHandle, NULL);

            if (GetLastError() != ERROR_MORE_DATA) {
                CloseHandle(hSCM);
                return result;
            }

            std::vector<BYTE> buffer(bytesNeeded);
            LPENUM_SERVICE_STATUS_PROCESSW services = reinterpret_cast<LPENUM_SERVICE_STATUS_PROCESSW>(buffer.data());

            if (!EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, 
                                       buffer.data(), bytesNeeded, &bytesNeeded, &servicesReturned, &resumeHandle, NULL)) {
                CloseHandle(hSCM);
                return result;
            }

            std::vector<std::wstring> weakGroups = { L"Everyone", L"Authenticated Users", L"Users", L"BUILTIN\\Users" };

            for (DWORD i = 0; i < servicesReturned; i++) {
                SC_HANDLE hService = OpenServiceW(hSCM, services[i].lpServiceName, SERVICE_QUERY_CONFIG);
                if (hService == NULL) continue;

                DWORD configBytesNeeded = 0;
                QueryServiceConfigW(hService, NULL, 0, &configBytesNeeded);

                std::vector<BYTE> configBuffer(configBytesNeeded);
                LPQUERY_SERVICE_CONFIGW serviceConfig = reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(configBuffer.data());

                if (QueryServiceConfigW(hService, serviceConfig, configBytesNeeded, &configBytesNeeded)) {
                    std::wstring rawPath = serviceConfig->lpBinaryPathName;
                    std::wstring cleanPath = ExtractFilePath(rawPath);

                    if (!cleanPath.empty()) {
                        if (cleanPath.find(L"system32") == std::wstring::npos && cleanPath.find(L"System32") == std::wstring::npos) {
                            
                            for (const auto& group : weakGroups) {
                                if (HasGroupWriteAccess(cleanPath, group)) {
                                    std::string sServiceName(services[i].lpServiceName, services[i].lpServiceName + wcslen(services[i].lpServiceName));
                                    std::string sCleanPath(cleanPath.begin(), cleanPath.end());
                                    std::string sGroup(group.begin(), group.end());

                                    Finding finding;
                                    finding.severity = Severity::Critical;
                                    finding.title = "Weak file permissions on service binary: " + sServiceName;
                                    finding.details.push_back({"Impact", "Any user in the vulnerable group can replace the binary to gain elevated privileges."});
                                    finding.details.push_back({"Binary Path", sCleanPath});
                                    finding.details.push_back({"Vulnerable Group", sGroup});
                                    finding.details.push_back({"Service User Context", serviceConfig->lpServiceStartName ? std::string(serviceConfig->lpServiceStartName, serviceConfig->lpServiceStartName + wcslen(serviceConfig->lpServiceStartName)) : "Unknown"});
                                    
                                    result.findings.push_back(std::move(finding));
                                    break; // Eine verwundbare Gruppe reicht für ein valides Finding
                                }
                            }
                        }
                    }
                }
                CloseHandle(hService);
            }

            CloseHandle(hSCM);
            return result;
        }
    }
}