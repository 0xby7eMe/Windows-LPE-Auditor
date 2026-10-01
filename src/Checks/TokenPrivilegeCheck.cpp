#include "Checks/TokenPrivilegeCheck.h"
#include "Core/Severity.h"
#include <windows.h>
#include <vector>

namespace WinLpeAuditor
{
    namespace Checks
    {
        CheckResult TokenPrivilegeCheck::Run() {
            CheckResult result;
            result.checkName = Name();

            HANDLE hToken = NULL;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
                Finding errorFinding;
                errorFinding.severity = Severity::Low;
                errorFinding.title = "Failed to open process token";
                errorFinding.details.push_back({"Error Code", std::to_string(GetLastError())});
                result.findings.push_back(std::move(errorFinding));
                return result;
            }

            DWORD tokenInfoLength = 0;
            GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &tokenInfoLength);
            
            if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
                CloseHandle(hToken);
                return result;
            }

            std::vector<BYTE> buffer(tokenInfoLength);
            PTOKEN_PRIVILEGES privileges = reinterpret_cast<PTOKEN_PRIVILEGES>(buffer.data());

            if (!GetTokenInformation(hToken, TokenPrivileges, privileges, tokenInfoLength, &tokenInfoLength)) {
                CloseHandle(hToken);
                return result;
            }

            for (DWORD i = 0; i < privileges->PrivilegeCount; i++) {
                wchar_t privName[256];
                DWORD privNameSize = sizeof(privName) / sizeof(wchar_t);

                if (LookupPrivilegeNameW(NULL, &privileges->Privileges[i].Luid, privName, &privNameSize)) {
                    std::wstring wideName(privName);
                    std::string name(wideName.begin(), wideName.end()); 
                    
                    bool isEnabled = (privileges->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED);
                    std::string status = isEnabled ? "Enabled" : "Disabled (Available)";

                    Finding finding;
                    bool isDangerous = false;

                    if (name == "SeImpersonatePrivilege" || name == "SeAssignPrimaryTokenPrivilege") {
                        finding.severity = Severity::Critical;
                        finding.title = "Dangerous privilege available: " + name;
                        finding.details.push_back({"Impact", "Allows SYSTEM escalation via Potato exploits (e.g., PrintSpoofer, GodPotato)."});
                        isDangerous = true;
                    }
                    else if (name == "SeDebugPrivilege") {
                        finding.severity = Severity::Critical;
                        finding.title = "Dangerous privilege available: " + name;
                        finding.details.push_back({"Impact", "Allows memory dumping (e.g., LSASS) and process injection into SYSTEM processes."});
                        isDangerous = true;
                    }
                    else if (name == "SeTakeOwnershipPrivilege") {
                        finding.severity = Severity::High;
                        finding.title = "High-risk privilege available: " + name;
                        finding.details.push_back({"Impact", "Allows taking ownership of any file or registry key, bypassing ACLs."});
                        isDangerous = true;
                    }
                    else if (name == "SeBackupPrivilege" || name == "SeRestorePrivilege") {
                        finding.severity = Severity::High;
                        finding.title = "High-risk privilege available: " + name;
                        finding.details.push_back({"Impact", "Allows reading/writing any system file, making it easy to dump SAM or NTDS.dit."});
                        isDangerous = true;
                    }

                    if (isDangerous) {
                        finding.details.push_back({"Current Status", status});
                        result.findings.push_back(std::move(finding));
                    }
                }
            }

            CloseHandle(hToken);
            return result;
        }
    }
}
