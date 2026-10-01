#include "Checks/StartupFolderCheck.h"
#include "Core/Severity.h"
#include <windows.h>
#include <shlobj.h>
#include <aclapi.h>
#include <vector>
#include <string>

namespace WinLpeAuditor
{
    namespace Checks
    {
        bool IsDirectoryWritableByGroup(const std::wstring& dirPath, const std::wstring& groupName) {
            PSECURITY_DESCRIPTOR pSD = NULL;
            PACL pDacl = NULL;
            
            if (GetNamedSecurityInfoW(dirPath.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, 
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
                ACCESS_MASK writeMask = GENERIC_WRITE | FILE_WRITE_DATA | FILE_ADD_FILE | FILE_APPEND_DATA | FILE_ADD_SUBDIRECTORY;
                if ((accessRights & writeMask) != 0) {
                    LocalFree(pSD);
                    return true;
                }
            }

            if (pSD) LocalFree(pSD);
            return false;
        }

        CheckResult StartupFolderCheck::Run() {
            CheckResult result;
            result.checkName = Name();

            wchar_t szPath[MAX_PATH];
            if (SHGetFolderPathW(NULL, CSIDL_COMMON_STARTUP, NULL, 0, szPath) != S_OK) {
                Finding errorFinding;
                errorFinding.severity = Severity::Low;
                errorFinding.title = "Failed to resolve global Startup folder path";
                result.findings.push_back(std::move(errorFinding));
                return result;
            }

            std::wstring startupPath(szPath);
            std::vector<std::wstring> weakGroups = { L"Everyone", L"Authenticated Users", L"Users", L"BUILTIN\\Users" };

            for (const auto& group : weakGroups) {
                if (IsDirectoryWritableByGroup(startupPath, group)) {
                    std::string sStartupPath(startupPath.begin(), startupPath.end());
                    std::string sGroup(group.begin(), group.end());

                    Finding finding;
                    finding.severity = Severity::High;
                    finding.title = "Global Startup directory is writable by unprivileged group";
                    finding.details.push_back({"Impact", "Any user can drop a shortcut (.lnk) or binary here, compromising high-privileged users upon login."});
                    finding.details.push_back({"Path Detected", sStartupPath});
                    finding.details.push_back({"Vulnerable Group", sGroup});
                    
                    result.findings.push_back(std::move(finding));
                    break;
                }
            }

            return result;
        }
    }
}
