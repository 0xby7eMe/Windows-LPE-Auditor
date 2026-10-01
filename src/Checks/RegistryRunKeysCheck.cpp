#include "Checks/RegistryRunKeysCheck.h"
#include "Core/Severity.h"
#include <windows.h>
#include <aclapi.h>
#include <vector>
#include <string>

namespace WinLpeAuditor
{
    namespace Checks
    {
        bool HasRegistryKeyWriteAccess(HKEY hKeyRoot, const std::wstring& subKey, const std::wstring& groupName) {
            HKEY hKey = NULL;
            if (RegOpenKeyExW(hKeyRoot, subKey.c_str(), 0, READ_CONTROL, &hKey) != ERROR_SUCCESS) {
                return false;
            }

            PSECURITY_DESCRIPTOR pSD = NULL;
            PACL pDacl = NULL;
            if (GetSecurityInfo(hKey, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, &pDacl, NULL, &pSD) != ERROR_SUCCESS) {
                RegCloseKey(hKey);
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
                if ((accessRights & (KEY_WRITE | KEY_SET_VALUE)) != 0) {
                    LocalFree(pSD);
                    RegCloseKey(hKey);
                    return true;
                }
            }

            if (pSD) LocalFree(pSD);
            RegCloseKey(hKey);
            return false;
        }

        CheckResult RegistryRunKeysCheck::Run() {
            CheckResult result;
            result.checkName = Name();

            std::vector<std::wstring> runKeys = {
                L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
                L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
            };

            std::vector<std::wstring> weakGroups = { L"Everyone", L"Authenticated Users", L"Users", L"BUILTIN\\Users" };

            for (const auto& keyPath : runKeys) {
                for (const auto& group : weakGroups) {
                    if (HasRegistryKeyWriteAccess(HKEY_LOCAL_MACHINE, keyPath, group)) {
                        std::string sKeyPath(keyPath.begin(), keyPath.end());
                        std::string sGroup(group.begin(), group.end());

                        Finding finding;
                        finding.severity = Severity::High;
                        finding.title = "Weak permissions on global Autostart Registry Key";
                        finding.details.push_back({"Impact", "An unprivileged user can insert commands executed automatically when any user (including Administrators) logs in."});
                        finding.details.push_back({"Registry Path", "HKLM\\" + sKeyPath});
                        finding.details.push_back({"Vulnerable Group", sGroup});
                        
                        result.findings.push_back(std::move(finding));
                        break; 
                    }
                }
            }

            return result;
        }
    }
}
