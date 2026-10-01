#include "Checks/AlwaysInstallElevatedCheck.h"
#include "Checks/RegistryUtils.h"
#include "Core/Severity.h"

namespace WinLpeAuditor
{
    namespace Checks
    {

        CheckResult AlwaysInstallElevatedCheck::Run() {
            CheckResult result;
            result.checkName = Name();

            const std::wstring regPath = L"Software\\Policies\\Microsoft\\Windows\\Installer";
            const bool hkcuSet = Util::RegistryDwordEquals1(HKEY_CURRENT_USER, regPath, L"AlwaysInstallElevated");
            const bool hklmSet = Util::RegistryDwordEquals1(HKEY_LOCAL_MACHINE, regPath, L"AlwaysInstallElevated");

            if (hkcuSet && hklmSet) {
                Finding finding;
                finding.severity = Severity::Critical;
                finding.title = "AlwaysInstallElevated is enabled machine-wide and per-user";
                finding.details.push_back(
                    {"Impact", "Any local user can craft a malicious .msi that installs with SYSTEM rights."});
                finding.details.push_back({"HKCU", "Enabled"});
                finding.details.push_back({"HKLM", "Enabled"});
                result.findings.push_back(std::move(finding));
            }

            return result;
        }
    }
}
