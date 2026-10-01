#include "Checks/PointAndPrintCheck.h"
#include "Checks/RegistryUtils.h"
#include "Core/Severity.h"

namespace WinLpeAuditor
{
    namespace Checks
    {
        CheckResult PointAndPrintCheck::Run() {
            CheckResult result;
            result.checkName = Name();

            const std::wstring regPath = L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint";
            
            const bool noWarningInstall = Util::RegistryDwordEquals1(HKEY_LOCAL_MACHINE, regPath, L"NoWarningNoElevationOnInstall");
            
            const bool noWarningUpdate = Util::RegistryDwordEquals1(HKEY_LOCAL_MACHINE, regPath, L"UpdatePromptSettings");

            const bool restrictToAdmins = Util::RegistryDwordEquals1(HKEY_LOCAL_MACHINE, regPath, L"RestrictDriverInstallationToAdministrators");

            if (noWarningInstall || !restrictToAdmins) {
                Finding finding;
                finding.severity = Severity::Critical;
                finding.title = "Vulnerable Point and Print configuration detected";
                
                finding.details.push_back({
                    "Impact", "A low-privileged user can trick the Print Spooler into installing a "
                              "remote malicious print driver, leading to immediate SYSTEM privilege escalation."
                });

                finding.details.push_back({"NoWarningNoElevationOnInstall", noWarningInstall ? "Enabled (Vulnerable)" : "Disabled/Not Configured"});
                finding.details.push_back({"UpdatePromptSettings", noWarningUpdate ? "Suppress Warnings (Vulnerable)" : "Show Prompt"});
                finding.details.push_back({"RestrictDriverInstallationToAdministrators", restrictToAdmins ? "Restricted to Admins (Secure)" : "Allowed for regular users (Vulnerable)"});
                
                result.findings.push_back(std::move(finding));
            }

            return result;
        }
    }
}
