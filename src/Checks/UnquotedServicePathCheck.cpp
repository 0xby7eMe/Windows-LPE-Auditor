
#include <vector>
#include <windows.h>

#include "Core/Severity.h"
#include "Checks/UnquotedServicePathCheck.h"
#include "Util/StringUtils.h"

namespace WinLpeAuditor
{
    namespace Checks
    {

        namespace {

            bool IsUnquotedAndVulnerable(const std::wstring& binaryPath) {
                if (binaryPath.find(L' ') == std::wstring::npos) return false;
                if (!binaryPath.empty() && binaryPath.front() == L'"') return false;
                if (binaryPath.find(L"system32") != std::wstring::npos ||
                    binaryPath.find(L"System32") != std::wstring::npos) {
                    return false;
                }
                return true;
            }

        }  // namespace

        CheckResult UnquotedServicePathCheck::Run() {
            CheckResult result;
            result.checkName = Name();

            SC_HANDLE hScm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
            if (hScm == nullptr) {
                result.ranSuccessfully = false;
                result.errorMessage = "Could not open the Service Control Manager (error " +
                                       std::to_string(GetLastError()) + ").";
                return result;
            }

            DWORD bytesNeeded = 0, servicesReturned = 0, resumeHandle = 0;
            EnumServicesStatusExW(hScm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                                   nullptr, 0, &bytesNeeded, &servicesReturned, &resumeHandle, nullptr);

            if (GetLastError() != ERROR_MORE_DATA) {
                result.ranSuccessfully = false;
                result.errorMessage =
                    "Initial service enumeration failed (error " + std::to_string(GetLastError()) + ").";
                CloseServiceHandle(hScm);
                return result;
            }

            std::vector<BYTE> buffer(bytesNeeded);
            auto* services = reinterpret_cast<LPENUM_SERVICE_STATUS_PROCESSW>(buffer.data());

            if (!EnumServicesStatusExW(hScm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                                        buffer.data(), bytesNeeded, &bytesNeeded, &servicesReturned,
                                        &resumeHandle, nullptr)) {
                result.ranSuccessfully = false;
                result.errorMessage =
                    "Could not enumerate services (error " + std::to_string(GetLastError()) + ").";
                CloseServiceHandle(hScm);
                return result;
            }

            for (DWORD i = 0; i < servicesReturned; ++i) {
                SC_HANDLE hService = OpenServiceW(hScm, services[i].lpServiceName, SERVICE_QUERY_CONFIG);
                if (hService == nullptr) continue;

                DWORD configBytesNeeded = 0;
                QueryServiceConfigW(hService, nullptr, 0, &configBytesNeeded);

                std::vector<BYTE> configBuffer(configBytesNeeded);
                auto* serviceConfig = reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(configBuffer.data());

                if (QueryServiceConfigW(hService, serviceConfig, configBytesNeeded, &configBytesNeeded)) {
                    std::wstring binaryPath = serviceConfig->lpBinaryPathName;
                    if (IsUnquotedAndVulnerable(binaryPath)) {
                        Finding finding;
                        finding.severity = Severity::High;
                        finding.title = Util::WideToUtf8(services[i].lpServiceName);
                        finding.details.push_back({"Binary path", Util::WideToUtf8(binaryPath)});
                        finding.details.push_back(
                            {"Start type", std::to_string(serviceConfig->dwStartType)});
                        result.findings.push_back(std::move(finding));
                    }
                }
                CloseServiceHandle(hService);
            }

            CloseServiceHandle(hScm);
            return result;
        }
    }
}
