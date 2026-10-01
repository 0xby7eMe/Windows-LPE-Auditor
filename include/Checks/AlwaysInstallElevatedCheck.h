#pragma once
#include "../Core/ICheck.h"

namespace WinLpeAuditor
{
    namespace Checks
    {

        class AlwaysInstallElevatedCheck : public ICheck {
        public:
            std::string Id() const override { return "always-install-elevated"; }
            std::string Name() const override { return "AlwaysInstallElevated Policy"; }
            std::string Description() const override {
                return "Checks whether both HKCU and HKLM set AlwaysInstallElevated=1, which "
                       "lets any local user run a malicious .msi with SYSTEM privileges.";
            }
            CheckResult Run() override;
        };
    }
}
