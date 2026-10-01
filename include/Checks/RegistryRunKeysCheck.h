#pragma once
#include "Core/ICheck.h"

namespace WinLpeAuditor
{
    namespace Checks
    {
        class RegistryRunKeysCheck : public ICheck {
        public:
            std::string Id() const override { return "registry-run-keys"; }
            std::string Name() const override { return "Logon Autostart (Registry Run Keys)"; }
            std::string Description() const override {
                return "Checks the permissions (ACLs) of global Windows Run/RunOnce registry keys "
                       "to ensure low-privileged users cannot inject autostart entries for administrators.";
            }
            CheckResult Run() override;
        };
    }
}