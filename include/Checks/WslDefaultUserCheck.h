#pragma once
#include "Core/ICheck.h"

namespace WinLpeAuditor
{
    namespace Checks
    {
        class WslDefaultUserCheck : public ICheck {
        public:
            std::string Id() const override { return "wsl-default-user"; }
            std::string Name() const override { return "WSL Root Default User Configuration"; }
            std::string Description() const override {
                return "Audits installed Windows Subsystem for Linux (WSL) distributions "
                       "to check if they default to the root user (UID 0), increasing cross-subsystem risks.";
            }
            CheckResult Run() override;
        };
    }
}
