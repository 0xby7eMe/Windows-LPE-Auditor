#pragma once
#include "Core/ICheck.h"

namespace WinLpeAuditor
{
    namespace Checks
    {
        class TokenPrivilegeCheck : public ICheck {
        public:
            std::string Id() const override { return "token-privileges"; }
            std::string Name() const override { return "Dangerous Token Privileges"; }
            std::string Description() const override {
                return "Analyzes the current process token for high-risk Windows privileges "
                       "(e.g., SeImpersonatePrivilege, SeDebugPrivilege) that can be abused for LPE.";
            }
            CheckResult Run() override;
        };
    }
}
