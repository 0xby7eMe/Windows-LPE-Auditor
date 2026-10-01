#pragma once
#include "../Core/ICheck.h"

namespace WinLpeAuditor
{
    namespace Checks
    {

        class UnquotedServicePathCheck : public ICheck {
        public:
            std::string Id() const override { return "unquoted-service-path"; }
            std::string Name() const override { return "Unquoted Service Paths"; }
            std::string Description() const override {
                return "Finds Win32 services whose binary path is unquoted and contains spaces "
                       "outside system32. A local user who can write earlier in that path can "
                       "plant an executable and gain SYSTEM on service start.";
            }
            CheckResult Run() override;
        };
    }
}
