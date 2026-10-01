#pragma once
#include "Core/ICheck.h"

namespace WinLpeAuditor
{
    namespace Checks
    {
        class ModifiableServiceBinariesCheck : public ICheck
        {
        public:
            std::string Id() const override { return "modifiable-service-binaries"; };
            std::string Name() const override { return "Modifiable Service Binaries"; }
            std::string Description() const override
            {
                return "Scans all Windows services and checks their binary file permission (ACLs) "
                          "for weak write permissions granted to low-privileged user groups.";
            }
            CheckResult Run() override;
        };
    }
}