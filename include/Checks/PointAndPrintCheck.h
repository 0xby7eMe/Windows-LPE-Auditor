#pragma once
#include "Core/ICheck.h"

namespace WinLpeAuditor
{
    namespace Checks
    {
        class PointAndPrintCheck : public ICheck {
        public:
            std::string Id() const override { return "point-and-print"; }
            std::string Name() const override { return "Point and Print Restrictions Policy"; }
            std::string Description() const override {
                return "Checks the Point and Print registry configurations under HKLM. If configured "
                       "to suppress warnings and elevation, any local user can force the Print Spooler "
                       "to load an arbitrary driver/DLL as SYSTEM (PrintNightmare variant).";
            }
            CheckResult Run() override;
        };
    }
}
