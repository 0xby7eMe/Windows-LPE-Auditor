#pragma once
#include "Core/ICheck.h"

namespace WinLpeAuditor
{
    namespace Checks
    {
        class StartupFolderCheck : public ICheck {
        public:
            std::string Id() const override { return "startup-folder"; }
            std::string Name() const override { return "Logon Autostart (Startup Folder)"; }
            std::string Description() const override {
                return "Audits the file system permissions of the global Windows Startup folder "
                       "to check for weak ACLs that allow standard users to plant malicious shortcuts.";
            }
            CheckResult Run() override;
        };
    }
}
