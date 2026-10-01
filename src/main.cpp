#include "Checks/AlwaysInstallElevatedCheck.h"
#include "Checks/UnquotedServicePathCheck.h"
#include "Checks/TokenPrivilegeCheck.h"
#include "Checks/RegistryRunKeysCheck.h"
#include "Checks/StartupFolderCheck.h"
#include "Checks/PointAndPrintCheck.h"
#include "Checks/ModifiableServiceBinariesCheck.h"
#include "Checks/WslDefaultUserCheck.h"
#include "Core/AuditEngine.h"
#include "UI/TuiApp.h"

#include <memory>


int main() {
    using namespace WinLpeAuditor;

    AuditEngine engine;
    engine.Register(std::make_unique<Checks::UnquotedServicePathCheck>());
    engine.Register(std::make_unique<Checks::AlwaysInstallElevatedCheck>());
    engine.Register(std::make_unique<Checks::TokenPrivilegeCheck>());
    engine.Register(std::make_unique<Checks::ModifiableServiceBinariesCheck>());
    engine.Register(std::make_unique<Checks::PointAndPrintCheck>());
    engine.Register(std::make_unique<Checks::RegistryRunKeysCheck>());
    engine.Register(std::make_unique<Checks::StartupFolderCheck>());
    engine.Register(std::make_unique<Checks::WslDefaultUserCheck>());

    UI::TuiApp app(engine);
    app.Run();
    return 0;
}
