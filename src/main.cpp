#include "Checks/AlwaysInstallElevatedCheck.h"
#include "Checks/UnquotedServicePathCheck.h"
#include "Core/AuditEngine.h"
#include "UI/TuiApp.h"

#include <memory>

int main() {
    using namespace WinLpeAuditor;

    AuditEngine engine;
    engine.Register(std::make_unique<Checks::UnquotedServicePathCheck>());
    engine.Register(std::make_unique<Checks::AlwaysInstallElevatedCheck>());

    UI::TuiApp app(engine);
    app.Run();
    return 0;
}