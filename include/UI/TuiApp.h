#pragma once
#include "../Core/AuditEngine.h"

namespace WinLpeAuditor
{
    namespace UI
    {

        class TuiApp {
        public:
            explicit TuiApp(AuditEngine& engine) : engine_(engine) {}
            void Run();

        private:
            AuditEngine& engine_;
        };
    }
}
