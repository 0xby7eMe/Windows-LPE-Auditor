#include <memory>

#include "Core/ICheck.h"
#include "Core/AuditEngine.h"

namespace WinLpeAuditor
{
    void AuditEngine::Register(std::unique_ptr<ICheck> check)
    {
        checks_.push_back(std::move(check));
    }
    
    std::vector<CheckResult> AuditEngine::RunAll(const std::vector<size_t>& indices, const ProgressCallback& onProgress) {
        std::vector<CheckResult> results(checks_.size());

        size_t done = 0;
        for (size_t index : indices) {
            if (index >= checks_.size()) continue;
            ICheck& check = *checks_[index];

            if (onProgress) onProgress(done, indices.size(), check);

            CheckResult result;
            result.checkName = check.Name();
            try {
                result = check.Run();
                result.checkName = check.Name();
            } catch (const std::exception& ex) {
                result.ranSuccessfully = false;
                result.errorMessage = ex.what();
            } catch (...) {
                result.ranSuccessfully = false;
                result.errorMessage = "Unknown error";
            }

            results[index] = std::move(result);
            ++done;
        }
        return results;
    }
    
}
