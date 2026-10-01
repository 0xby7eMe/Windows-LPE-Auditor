#pragma once
#include "ICheck.h"
#include <functional>
#include <memory>
#include <vector>

namespace WinLpeAuditor
{
    class AuditEngine
    {
    public: 
        void Register(std::unique_ptr<ICheck> check);
        const std::vector<std::unique_ptr<ICheck>>& Checks() const { return checks_; }
        
        using ProgressCallback = std::function<void(size_t done, size_t total, const ICheck& check)>;
        
        std::vector<CheckResult> RunAll(const std::vector<size_t>& indices,
                                    const ProgressCallback& onProgress = nullptr);
        
    private:
        std::vector<std::unique_ptr<ICheck>> checks_;
    };
}