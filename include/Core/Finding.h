#pragma once
#include <string>
#include <utility>
#include <vector>

#include "Severity.h"

namespace WinLpeAuditor
{
    struct Finding
    {
        Severity severity = Severity::Info;
        std::string title;
        std::vector<std::pair<std::string, std::string>> details; // label -> value
    };
    
    struct CheckResult
    {
        std::string checkName;
        bool ranSuccessfully = true;
        std::string errorMessage;
        std::vector<Finding> findings;
        
        bool IsClean() const { return ranSuccessfully && findings.empty(); }
    };
}
