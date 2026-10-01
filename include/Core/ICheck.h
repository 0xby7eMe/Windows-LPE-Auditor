#pragma once
#include "Finding.h"
#include <string>

namespace WinLpeAuditor
{
    class ICheck
    {
    public:
        virtual ~ICheck() = default;
        virtual std::string Id() const = 0;
        virtual std::string Name() const = 0;
        virtual std::string Description() const = 0;
        virtual CheckResult Run() = 0;
    };
}