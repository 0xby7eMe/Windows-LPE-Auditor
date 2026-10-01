#pragma once
#include <string>
#include <windows.h>

namespace WinLpeAuditor
{
    namespace Util
    {
        inline std::string WideToUtf8(const std::wstring& wide) {
            if (wide.empty()) return {};
            int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()),
                                                  nullptr, 0, nullptr, nullptr);
            std::string result(sizeNeeded, '\0');
            WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()),
                                 LPSTR(result.data()), sizeNeeded, nullptr, nullptr);
            return result;
        }
    }
}
