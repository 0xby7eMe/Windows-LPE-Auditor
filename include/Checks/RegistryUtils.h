#pragma once
#include <string>
#include <windows.h>

namespace WinLpeAuditor
{
    namespace Util
    {

        bool RegistryDwordEquals1(HKEY hKeyRoot, const std::wstring& subKey, const std::wstring& valueName);
    }
}
