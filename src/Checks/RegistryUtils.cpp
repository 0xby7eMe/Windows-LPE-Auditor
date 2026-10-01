#include "Checks/RegistryUtils.h"

namespace WinLpeAuditor
{
    namespace Util
    {

    bool RegistryDwordEquals1(HKEY hKeyRoot, const std::wstring& subKey, const std::wstring& valueName) {
        HKEY hKey;
        if (RegOpenKeyExW(hKeyRoot, subKey.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
            return false;
        }

        DWORD value = 0;
        DWORD valueSize = sizeof(DWORD);
        DWORD type = 0;
        LONG status = RegQueryValueExW(hKey, valueName.c_str(), nullptr, &type,
                                        reinterpret_cast<LPBYTE>(&value), &valueSize);
        RegCloseKey(hKey);

        if (status != ERROR_SUCCESS || type != REG_DWORD) return false;
        return value == 1;
    }
    }
}
