cmake_minimum_required(VERSION 3.21)
project(WinLpeAuditor LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT WIN32)
    message(FATAL_ERROR "WinLpeAuditor targets Windows only (uses Win32 Registry/SCM APIs).")
endif()

include(FetchContent)
FetchContent_Declare(ftxui
    GIT_REPOSITORY https://github.com/ArthurSonzogni/FTXUI.git
    GIT_TAG v5.0.0
)
FetchContent_MakeAvailable(ftxui)

add_executable(WinLpeAuditor
    src/main.cpp
    src/Core/AuditEngine.cpp
    src/Checks/RegistryUtils.cpp
    src/Checks/UnquotedServicePathCheck.cpp
    src/Checks/AlwaysInstallElevatedCheck.cpp
    src/Checks/TokenPrivilegeCheck.cpp
    src/Checks/ModifiableServiceBinariesCheck.cpp
    src/Checks/PointAndPrintCheck.cpp
    src/Checks/StartupFolderCheck.cpp
    src/Checks/RegistryRunKeysCheck.cpp
    src/Checks/WslDefaultUserCheck.cpp
    src/UI/TuiApp.cpp
)

target_include_directories(WinLpeAuditor PRIVATE include)

target_link_libraries(WinLpeAuditor
    PRIVATE
        ftxui::screen
        ftxui::dom
        ftxui::component
        Advapi32
)

target_compile_definitions(WinLpeAuditor PRIVATE UNICODE _UNICODE)