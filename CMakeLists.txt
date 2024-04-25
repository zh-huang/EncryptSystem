cmake_minimum_required(VERSION 3.10)

project(EncryptSystem)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread -march=native")

if(WIN32)
    include_directories(C:/msys64/usr/local/include)
endif()

add_executable(EncryptSystem main.cpp common.cpp crypt.cpp keygen.cpp sign.cpp)

if(WIN32)
    find_library(NTL_LIB NAMES ntl PATHS C:/msys64/usr/local/lib NO_DEFAULT_PATH)
    target_link_libraries(EncryptSystem ${NTL_LIB} gmp m)
else()
    target_link_libraries(EncryptSystem ntl gmp m)
endif()

if(WIN32)
    install(TARGETS EncryptSystem DESTINATION EncryptSystem)
else()
    install(TARGETS EncryptSystem DESTINATION /usr/local/bin)
endif()

if(WIN32)
    set(CPACK_GENERATOR NSIS)
    set(CPACK_NSIS_CREATE_ICONS_EXTRA "CreateShortCut \\\"$SMPROGRAMS\\\\$STARTMENU_FOLDER\\\\EncryptSystem.lnk\\\" \\\"$INSTDIR\\\\EncryptSystem.exe\\\"")
    set(CPACK_NSIS_MODIFY_PATH ON)
else()
    set(CPACK_GENERATOR DEB)
endif()
set(CPACK_PACKAGE_NAME "EncryptSystem")
set(CPACK_PACKAGE_VERSION "1.0.4")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Zehua Huang <huangzh84@outlook.com>")
include(CPack)