cmake_minimum_required(VERSION 3.10)

project(EncryptSystem)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread -march=native")

add_executable(EncryptSystem main.cpp common.cpp crypt.cpp keygen.cpp sign.cpp)

target_link_libraries(EncryptSystem ntl gmp m)

install(TARGETS EncryptSystem DESTINATION /usr/local/bin)

set(CPACK_GENERATOR DEB)
set(CPACK_PACKAGE_NAME "EncryptSystem")
set(CPACK_PACKAGE_VERSION "1.0.1")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Zehua Huang <huangzh84@outlook.com>")
include(CPack)