cmake_minimum_required(VERSION 3.10)

project(FileEncryptor)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread -march=native")

add_executable(FileEncryptor main.cpp common.cpp crypt.cpp keygen.cpp sign.cpp verify.cpp)

target_link_libraries(FileEncryptor ntl gmp m)