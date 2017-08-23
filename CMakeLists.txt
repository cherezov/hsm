cmake_minimum_required (VERSION 2.6)

project (engine)

SET(CMAKE_CXX_FLAGS "-std=c++11")
SET(CMAKE_CXX_COMPILER "g++")

include_directories(/git/OpenSC/src/pkcs11)
link_directories(/git/OpenSC/src/common/.libs)

add_executable(engine aes_hsm.cpp)
target_link_libraries (engine pkcs11 scdl dl)
