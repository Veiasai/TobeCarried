PROJECT(CTP)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14")
set(CMAKE_BUILD_TYPE "Debug")

CMAKE_MINIMUM_REQUIRED(VERSION 2.6)

add_subdirectory(ptrace)
add_subdirectory(benchmark)
add_subdirectory(spdlog)
add_subdirectory(yaml-cpp)
add_subdirectory(cxxopts)

# GTest
add_subdirectory(googletest)
enable_testing()