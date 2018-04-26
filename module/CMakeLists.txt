cmake_minimum_required(VERSION 3.8)
project(iptables_verification)

set(CMAKE_C_STANDARD 99)

set(SOURCE_FILES src/test.c src/algorithm.c src/algorithm.h)
add_executable(alg_test ${SOURCE_FILES})
