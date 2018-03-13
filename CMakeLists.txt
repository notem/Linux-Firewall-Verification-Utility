cmake_minimum_required(VERSION 3.8)
project(iptables_verification)

set(CMAKE_C_STANDARD 99)

set(SOURCE_FILES test.c utils.c/algorithm.c utils.h/algorithm.h)
add_executable(iptables_verification ${SOURCE_FILES})