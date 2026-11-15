cmake_minimum_required(VERSION 3.22.1)
project(kanaf_scan LANGUAGES CXX)
add_library(kanaf_scan SHARED native_scanner.cpp)
target_compile_features(kanaf_scan PRIVATE cxx_std_17)
# Android 15+ requires 16 KiB ELF PT_LOAD alignment for native libraries.
target_link_options(kanaf_scan PRIVATE
    "-Wl,-z,max-page-size=16384"
    "-Wl,-z,common-page-size=16384")
target_compile_options(kanaf_scan PRIVATE -Wall -Wextra -Werror -fstack-protector-strong)
target_link_libraries(kanaf_scan PRIVATE ${CMAKE_DL_LIBS} log)
