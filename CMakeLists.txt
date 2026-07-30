cmake_minimum_required(VERSION 3.20)
project(c2_loader C)

# Static CRT (/MT) — no vcruntime140.dll dependency on the target.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")

set(LOADER_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/loader.c)

# EXE variant: WIN32 → /SUBSYSTEM:WINDOWS (no console window), entry wWinMain.
add_executable(loader_exe WIN32 ${LOADER_SRC})
set_target_properties(loader_exe PROPERTIES OUTPUT_NAME "loader")

# DLL variant: BUILD_DLL → DllMain entry, loads via rundll32/inject.
add_library(loader_dll SHARED ${LOADER_SRC})
target_compile_definitions(loader_dll PRIVATE BUILD_DLL)
set_target_properties(loader_dll PROPERTIES OUTPUT_NAME "loader")
