# CMake snippet for building the host-side tools.
cmake_minimum_required(VERSION 2.6.4)
project(CFETOOLS C)

set(CMAKE_C_FLAGS_RELEASE "-O3")

add_compile_definitions(DontPrint=1)

set(CFS_DIR /code)

add_subdirectory(benchmark)

add_subdirectory(cFS-GroundSystem/Subsystems/cmdUtil)
add_subdirectory(elf2cfetbl)
add_subdirectory(tblCRCTool)

