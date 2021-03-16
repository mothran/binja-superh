cmake_minimum_required(VERSION 3.11)
project(BinjaArchSuperH)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build Types: Debug|Release" FORCE)
endif(NOT CMAKE_BUILD_TYPE)

SET(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -march=native")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -march=native")
endif(CMAKE_BUILD_TYPE STREQUAL "Release")

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O1 -g")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O1 -g")
endif(CMAKE_BUILD_TYPE STREQUAL "Debug")

set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)


# binaryninja-api
FetchContent_Declare(
    binaryninja_api
    GIT_REPOSITORY  https://github.com/Vector35/binaryninja-api.git
    GIT_TAG         dev
)
message("Fetching binaryninja-api, please hold ....")
FetchContent_MakeAvailable(binaryninja_api)

# catch2
FetchContent_Declare(
  Catch2
  GIT_REPOSITORY https://github.com/catchorg/Catch2.git
  GIT_TAG        v2.13.1)
FetchContent_MakeAvailable(Catch2)
list(APPEND CMAKE_MODULE_PATH ${Catch2_SOURCE_DIR}/contrib)


# Generated code
find_program(PYTHON3_BIN NAMES python3)

set(generated_code ${CMAKE_CURRENT_SOURCE_DIR}/src/disasm-gen.inc)
add_custom_command(OUTPUT ${generated_code}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/fetch-parse.py
    COMMAND ${PYTHON3_BIN} ${CMAKE_CURRENT_SOURCE_DIR}/fetch-parse.py > ${generated_code}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Generating decoder..."
)
add_custom_target(gen-decoder ALL DEPENDS ${generated_code})

# Disassembler code
add_library(disasm_superh STATIC
    src/disasm.cpp
)
add_dependencies(disasm_superh gen-decoder)
target_include_directories(disasm_superh PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src/
)
target_link_libraries(disasm_superh PRIVATE
    binaryninjaapi
)

# Helper tool

add_executable(sh_disasm
    src/sh_disasm.cpp
)
target_link_libraries(sh_disasm PRIVATE
    disasm_superh
)
target_include_directories(sh_disasm PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/
    ${binaryninja_api_SOURCE_DIR}
)

# binja plugin

add_library(arch_superh SHARED
    src/arch_superh.cpp
    src/branches.cpp
    src/il.cpp
)
target_link_libraries(arch_superh PRIVATE
    binaryninjaapi
    disasm_superh
)
target_include_directories(arch_superh PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/
)

set_target_properties(arch_superh PROPERTIES
    CXX_STANDARD 17
    CXX_VISIBILITY_PRESET hidden
    CXX_STANDARD_REQUIRED ON
    C_STANDARD 99
    C_STANDARD_REQUIRED ON
    C_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
    POSITION_INDEPENDENT_CODE ON
)

# grouped target
add_custom_target(sh-all)
add_dependencies(sh-all arch_superh sh_disasm)


# Testing
enable_testing()
add_subdirectory(test/)