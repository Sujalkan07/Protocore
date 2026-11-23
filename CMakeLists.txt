cmake_minimum_required(VERSION 3.16)
project(Protocore VERSION 1.0 LANGUAGES CXX)

# ── C++17 Standard ───────────────────────────────────────────────
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ── Compiler Warnings ───────────────────────────────────────────
if(MSVC)
    add_compile_options(/W4)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# ── Include Directory ────────────────────────────────────────────
include_directories(${CMAKE_SOURCE_DIR}/include)

# ── Source Files (shared library modules) ────────────────────────
set(PROTOCORE_SOURCES
    src/packet.cpp
    src/kmp.cpp
    src/crc32.cpp
    src/packet_parser.cpp
    src/stream_generator.cpp
    src/file_handler.cpp
    src/statistics.cpp
)

# ── Main Application Executable ─────────────────────────────────
# The main app includes test_cases.cpp so "Run Test Scenarios" works
# from the menu (option 7 calls runAllTests defined in test_cases.cpp).
add_executable(protocore
    src/main.cpp
    tests/test_cases.cpp
    ${PROTOCORE_SOURCES}
)

# ── Standalone Test Executable ──────────────────────────────────
# A separate executable for running tests without the interactive menu.
add_executable(protocore_tests
    tests/test_main.cpp
    tests/test_cases.cpp
    ${PROTOCORE_SOURCES}
)

# ── Copy sample_data directory to build output ──────────────────
file(COPY ${CMAKE_SOURCE_DIR}/sample_data DESTINATION ${CMAKE_BINARY_DIR})
