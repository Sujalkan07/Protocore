// test_main.cpp — Standalone test runner for PROTOCORE
//
// This file provides a main() function for running the test suite
// independently from the main application.
// Build the test executable separately using CMake (target: protocore_tests).

#include <iostream>

// Defined in test_cases.cpp
extern int runAllTests();

int main() {
    std::cout << "\n";
    std::cout << "========================================================\n";
    std::cout << "             PROTOCORE — TEST SUITE\n";
    std::cout << "========================================================\n\n";

    int failures = runAllTests();

    std::cout << "\n========================================================\n";
    if (failures == 0) {
        std::cout << "  RESULT: ALL TESTS PASSED\n";
    } else {
        std::cout << "  RESULT: " << failures << " TEST(S) FAILED\n";
    }
    std::cout << "========================================================\n\n";

    return failures;
}
