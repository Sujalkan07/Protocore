// kmp.cpp — Knuth-Morris-Pratt pattern matching implementation
#include "kmp.hpp"

namespace protocore {

// ═══════════════════════════════════════════════════════════════════
// LPS ARRAY CONSTRUCTION
// ═══════════════════════════════════════════════════════════════════
//
// The LPS (Longest Proper Prefix which is also Suffix) array is the
// key preprocessing step of the KMP algorithm.
//
// For each position i in the pattern, lps[i] stores the length of
// the longest proper prefix of pattern[0..i] that is also a suffix.
//
// Example: pattern = "ABCABD"
//   lps = [0, 0, 0, 1, 2, 0]
//
// This allows KMP to skip redundant comparisons when a mismatch
// occurs, achieving O(n + m) time complexity.

std::vector<int> buildLPSArray(const uint8_t* pattern, int patternLength) {
    std::vector<int> lps(patternLength, 0);

    // `matchLength` tracks the length of the previous longest
    // prefix-suffix match
    int matchLength = 0;

    // LPS of the first character is always 0
    int i = 1;

    while (i < patternLength) {
        if (pattern[i] == pattern[matchLength]) {
            // Characters match: extend the current prefix-suffix
            matchLength++;
            lps[i] = matchLength;
            i++;
        } else {
            if (matchLength != 0) {
                // Mismatch after some matches: fall back using
                // the LPS array itself (do NOT increment i)
                matchLength = lps[matchLength - 1];
            } else {
                // No match at all: LPS is 0, move to next character
                lps[i] = 0;
                i++;
            }
        }
    }

    return lps;
}

// ═══════════════════════════════════════════════════════════════════
// KMP PATTERN SEARCH
// ═══════════════════════════════════════════════════════════════════
//
// Searches for all occurrences of `pattern` in `text`.
//
// How it works:
// 1. Preprocess the pattern to build the LPS array.
// 2. Scan through the text with two indices:
//    - textIndex:    current position in the text
//    - patternIndex: current position in the pattern
// 3. When characters match, advance both indices.
// 4. When all pattern characters match, record the position and
//    use the LPS array to continue searching (handles overlapping).
// 5. On a mismatch, use the LPS array to skip ahead in the pattern
//    without re-examining text characters we've already matched.
//
// Time:  O(n + m) — each text character is compared at most twice
// Space: O(m) for the LPS array

std::vector<size_t> kmpSearch(const uint8_t* text, size_t textLength,
                              const uint8_t* pattern, int patternLength,
                              uint64_t* comparisonCount) {
    std::vector<size_t> matchedPositions;

    if (patternLength <= 0 || textLength == 0) {
        if (comparisonCount != nullptr) {
            *comparisonCount = 0;
        }
        return matchedPositions;
    }

    // Step 1: Build the LPS array
    std::vector<int> lps = buildLPSArray(pattern, patternLength);

    uint64_t comparisons = 0;

    // Step 2: Search through the text
    size_t textIndex    = 0;   // Current position in text
    int    patternIndex = 0;   // Current position in pattern

    while (textIndex < textLength) {
        comparisons++;

        if (text[textIndex] == pattern[patternIndex]) {
            // Characters match — advance both
            textIndex++;
            patternIndex++;

            if (patternIndex == patternLength) {
                // Full pattern matched! Record the starting position.
                matchedPositions.push_back(textIndex - patternLength);

                // Use LPS to find next potential match (supports overlapping)
                patternIndex = lps[patternIndex - 1];
            }
        } else {
            // Mismatch after patternIndex matches
            if (patternIndex != 0) {
                // Fall back in pattern using LPS without advancing textIndex
                patternIndex = lps[patternIndex - 1];
            } else {
                // No match at all — advance text
                textIndex++;
            }
        }
    }

    if (comparisonCount != nullptr) {
        *comparisonCount = comparisons;
    }

    return matchedPositions;
}

// Convenience overload for vectors
std::vector<size_t> kmpSearch(const ByteStream& text,
                              const ByteStream& pattern,
                              uint64_t* comparisonCount) {
    return kmpSearch(text.data(), text.size(),
                     pattern.data(), static_cast<int>(pattern.size()),
                     comparisonCount);
}

// ═══════════════════════════════════════════════════════════════════
// NAIVE PATTERN SEARCH
// ═══════════════════════════════════════════════════════════════════
//
// Simple brute-force O(n * m) approach. For every position in the
// text, checks if the pattern matches starting at that position.
// Used only for the performance comparison feature.

std::vector<size_t> naiveSearch(const uint8_t* text, size_t textLength,
                                const uint8_t* pattern, int patternLength,
                                uint64_t* comparisonCount) {
    std::vector<size_t> matchedPositions;

    if (patternLength <= 0 || textLength == 0 ||
        textLength < static_cast<size_t>(patternLength)) {
        if (comparisonCount != nullptr) {
            *comparisonCount = 0;
        }
        return matchedPositions;
    }

    uint64_t comparisons = 0;

    // Try every starting position in the text
    for (size_t i = 0; i <= textLength - patternLength; i++) {
        bool match = true;

        for (int j = 0; j < patternLength; j++) {
            comparisons++;
            if (text[i + j] != pattern[j]) {
                match = false;
                break;
            }
        }

        if (match) {
            matchedPositions.push_back(i);
        }
    }

    if (comparisonCount != nullptr) {
        *comparisonCount = comparisons;
    }

    return matchedPositions;
}

std::vector<size_t> naiveSearch(const ByteStream& text,
                                const ByteStream& pattern,
                                uint64_t* comparisonCount) {
    return naiveSearch(text.data(), text.size(),
                      pattern.data(), static_cast<int>(pattern.size()),
                      comparisonCount);
}

} // namespace protocore
