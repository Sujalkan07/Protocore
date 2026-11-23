// kmp.hpp — Knuth-Morris-Pratt pattern matching for binary streams
#ifndef PROTOCORE_KMP_HPP
#define PROTOCORE_KMP_HPP

#include "protocol.hpp"
#include <vector>
#include <cstdint>

namespace protocore {

// ─── LPS Array Construction ─────────────────────────────────────────
// Builds the Longest Proper Prefix which is also Suffix (LPS) array
// for the given pattern.
//
// Time:  O(m) where m = pattern length
// Space: O(m)
std::vector<int> buildLPSArray(const uint8_t* pattern, int patternLength);

// ─── KMP Pattern Search ─────────────────────────────────────────────
// Searches for all occurrences of `pattern` in `text` using the KMP
// algorithm. Returns a vector of zero-based byte offsets where the
// pattern starts.
//
// Works correctly with binary data, null bytes, non-printable bytes,
// repeated and overlapping patterns.
//
// Time:  O(n + m) where n = text length, m = pattern length
// Space: O(m) for the LPS array
//
// `comparisonCount` (optional): if non-null, the total number of
//   byte comparisons performed is stored here.
std::vector<size_t> kmpSearch(const uint8_t* text, size_t textLength,
                              const uint8_t* pattern, int patternLength,
                              uint64_t* comparisonCount = nullptr);

// ─── Convenience overloads using vectors ────────────────────────────
std::vector<size_t> kmpSearch(const ByteStream& text,
                              const ByteStream& pattern,
                              uint64_t* comparisonCount = nullptr);

// ─── Naive Pattern Search (for comparison) ──────────────────────────
// Simple O(n*m) brute-force search, used only for the performance
// comparison feature.
std::vector<size_t> naiveSearch(const uint8_t* text, size_t textLength,
                                const uint8_t* pattern, int patternLength,
                                uint64_t* comparisonCount = nullptr);

std::vector<size_t> naiveSearch(const ByteStream& text,
                                const ByteStream& pattern,
                                uint64_t* comparisonCount = nullptr);

} // namespace protocore

#endif // PROTOCORE_KMP_HPP
