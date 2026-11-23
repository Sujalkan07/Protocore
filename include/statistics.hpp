// statistics.hpp — Validation statistics computed from analysis results
#ifndef PROTOCORE_STATISTICS_HPP
#define PROTOCORE_STATISTICS_HPP

#include "packet_parser.hpp"
#include <cstdint>

namespace protocore {

// ─── Statistics Summary ─────────────────────────────────────────────
struct Statistics {
    size_t totalBytes          = 0;
    size_t signatureMatches    = 0;
    size_t packetsAccepted     = 0;
    size_t corruptedPackets    = 0;  // CRC failures
    size_t incompletePackets   = 0;
    size_t malformedCandidates = 0;
    size_t invalidEndMarker    = 0;
    size_t noiseBytes          = 0;
    size_t totalValidPayload   = 0;  // Sum of payload lengths of valid packets
};

// ─── Compute Statistics ─────────────────────────────────────────────
// Calculates statistics from an AnalysisResult.
Statistics computeStatistics(const AnalysisResult& result);

// ─── Display Statistics ─────────────────────────────────────────────
// Prints a formatted statistics summary to the terminal.
void displayStatistics(const Statistics& stats);

} // namespace protocore

#endif // PROTOCORE_STATISTICS_HPP
