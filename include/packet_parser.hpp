// packet_parser.hpp — Packet detection, extraction and validation engine
#ifndef PROTOCORE_PACKET_PARSER_HPP
#define PROTOCORE_PACKET_PARSER_HPP

#include "protocol.hpp"
#include "packet.hpp"
#include <vector>

namespace protocore {

// ─── Analysis Result ────────────────────────────────────────────────
// Contains all packets found in a stream plus parsing metadata.
struct AnalysisResult {
    std::vector<ParsedPacket> packets;      // All detected packet candidates
    std::vector<size_t>       signatureHits; // All signature positions (from KMP)
    size_t                    totalBytes;    // Total bytes in the stream
    size_t                    noiseBytes;    // Bytes not belonging to any packet
};

// ─── Stream Analyzer ────────────────────────────────────────────────
// 1. Uses KMP to find all occurrences of the start signature.
// 2. For each candidate, attempts to parse a full packet.
// 3. After validating a packet, advances past its boundary.
// 4. For invalid candidates, resumes from the next byte.
// 5. For incomplete candidates, records them and stops (no bytes to read).
//
// Returns an AnalysisResult containing all findings.
AnalysisResult analyzeStream(const ByteStream& stream);

// ─── Single Packet Parser (internal but exposed for testing) ────────
// Attempts to parse a packet starting at `offset` in the stream.
// Returns a ParsedPacket with appropriate status.
ParsedPacket parsePacketAt(const ByteStream& stream, size_t offset);

} // namespace protocore

#endif // PROTOCORE_PACKET_PARSER_HPP
