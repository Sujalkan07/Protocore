// packet_parser.cpp — Packet detection, extraction and validation engine
#include "packet_parser.hpp"
#include "kmp.hpp"
#include "crc32.hpp"
#include <algorithm>
#include <set>

namespace protocore {

// ═══════════════════════════════════════════════════════════════════
// SINGLE PACKET PARSER
// ═══════════════════════════════════════════════════════════════════
// Attempts to parse a complete packet starting at `offset`.
// The offset should point to the first byte of the start signature.

ParsedPacket parsePacketAt(const ByteStream& stream, size_t offset) {
    ParsedPacket pkt;
    pkt.streamOffset = offset;
    pkt.payloadLength = 0;
    pkt.expectedCRC = 0;
    pkt.calculatedCRC = 0;
    pkt.endMarker[0] = 0;
    pkt.endMarker[1] = 0;

    size_t streamSize = stream.size();
    size_t pos = offset + SIGNATURE_SIZE; // Move past the signature

    // ── Check: enough bytes for the length field? ───────────────
    if (pos + LENGTH_FIELD_SIZE > streamSize) {
        pkt.status = PacketStatus::INCOMPLETE;
        pkt.statusDetail = "Not enough bytes for length field";
        return pkt;
    }

    // ── Read payload length (big-endian uint16) ─────────────────
    uint16_t payloadLength = (static_cast<uint16_t>(stream[pos]) << 8)
                            | static_cast<uint16_t>(stream[pos + 1]);
    pkt.payloadLength = payloadLength;
    pos += LENGTH_FIELD_SIZE;

    // ── Calculate expected total packet size ─────────────────────
    size_t expectedEnd = offset + PACKET_OVERHEAD + payloadLength;

    // ── Check: enough bytes for the complete packet? ────────────
    if (expectedEnd > streamSize) {
        pkt.status = PacketStatus::INCOMPLETE;
        pkt.statusDetail = "Stream ends before packet is complete (need "
                         + std::to_string(expectedEnd - offset)
                         + " bytes, have "
                         + std::to_string(streamSize - offset) + ")";
        return pkt;
    }

    // ── Extract the payload ─────────────────────────────────────
    pkt.payload.assign(stream.begin() + pos,
                       stream.begin() + pos + payloadLength);
    pos += payloadLength;

    // ── Read the transmitted CRC (big-endian uint32) ────────────
    pkt.expectedCRC = (static_cast<uint32_t>(stream[pos])     << 24)
                    | (static_cast<uint32_t>(stream[pos + 1]) << 16)
                    | (static_cast<uint32_t>(stream[pos + 2]) <<  8)
                    | (static_cast<uint32_t>(stream[pos + 3]));
    pos += CRC_SIZE;

    // ── Read the end marker ─────────────────────────────────────
    pkt.endMarker[0] = stream[pos];
    pkt.endMarker[1] = stream[pos + 1];

    // ── Recalculate CRC over length + payload ───────────────────
    pkt.calculatedCRC = calculatePacketCRC(payloadLength,
                                           pkt.payload.data(),
                                           pkt.payload.size());

    // ── Validate CRC ────────────────────────────────────────────
    if (pkt.expectedCRC != pkt.calculatedCRC) {
        pkt.status = PacketStatus::CRC_FAILURE;
        pkt.statusDetail = "CRC mismatch: expected 0x"
                         + ([](uint32_t v) {
                               char buf[16];
                               std::snprintf(buf, sizeof(buf), "%08X", v);
                               return std::string(buf);
                           })(pkt.expectedCRC)
                         + " but calculated 0x"
                         + ([](uint32_t v) {
                               char buf[16];
                               std::snprintf(buf, sizeof(buf), "%08X", v);
                               return std::string(buf);
                           })(pkt.calculatedCRC);
        return pkt;
    }

    // ── Validate end marker ─────────────────────────────────────
    if (pkt.endMarker[0] != END_MARKER[0] ||
        pkt.endMarker[1] != END_MARKER[1]) {
        pkt.status = PacketStatus::INVALID_END_MARKER;
        pkt.statusDetail = "End marker mismatch: expected EE FF, got "
                         + ([](uint8_t a, uint8_t b) {
                               char buf[16];
                               std::snprintf(buf, sizeof(buf), "%02X %02X", a, b);
                               return std::string(buf);
                           })(pkt.endMarker[0], pkt.endMarker[1]);
        return pkt;
    }

    // ── All checks passed ───────────────────────────────────────
    pkt.status = PacketStatus::VALID;
    pkt.statusDetail = "All validations passed";
    return pkt;
}

// ═══════════════════════════════════════════════════════════════════
// STREAM ANALYZER
// ═══════════════════════════════════════════════════════════════════
//
// Strategy:
// 1. Use KMP to find ALL occurrences of the start signature.
// 2. Walk through the matches in order.
// 3. For each match, attempt to parse a packet.
// 4. If the packet is VALID, mark its byte range as "consumed"
//    and skip any signature matches that fall inside it.
// 5. If the packet is invalid (CRC failure, bad end marker),
//    record it and move on to the next match.
// 6. If the packet is incomplete, record it and continue.
// 7. Any bytes not covered by a recognized packet are noise.

AnalysisResult analyzeStream(const ByteStream& stream) {
    AnalysisResult result;
    result.totalBytes = stream.size();
    result.noiseBytes = 0;

    if (stream.empty()) {
        return result;
    }

    // Step 1: Find all signature positions using KMP
    ByteStream pattern(START_SIGNATURE.begin(), START_SIGNATURE.end());
    result.signatureHits = kmpSearch(stream, pattern);

    // Track which byte ranges are consumed by valid/parsed packets
    // We use a set of consumed byte offsets for noise calculation
    std::set<size_t> consumedBytes;

    size_t nextValidStart = 0; // Don't re-parse inside a validated packet

    for (size_t idx = 0; idx < result.signatureHits.size(); idx++) {
        size_t sigPos = result.signatureHits[idx];

        // Skip this signature if it falls inside a previously validated packet
        if (sigPos < nextValidStart) {
            continue;
        }

        // Step 2: Attempt to parse a packet at this position
        ParsedPacket pkt = parsePacketAt(stream, sigPos);
        result.packets.push_back(pkt);

        // Step 3: If valid, advance past this packet's boundary
        if (pkt.status == PacketStatus::VALID) {
            size_t packetEnd = sigPos + PACKET_OVERHEAD + pkt.payloadLength;
            for (size_t b = sigPos; b < packetEnd; b++) {
                consumedBytes.insert(b);
            }
            nextValidStart = packetEnd;
        }
        else if (pkt.status == PacketStatus::CRC_FAILURE ||
                 pkt.status == PacketStatus::INVALID_END_MARKER) {
            // These are structurally complete but invalid packets —
            // still mark their bytes as consumed (they're not noise)
            size_t packetEnd = sigPos + PACKET_OVERHEAD + pkt.payloadLength;
            for (size_t b = sigPos; b < packetEnd; b++) {
                consumedBytes.insert(b);
            }
        }
        else if (pkt.status == PacketStatus::INCOMPLETE) {
            // Mark consumed from sigPos to end of stream
            for (size_t b = sigPos; b < stream.size(); b++) {
                consumedBytes.insert(b);
            }
        }
    }

    // Step 4: Calculate noise bytes
    result.noiseBytes = stream.size() - consumedBytes.size();

    return result;
}

} // namespace protocore
