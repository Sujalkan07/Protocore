// packet_parser.cpp — Packet detection, extraction and validation engine
#include "packet_parser.hpp"
#include "kmp.hpp"
#include "crc32.hpp"
#include <algorithm>
#include <vector>
#include <cstdio>

namespace protocore {

// ═══════════════════════════════════════════════════════════════════
// SINGLE PACKET PARSER
// ═══════════════════════════════════════════════════════════════════
// Inspects candidate packet starting at `offset`.
// Returns a ParsedPacket with the exact classification and detail.

ParsedPacket parsePacketAt(const ByteStream& stream, size_t offset) {
    ParsedPacket pkt;
    pkt.streamOffset = offset;
    pkt.payloadLength = 0;
    pkt.expectedCRC = 0;
    pkt.calculatedCRC = 0;
    pkt.endMarker[0] = 0;
    pkt.endMarker[1] = 0;

    size_t streamSize = stream.size();

    // ── Check: start signature available? ───────────────────────
    if (offset + SIGNATURE_SIZE > streamSize) {
        pkt.status = PacketStatus::INCOMPLETE;
        pkt.statusDetail = "Stream truncated within start signature";
        return pkt;
    }

    for (size_t i = 0; i < SIGNATURE_SIZE; i++) {
        if (stream[offset + i] != START_SIGNATURE[i]) {
            pkt.status = PacketStatus::MALFORMED;
            pkt.statusDetail = "Invalid start signature bytes";
            return pkt;
        }
    }

    size_t pos = offset + SIGNATURE_SIZE; // Move past the signature

    // ── Check: enough bytes for length field? ───────────────────
    if (pos + LENGTH_FIELD_SIZE > streamSize) {
        pkt.status = PacketStatus::INCOMPLETE;
        pkt.statusDetail = "Stream truncated before length field complete";
        return pkt;
    }

    // ── Read payload length (big-endian uint16) ─────────────────
    uint16_t payloadLength = (static_cast<uint16_t>(stream[pos]) << 8)
                            | static_cast<uint16_t>(stream[pos + 1]);
    pkt.payloadLength = payloadLength;
    pos += LENGTH_FIELD_SIZE;

    // ── Check: enough bytes for the complete packet? ────────────
    size_t expectedTotalSize = PACKET_OVERHEAD + payloadLength;
    size_t expectedEnd = offset + expectedTotalSize;

    if (expectedEnd > streamSize) {
        pkt.status = PacketStatus::INCOMPLETE;
        pkt.statusDetail = "Stream ends before packet is complete (need "
                         + std::to_string(expectedTotalSize)
                         + " bytes, have "
                         + std::to_string(streamSize - offset) + ")";
        return pkt;
    }

    // ── Extract payload ─────────────────────────────────────────
    pkt.payload.assign(stream.begin() + pos,
                       stream.begin() + pos + payloadLength);
    pos += payloadLength;

    // ── Read transmitted CRC (big-endian uint32) ────────────────
    pkt.expectedCRC = (static_cast<uint32_t>(stream[pos])     << 24)
                    | (static_cast<uint32_t>(stream[pos + 1]) << 16)
                    | (static_cast<uint32_t>(stream[pos + 2]) <<  8)
                    | (static_cast<uint32_t>(stream[pos + 3]));
    pos += CRC_SIZE;

    // ── Read end marker ─────────────────────────────────────────
    pkt.endMarker[0] = stream[pos];
    pkt.endMarker[1] = stream[pos + 1];

    // ── Recalculate CRC over length (2 bytes) + payload ─────────
    pkt.calculatedCRC = calculatePacketCRC(payloadLength,
                                           pkt.payload.data(),
                                           pkt.payload.size());

    // ── Step 1: Validate end marker FIRST to verify framing ──────
    if (pkt.endMarker[0] != END_MARKER[0] ||
        pkt.endMarker[1] != END_MARKER[1]) {
        pkt.status = PacketStatus::INVALID_END_MARKER;
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%02X %02X", pkt.endMarker[0], pkt.endMarker[1]);
        pkt.statusDetail = std::string("End marker mismatch: expected EE FF, got ") + buf;
        return pkt;
    }

    // ── Step 2: Validate CRC-32 checksum ────────────────────────
    if (pkt.expectedCRC != pkt.calculatedCRC) {
        pkt.status = PacketStatus::CRC_FAILURE;
        char expBuf[16], calcBuf[16];
        std::snprintf(expBuf, sizeof(expBuf), "%08X", pkt.expectedCRC);
        std::snprintf(calcBuf, sizeof(calcBuf), "%08X", pkt.calculatedCRC);
        pkt.statusDetail = std::string("CRC mismatch: expected 0x") + expBuf
                         + " but calculated 0x" + calcBuf;
        return pkt;
    }

    // ── Step 3: All checks passed ───────────────────────────────
    pkt.status = PacketStatus::VALID;
    pkt.statusDetail = "All validations passed";
    return pkt;
}

// ═══════════════════════════════════════════════════════════════════
// STREAM ANALYZER & DETERMINISTIC RECOVERY POLICY
// ═══════════════════════════════════════════════════════════════════
//
// Recovery Strategy:
// 1. Locate all candidate synchronization signatures using KMP.
// 2. Iterate through signature positions:
//    - If position is inside an already validated packet boundary,
//      skip it (preserves encapsulated payload signatures).
//    - Parse candidate at position.
//    - If candidate claims length exceeding remaining stream:
//      Check if any subsequent signature hit in the stream yields
//      a VALID packet. If so, candidate had a corrupted length field
//      (or was malformed data) -> classify as MALFORMED.
//      Otherwise -> classify as INCOMPLETE (stream truncated at end).
//    - If VALID: mark [start, end) as packet bytes, advance search
//      past this packet.
//    - If CRC_FAILURE: frame structure was verified (end marker EE FF
//      was present), so mark [start, end) as packet bytes and advance
//      past it to avoid parsing signatures in corrupted payload.
//    - If INCOMPLETE: mark received bytes to end of stream as packet
//      bytes and stop (truncated stream tail).
//    - If INVALID_END_MARKER or MALFORMED: do NOT advance boundary.
//      Recover by evaluating the very next signature hit.
// 3. Noise bytes = total stream bytes - recognized packet bytes.

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

    if (result.signatureHits.empty()) {
        result.noiseBytes = stream.size();
        return result;
    }

    // Boolean tracker for bytes consumed by recognized packets
    std::vector<bool> isPacketByte(stream.size(), false);

    // Helper: checks whether any signature after fromHitIdx forms a VALID packet
    auto hasLaterValidPacket = [&](size_t fromHitIdx) -> bool {
        for (size_t j = fromHitIdx; j < result.signatureHits.size(); j++) {
            size_t nextSig = result.signatureHits[j];
            ParsedPacket checkPkt = parsePacketAt(stream, nextSig);
            if (checkPkt.status == PacketStatus::VALID) {
                return true;
            }
        }
        return false;
    };

    size_t nextValidStart = 0; // Boundary past the last accepted packet

    for (size_t idx = 0; idx < result.signatureHits.size(); idx++) {
        size_t sigPos = result.signatureHits[idx];

        // Skip signature hits that fall inside the boundary of an already validated packet
        if (sigPos < nextValidStart) {
            continue;
        }

        ParsedPacket pkt = parsePacketAt(stream, sigPos);

        // Disambiguate INCOMPLETE vs MALFORMED:
        // If candidate claims a length exceeding the stream, but subsequent signature
        // occurrences contain a VALID packet, then this candidate's length field was
        // corrupted (or it's malformed noise), NOT a truncated stream at the end.
        if (pkt.status == PacketStatus::INCOMPLETE && hasLaterValidPacket(idx + 1)) {
            pkt.status = PacketStatus::MALFORMED;
            pkt.statusDetail = "Corrupted length field: declared length exceeds stream, followed by valid packet data";
        }

        result.packets.push_back(pkt);

        if (pkt.status == PacketStatus::VALID) {
            size_t packetEnd = sigPos + PACKET_OVERHEAD + pkt.payloadLength;
            for (size_t b = sigPos; b < packetEnd && b < stream.size(); b++) {
                isPacketByte[b] = true;
            }
            nextValidStart = packetEnd;
        }
        else if (pkt.status == PacketStatus::CRC_FAILURE) {
            // Intact framing (end marker matched EE FF), but CRC check failed
            size_t packetEnd = sigPos + PACKET_OVERHEAD + pkt.payloadLength;
            for (size_t b = sigPos; b < packetEnd && b < stream.size(); b++) {
                isPacketByte[b] = true;
            }
            // For a corrupted packet with intact framing, advance past it
            // so internal signatures in its corrupted payload are not re-parsed
            nextValidStart = packetEnd;
        }
        else if (pkt.status == PacketStatus::INCOMPLETE) {
            // Truly incomplete packet at the end of stream
            for (size_t b = sigPos; b < stream.size(); b++) {
                isPacketByte[b] = true;
            }
            // Stream ends with this incomplete packet
            break;
        }
        else {
            // INVALID_END_MARKER or MALFORMED:
            // Do NOT advance nextValidStart! Recovery policy continues search
            // at the very next signature hit (idx + 1).
            // Unclaimed bytes remain marked false (noise).
        }
    }

    // Calculate noise bytes (bytes not part of any recognized packet)
    size_t noiseCount = 0;
    for (bool b : isPacketByte) {
        if (!b) noiseCount++;
    }
    result.noiseBytes = noiseCount;

    return result;
}

} // namespace protocore
