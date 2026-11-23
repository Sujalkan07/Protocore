// packet.hpp — Packet data structure and status definitions
#ifndef PROTOCORE_PACKET_HPP
#define PROTOCORE_PACKET_HPP

#include "protocol.hpp"
#include <string>

namespace protocore {

// ─── Packet Status Categories ───────────────────────────────────────
enum class PacketStatus {
    VALID,              // All checks passed
    CRC_FAILURE,        // Structure readable but CRC mismatch
    INVALID_END_MARKER, // End marker does not match expected value
    INCOMPLETE,         // Not enough bytes in stream to complete packet
    MALFORMED,          // Cannot be interpreted as a valid packet structure
    NOISE               // Bytes that don't belong to any recognized packet
};

// Convert PacketStatus to a human-readable string
std::string statusToString(PacketStatus status);

// ─── Parsed Packet Structure ────────────────────────────────────────
struct ParsedPacket {
    size_t       streamOffset;      // Position of the signature in the stream
    uint16_t     payloadLength;     // Declared payload length
    ByteStream   payload;           // Extracted payload bytes
    uint32_t     expectedCRC;       // CRC stored in the packet (transmitted)
    uint32_t     calculatedCRC;     // CRC recalculated from length + payload
    uint8_t      endMarker[2];      // The two end-marker bytes read from stream
    PacketStatus status;            // Final classification
    std::string  statusDetail;      // Human-readable reason for the status
};

// ─── Utility Functions ──────────────────────────────────────────────

// Convert payload bytes to printable text (non-printable → '.')
std::string payloadToText(const ByteStream& payload);

// Convert payload bytes to hex string like "48 45 4C 4C 4F"
std::string payloadToHex(const ByteStream& payload);

} // namespace protocore

#endif // PROTOCORE_PACKET_HPP
