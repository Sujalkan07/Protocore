// protocol.hpp — Protocol constants and common type definitions for PROTOCORE
#ifndef PROTOCORE_PROTOCOL_HPP
#define PROTOCORE_PROTOCOL_HPP

#include <cstdint>
#include <vector>
#include <array>

namespace protocore {

// ─── Packet Synchronization Signature (4 bytes) ─────────────────────
// Every valid packet begins with these four bytes.
constexpr std::array<uint8_t, 4> START_SIGNATURE = {0xAA, 0xBB, 0xCC, 0xDD};

// ─── Packet End Marker (2 bytes) ────────────────────────────────────
// Every valid packet ends with these two bytes.
constexpr std::array<uint8_t, 2> END_MARKER = {0xEE, 0xFF};

// ─── Field Sizes ────────────────────────────────────────────────────
constexpr size_t SIGNATURE_SIZE    = 4;   // Start signature
constexpr size_t LENGTH_FIELD_SIZE = 2;   // Payload length (uint16, big-endian)
constexpr size_t CRC_SIZE          = 4;   // CRC-32 checksum
constexpr size_t END_MARKER_SIZE   = 2;   // End marker

// Fixed overhead = signature + length + CRC + end marker = 12 bytes
constexpr size_t PACKET_OVERHEAD = SIGNATURE_SIZE + LENGTH_FIELD_SIZE
                                 + CRC_SIZE + END_MARKER_SIZE;

// ─── Maximum Payload ────────────────────────────────────────────────
constexpr uint16_t MAX_PAYLOAD_LENGTH = 65535;

// ─── CRC-32 Configuration ───────────────────────────────────────────
constexpr uint32_t CRC_POLYNOMIAL  = 0xEDB88320;  // Reflected polynomial
constexpr uint32_t CRC_INIT_VALUE  = 0xFFFFFFFF;
constexpr uint32_t CRC_FINAL_XOR   = 0xFFFFFFFF;

// ─── Convenience type alias ─────────────────────────────────────────
using ByteStream = std::vector<uint8_t>;

} // namespace protocore

#endif // PROTOCORE_PROTOCOL_HPP
