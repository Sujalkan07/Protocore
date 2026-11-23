// crc32.hpp — CRC-32/ISO-HDLC checksum computation
#ifndef PROTOCORE_CRC32_HPP
#define PROTOCORE_CRC32_HPP

#include "protocol.hpp"
#include <cstdint>
#include <vector>

namespace protocore {

// ─── CRC-32 Calculation ─────────────────────────────────────────────
// Computes CRC-32/ISO-HDLC over the given data.
//
// Uses reflected polynomial 0xEDB88320.
// Initial value:  0xFFFFFFFF
// Final XOR:      0xFFFFFFFF
//
// This matches the standard CRC-32 used in Ethernet, ZIP, PNG, etc.
uint32_t calculateCRC32(const uint8_t* data, size_t length);

// Convenience overload for vectors
uint32_t calculateCRC32(const std::vector<uint8_t>& data);

// ─── Packet CRC Calculation ─────────────────────────────────────────
// Calculates CRC-32 over the length field (2 bytes, big-endian)
// followed by the payload bytes, exactly as defined by our protocol.
uint32_t calculatePacketCRC(uint16_t payloadLength,
                            const uint8_t* payload, size_t payloadLen);

// ─── Known-Answer Test ──────────────────────────────────────────────
// CRC-32 of the ASCII string "123456789" must equal 0xCBF43926.
// Returns true if the implementation is correct.
bool verifyCRC32KnownAnswer();

} // namespace protocore

#endif // PROTOCORE_CRC32_HPP
