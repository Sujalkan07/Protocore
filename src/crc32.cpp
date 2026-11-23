// crc32.cpp — CRC-32/ISO-HDLC implementation
#include "crc32.hpp"
#include <cstring>

namespace protocore {

// ─── CRC-32 Lookup Table ────────────────────────────────────────────
// Pre-computed table for the reflected polynomial 0xEDB88320.
// Using a table makes CRC computation much faster than computing
// each bit individually (table-driven approach).

static uint32_t crcTable[256];
static bool     tableInitialized = false;

// Generates the 256-entry lookup table.
// Each entry represents the CRC remainder for a single byte value (0–255).
static void initCRCTable() {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t crc = i;
        for (int bit = 0; bit < 8; bit++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ CRC_POLYNOMIAL;
            } else {
                crc = crc >> 1;
            }
        }
        crcTable[i] = crc;
    }
    tableInitialized = true;
}

// ─── Core CRC-32 Calculation ────────────────────────────────────────
uint32_t calculateCRC32(const uint8_t* data, size_t length) {
    if (!tableInitialized) {
        initCRCTable();
    }

    uint32_t crc = CRC_INIT_VALUE;

    for (size_t i = 0; i < length; i++) {
        // XOR the current byte into the low 8 bits of CRC,
        // then look up the table entry and shift
        uint8_t tableIndex = static_cast<uint8_t>(crc ^ data[i]);
        crc = (crc >> 8) ^ crcTable[tableIndex];
    }

    // Final XOR to produce the standard CRC-32 result
    return crc ^ CRC_FINAL_XOR;
}

uint32_t calculateCRC32(const std::vector<uint8_t>& data) {
    return calculateCRC32(data.data(), data.size());
}

// ─── Packet CRC ─────────────────────────────────────────────────────
// CRC covers: [lengthHighByte, lengthLowByte, payload...]
uint32_t calculatePacketCRC(uint16_t payloadLength,
                            const uint8_t* payload, size_t payloadLen) {
    // Build the data buffer: 2 length bytes + payload
    std::vector<uint8_t> crcData;
    crcData.reserve(2 + payloadLen);

    // Length in big-endian: high byte first
    crcData.push_back(static_cast<uint8_t>((payloadLength >> 8) & 0xFF));
    crcData.push_back(static_cast<uint8_t>(payloadLength & 0xFF));

    // Append payload bytes
    for (size_t i = 0; i < payloadLen; i++) {
        crcData.push_back(payload[i]);
    }

    return calculateCRC32(crcData);
}

// ─── Known-Answer Test ──────────────────────────────────────────────
bool verifyCRC32KnownAnswer() {
    // The CRC-32 of "123456789" must equal 0xCBF43926
    const char* testString = "123456789";
    size_t len = std::strlen(testString);
    uint32_t result = calculateCRC32(
        reinterpret_cast<const uint8_t*>(testString), len);
    return (result == 0xCBF43926);
}

} // namespace protocore
