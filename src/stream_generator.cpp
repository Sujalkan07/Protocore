// stream_generator.cpp — Binary stream generator for test scenarios
#include "stream_generator.hpp"
#include "crc32.hpp"
#include <cstdlib>
#include <ctime>

namespace protocore {

// ─── Build a Single Valid Packet ────────────────────────────────────
ByteStream buildPacket(const uint8_t* payload, uint16_t payloadLength) {
    ByteStream packet;
    packet.reserve(PACKET_OVERHEAD + payloadLength);

    // 1. Start signature: AA BB CC DD
    for (uint8_t b : START_SIGNATURE) {
        packet.push_back(b);
    }

    // 2. Payload length (big-endian)
    packet.push_back(static_cast<uint8_t>((payloadLength >> 8) & 0xFF));
    packet.push_back(static_cast<uint8_t>(payloadLength & 0xFF));

    // 3. Payload
    for (uint16_t i = 0; i < payloadLength; i++) {
        packet.push_back(payload[i]);
    }

    // 4. CRC-32 over length bytes + payload
    uint32_t crc = calculatePacketCRC(payloadLength, payload, payloadLength);
    packet.push_back(static_cast<uint8_t>((crc >> 24) & 0xFF));
    packet.push_back(static_cast<uint8_t>((crc >> 16) & 0xFF));
    packet.push_back(static_cast<uint8_t>((crc >>  8) & 0xFF));
    packet.push_back(static_cast<uint8_t>(crc & 0xFF));

    // 5. End marker: EE FF
    for (uint8_t b : END_MARKER) {
        packet.push_back(b);
    }

    return packet;
}

ByteStream buildPacket(const std::string& payloadText) {
    return buildPacket(reinterpret_cast<const uint8_t*>(payloadText.data()),
                       static_cast<uint16_t>(payloadText.size()));
}

// ─── Reproducible PRNG for Noise Generation ─────────────────────────
static uint32_t activeSeed = DEFAULT_GENERATOR_SEED;
static uint32_t rngState   = DEFAULT_GENERATOR_SEED;

void setGeneratorSeed(uint32_t seed) {
    activeSeed = seed;
    rngState   = seed;
}

static uint8_t nextRandomByte() {
    // 32-bit Linear Congruential Generator (Knuth / Numerical Recipes)
    rngState = rngState * 1664525u + 1013904223u;
    return static_cast<uint8_t>((rngState >> 16) & 0xFF);
}

// ─── Helper: generate random noise bytes ────────────────────────────
// Guarantees that the start signature AA BB CC DD is NEVER accidentally formed.
static ByteStream generateNoise(size_t length) {
    ByteStream noise;
    noise.reserve(length);
    for (size_t i = 0; i < length; i++) {
        uint8_t b = nextRandomByte();
        // Check if appending this byte would form AA BB CC DD
        if (noise.size() >= 3 &&
            noise[noise.size() - 3] == START_SIGNATURE[0] &&
            noise[noise.size() - 2] == START_SIGNATURE[1] &&
            noise[noise.size() - 1] == START_SIGNATURE[2] &&
            b == START_SIGNATURE[3]) {
            b ^= 0x55; // Alter byte to prevent accidental signature
        }
        noise.push_back(b);
    }
    return noise;
}

// ─── Helper: append bytes to a stream ───────────────────────────────
static void appendBytes(ByteStream& stream, const ByteStream& data) {
    stream.insert(stream.end(), data.begin(), data.end());
}

// ─── Scenario Generators ────────────────────────────────────────────

static ByteStream generateNormal() {
    // Multiple valid packets with sample payloads
    ByteStream stream;
    std::vector<std::string> payloads = {
        "HELLO", "WORLD", "PROTOCORE", "NETWORK", "COMPUTER SCIENCE"
    };

    for (const auto& text : payloads) {
        appendBytes(stream, buildPacket(text));
    }

    return stream;
}

static ByteStream generateNoisy() {
    ByteStream stream;

    // Noise before first packet
    appendBytes(stream, generateNoise(10));

    appendBytes(stream, buildPacket("HELLO"));

    // Noise between packets
    appendBytes(stream, generateNoise(15));

    appendBytes(stream, buildPacket("WORLD"));

    // Noise after last packet
    appendBytes(stream, generateNoise(8));

    appendBytes(stream, buildPacket("PROTOCORE"));

    appendBytes(stream, generateNoise(12));

    return stream;
}

static ByteStream generateCorrupted() {
    ByteStream stream;

    // Valid packet
    appendBytes(stream, buildPacket("HELLO"));

    // Corrupted packet: build valid then modify payload byte
    ByteStream corrupted = buildPacket("WORLD");
    // Modify a payload byte (position: signature(4) + length(2) + 1 = 7)
    if (corrupted.size() > 7) {
        corrupted[7] ^= 0xFF; // Flip all bits of second payload byte
    }
    appendBytes(stream, corrupted);

    // Another valid packet
    appendBytes(stream, buildPacket("NETWORK"));

    return stream;
}

static ByteStream generateIncomplete() {
    ByteStream stream;

    // Valid packet
    appendBytes(stream, buildPacket("HELLO"));

    // Incomplete packet: only signature + partial length
    ByteStream incomplete = buildPacket("WORLD");
    // Truncate to just signature + length + partial payload
    size_t truncateAt = SIGNATURE_SIZE + LENGTH_FIELD_SIZE + 2;
    incomplete.resize(truncateAt);
    appendBytes(stream, incomplete);

    return stream;
}

static ByteStream generateMixed() {
    ByteStream stream;

    // Leading noise
    appendBytes(stream, generateNoise(8));

    // Valid packet
    appendBytes(stream, buildPacket("HELLO"));

    // More noise
    appendBytes(stream, generateNoise(5));

    // Corrupted packet
    ByteStream corrupted = buildPacket("PROTOCORE");
    if (corrupted.size() > 8) {
        corrupted[8] ^= 0xAA; // Corrupt a payload byte
    }
    appendBytes(stream, corrupted);

    // Valid packet with signature-like payload
    // Payload contains 0xAA 0xBB 0xCC 0xDD inside it
    uint8_t specialPayload[] = {0x41, 0xAA, 0xBB, 0xCC, 0xDD, 0x42};
    appendBytes(stream, buildPacket(specialPayload, 6));

    // Noise between
    appendBytes(stream, generateNoise(6));

    // Valid packet
    appendBytes(stream, buildPacket("NETWORK"));

    // Incomplete packet at the end
    ByteStream incomplete = buildPacket("COMPUTER SCIENCE");
    incomplete.resize(SIGNATURE_SIZE + LENGTH_FIELD_SIZE + 3);
    appendBytes(stream, incomplete);

    return stream;
}

// ─── Main Generator Function ────────────────────────────────────────
ByteStream generateStream(StreamScenario scenario, uint32_t seed) {
    // Re-initialize RNG with the requested seed for guaranteed reproducibility
    rngState = seed;

    switch (scenario) {
        case StreamScenario::NORMAL:     return generateNormal();
        case StreamScenario::NOISY:      return generateNoisy();
        case StreamScenario::CORRUPTED:  return generateCorrupted();
        case StreamScenario::INCOMPLETE: return generateIncomplete();
        case StreamScenario::MIXED:      return generateMixed();
        default:                         return generateNormal();
    }
}

std::string scenarioName(StreamScenario scenario) {
    switch (scenario) {
        case StreamScenario::NORMAL:     return "Normal (Multiple Valid Packets)";
        case StreamScenario::NOISY:      return "Noisy (Packets with Random Noise)";
        case StreamScenario::CORRUPTED:  return "Corrupted (Modified Payload Bytes)";
        case StreamScenario::INCOMPLETE: return "Incomplete (Truncated Stream)";
        case StreamScenario::MIXED:      return "Mixed (Valid + Corrupted + Noise + Incomplete)";
        default:                         return "Unknown";
    }
}

} // namespace protocore
