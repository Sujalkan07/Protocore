// stream_generator.hpp — Binary stream generator for test scenarios
#ifndef PROTOCORE_STREAM_GENERATOR_HPP
#define PROTOCORE_STREAM_GENERATOR_HPP

#include "protocol.hpp"
#include <string>

namespace protocore {

// ─── Scenario Types ─────────────────────────────────────────────────
enum class StreamScenario {
    NORMAL,       // Multiple valid packets
    NOISY,        // Valid packets with random noise between them
    CORRUPTED,    // Some packets with deliberately modified payload bytes
    INCOMPLETE,   // Stream truncated before a packet finishes
    MIXED         // Combination of valid, corrupted, noise and incomplete
};

// ─── Default Reproducible Seed ──────────────────────────────────────
constexpr uint32_t DEFAULT_GENERATOR_SEED = 0x50524F54; // ASCII for 'PROT'

// Set custom seed for stream generation
void setGeneratorSeed(uint32_t seed);

// ─── Build a Single Valid Packet ────────────────────────────────────
// Creates a complete packet: signature + length + payload + CRC + end marker
ByteStream buildPacket(const uint8_t* payload, uint16_t payloadLength);

// Convenience: build packet from a text string
ByteStream buildPacket(const std::string& payloadText);

// ─── Generate a Complete Stream ─────────────────────────────────────
// Generates a binary stream according to the chosen scenario and seed.
ByteStream generateStream(StreamScenario scenario, uint32_t seed = DEFAULT_GENERATOR_SEED);

// ─── Scenario Name ──────────────────────────────────────────────────
std::string scenarioName(StreamScenario scenario);

} // namespace protocore

#endif // PROTOCORE_STREAM_GENERATOR_HPP
