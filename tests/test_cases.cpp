// test_cases.cpp — Comprehensive test suite for PROTOCORE
//
// Each test function returns true on success, false on failure.
// The runAllTests() function runs every test and reports results.

#include "protocol.hpp"
#include "packet.hpp"
#include "kmp.hpp"
#include "crc32.hpp"
#include "packet_parser.hpp"
#include "stream_generator.hpp"
#include "file_handler.hpp"
#include "statistics.hpp"

#include <iostream>
#include <iomanip>
#include <string>
#include <cstring>
#include <vector>
#include <functional>

using namespace protocore;

// ═══════════════════════════════════════════════════════════════════
// TEST FRAMEWORK
// ═══════════════════════════════════════════════════════════════════

struct TestCase {
    std::string name;
    std::function<bool()> testFunction;
};

static int totalPassed = 0;
static int totalFailed = 0;

static void reportTest(const std::string& name, bool passed) {
    if (passed) {
        totalPassed++;
        std::cout << "  [PASS] " << name << "\n";
    } else {
        totalFailed++;
        std::cout << "  [FAIL] " << name << "\n";
    }
}

// ═══════════════════════════════════════════════════════════════════
// TEST 1: Single Valid Packet
// ═══════════════════════════════════════════════════════════════════

static bool testSingleValidPacket() {
    ByteStream stream = buildPacket("HELLO");
    AnalysisResult result = analyzeStream(stream);

    if (result.packets.size() != 1) return false;
    if (result.packets[0].status != PacketStatus::VALID) return false;
    if (result.packets[0].payloadLength != 5) return false;

    std::string text = payloadToText(result.packets[0].payload);
    return (text == "HELLO");
}

// ═══════════════════════════════════════════════════════════════════
// TEST 2: Multiple Valid Packets
// ═══════════════════════════════════════════════════════════════════

static bool testMultipleValidPackets() {
    ByteStream stream;
    ByteStream p1 = buildPacket("HELLO");
    ByteStream p2 = buildPacket("WORLD");
    ByteStream p3 = buildPacket("PROTOCORE");

    stream.insert(stream.end(), p1.begin(), p1.end());
    stream.insert(stream.end(), p2.begin(), p2.end());
    stream.insert(stream.end(), p3.begin(), p3.end());

    AnalysisResult result = analyzeStream(stream);

    int validCount = 0;
    for (const auto& pkt : result.packets) {
        if (pkt.status == PacketStatus::VALID) validCount++;
    }

    return (validCount == 3);
}

// ═══════════════════════════════════════════════════════════════════
// TEST 3: Noise Before a Packet
// ═══════════════════════════════════════════════════════════════════

static bool testNoiseBeforePacket() {
    ByteStream stream = {0x11, 0x22, 0x33, 0x44, 0x55}; // 5 noise bytes
    ByteStream pkt = buildPacket("HELLO");
    stream.insert(stream.end(), pkt.begin(), pkt.end());

    AnalysisResult result = analyzeStream(stream);

    bool hasValid = false;
    for (const auto& p : result.packets) {
        if (p.status == PacketStatus::VALID) hasValid = true;
    }

    return hasValid && result.noiseBytes == 5;
}

// ═══════════════════════════════════════════════════════════════════
// TEST 4: Noise Between Packets
// ═══════════════════════════════════════════════════════════════════

static bool testNoiseBetweenPackets() {
    ByteStream stream;
    ByteStream p1 = buildPacket("HELLO");
    ByteStream noise = {0x11, 0x22, 0x33};
    ByteStream p2 = buildPacket("WORLD");

    stream.insert(stream.end(), p1.begin(), p1.end());
    stream.insert(stream.end(), noise.begin(), noise.end());
    stream.insert(stream.end(), p2.begin(), p2.end());

    AnalysisResult result = analyzeStream(stream);

    int validCount = 0;
    for (const auto& p : result.packets) {
        if (p.status == PacketStatus::VALID) validCount++;
    }

    return (validCount == 2) && (result.noiseBytes == 3);
}

// ═══════════════════════════════════════════════════════════════════
// TEST 5: Corrupted Payload
// ═══════════════════════════════════════════════════════════════════

static bool testCorruptedPayload() {
    ByteStream stream = buildPacket("HELLO");

    // Corrupt a payload byte (offset 6 = first payload byte)
    if (stream.size() > 6) {
        stream[6] ^= 0xFF;
    }

    AnalysisResult result = analyzeStream(stream);

    if (result.packets.size() != 1) return false;
    return (result.packets[0].status == PacketStatus::CRC_FAILURE);
}

// ═══════════════════════════════════════════════════════════════════
// TEST 6: Incorrect CRC
// ═══════════════════════════════════════════════════════════════════

static bool testIncorrectCRC() {
    ByteStream stream = buildPacket("TEST");

    // Modify the CRC bytes (after signature + length + payload)
    size_t crcOffset = SIGNATURE_SIZE + LENGTH_FIELD_SIZE + 4; // "TEST" = 4 bytes
    if (stream.size() > crcOffset + 3) {
        stream[crcOffset]     = 0x00;
        stream[crcOffset + 1] = 0x00;
        stream[crcOffset + 2] = 0x00;
        stream[crcOffset + 3] = 0x00;
    }

    AnalysisResult result = analyzeStream(stream);

    if (result.packets.size() != 1) return false;
    return (result.packets[0].status == PacketStatus::CRC_FAILURE);
}

// ═══════════════════════════════════════════════════════════════════
// TEST 7: Invalid End Marker
// ═══════════════════════════════════════════════════════════════════

static bool testInvalidEndMarker() {
    ByteStream stream = buildPacket("HELLO");

    // Replace end marker bytes with wrong values
    size_t markerOffset = stream.size() - 2;
    stream[markerOffset]     = 0x00;
    stream[markerOffset + 1] = 0x00;

    AnalysisResult result = analyzeStream(stream);

    if (result.packets.size() != 1) return false;
    // Note: since CRC covers length + payload (not end marker),
    // CRC should still pass, but end marker should fail
    return (result.packets[0].status == PacketStatus::INVALID_END_MARKER);
}

// ═══════════════════════════════════════════════════════════════════
// TEST 8: Incomplete Packet
// ═══════════════════════════════════════════════════════════════════

static bool testIncompletePacket() {
    ByteStream fullPacket = buildPacket("HELLO WORLD");
    // Truncate the stream — keep only first 8 bytes
    ByteStream stream(fullPacket.begin(), fullPacket.begin() + 8);

    AnalysisResult result = analyzeStream(stream);

    if (result.packets.size() != 1) return false;
    return (result.packets[0].status == PacketStatus::INCOMPLETE);
}

// ═══════════════════════════════════════════════════════════════════
// TEST 9: Empty Payload
// ═══════════════════════════════════════════════════════════════════

static bool testEmptyPayload() {
    // Build a packet with 0-length payload
    ByteStream stream = buildPacket(reinterpret_cast<const uint8_t*>(""), 0);

    AnalysisResult result = analyzeStream(stream);

    if (result.packets.size() != 1) return false;
    if (result.packets[0].status != PacketStatus::VALID) return false;
    return (result.packets[0].payloadLength == 0);
}

// ═══════════════════════════════════════════════════════════════════
// TEST 10: Maximum Supported Payload (small test — 1000 bytes)
// ═══════════════════════════════════════════════════════════════════

static bool testLargePayload() {
    // Use 1000 bytes to keep the test fast
    std::vector<uint8_t> payload(1000);
    for (size_t i = 0; i < payload.size(); i++) {
        payload[i] = static_cast<uint8_t>(i % 256);
    }

    ByteStream stream = buildPacket(payload.data(),
                                     static_cast<uint16_t>(payload.size()));

    AnalysisResult result = analyzeStream(stream);

    if (result.packets.size() != 1) return false;
    if (result.packets[0].status != PacketStatus::VALID) return false;
    return (result.packets[0].payloadLength == 1000);
}

// ═══════════════════════════════════════════════════════════════════
// TEST 11: Payload Containing Null Bytes
// ═══════════════════════════════════════════════════════════════════

static bool testNullBytesInPayload() {
    uint8_t payload[] = {0x48, 0x00, 0x45, 0x00, 0x4C}; // H.E.L
    ByteStream stream = buildPacket(payload, 5);

    AnalysisResult result = analyzeStream(stream);

    if (result.packets.size() != 1) return false;
    if (result.packets[0].status != PacketStatus::VALID) return false;

    // Verify the null bytes are preserved
    return (result.packets[0].payload[1] == 0x00 &&
            result.packets[0].payload[3] == 0x00);
}

// ═══════════════════════════════════════════════════════════════════
// TEST 12: Payload Containing Non-Printable Bytes
// ═══════════════════════════════════════════════════════════════════

static bool testNonPrintablePayload() {
    uint8_t payload[] = {0x01, 0x02, 0x03, 0x7F, 0xFF};
    ByteStream stream = buildPacket(payload, 5);

    AnalysisResult result = analyzeStream(stream);

    if (result.packets.size() != 1) return false;
    if (result.packets[0].status != PacketStatus::VALID) return false;

    // Verify payloadToText converts non-printable to '.'
    std::string text = payloadToText(result.packets[0].payload);
    return (text == ".....");
}

// ═══════════════════════════════════════════════════════════════════
// TEST 13: Synchronization Signature Inside Payload
// ═══════════════════════════════════════════════════════════════════

static bool testSignatureInsidePayload() {
    // Payload contains 0xAA 0xBB 0xCC 0xDD — the start signature
    uint8_t payload[] = {0x41, 0xAA, 0xBB, 0xCC, 0xDD, 0x42};
    ByteStream stream = buildPacket(payload, 6);

    AnalysisResult result = analyzeStream(stream);

    // Should find exactly one valid packet (the outer one).
    // The inner signature occurrence should NOT create a second packet
    // because it falls within the first packet's validated boundary.
    int validCount = 0;
    for (const auto& p : result.packets) {
        if (p.status == PacketStatus::VALID) validCount++;
    }

    return (validCount == 1);
}

// ═══════════════════════════════════════════════════════════════════
// TEST 14: Repeated Synchronization Signatures
// ═══════════════════════════════════════════════════════════════════

static bool testRepeatedSignatures() {
    ByteStream stream;
    // Three consecutive signatures without valid packet structure
    for (int i = 0; i < 3; i++) {
        for (uint8_t b : START_SIGNATURE) {
            stream.push_back(b);
        }
    }

    AnalysisResult result = analyzeStream(stream);

    // All should be incomplete (not enough data after signature)
    // and KMP should find matches
    return (result.signatureHits.size() == 3);
}

// ═══════════════════════════════════════════════════════════════════
// TEST 15: Multiple Patterns in Continuous Stream
// ═══════════════════════════════════════════════════════════════════

static bool testContinuousStream() {
    ByteStream stream = generateStream(StreamScenario::NORMAL);

    AnalysisResult result = analyzeStream(stream);

    // The normal scenario generates 5 valid packets
    int validCount = 0;
    for (const auto& p : result.packets) {
        if (p.status == PacketStatus::VALID) validCount++;
    }

    return (validCount == 5);
}

// ═══════════════════════════════════════════════════════════════════
// TEST 16: Empty Input Stream
// ═══════════════════════════════════════════════════════════════════

static bool testEmptyStream() {
    ByteStream stream;
    AnalysisResult result = analyzeStream(stream);

    return (result.packets.empty() &&
            result.signatureHits.empty() &&
            result.totalBytes == 0);
}

// ═══════════════════════════════════════════════════════════════════
// TEST 17: File Loading Errors
// ═══════════════════════════════════════════════════════════════════

static bool testFileLoadingErrors() {
    ByteStream data;
    std::string error;

    // Try to load a file that doesn't exist
    bool result = loadBinaryFile("nonexistent_file_xyz.bin", data, error);

    // Should fail and provide an error message
    return (!result && !error.empty());
}

// ═══════════════════════════════════════════════════════════════════
// TEST 18: KMP Overlapping Pattern Matches
// ═══════════════════════════════════════════════════════════════════

static bool testKMPOverlappingMatches() {
    // Pattern "ABAB" in text "ABABAB"
    // Should find matches at positions 0 and 2
    uint8_t text[]    = {'A', 'B', 'A', 'B', 'A', 'B'};
    uint8_t pattern[] = {'A', 'B', 'A', 'B'};

    auto matches = kmpSearch(text, 6, pattern, 4);

    // Expected: positions 0 and 2
    if (matches.size() != 2) return false;
    return (matches[0] == 0 && matches[1] == 2);
}

// ═══════════════════════════════════════════════════════════════════
// TEST 19: Known CRC-32 Test Vector
// ═══════════════════════════════════════════════════════════════════

static bool testCRC32KnownAnswer() {
    return verifyCRC32KnownAnswer();
}

// ═══════════════════════════════════════════════════════════════════
// TEST 20: Length Field Boundary Cases
// ═══════════════════════════════════════════════════════════════════

static bool testLengthBoundary() {
    // Test with payload length = 1 (smallest non-empty)
    uint8_t payload1[] = {0x42};
    ByteStream stream1 = buildPacket(payload1, 1);
    AnalysisResult result1 = analyzeStream(stream1);

    if (result1.packets.size() != 1) return false;
    if (result1.packets[0].status != PacketStatus::VALID) return false;
    if (result1.packets[0].payloadLength != 1) return false;

    // Test with payload length = 256 (crosses single-byte boundary)
    std::vector<uint8_t> payload256(256, 0x41);
    ByteStream stream2 = buildPacket(payload256.data(), 256);
    AnalysisResult result2 = analyzeStream(stream2);

    if (result2.packets.size() != 1) return false;
    if (result2.packets[0].status != PacketStatus::VALID) return false;
    if (result2.packets[0].payloadLength != 256) return false;

    return true;
}

// ═══════════════════════════════════════════════════════════════════
// ADDITIONAL TESTS
// ═══════════════════════════════════════════════════════════════════

// TEST 21: LPS Array Correctness
static bool testLPSArray() {
    // Pattern "AABAACAABAA"
    // Expected LPS: [0, 1, 0, 1, 2, 0, 1, 2, 3, 4, 5]
    uint8_t pattern[] = {'A','A','B','A','A','C','A','A','B','A','A'};
    auto lps = buildLPSArray(pattern, 11);

    std::vector<int> expected = {0, 1, 0, 1, 2, 0, 1, 2, 3, 4, 5};
    return (lps == expected);
}

// TEST 22: KMP vs Naive Agreement
static bool testKMPNaiveAgreement() {
    // Both algorithms must find the same matches
    ByteStream text = {0xAA, 0xBB, 0x11, 0xAA, 0xBB, 0xCC,
                       0xAA, 0xBB, 0xCC, 0xDD, 0x22, 0x33,
                       0xAA, 0xBB, 0xCC, 0xDD};
    ByteStream pattern(START_SIGNATURE.begin(), START_SIGNATURE.end());

    auto kmpResult   = kmpSearch(text, pattern);
    auto naiveResult = naiveSearch(text, pattern);

    return (kmpResult == naiveResult);
}

// TEST 23: Statistics Computation
static bool testStatisticsComputation() {
    ByteStream stream;

    // Valid packet
    ByteStream p1 = buildPacket("HELLO");
    stream.insert(stream.end(), p1.begin(), p1.end());

    // Some noise
    stream.push_back(0x11);
    stream.push_back(0x22);

    // Corrupted packet
    ByteStream p2 = buildPacket("WORLD");
    p2[7] ^= 0xFF; // corrupt payload
    stream.insert(stream.end(), p2.begin(), p2.end());

    AnalysisResult result = analyzeStream(stream);
    Statistics stats = computeStatistics(result);

    if (stats.packetsAccepted != 1) return false;
    if (stats.corruptedPackets != 1) return false;
    if (stats.noiseBytes != 2) return false;
    if (stats.totalValidPayload != 5) return false;

    return true;
}

// TEST 24: PayloadToHex Formatting
static bool testPayloadToHex() {
    ByteStream payload = {0x48, 0x45, 0x4C, 0x4C, 0x4F};
    std::string hex = payloadToHex(payload);
    return (hex == "48 45 4C 4C 4F");
}

// TEST 25: Packet built from text has correct structure
static bool testPacketStructure() {
    ByteStream pkt = buildPacket("AB");

    // Expected: AA BB CC DD 00 02 41 42 [CRC 4 bytes] EE FF
    // Total = 4 + 2 + 2 + 4 + 2 = 14 bytes
    if (pkt.size() != 14) return false;

    // Check signature
    if (pkt[0] != 0xAA || pkt[1] != 0xBB ||
        pkt[2] != 0xCC || pkt[3] != 0xDD) return false;

    // Check length (big-endian 0x0002)
    if (pkt[4] != 0x00 || pkt[5] != 0x02) return false;

    // Check payload
    if (pkt[6] != 0x41 || pkt[7] != 0x42) return false;

    // Check end marker
    if (pkt[12] != 0xEE || pkt[13] != 0xFF) return false;

    return true;
}

// ═══════════════════════════════════════════════════════════════════
// NEW TESTS (AUDIT & ROBUSTNESS VERIFICATION)
// ═══════════════════════════════════════════════════════════════════

// TEST 26: Maximum supported payload of 65,535 bytes
static bool testMaxPayload65535() {
    std::vector<uint8_t> payload(65535);
    for (size_t i = 0; i < payload.size(); i++) {
        payload[i] = static_cast<uint8_t>(i & 0xFF);
    }

    ByteStream stream = buildPacket(payload.data(), 65535);
    if (stream.size() != 65535 + PACKET_OVERHEAD) return false;

    AnalysisResult result = analyzeStream(stream);

    if (result.packets.size() != 1) return false;
    if (result.packets[0].status != PacketStatus::VALID) return false;
    if (result.packets[0].payloadLength != 65535) return false;
    if (result.packets[0].payload != payload) return false;
    return (result.packets[0].expectedCRC == result.packets[0].calculatedCRC);
}

// TEST 27: Corrupted length field followed by valid packet
static bool testCorruptedLengthField() {
    // Packet 1: length field claims 50,000 bytes in a 50-byte stream
    ByteStream stream;
    for (uint8_t b : START_SIGNATURE) stream.push_back(b);
    stream.push_back(0xC3); // 50,000 = 0xC350
    stream.push_back(0x50);
    for (int i = 0; i < 10; i++) stream.push_back(0x55); // arbitrary data

    // Packet 2: a valid packet immediately follows
    ByteStream validPkt = buildPacket("VALID");
    stream.insert(stream.end(), validPkt.begin(), validPkt.end());

    AnalysisResult result = analyzeStream(stream);

    // Should detect 2 packets: 1 malformed (corrupted length) and 1 valid
    if (result.packets.size() != 2) return false;
    if (result.packets[0].status != PacketStatus::MALFORMED) return false;
    if (result.packets[1].status != PacketStatus::VALID) return false;
    return (payloadToText(result.packets[1].payload) == "VALID");
}

// TEST 28: Signature inside corrupted payload
static bool testSignatureInsideCorruptedPayload() {
    // Payload contains the signature AA BB CC DD
    uint8_t payload[] = {0x10, 0xAA, 0xBB, 0xCC, 0xDD, 0x20};
    ByteStream stream = buildPacket(payload, 6);

    // Corrupt payload byte 6 (the 0x10 byte) so CRC fails, but end marker EE FF is intact
    stream[6] ^= 0xFF;

    AnalysisResult result = analyzeStream(stream);

    // Exactly one packet reported with CRC_FAILURE; inner signature is not parsed as new packet
    if (result.packets.size() != 1) return false;
    return (result.packets[0].status == PacketStatus::CRC_FAILURE);
}

// TEST 29: Incomplete candidate with internal signature occurrence
static bool testIncompleteWithInternalSignature() {
    ByteStream stream;
    // Start of packet claiming length 50
    for (uint8_t b : START_SIGNATURE) stream.push_back(b);
    stream.push_back(0x00);
    stream.push_back(0x32); // 50 bytes

    // 4 arbitrary bytes
    for (int i = 0; i < 4; i++) stream.push_back(0x77);

    // Another signature occurrence within the truncated data
    for (uint8_t b : START_SIGNATURE) stream.push_back(b);

    // Stream ends at 14 bytes (far short of 50 + 12 = 62 bytes)
    AnalysisResult result = analyzeStream(stream);

    if (result.packets.size() != 1) return false;
    return (result.packets[0].status == PacketStatus::INCOMPLETE);
}

// TEST 30: Valid packet immediately following malformed candidate
static bool testValidFollowingMalformed() {
    ByteStream stream;
    // Malformed candidate: signature + length 4 + payload 4 + bad end marker (0x00 0x00)
    for (uint8_t b : START_SIGNATURE) stream.push_back(b);
    stream.push_back(0x00);
    stream.push_back(0x04);
    stream.push_back('N'); stream.push_back('O'); stream.push_back('P'); stream.push_back('E');
    stream.push_back(0x12); stream.push_back(0x34); stream.push_back(0x56); stream.push_back(0x78);
    stream.push_back(0x00); stream.push_back(0x00); // Invalid end marker

    // Immediately followed by a valid packet
    ByteStream validPkt = buildPacket("RECOVERED");
    stream.insert(stream.end(), validPkt.begin(), validPkt.end());

    AnalysisResult result = analyzeStream(stream);

    if (result.packets.size() != 2) return false;
    if (result.packets[0].status != PacketStatus::INVALID_END_MARKER) return false;
    if (result.packets[1].status != PacketStatus::VALID) return false;
    return (payloadToText(result.packets[1].payload) == "RECOVERED");
}

// TEST 31: Empty binary file handling
static bool testEmptyBinaryFileHandling() {
    const std::string emptyPath = "sample_data/empty_test_file.bin";
    std::string error;

    // Create a 0-byte file
    if (!saveBinaryFile(emptyPath, ByteStream{}, error)) {
        return false;
    }

    ByteStream loaded;
    bool success = loadBinaryFile(emptyPath, loaded, error);
    std::remove(emptyPath.c_str());

    if (!success) return false;
    if (!loaded.empty()) return false;

    // Analyze empty stream
    AnalysisResult result = analyzeStream(loaded);
    return (result.totalBytes == 0 && result.packets.empty() && result.noiseBytes == 0);
}

// TEST 32: File path containing spaces
static bool testFilePathWithSpacesHandling() {
    const std::string pathWithSpaces = "sample_data/stream with spaces test.bin";
    std::string error;
    ByteStream original = buildPacket("SPACES_PATH");

    if (!saveBinaryFile(pathWithSpaces, original, error)) {
        return false;
    }

    ByteStream loaded;
    bool success = loadBinaryFile(pathWithSpaces, loaded, error);
    std::remove(pathWithSpaces.c_str());

    if (!success) return false;
    return (loaded == original);
}

// TEST 33: Exact KMP comparison counting
static bool testExactKMPComparisonCounting() {
    // Text: "AAAA", Pattern: "AA"
    // Each text character is compared with a pattern character exactly once!
    // Iteration 0: text[0]=='A' == pattern[0]=='A' (comp 1) -> textIndex=1, patternIndex=1
    // Iteration 1: text[1]=='A' == pattern[1]=='A' (comp 2) -> match at 0! patternIndex = lps[1] = 1
    // Iteration 2: text[2]=='A' == pattern[1]=='A' (comp 3) -> match at 1! patternIndex = lps[1] = 1
    // Iteration 3: text[3]=='A' == pattern[1]=='A' (comp 4) -> match at 2! patternIndex = lps[1] = 1
    // Loop ends (textIndex = 4).
    // Total exact comparisons = 4.
    uint8_t text[]    = {'A', 'A', 'A', 'A'};
    uint8_t pattern[] = {'A', 'A'};

    uint64_t kmpComparisons = 0;
    auto kmpMatches = kmpSearch(text, 4, pattern, 2, &kmpComparisons);

    if (kmpMatches.size() != 3) return false;
    if (kmpMatches[0] != 0 || kmpMatches[1] != 1 || kmpMatches[2] != 2) return false;
    if (kmpComparisons != 4) return false;

    // Verify Naive search on same input
    uint64_t naiveComparisons = 0;
    auto naiveMatches = naiveSearch(text, 4, pattern, 2, &naiveComparisons);

    // Naive compares:
    //   i=0: text[0], text[1] (2 comps) -> match at 0
    //   i=1: text[1], text[2] (2 comps) -> match at 1
    //   i=2: text[2], text[3] (2 comps) -> match at 2
    // Total naive comparisons = 6
    if (naiveMatches.size() != 3) return false;
    if (naiveMatches != kmpMatches) return false;
    return (naiveComparisons == 6 && kmpComparisons <= naiveComparisons);
}

// TEST 34: Reproducible stream generator output
static bool testReproducibleGenerator() {
    uint32_t testSeed = 987654321;
    ByteStream s1 = generateStream(StreamScenario::MIXED, testSeed);
    ByteStream s2 = generateStream(StreamScenario::MIXED, testSeed);

    if (s1.empty() || s1 != s2) return false;

    ByteStream n1 = generateStream(StreamScenario::NOISY, testSeed);
    ByteStream n2 = generateStream(StreamScenario::NOISY, testSeed);

    return (!n1.empty() && n1 == n2);
}

// TEST 35: Noise accounting with overlapping candidates
static bool testNoiseAccountingWithOverlap() {
    // Stream:
    // 5 bytes noise: 0x11, 0x22, 0x33, 0x44, 0x55
    // 16 bytes malformed candidate (bad end marker)
    // 17 bytes valid packet ("TEST!")
    // 3 bytes trailing noise: 0x99, 0x88, 0x77
    ByteStream stream = {0x11, 0x22, 0x33, 0x44, 0x55};

    // Malformed candidate (16 bytes)
    for (uint8_t b : START_SIGNATURE) stream.push_back(b);
    stream.push_back(0x00); stream.push_back(0x04);
    stream.push_back('B'); stream.push_back('A'); stream.push_back('D'); stream.push_back('!');
    stream.push_back(0x01); stream.push_back(0x02); stream.push_back(0x03); stream.push_back(0x04);
    stream.push_back(0x00); stream.push_back(0x00); // Invalid end marker

    // Valid packet (17 bytes)
    ByteStream validPkt = buildPacket("TEST!");
    stream.insert(stream.end(), validPkt.begin(), validPkt.end());

    // 3 bytes trailing noise
    stream.push_back(0x99); stream.push_back(0x88); stream.push_back(0x77);

    // Total stream size: 5 + 16 + 17 + 3 = 41 bytes.
    // Valid packet consumes 17 bytes.
    // The rest (5 + 16 + 3 = 24 bytes) are noise bytes.
    AnalysisResult result = analyzeStream(stream);

    if (result.totalBytes != 41) return false;
    if (result.noiseBytes != 24) return false;

    int validCount = 0;
    for (const auto& p : result.packets) {
        if (p.status == PacketStatus::VALID) validCount++;
    }
    return (validCount == 1);
}

// ═══════════════════════════════════════════════════════════════════
// TEST RUNNER
// ═══════════════════════════════════════════════════════════════════

int runAllTests() {
    totalPassed = 0;
    totalFailed = 0;

    std::vector<TestCase> tests = {
        {"01. Single valid packet",                testSingleValidPacket},
        {"02. Multiple valid packets",             testMultipleValidPackets},
        {"03. Noise before a packet",              testNoiseBeforePacket},
        {"04. Noise between packets",              testNoiseBetweenPackets},
        {"05. Corrupted payload",                  testCorruptedPayload},
        {"06. Incorrect CRC",                      testIncorrectCRC},
        {"07. Invalid end marker",                 testInvalidEndMarker},
        {"08. Incomplete packet",                  testIncompletePacket},
        {"09. Empty payload",                      testEmptyPayload},
        {"10. Large payload (1000 bytes)",          testLargePayload},
        {"11. Null bytes in payload",              testNullBytesInPayload},
        {"12. Non-printable payload",              testNonPrintablePayload},
        {"13. Signature inside payload",           testSignatureInsidePayload},
        {"14. Repeated signatures",                testRepeatedSignatures},
        {"15. Continuous stream (5 packets)",       testContinuousStream},
        {"16. Empty input stream",                 testEmptyStream},
        {"17. File loading errors",                testFileLoadingErrors},
        {"18. KMP overlapping matches",            testKMPOverlappingMatches},
        {"19. CRC-32 known answer (0xCBF43926)",   testCRC32KnownAnswer},
        {"20. Length field boundary cases",         testLengthBoundary},
        {"21. LPS array correctness",              testLPSArray},
        {"22. KMP vs Naive agreement",             testKMPNaiveAgreement},
        {"23. Statistics computation",             testStatisticsComputation},
        {"24. PayloadToHex formatting",            testPayloadToHex},
        {"25. Packet structure verification",      testPacketStructure},
        {"26. Maximum payload (65,535 bytes)",      testMaxPayload65535},
        {"27. Corrupted length field",             testCorruptedLengthField},
        {"28. Signature in corrupted payload",     testSignatureInsideCorruptedPayload},
        {"29. Incomplete with internal signature", testIncompleteWithInternalSignature},
        {"30. Valid following malformed",          testValidFollowingMalformed},
        {"31. Empty binary file handling",         testEmptyBinaryFileHandling},
        {"32. File path with spaces",              testFilePathWithSpacesHandling},
        {"33. Exact KMP comparison count",         testExactKMPComparisonCounting},
        {"34. Reproducible generator output",      testReproducibleGenerator},
        {"35. Noise accounting with overlap",      testNoiseAccountingWithOverlap},
    };

    for (const auto& tc : tests) {
        bool passed = false;
        try {
            passed = tc.testFunction();
        } catch (const std::exception& e) {
            std::cout << "  [EXCEPTION] " << tc.name << ": " << e.what() << "\n";
            passed = false;
        } catch (...) {
            std::cout << "  [EXCEPTION] " << tc.name << ": unknown error\n";
            passed = false;
        }
        reportTest(tc.name, passed);
    }

    std::cout << "\n  ────────────────────────────────────────\n";
    std::cout << "  Total: " << (totalPassed + totalFailed)
              << "  Passed: " << totalPassed
              << "  Failed: " << totalFailed << "\n";

    return totalFailed;
}
