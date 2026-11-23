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
