// main.cpp — PROTOCORE main application with terminal interface
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
#include <chrono>
#include <cstdlib>

using namespace protocore;

// ═══════════════════════════════════════════════════════════════════
// GLOBAL STATE
// ═══════════════════════════════════════════════════════════════════
// The current binary stream and analysis result are stored globally
// so the user can generate/load a stream, analyze it, then view
// results across multiple menu actions.

static ByteStream      currentStream;
static AnalysisResult  currentResult;
static bool            streamLoaded  = false;
static bool            streamAnalyzed = false;

// ═══════════════════════════════════════════════════════════════════
// TERMINAL DISPLAY HELPERS
// ═══════════════════════════════════════════════════════════════════

static void printHeader() {
    std::cout << "\n";
    std::cout << "========================================================\n";
    std::cout << "                       PROTOCORE\n";
    std::cout << "          INTELLIGENT NETWORK PACKET DETECTION\n";
    std::cout << "                  AND VALIDATION SYSTEM\n";
    std::cout << "========================================================\n";
}

static void printMenu() {
    std::cout << "\nMAIN MENU\n\n";
    std::cout << "  1. Generate Sample Network Stream\n";
    std::cout << "  2. Load Binary Stream from File\n";
    std::cout << "  3. Analyze Network Stream\n";
    std::cout << "  4. View Detected Packets\n";
    std::cout << "  5. View Validation Statistics\n";
    std::cout << "  6. Compare KMP vs Naive Search\n";
    std::cout << "  7. Run Test Scenarios\n";
    std::cout << "  8. Exit\n";
    std::cout << "\n  Enter your choice: ";
}

static void pressEnterToContinue() {
    std::cout << "\n  Press Enter to continue...";
    std::cin.ignore(10000, '\n');
    std::cin.get();
}

static void printStreamPreview(const ByteStream& stream, size_t maxBytes = 64) {
    size_t displayCount = std::min(stream.size(), maxBytes);
    std::cout << "  Stream preview (" << stream.size() << " bytes total):\n  ";
    for (size_t i = 0; i < displayCount; i++) {
        std::cout << std::uppercase << std::hex << std::setfill('0')
                  << std::setw(2) << static_cast<int>(stream[i]) << " ";
        if ((i + 1) % 16 == 0 && i + 1 < displayCount) {
            std::cout << "\n  ";
        }
    }
    std::cout << std::dec;
    if (stream.size() > maxBytes) {
        std::cout << "...";
    }
    std::cout << "\n";
}

// ═══════════════════════════════════════════════════════════════════
// MENU OPTION 1: Generate Sample Stream
// ═══════════════════════════════════════════════════════════════════

static void menuGenerateStream() {
    std::cout << "\n";
    std::cout << "--------------------------------------------------------\n";
    std::cout << "          GENERATE SAMPLE NETWORK STREAM\n";
    std::cout << "--------------------------------------------------------\n\n";

    std::cout << "  Select a scenario:\n\n";
    std::cout << "    A. Normal    — Multiple valid packets\n";
    std::cout << "    B. Noisy     — Valid packets with random noise\n";
    std::cout << "    C. Corrupted — Packets with modified payload bytes\n";
    std::cout << "    D. Incomplete— Stream truncated before packet ends\n";
    std::cout << "    E. Mixed     — Valid + Corrupted + Noise + Incomplete\n";
    std::cout << "\n  Enter choice (A-E): ";

    char choice;
    std::cin >> choice;

    StreamScenario scenario;
    switch (std::toupper(choice)) {
        case 'A': scenario = StreamScenario::NORMAL;     break;
        case 'B': scenario = StreamScenario::NOISY;      break;
        case 'C': scenario = StreamScenario::CORRUPTED;  break;
        case 'D': scenario = StreamScenario::INCOMPLETE;  break;
        case 'E': scenario = StreamScenario::MIXED;      break;
        default:
            std::cout << "\n  Invalid choice. Returning to menu.\n";
            return;
    }

    currentStream = generateStream(scenario);
    streamLoaded  = true;
    streamAnalyzed = false;

    std::cout << "\n  Stream generated: " << scenarioName(scenario) << "\n";
    std::cout << "  Total bytes: " << currentStream.size() << "\n\n";
    printStreamPreview(currentStream);

    // Offer to save the stream to a file
    std::cout << "\n  Save stream to file? (y/n): ";
    char save;
    std::cin >> save;
    if (std::tolower(save) == 'y') {
        std::string filename = "sample_data/generated_stream.bin";
        std::string error;
        if (saveBinaryFile(filename, currentStream, error)) {
            std::cout << "  Saved to: " << filename << "\n";
        } else {
            std::cout << "  Error: " << error << "\n";
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// MENU OPTION 2: Load Binary Stream from File
// ═══════════════════════════════════════════════════════════════════

static void menuLoadFile() {
    std::cout << "\n";
    std::cout << "--------------------------------------------------------\n";
    std::cout << "            LOAD BINARY STREAM FROM FILE\n";
    std::cout << "--------------------------------------------------------\n\n";
    std::cout << "  The file should contain raw binary data with packets\n";
    std::cout << "  in the PROTOCORE format (signature: AA BB CC DD).\n\n";
    std::cout << "  Enter file path: ";

    std::string filePath;
    std::getline(std::cin >> std::ws, filePath);

    // Strip surrounding quotes if the user pasted/dragged a path with quotes
    if (filePath.size() >= 2 && filePath.front() == '"' && filePath.back() == '"') {
        filePath = filePath.substr(1, filePath.size() - 2);
    }

    std::string error;
    ByteStream data;
    if (loadBinaryFile(filePath, data, error)) {
        currentStream  = data;
        streamLoaded   = true;
        streamAnalyzed = false;
        std::cout << "\n  File loaded successfully.\n";
        std::cout << "  Bytes loaded: " << currentStream.size() << "\n\n";
        printStreamPreview(currentStream);
    } else {
        std::cout << "\n  Error: " << error << "\n";
    }
}

// ═══════════════════════════════════════════════════════════════════
// MENU OPTION 3: Analyze Network Stream
// ═══════════════════════════════════════════════════════════════════

static void menuAnalyzeStream() {
    std::cout << "\n";
    std::cout << "--------------------------------------------------------\n";
    std::cout << "             ANALYZE NETWORK STREAM\n";
    std::cout << "--------------------------------------------------------\n\n";

    if (!streamLoaded) {
        std::cout << "  No stream loaded. Please generate or load a stream first.\n";
        return;
    }

    std::cout << "  Analyzing " << currentStream.size() << " bytes...\n";

    auto startTime = std::chrono::high_resolution_clock::now();
    currentResult = analyzeStream(currentStream);
    auto endTime = std::chrono::high_resolution_clock::now();

    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(
                        endTime - startTime);

    streamAnalyzed = true;

    std::cout << "\n  Analysis complete.\n\n";
    std::cout << "  Time elapsed      : " << duration.count() << " microseconds\n";
    std::cout << "  Signature matches : " << currentResult.signatureHits.size() << "\n";
    std::cout << "  Packets found     : " << currentResult.packets.size() << "\n";
    std::cout << "  Noise bytes       : " << currentResult.noiseBytes << "\n";

    // Quick summary
    size_t valid = 0, invalid = 0;
    for (const auto& pkt : currentResult.packets) {
        if (pkt.status == PacketStatus::VALID) valid++;
        else invalid++;
    }
    std::cout << "  Valid packets     : " << valid << "\n";
    std::cout << "  Invalid/Other     : " << invalid << "\n";
}

// ═══════════════════════════════════════════════════════════════════
// MENU OPTION 4: View Detected Packets
// ═══════════════════════════════════════════════════════════════════

static void menuViewPackets() {
    std::cout << "\n";
    std::cout << "--------------------------------------------------------\n";
    std::cout << "               DETECTED PACKETS\n";
    std::cout << "--------------------------------------------------------\n";

    if (!streamAnalyzed) {
        std::cout << "\n  No analysis results. Please analyze a stream first.\n";
        return;
    }

    if (currentResult.packets.empty()) {
        std::cout << "\n  No packets detected in the stream.\n";
        return;
    }

    for (size_t i = 0; i < currentResult.packets.size(); i++) {
        const ParsedPacket& pkt = currentResult.packets[i];

        std::cout << "\n--------------------------------------------------------\n";
        std::cout << "PACKET #" << (i + 1) << "\n";
        std::cout << "--------------------------------------------------------\n\n";

        std::cout << "  Offset          : " << pkt.streamOffset << "\n";
        std::cout << "  Payload Length  : " << pkt.payloadLength << " bytes\n";

        if (!pkt.payload.empty()) {
            std::cout << "  Payload Text    : " << payloadToText(pkt.payload) << "\n";
            // Limit hex display for very large payloads
            if (pkt.payload.size() <= 128) {
                std::cout << "  Payload Hex     : " << payloadToHex(pkt.payload) << "\n";
            } else {
                std::string hex = payloadToHex(
                    ByteStream(pkt.payload.begin(), pkt.payload.begin() + 64));
                std::cout << "  Payload Hex     : " << hex << " ...\n";
            }
        }

        std::cout << "\n";

        // CRC information
        if (pkt.status != PacketStatus::INCOMPLETE &&
            pkt.status != PacketStatus::MALFORMED) {
            char expectedBuf[16], calculatedBuf[16];
            std::snprintf(expectedBuf, sizeof(expectedBuf), "%08X", pkt.expectedCRC);
            std::snprintf(calculatedBuf, sizeof(calculatedBuf), "%08X", pkt.calculatedCRC);

            std::cout << "  Expected CRC    : 0x" << expectedBuf << "\n";
            std::cout << "  Calculated CRC  : 0x" << calculatedBuf << "\n";
            std::cout << "  CRC Status      : "
                      << (pkt.expectedCRC == pkt.calculatedCRC ? "PASSED" : "FAILED")
                      << "\n";

            // End marker
            char markerBuf[16];
            std::snprintf(markerBuf, sizeof(markerBuf), "%02X %02X",
                          pkt.endMarker[0], pkt.endMarker[1]);
            std::cout << "  End Marker      : " << markerBuf;
            bool markerValid = (pkt.endMarker[0] == END_MARKER[0] &&
                                pkt.endMarker[1] == END_MARKER[1]);
            std::cout << (markerValid ? " (VALID)" : " (INVALID)") << "\n";
        }

        std::cout << "  Final Status    : " << statusToString(pkt.status) << "\n";
        std::cout << "  Detail          : " << pkt.statusDetail << "\n";
    }

    std::cout << "\n--------------------------------------------------------\n";
}

// ═══════════════════════════════════════════════════════════════════
// MENU OPTION 5: View Validation Statistics
// ═══════════════════════════════════════════════════════════════════

static void menuViewStatistics() {
    if (!streamAnalyzed) {
        std::cout << "\n  No analysis results. Please analyze a stream first.\n";
        return;
    }

    Statistics stats = computeStatistics(currentResult);
    displayStatistics(stats);
}

// ═══════════════════════════════════════════════════════════════════
// MENU OPTION 6: Compare KMP vs Naive Search
// ═══════════════════════════════════════════════════════════════════

static void menuCompareAlgorithms() {
    std::cout << "\n";
    std::cout << "--------------------------------------------------------\n";
    std::cout << "         KMP vs NAIVE PATTERN SEARCH COMPARISON\n";
    std::cout << "--------------------------------------------------------\n\n";

    // Generate a large test stream for meaningful timing
    const size_t STREAM_SIZE = 500000; // 500 KB
    std::cout << "  Generating test stream (" << STREAM_SIZE << " bytes)...\n";

    ByteStream testStream;
    testStream.reserve(STREAM_SIZE);

    // Fill with semi-random data, inserting signatures periodically
    std::srand(42); // Fixed seed for reproducibility
    ByteStream sigVec(START_SIGNATURE.begin(), START_SIGNATURE.end());

    for (size_t i = 0; i < STREAM_SIZE; i++) {
        testStream.push_back(static_cast<uint8_t>(std::rand() % 256));
    }

    // Insert known signatures at specific positions
    size_t insertCount = 0;
    for (size_t pos = 1000; pos + SIGNATURE_SIZE < STREAM_SIZE; pos += 5000) {
        for (size_t j = 0; j < SIGNATURE_SIZE; j++) {
            testStream[pos + j] = START_SIGNATURE[j];
        }
        insertCount++;
    }

    std::cout << "  Inserted " << insertCount
              << " known signature occurrences.\n\n";

    // ── KMP Search ──────────────────────────────────────────────
    uint64_t kmpComparisons = 0;
    auto kmpStart = std::chrono::high_resolution_clock::now();
    auto kmpMatches = kmpSearch(testStream, sigVec, &kmpComparisons);
    auto kmpEnd = std::chrono::high_resolution_clock::now();
    auto kmpTime = std::chrono::duration_cast<std::chrono::microseconds>(
                       kmpEnd - kmpStart);

    // ── Naive Search ────────────────────────────────────────────
    uint64_t naiveComparisons = 0;
    auto naiveStart = std::chrono::high_resolution_clock::now();
    auto naiveMatches = naiveSearch(testStream, sigVec, &naiveComparisons);
    auto naiveEnd = std::chrono::high_resolution_clock::now();
    auto naiveTime = std::chrono::duration_cast<std::chrono::microseconds>(
                         naiveEnd - naiveStart);

    // ── Display Results ─────────────────────────────────────────
    std::cout << "  " << std::left << std::setw(25) << "Metric"
              << std::setw(20) << "KMP"
              << std::setw(20) << "Naive" << "\n";
    std::cout << "  " << std::string(65, '-') << "\n";

    std::cout << "  " << std::setw(25) << "Execution Time"
              << std::setw(20) << (std::to_string(kmpTime.count()) + " us")
              << std::setw(20) << (std::to_string(naiveTime.count()) + " us")
              << "\n";

    std::cout << "  " << std::setw(25) << "Comparisons"
              << std::setw(20) << kmpComparisons
              << std::setw(20) << naiveComparisons << "\n";

    std::cout << "  " << std::setw(25) << "Matches Found"
              << std::setw(20) << kmpMatches.size()
              << std::setw(20) << naiveMatches.size() << "\n";

    std::cout << "  " << std::setw(25) << "Time Complexity"
              << std::setw(20) << "O(n + m)"
              << std::setw(20) << "O(n * m)" << "\n";

    // Verify both algorithms found the same matches
    bool resultsMatch = (kmpMatches == naiveMatches);
    std::cout << "\n  Results match: " << (resultsMatch ? "YES" : "NO") << "\n";

    std::cout << "\n  Note: Actual timing depends on hardware, compiler\n"
              << "  optimizations, and input characteristics. For short\n"
              << "  patterns, the difference may be small.\n";
}

// ═══════════════════════════════════════════════════════════════════
// MENU OPTION 7: Run Test Scenarios (delegates to test runner)
// ═══════════════════════════════════════════════════════════════════
// Forward declaration — defined in the test module, linked in
extern int runAllTests();

static void menuRunTests() {
    std::cout << "\n";
    std::cout << "--------------------------------------------------------\n";
    std::cout << "                 RUNNING TEST SUITE\n";
    std::cout << "--------------------------------------------------------\n\n";

    int failures = runAllTests();

    if (failures == 0) {
        std::cout << "\n  All tests PASSED.\n";
    } else {
        std::cout << "\n  " << failures << " test(s) FAILED.\n";
    }
}

// ═══════════════════════════════════════════════════════════════════
// MAIN FUNCTION
// ═══════════════════════════════════════════════════════════════════

int main() {
    printHeader();

    bool running = true;

    while (running) {
        printMenu();

        int choice = 0;
        if (!(std::cin >> choice)) {
            std::cin.clear();
            std::cin.ignore(10000, '\n');
            std::cout << "\n  Invalid input. Please enter a number (1-8).\n";
            continue;
        }

        switch (choice) {
            case 1: menuGenerateStream();     pressEnterToContinue(); break;
            case 2: menuLoadFile();            pressEnterToContinue(); break;
            case 3: menuAnalyzeStream();       pressEnterToContinue(); break;
            case 4: menuViewPackets();         pressEnterToContinue(); break;
            case 5: menuViewStatistics();      pressEnterToContinue(); break;
            case 6: menuCompareAlgorithms();   pressEnterToContinue(); break;
            case 7: menuRunTests();            pressEnterToContinue(); break;
            case 8:
                std::cout << "\n  Exiting PROTOCORE. Goodbye!\n\n";
                running = false;
                break;
            default:
                std::cout << "\n  Invalid choice. Please select 1-8.\n";
                break;
        }
    }

    return 0;
}
