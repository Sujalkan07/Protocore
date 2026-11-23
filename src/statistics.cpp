// statistics.cpp — Validation statistics computation and display
#include "statistics.hpp"
#include <iostream>
#include <iomanip>

namespace protocore {

Statistics computeStatistics(const AnalysisResult& result) {
    Statistics stats;

    stats.totalBytes       = result.totalBytes;
    stats.signatureMatches = result.signatureHits.size();
    stats.noiseBytes       = result.noiseBytes;

    for (const auto& pkt : result.packets) {
        switch (pkt.status) {
            case PacketStatus::VALID:
                stats.packetsAccepted++;
                stats.totalValidPayload += pkt.payloadLength;
                break;
            case PacketStatus::CRC_FAILURE:
                stats.corruptedPackets++;
                break;
            case PacketStatus::INCOMPLETE:
                stats.incompletePackets++;
                break;
            case PacketStatus::INVALID_END_MARKER:
                stats.invalidEndMarker++;
                break;
            case PacketStatus::MALFORMED:
                stats.malformedCandidates++;
                break;
            default:
                break;
        }
    }

    return stats;
}

void displayStatistics(const Statistics& stats) {
    std::cout << "\n";
    std::cout << "========================================================\n";
    std::cout << "                 VALIDATION STATISTICS\n";
    std::cout << "========================================================\n\n";

    std::cout << std::left;
    std::cout << "  " << std::setw(30) << "Total Bytes Processed"
              << ": " << stats.totalBytes << "\n";
    std::cout << "  " << std::setw(30) << "Synchronization Matches"
              << ": " << stats.signatureMatches << "\n";
    std::cout << "  " << std::setw(30) << "Packets Accepted (Valid)"
              << ": " << stats.packetsAccepted << "\n";
    std::cout << "  " << std::setw(30) << "Corrupted Packets (CRC)"
              << ": " << stats.corruptedPackets << "\n";
    std::cout << "  " << std::setw(30) << "Invalid End Marker"
              << ": " << stats.invalidEndMarker << "\n";
    std::cout << "  " << std::setw(30) << "Incomplete Packets"
              << ": " << stats.incompletePackets << "\n";
    std::cout << "  " << std::setw(30) << "Malformed Candidates"
              << ": " << stats.malformedCandidates << "\n";
    std::cout << "  " << std::setw(30) << "Noise Bytes"
              << ": " << stats.noiseBytes << "\n";
    std::cout << "  " << std::setw(30) << "Total Valid Payload Bytes"
              << ": " << stats.totalValidPayload << "\n";

    // Valid packet percentage
    size_t totalCandidates = stats.packetsAccepted + stats.corruptedPackets
                           + stats.incompletePackets + stats.malformedCandidates
                           + stats.invalidEndMarker;
    if (totalCandidates > 0) {
        double percentage = (static_cast<double>(stats.packetsAccepted)
                            / totalCandidates) * 100.0;
        std::cout << "\n  " << std::setw(30) << "Valid Packet Rate"
                  << ": " << std::fixed << std::setprecision(1)
                  << percentage << "%\n";
    }

    std::cout << "\n========================================================\n";
}

} // namespace protocore
