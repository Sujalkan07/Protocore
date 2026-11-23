// packet.cpp — Packet utilities and status handling
#include "packet.hpp"
#include <sstream>
#include <iomanip>
#include <cctype>

namespace protocore {

std::string statusToString(PacketStatus status) {
    switch (status) {
        case PacketStatus::VALID:              return "VALID PACKET";
        case PacketStatus::CRC_FAILURE:        return "CRC FAILURE";
        case PacketStatus::INVALID_END_MARKER: return "INVALID END MARKER";
        case PacketStatus::INCOMPLETE:         return "INCOMPLETE PACKET";
        case PacketStatus::MALFORMED:          return "MALFORMED PACKET";
        case PacketStatus::NOISE:              return "NOISE";
        default:                               return "UNKNOWN";
    }
}

// Convert payload to printable text: non-printable bytes become '.'
std::string payloadToText(const ByteStream& payload) {
    std::string text;
    text.reserve(payload.size());

    for (uint8_t byte : payload) {
        if (std::isprint(static_cast<unsigned char>(byte))) {
            text += static_cast<char>(byte);
        } else {
            text += '.';
        }
    }

    return text;
}

// Convert payload to hex string like "48 45 4C 4C 4F"
std::string payloadToHex(const ByteStream& payload) {
    std::ostringstream oss;
    for (size_t i = 0; i < payload.size(); i++) {
        if (i > 0) oss << " ";
        oss << std::uppercase << std::hex << std::setfill('0')
            << std::setw(2) << static_cast<int>(payload[i]);
    }
    return oss.str();
}

} // namespace protocore
