// file_handler.cpp — Binary file I/O
#include "file_handler.hpp"
#include <fstream>

namespace protocore {

bool loadBinaryFile(const std::string& filePath,
                    ByteStream& output,
                    std::string& errorMessage) {
    // Open the file in binary mode, positioned at end to get size
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);

    if (!file.is_open()) {
        errorMessage = "Could not open file: " + filePath;
        return false;
    }

    // Get file size from the current position (at end)
    std::streamsize fileSize = file.tellg();

    if (fileSize < 0) {
        errorMessage = "Could not determine file size: " + filePath;
        return false;
    }

    if (fileSize == 0) {
        // A 0-byte file is valid binary input with zero bytes
        output.clear();
        errorMessage.clear();
        return true;
    }

    // Seek back to the beginning
    file.seekg(0, std::ios::beg);

    // Read all bytes
    output.resize(static_cast<size_t>(fileSize));
    if (!file.read(reinterpret_cast<char*>(output.data()), fileSize)) {
        errorMessage = "Error reading file: " + filePath;
        output.clear();
        return false;
    }

    return true;
}

bool saveBinaryFile(const std::string& filePath,
                    const ByteStream& data,
                    std::string& errorMessage) {
    std::ofstream file(filePath, std::ios::binary);

    if (!file.is_open()) {
        errorMessage = "Could not create file: " + filePath;
        return false;
    }

    if (!data.empty()) {
        file.write(reinterpret_cast<const char*>(data.data()),
                   static_cast<std::streamsize>(data.size()));

        if (!file.good()) {
            errorMessage = "Error writing to file: " + filePath;
            return false;
        }
    }

    return true;
}

} // namespace protocore
