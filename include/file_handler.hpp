// file_handler.hpp — Binary file I/O for loading and saving streams
#ifndef PROTOCORE_FILE_HANDLER_HPP
#define PROTOCORE_FILE_HANDLER_HPP

#include "protocol.hpp"
#include <string>

namespace protocore {

// ─── Load Binary File ───────────────────────────────────────────────
// Reads raw bytes from a file into a ByteStream.
// Returns true on success, false on error.
// Sets `errorMessage` on failure.
bool loadBinaryFile(const std::string& filePath,
                    ByteStream& output,
                    std::string& errorMessage);

// ─── Save Binary File ──────────────────────────────────────────────
// Writes a ByteStream to a file as raw bytes.
// Returns true on success, false on error.
bool saveBinaryFile(const std::string& filePath,
                    const ByteStream& data,
                    std::string& errorMessage);

} // namespace protocore

#endif // PROTOCORE_FILE_HANDLER_HPP
