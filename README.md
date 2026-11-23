# PROTOCORE — Intelligent Network Packet Detection and Validation System

A C++17 Data Structures and Algorithms terminal application demonstrating binary packet framing, Knuth-Morris-Pratt (KMP) signature synchronization, and CRC-32 integrity validation.

---

## 1. Project Overview

**PROTOCORE** simulates a system receiving a continuous binary network stream containing multiple framed packets. Real-world network streams often suffer from noise, byte corruption, truncated transmissions, and arbitrary payloads (which may even contain synchronization patterns). PROTOCORE detects, extracts, validates, and classifies these packets using exact algorithmic methods.

### Key Objectives
- **Accurate Pattern Search:** Custom Knuth-Morris-Pratt (KMP) pattern-matching with $O(n + m)$ time complexity.
- **Robust Boundary Disambiguation:** Resolves signature collisions (signatures appearing inside payload data) using length-based framing.
- **Integrity Verification:** Table-driven CRC-32/ISO-HDLC checksum validation.
- **Resilience:** Handles noise bytes, payload bit errors, truncated packets, and empty payloads.
- **Performance Evaluation:** Benchmarks KMP against Naive brute-force search on large binary streams.

---

## 2. Packet Protocol Specification

Every packet follows this strict 12-byte fixed-overhead binary structure:

```
+--------------------+----------------+------------------+----------------+----------------+
|  Start Signature   | Payload Length |     Payload      |     CRC-32     |   End Marker   |
|      (4 bytes)     |   (2 bytes)    |  (0–65535 bytes) |   (4 bytes)    |   (2 bytes)    |
|   AA BB CC DD      |   Big-Endian   |   Raw Binary     |   Big-Endian   |     EE FF      |
+--------------------+----------------+------------------+----------------+----------------+
```

- **Start Signature:** `0xAA 0xBB 0xCC 0xDD` (4 bytes)
- **Payload Length:** 16-bit unsigned integer in big-endian order (high byte first)
- **Payload:** Variable length (0 to 65,535 bytes)
- **CRC-32:** Computed over `[Length High Byte, Length Low Byte, Payload...]` using reflected polynomial `0xEDB88320`
- **End Marker:** `0xEE 0xFF` (2 bytes)
- **Fixed Packet Overhead:** 12 bytes

---

## 3. Core Algorithms

### Knuth-Morris-Pratt (KMP) Pattern Search
- **LPS Array Construction:** Precomputes the Longest Proper Prefix which is also Suffix for the signature `AA BB CC DD` in $O(m)$ time and space.
- **Search Execution:** Scans the binary stream without backtracking the text index (`textIndex`). On mismatch, uses `lps[patternIndex - 1]` to shift pattern alignment, achieving optimal $O(n + m)$ search time.

### CRC-32/ISO-HDLC Checksum
- Reflected polynomial: `0xEDB88320`
- Initial CRC: `0xFFFFFFFF`, Final XOR: `0xFFFFFFFF`
- Precomputed 256-entry lookup table for high-throughput byte processing.
- Verified against the standard test vector: `"123456789"` $\rightarrow$ `0xCBF43926`.

---

## 4. Project Structure

```
Protocore/
├── CMakeLists.txt              # CMake build configuration
├── README.md                   # Complete system documentation
├── include/
│   ├── protocol.hpp            # Constants, signature, marker, and types
│   ├── packet.hpp              # ParsedPacket struct and classification enums
│   ├── kmp.hpp                 # KMP and Naive search interface
│   ├── crc32.hpp               # CRC-32/ISO-HDLC interface
│   ├── packet_parser.hpp       # Stream analysis and packet extraction engine
│   ├── stream_generator.hpp    # Multi-scenario binary stream generator
│   ├── file_handler.hpp        # Binary file read/write routines
│   └── statistics.hpp          # Metrics and validation summary
├── src/
│   ├── main.cpp                # Terminal interactive menu loop
│   ├── packet.cpp              # Status string conversion and hex/text formatters
│   ├── kmp.cpp                 # Manual KMP and Naive search implementations
│   ├── crc32.cpp               # Table-driven CRC-32 engine
│   ├── packet_parser.cpp       # Framing engine and boundary resolver
│   ├── stream_generator.cpp    # Normal, noisy, corrupted, and incomplete streams
│   ├── file_handler.cpp        # Safe binary I/O handling
│   └── statistics.cpp          # Metric computations and terminal display
├── tests/
│   ├── test_main.cpp           # Standalone unit test runner
│   └── test_cases.cpp          # 25 comprehensive unit and boundary tests
├── docs/
│   └── protocol_specification.md # Detailed protocol & validation rules
└── sample_data/
    └── README.md               # Guide to binary stream files
```

---

## 5. How to Build and Run

### Prerequisites
- C++17 compatible compiler: **GCC / MinGW** (`g++`) or **MSVC** (`cl`).
- Optional: **CMake** (3.16+).

---

### Method 1: Direct g++ Compilation (Fastest on Windows / MinGW)

Open your terminal (PowerShell, Command Prompt, or VS Code Terminal) in the project root:

```powershell
# 1. Create a build directory
mkdir -Force build

# 2. Compile the main application
g++ -std=c++17 -O2 -I include src/*.cpp tests/test_cases.cpp -o build/protocore.exe

# 3. Run PROTOCORE
.\build\protocore.exe
```

To build and run the standalone unit test suite:
```powershell
g++ -std=c++17 -O2 -I include src/packet.cpp src/kmp.cpp src/crc32.cpp src/packet_parser.cpp src/stream_generator.cpp src/file_handler.cpp src/statistics.cpp tests/test_cases.cpp tests/test_main.cpp -o build/protocore_tests.exe

.\build\protocore_tests.exe
```

---

### Method 2: Using CMake

```powershell
# Configure build
cmake -S . -B build

# Build targets
cmake --build build

# Run application
.\build\protocore.exe
```

---

## 6. Menu Options

1. **Generate Sample Network Stream:** Create sample streams (Normal, Noisy, Corrupted, Incomplete, Mixed) and optionally save to disk.
2. **Load Binary Stream from File:** Read raw binary streams from disk safely without text conversion.
3. **Analyze Network Stream:** Run KMP detection, extract packet boundaries, compute CRCs, and classify packets.
4. **View Detected Packets:** Detailed packet inspector showing offset, hex payload, readable ASCII, CRC status, and error classification.
5. **View Validation Statistics:** Real-time summary of processed bytes, valid packets, corruption rate, noise bytes, and payload throughput.
6. **Compare KMP vs Naive Search:** Microsecond-level benchmark comparing execution times and comparison counts over 500 KB test streams.
7. **Run Test Scenarios:** Execute the 25 integrated validation tests directly inside the console.
8. **Exit:** Terminate the program cleanly.

---

## 7. Test Suite Summary

The test suite covers 25 comprehensive verification scenarios:
- Single & multiple valid packets
- Noise prefixing, interleaving, and suffixing
- Corrupted payload bitflips & invalid CRCs
- Malformed and missing end markers
- Stream truncation (incomplete packet headers and payloads)
- Zero-length payload and 1000-byte payloads
- Binary payloads containing `0x00` null bytes and non-printable bytes
- Synchronization signature `AA BB CC DD` embedded inside the payload data
- Repeated signatures without packet data
- KMP overlapping pattern recognition (`ABAB` in `ABABAB`)
- Official CRC-32/ISO-HDLC test vector (`"123456789"` $\rightarrow$ `0xCBF43926`)
- Metric calculation and hex string formatting
