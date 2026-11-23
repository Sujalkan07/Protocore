# PROTOCORE — Intelligent Network Packet Detection and Validation System

A C++17 Data Structures and Algorithms terminal application demonstrating binary packet framing, Knuth-Morris-Pratt (KMP) signature synchronization, and CRC-32 integrity validation.

---

## 1. Project Overview

**PROTOCORE** simulates a system receiving a continuous binary network stream containing multiple framed packets. Real-world network streams suffer from noise, bit errors, truncated transmissions, and arbitrary payloads (which may even contain synchronization patterns). PROTOCORE detects, extracts, validates, and classifies these packets using exact algorithmic methods.

> **Educational Project Scope:**
> This project is a custom educational packet-framing simulator. It does not implement or claim to implement production-level protocol stacks such as Ethernet (IEEE 802.3), IP (IPv4/IPv6), TCP, or UDP. It models the core Data Structures and Algorithms concepts behind stream framing and boundary recovery.

### Separation of Responsibilities
1. **Candidate Detection (KMP):** Knuth-Morris-Pratt algorithm scans the continuous binary stream in optimal $O(n + m)$ time to locate the synchronization signature `0xAA 0xBB 0xCC 0xDD`.
2. **Boundary Disambiguation (Parser Engine):** Inspects the length header, validates the terminal end marker `0xEE 0xFF`, and establishes physical packet boundaries without re-parsing encapsulated payload bytes.
3. **Integrity Validation (CRC-32):** CRC-32/ISO-HDLC recalculation detects accidental single-bit and multi-bit data corruption across the length header and payload.

---

## 2. Packet Protocol Specification

Every packet follows a strict 12-byte fixed-overhead binary framing structure:

```
+--------------------+----------------+------------------+----------------+----------------+
|  Start Signature   | Payload Length |     Payload      |     CRC-32     |   End Marker   |
|      (4 bytes)     |   (2 bytes)    |  (0–65535 bytes) |   (4 bytes)    |   (2 bytes)    |
|   AA BB CC DD      |   Big-Endian   |   Raw Binary     |   Big-Endian   |     EE FF      |
+--------------------+----------------+------------------+----------------+----------------+
```

- **Start Signature:** `0xAA 0xBB 0xCC 0xDD` (4 bytes)
- **Payload Length:** 16-bit unsigned integer in big-endian order ($0$ to $65,535$ bytes)
- **Payload:** Variable length ($0$ to $65,535$ bytes, supports null bytes, non-printable characters, and encapsulated signatures)
- **CRC-32:** Computed over `[Length High Byte, Length Low Byte, Payload...]` using reflected polynomial `0xEDB88320`
- **End Marker:** `0xEE 0xFF` (2 bytes)
- **Fixed Overhead:** 12 bytes

---

## 3. Packet Classifications & Recovery Policy

PROTOCORE enforces clean, unambiguous status categories:

- **`VALID`:** Structural framing and CRC-32 match. Parsing advances past this packet.
- **`CRC_FAILURE` (Corrupted Packet):** Structural framing is intact (end marker `EE FF` verified at the declared boundary), but CRC-32 mismatch indicates accidental payload corruption.
- **`INVALID_END_MARKER`:** Declared length fits within the stream, but the expected end marker is not `EE FF`. Boundary is untrusted; parser recovers at the next candidate signature.
- **`INCOMPLETE` (Truncated Packet):** Stream terminates abruptly at the end of transmission before the packet can complete.
- **`MALFORMED`:** Structural failure (e.g., corrupted length field claiming more bytes than exist in the stream, but followed by later valid packets).
- **`NOISE`:** Bytes not belonging to any recognized or validated packet.

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
│   ├── stream_generator.hpp    # Multi-scenario binary stream generator (seeded PRNG)
│   ├── file_handler.hpp        # Binary file read/write routines (empty-file safe)
│   └── statistics.hpp          # Metrics and validation summary
├── src/
│   ├── main.cpp                # Terminal interactive menu loop (quoted path support)
│   ├── packet.cpp              # Status string conversion and hex/text formatters
│   ├── kmp.cpp                 # Manual KMP (exact comparison count) and Naive search
│   ├── crc32.cpp               # Table-driven CRC-32 engine
│   ├── packet_parser.cpp       # Deterministic framing recovery engine
│   ├── stream_generator.cpp    # Normal, noisy, corrupted, and incomplete streams
│   ├── file_handler.cpp        # Safe binary I/O handling
│   └── statistics.cpp          # Metric computations and terminal display
├── tests/
│   ├── test_main.cpp           # Standalone unit test runner
│   └── test_cases.cpp          # 35 comprehensive unit and boundary tests
├── docs/
│   └── protocol_specification.md # Detailed protocol & validation rules
└── sample_data/
    └── README.md               # Guide to binary stream files
```

---

## 5. How to Build and Run

### Option A: Direct GCC / MinGW Compilation (Recommended on Windows)

Open your terminal (PowerShell, Command Prompt, or VS Code Terminal) in the project root:

```powershell
# 1. Compile the main application
g++ -std=c++17 -Wall -Wextra -Wpedantic -O2 -I include src/*.cpp tests/test_cases.cpp -o build/protocore.exe

# 2. Run PROTOCORE
.\build\protocore.exe
```

To compile and execute the standalone unit test suite:
```powershell
g++ -std=c++17 -Wall -Wextra -Wpedantic -O2 -I include src/packet.cpp src/kmp.cpp src/crc32.cpp src/packet_parser.cpp src/stream_generator.cpp src/file_handler.cpp src/statistics.cpp tests/test_cases.cpp tests/test_main.cpp -o build/test_runner.exe

.\build\test_runner.exe
```

---

### Option B: Using CMake with MinGW

```powershell
# Configure build for MinGW Makefiles
cmake -S . -B build -G "MinGW Makefiles"

# Build executables
cmake --build build

# Run application
.\build\protocore.exe
```

---

### Option C: Using CMake with MSVC (Visual Studio)

```powershell
# Configure build for default MSVC generator
cmake -S . -B build

# Build Release configuration
cmake --build build --config Release

# Run application
.\build\Release\protocore.exe
```

---

## 6. Menu Options

1. **Generate Sample Network Stream:** Create sample streams (Normal, Noisy, Corrupted, Incomplete, Mixed) using a reproducible seed, and optionally save to disk.
2. **Load Binary Stream from File:** Read raw binary streams from disk safely without text conversion (supports paths with spaces and empty 0-byte files).
3. **Analyze Network Stream:** Run KMP detection, extract packet boundaries, compute CRCs, and classify packets.
4. **View Detected Packets:** Detailed packet inspector showing offset, hex payload, readable ASCII, CRC status, and error classification.
5. **View Validation Statistics:** Real-time summary of processed bytes, valid packets, corruption rate, noise bytes, and payload throughput.
6. **Compare KMP vs Naive Search:** Microsecond-level benchmark comparing execution times and comparison counts over 500 KB test streams.
7. **Run Test Scenarios:** Execute all 35 integrated validation tests directly inside the console.
8. **Exit:** Terminate the program cleanly.

---

## 7. Test Suite Summary (35 Tests)

The test suite covers 35 comprehensive verification scenarios:
1. Single valid packet
2. Multiple valid packets
3. Noise before a packet
4. Noise between packets
5. Corrupted payload bitflips & CRC failure
6. Incorrect CRC bytes
7. Invalid end marker
8. Incomplete packet (truncated stream tail)
9. Zero-length payload
10. Large payload (1,000 bytes)
11. Binary payloads containing `0x00` null bytes
12. Binary payloads containing non-printable bytes
13. Synchronization signature `AA BB CC DD` embedded inside valid payload
14. Repeated signatures without packet data
15. Continuous stream (5 valid packets)
16. Empty input stream (0 bytes)
17. File loading error handling
18. KMP overlapping pattern recognition (`ABAB` in `ABABAB`)
19. Official CRC-32/ISO-HDLC test vector (`"123456789"` $\rightarrow$ `0xCBF43926`)
20. Length field boundary cases (1 byte and 256 bytes)
21. LPS array correctness verification
22. KMP vs Naive search result agreement
23. Validation statistics computation
24. Payload to hexadecimal string formatting
25. Packet binary framing structure verification
26. **Maximum supported payload of 65,535 bytes**
27. **Corrupted length field followed by valid packet data**
28. **Synchronization signature inside corrupted payload**
29. **Incomplete candidate with internal signature occurrence**
30. **Valid packet immediately following malformed candidate**
31. **Empty binary file (0 bytes) loaded and analyzed safely**
32. **File path containing spaces handled correctly**
33. **Exact KMP character comparison counting**
34. **Reproducible generator output using controlled seed**
35. **Noise accounting when candidate packets overlap**
