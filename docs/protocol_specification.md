# PROTOCORE Protocol Specification

## Document Version

Version 1.1 — November 2026 (Audited & Hardened)

---

## 1. Overview & Architectural Scope

**PROTOCORE** uses a custom binary packet-framing protocol specifically engineered for educational simulation of physical/data-link framing mechanisms.

> **Important Clarification:**
> - **Simulation Purpose:** This is a custom educational packet-framing simulator designed to demonstrate fundamental Data Structures and Algorithms principles (KMP pattern matching, CRC-32 error detection, stream framing, and boundary recovery).
> - **Not Production Network Protocols:** PROTOCORE does not implement or mimic Ethernet (IEEE 802.3), IP (IPv4/IPv6), TCP, or UDP stack layers.
> - **Separation of Responsibilities:**
>   1. **Signature Detection (KMP):** Scans the continuous raw stream in $O(n + m)$ time to identify candidate start signatures (`0xAA 0xBB 0xCC 0xDD`).
>   2. **Boundary Disambiguation (Parser Engine):** Reads the length field, inspects the end marker, and establishes the exact physical packet boundaries.
>   3. **Integrity Validation (CRC-32):** Detects accidental bit corruption across the length header and payload data.

---

## 2. Packet Structure

Every valid packet consists of exactly five fields, transmitted in strict sequential order:

```
+--------------------+----------------+------------------+----------------+----------------+
|  Start Signature   | Payload Length |     Payload      |     CRC-32     |   End Marker   |
|      (4 bytes)     |   (2 bytes)    |  (0–65535 bytes) |   (4 bytes)    |   (2 bytes)    |
|   AA BB CC DD      |   Big-Endian   |   Raw Binary     |   Big-Endian   |     EE FF      |
+--------------------+----------------+------------------+----------------+----------------+
```

| # | Field | Size | Encoding | Description |
|---|---|---:|---|---|
| 1 | Start Signature | 4 bytes | Raw binary (`AA BB CC DD`) | Identifies potential packet start candidate |
| 2 | Payload Length | 2 bytes | Unsigned 16-bit, big-endian | Number of payload bytes ($0$ to $65,535$) |
| 3 | Payload | Variable | Raw binary ($0$ to $65,535$ bytes) | The transmitted message data |
| 4 | CRC-32 | 4 bytes | Unsigned 32-bit, big-endian | Checksum for accidental data corruption |
| 5 | End Marker | 2 bytes | Raw binary (`EE FF`) | Confirms structural packet boundary |

**Fixed Overhead:** 12 bytes (`4 + 2 + 4 + 2`)
**Total Packet Size:** $12 + \text{Payload Length}$ bytes

---

## 3. Field Definitions & Protocols

### 3.1 Start Signature
```
Hexadecimal: AA BB CC DD
```
- A fixed 4-byte synchronization sequence.
- KMP searches for this exact byte sequence across the raw binary stream.
- **Important:** The occurrence of this signature merely indicates a *candidate*. It does not guarantee a valid packet.

### 3.2 Payload Length
```
Encoding: Big-endian unsigned 16-bit integer (uint16_t)
Range:    0 to 65,535 bytes
```
- First byte: **High byte** (`length >> 8`)
- Second byte: **Low byte** (`length & 0xFF`)
- Example: $5$ bytes $\rightarrow$ `0x00 0x05`
- Example: $256$ bytes $\rightarrow$ `0x01 0x00`
- Example: Maximum supported $65,535$ bytes $\rightarrow$ `0xFF 0xFF`
- Represents **only** the payload size (excludes all overhead bytes).

### 3.3 Payload
```
Size:    0 to 65,535 bytes (defined by Length field)
Content: Arbitrary 8-bit octets (0x00 to 0xFF)
```
- May contain null bytes (`0x00`).
- May contain arbitrary non-printable binary data.
- May contain the start signature sequence `AA BB CC DD`. A start signature embedded inside a validated packet payload is treated as payload data and is **never** re-parsed as a new packet.

### 3.4 CRC-32 Checksum
```
Algorithm:   CRC-32/ISO-HDLC (ITU-T V.42 / Ethernet / ZIP / PNG)
Polynomial:  0xEDB88320 (reflected / reverse representation)
Initial:     0xFFFFFFFF
Final XOR:   0xFFFFFFFF
Storage:     Big-endian (4 bytes, most-significant byte first)
```
**Coverage:** Computed strictly over:
$$\text{CRC Coverage} = [\text{Length High Byte}] \, [\text{Length Low Byte}] \, [\text{Payload}_0 \dots \text{Payload}_{N-1}]$$

Start signature and end marker are excluded from the CRC calculation.

**Standard Test Vector:**
$$\text{CRC-32}(\text{"123456789"}) = \text{0xCBF43926}$$

### 3.5 End Marker
```
Hexadecimal: EE FF
```
- Exactly 2 bytes immediately following the 4 CRC bytes.
- Validates the packet termination boundary.

---

## 4. Packet Status & Error Classifications

PROTOCORE enforces distinct, non-overlapping classification categories:

| Status | Exact Condition | Parser Recovery Action |
|---|---|---|
| `VALID` | All checks pass: start signature, readable length, available bytes, end marker `EE FF`, and CRC matches. | Advance parser cursor past packet boundary ($P + 12 + L$). Consume $[P, P + 12 + L)$ as valid bytes. |
| `CRC_FAILURE` | Frame boundaries are intact (end marker `EE FF` verified), but calculated CRC does not match stored CRC. | Advance parser cursor past packet boundary ($P + 12 + L$). Consume $[P, P + 12 + L)$ as corrupted packet bytes. Inner payload signatures are ignored. |
| `INVALID_END_MARKER` | Sufficient bytes exist for declared length, but bytes at expected end marker do not equal `EE FF`. | Do not trust boundaries. Resume candidate search from the next signature hit. Unclaimed bytes treated as noise. |
| `INCOMPLETE` | Stream truncates before packet completes at the end of the stream ($P + 12 + L > \text{size}$ and no subsequent valid packet exists). | Mark partial received bytes $[P, \text{size})$ as incomplete candidate. Stream processing halts at stream end. |
| `MALFORMED` | Candidate violates structural framing (e.g. declared length exceeds stream but is followed by valid packets, or invalid header structure). | Do not trust boundaries. Resume candidate search from the next signature hit. Unclaimed bytes treated as noise. |
| `NOISE` | Bytes that do not belong to any validated or recognized packet structure. | Preserved in stream statistics as noise bytes. |

---

## 5. Distinction: Incomplete vs. Corrupted Packets

A fundamental viva distinction is maintained:
- **`CRC_FAILURE` (Corrupted Packet):** The frame structure was received in its entirety (length field was parsed and the end marker `EE FF` arrived at the expected offset), but bit errors altered the length or payload bytes during transit.
- **`INCOMPLETE` (Truncated Packet):** The stream ended abruptly before the expected number of bytes arrived. The packet cannot be evaluated for CRC or end marker because the required bytes do not exist in the stream.
- **`MALFORMED` (Corrupted Length / Header):** A candidate claims an impossible or oversized length that extends beyond available stream data, yet later valid packets exist in the stream. This indicates a corrupted length field rather than a transmission cutoff at the end of the stream.
