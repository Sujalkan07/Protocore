# PROTOCORE Protocol Specification

## Document Version

Version 1.0 — November 2026

## Overview

PROTOCORE uses a custom binary packet-framing protocol designed for educational purposes. This document defines the exact packet format, field encoding, validation rules, and error classification.

> **Important:** This is a custom educational packet-framing simulator. It does not implement Ethernet, IP, TCP, or any production-grade network protocol.

---

## Packet Structure

Every valid packet consists of exactly five fields, in order:

| # | Field | Size | Description |
|---|---|---:|---|
| 1 | Start Signature | 4 bytes | Identifies potential packet beginning |
| 2 | Payload Length | 2 bytes | Number of payload bytes (big-endian) |
| 3 | Payload | Variable | The actual data being transmitted |
| 4 | CRC-32 | 4 bytes | Integrity checksum (big-endian) |
| 5 | End Marker | 2 bytes | Confirms packet termination |

**Fixed overhead per packet:** 12 bytes (4 + 2 + 4 + 2)

**Total packet size:** 12 + Payload Length

---

## Field Definitions

### 1. Start Signature

```
Hex: AA BB CC DD
```

- Exactly 4 bytes.
- Must appear at the beginning of every valid packet.
- Used by the KMP algorithm to locate potential packet starts in the binary stream.

### 2. Payload Length

```
Encoding: Unsigned 16-bit integer, big-endian
Range:    0 to 65,535
```

- The first byte is the **high byte**, the second byte is the **low byte**.
- Example: payload length 5 → `0x00 0x05`
- Example: payload length 256 → `0x01 0x00`
- Represents **only** the payload size (excludes signature, CRC, and end marker).

### 3. Payload

```
Size:    0 to 65,535 bytes (determined by the Length field)
Content: Any byte value from 0x00 to 0xFF
```

- May contain null bytes (`0x00`).
- May contain non-printable characters.
- May contain the synchronization signature `AA BB CC DD`.
- A signature appearing inside a valid payload does **not** indicate a new packet.

### 4. CRC-32

```
Algorithm:    CRC-32/ISO-HDLC
Polynomial:   0xEDB88320 (reflected)
Initial:      0xFFFFFFFF
Final XOR:    0xFFFFFFFF
Encoding:     Big-endian (most significant byte first)
```

**CRC coverage:** The two payload-length bytes followed by all payload bytes.

```
CRC input = [Length High Byte] [Length Low Byte] [Payload Byte 0] ... [Payload Byte N-1]
```

The CRC does **not** cover the start signature or the end marker.

**Known test vector:**
- Input: ASCII string `"123456789"` (9 bytes)
- Expected CRC-32: `0xCBF43926`

### 5. End Marker

```
Hex: EE FF
```

- Exactly 2 bytes.
- Must appear immediately after the CRC field.

---

## Validation Rules

A packet is classified as **VALID** only if all of the following conditions are met:

1. The start signature `AA BB CC DD` is present.
2. At least 2 bytes follow the signature (payload length field).
3. The declared payload length is readable and the total packet (12 + length bytes) fits within the stream.
4. The CRC-32 recalculated from the length field + payload matches the CRC stored in the packet.
5. The end marker `EE FF` is present at the expected position.

---

## Error Classification

| Status | Condition |
|---|---|
| `VALID` | All checks passed |
| `CRC_FAILURE` | Packet structure is complete but CRC does not match |
| `INVALID_END_MARKER` | CRC matches but end marker bytes are wrong |
| `INCOMPLETE` | Stream ends before the packet can be fully read |
| `MALFORMED` | Candidate cannot be interpreted as a valid structure |
| `NOISE` | Bytes not belonging to any recognized packet |

---

## Packet Boundary Rules

1. After validating a packet, parsing advances past its boundary (offset + 12 + payload length).
2. Signature occurrences inside a validated packet's payload are ignored.
3. For invalid candidates (CRC failure, bad end marker), the parser records the error and continues to the next candidate.
4. For incomplete candidates, the parser records the incomplete status.

---

## Example Packet

Payload: `"HELLO"` (5 bytes: `48 45 4C 4C 4F`)

```
AA BB CC DD     ← Start Signature
00 05           ← Payload Length (5, big-endian)
48 45 4C 4C 4F  ← Payload ("HELLO")
XX XX XX XX     ← CRC-32 (computed over: 00 05 48 45 4C 4C 4F)
EE FF           ← End Marker
```

Total packet size: 12 + 5 = 17 bytes
