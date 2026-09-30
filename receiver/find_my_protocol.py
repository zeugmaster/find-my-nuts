#!/usr/bin/env python3
"""Wire framing and 2-bit Find My key material for find-my-nuts.

This module deliberately uses only the Python standard library.  It can be
used to build/test frames without Apple credentials or the FindMy.py package.
"""

from __future__ import annotations

import binascii
import struct
from dataclasses import dataclass
from typing import Iterable, Sequence

MAGIC = b"FMN1"
HEADER_SIZE = 10
TOKEN_PREFIX = b"cashuB"
SYMBOLS_PER_BYTE = 4
CANDIDATES_PER_SYMBOL = 4
UINT16_MAX = (1 << 16) - 1
UINT32_MAX = (1 << 32) - 1

# NIST P-224 / secp224r1: y^2 = x^3 - 3x + b (mod p).
P224_P = (1 << 224) - (1 << 96) + 1
P224_B = int("B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4", 16)


class FrameError(ValueError):
    """A frame is malformed, incomplete, or fails integrity validation."""


@dataclass(frozen=True)
class FrameHeader:
    token_length: int
    token_crc32: int

    @property
    def frame_length(self) -> int:
        return HEADER_SIZE + self.token_length


def _check_u32(value: int, name: str) -> None:
    if not 0 <= value <= UINT32_MAX:
        raise ValueError(f"{name} must fit in an unsigned 32-bit integer")


def encode_frame(token: str | bytes) -> bytes:
    """Return ``FMN1 + length + CRC32 + ASCII cashuB token``."""
    if isinstance(token, str):
        try:
            token_bytes = token.encode("ascii")
        except UnicodeEncodeError as exc:
            raise FrameError("Cashu token must contain ASCII only") from exc
    elif isinstance(token, bytes):
        token_bytes = token
        try:
            token_bytes.decode("ascii")
        except UnicodeDecodeError as exc:
            raise FrameError("Cashu token must contain ASCII only") from exc
    else:
        raise TypeError("token must be str or bytes")

    if not token_bytes.startswith(TOKEN_PREFIX):
        raise FrameError("Cashu token must start with 'cashuB'")
    if len(token_bytes) > UINT16_MAX:
        raise FrameError("Cashu token is too long for the u16 frame length")

    checksum = binascii.crc32(token_bytes) & UINT32_MAX
    return MAGIC + struct.pack(">HI", len(token_bytes), checksum) + token_bytes


def decode_header(header: bytes) -> FrameHeader:
    """Validate and decode an exact 10-byte frame header."""
    if len(header) != HEADER_SIZE:
        raise FrameError(f"header must be exactly {HEADER_SIZE} bytes")
    magic, token_length, checksum = struct.unpack(">4sHI", header)
    if magic != MAGIC:
        raise FrameError(f"bad frame magic: expected {MAGIC!r}")
    return FrameHeader(token_length=token_length, token_crc32=checksum)


def decode_frame(frame: bytes) -> str:
    """Validate an exact frame and return its full ASCII Cashu token."""
    if len(frame) < HEADER_SIZE:
        raise FrameError("frame is shorter than its header")
    header = decode_header(frame[:HEADER_SIZE])
    if len(frame) != header.frame_length:
        raise FrameError(
            f"frame length mismatch: header says {header.frame_length}, got {len(frame)}"
        )

    token_bytes = frame[HEADER_SIZE:]
    checksum = binascii.crc32(token_bytes) & UINT32_MAX
    if checksum != header.token_crc32:
        raise FrameError(
            f"CRC32 mismatch: expected {header.token_crc32:08x}, got {checksum:08x}"
        )
    try:
        token = token_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise FrameError("Cashu token is not ASCII") from exc
    if not token_bytes.startswith(TOKEN_PREFIX):
        raise FrameError("payload is not a cashuB token")
    return token


def bytes_to_symbols(data: bytes) -> tuple[int, ...]:
    """Split bytes into four MSB-first 2-bit values (0, 1, 2, or 3)."""
    return tuple((byte >> shift) & 0x03 for byte in data for shift in (6, 4, 2, 0))


def symbols_to_bytes(symbols: Sequence[int]) -> bytes:
    """Pack complete MSB-first 2-bit symbols back into bytes."""
    if len(symbols) % SYMBOLS_PER_BYTE:
        raise ValueError("symbol count must be a multiple of four")

    packed = bytearray()
    for start in range(0, len(symbols), SYMBOLS_PER_BYTE):
        byte = 0
        for symbol in symbols[start : start + SYMBOLS_PER_BYTE]:
            if symbol not in (0, 1, 2, 3):
                raise ValueError("symbols must be integers from zero through three")
            byte = (byte << 2) | symbol
        packed.append(byte)
    return bytes(packed)


def is_valid_p224_x(x_bytes: bytes) -> bool:
    """Return whether x admits a (non-infinite) secp224r1 public point."""
    if len(x_bytes) != 28:
        return False
    x = int.from_bytes(x_bytes, "big")
    if x >= P224_P:
        return False
    rhs = (pow(x, 3, P224_P) - 3 * x + P224_B) % P224_P
    # Zero has the root y=0; otherwise Euler's criterion must be +1.
    return rhs == 0 or pow(rhs, (P224_P - 1) // 2, P224_P) == 1


def candidate_key_bytes(
    symbol_index: int,
    message_id: int,
    modem_id: int,
    symbol_value: int,
) -> tuple[bytes, int]:
    """Create the exact valid 28-byte P-224 x-coordinate used by firmware."""
    _check_u32(symbol_index, "symbol index")
    _check_u32(message_id, "message ID")
    _check_u32(modem_id, "modem ID")
    if symbol_value not in (0, 1, 2, 3):
        raise ValueError("symbol value must be zero through three")

    prefix = b"\xBA\xBE" + struct.pack(">III", symbol_index, message_id, modem_id)
    suffix = (b"\x00" * 9) + bytes((symbol_value,))
    for counter in range(UINT32_MAX + 1):
        candidate = prefix + struct.pack(">I", counter) + suffix
        if is_valid_p224_x(candidate):
            return candidate, counter
    raise RuntimeError("could not construct a valid P-224 public key")


def iter_candidate_material(
    message_id: int,
    modem_id: int,
    start_symbol: int,
    symbol_count: int,
) -> Iterable[tuple[int, int, bytes, int]]:
    """Yield index, value, key, counter for all four candidates per symbol."""
    _check_u32(start_symbol, "start symbol")
    if symbol_count < 0 or start_symbol + symbol_count > UINT32_MAX + 1:
        raise ValueError("symbol range must fit in unsigned 32-bit indices")
    for symbol_index in range(start_symbol, start_symbol + symbol_count):
        for symbol_value in range(CANDIDATES_PER_SYMBOL):
            key, counter = candidate_key_bytes(
                symbol_index,
                message_id,
                modem_id,
                symbol_value,
            )
            yield symbol_index, symbol_value, key, counter
