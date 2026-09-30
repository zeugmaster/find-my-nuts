import binascii
import struct
import unittest

from receiver.find_my_protocol import (
    HEADER_SIZE,
    FrameError,
    bytes_to_symbols,
    candidate_key_bytes,
    decode_frame,
    decode_header,
    encode_frame,
    is_valid_p224_x,
    iter_candidate_material,
    symbols_to_bytes,
)


class FindMyProtocolTests(unittest.TestCase):
    def test_frame_has_exact_big_endian_header_and_round_trips(self) -> None:
        token = "cashuBexample"
        frame = encode_frame(token)

        self.assertEqual(frame[:4], b"FMN1")
        self.assertEqual(frame[4:6], struct.pack(">H", len(token)))
        self.assertEqual(
            frame[6:10],
            struct.pack(">I", binascii.crc32(token.encode("ascii")) & 0xFFFFFFFF),
        )
        self.assertEqual(decode_header(frame[:HEADER_SIZE]).frame_length, len(frame))
        self.assertEqual(decode_frame(frame), token)

    def test_frame_rejects_non_cashu_non_ascii_and_bad_crc(self) -> None:
        with self.assertRaises(FrameError):
            encode_frame("not-a-token")
        with self.assertRaises(FrameError):
            encode_frame("cashuB€")

        frame = bytearray(encode_frame("cashuBexample"))
        frame[-1] ^= 1
        with self.assertRaisesRegex(FrameError, "CRC32 mismatch"):
            decode_frame(bytes(frame))

    def test_two_bit_symbols_are_msb_first(self) -> None:
        payload = bytes((0x1B, 0xE4))
        symbols = bytes_to_symbols(payload)
        self.assertEqual(symbols, (0, 1, 2, 3, 3, 2, 1, 0))
        self.assertEqual(symbols_to_bytes(symbols), payload)

    def test_candidate_key_matches_wire_layout_and_is_valid(self) -> None:
        key, counter = candidate_key_bytes(
            symbol_index=0x01020304,
            message_id=0x11223344,
            modem_id=0x4E555453,
            symbol_value=3,
        )

        self.assertEqual(len(key), 28)
        self.assertEqual(key[:2], b"\xBA\xBE")
        self.assertEqual(key[2:6], b"\x01\x02\x03\x04")
        self.assertEqual(key[6:10], b"\x11\x22\x33\x44")
        self.assertEqual(key[10:14], b"NUTS")
        self.assertEqual(key[14:18], struct.pack(">I", counter))
        self.assertEqual(key[18:27], b"\x00" * 9)
        self.assertEqual(key[27], 3)
        self.assertTrue(is_valid_p224_x(key))

    def test_one_source_byte_has_sixteen_candidates(self) -> None:
        candidates = list(iter_candidate_material(7, 0x4E555453, 0, 4))
        self.assertEqual(len(candidates), 16)
        self.assertEqual({item[0] for item in candidates}, {0, 1, 2, 3})
        self.assertEqual({item[1] for item in candidates}, {0, 1, 2, 3})
        self.assertEqual(len({item[2] for item in candidates}), 16)


if __name__ == "__main__":
    unittest.main()
