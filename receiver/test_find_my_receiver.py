import asyncio
import io
import re
import unittest
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch

from receiver.find_my_protocol import bytes_to_symbols, encode_frame
from receiver.find_my_receiver import (
    CONFLICT,
    DecodedReports,
    HEADER_SYMBOLS,
    MAX_KEYS_PER_FETCH,
    MessageSnapshot,
    WatchDisplay,
    _close_account,
    _run_watch,
    _snapshot_from_exact_frame,
    decode_reports,
    fetch_message_snapshot,
    fetch_reports_batched,
    make_candidate_keys,
    message_id_sequence,
)


MODEM_ID = 0x4E555453


def reports_for(keys, frame: bytes, visible_symbols: int | None = None):
    symbols = bytes_to_symbols(frame)
    reports = {}
    limit = len(symbols) if visible_symbols is None else visible_symbols
    for key in keys:
        if key.symbol_index >= min(limit, len(symbols)):
            reports[key] = []
            continue
        reports[key] = [object()] if key.symbol_value == symbols[key.symbol_index] else []
    return reports


def partial_frame(frame: bytes, missing=(), conflicting=()):
    symbols = list(bytes_to_symbols(frame))
    for index in missing:
        symbols[index] = None
    for index in conflicting:
        symbols[index] = CONFLICT
    return DecodedReports(
        symbols=tuple(symbols),
        rendered="",
        resolved_symbols=len(symbols) - len(missing) - len(conflicting),
        report_count=len(symbols) - len(missing),
        candidate_hits=len(symbols) - len(missing),
        conflicting_symbols=len(conflicting),
    )


class FindMyReceiverTests(unittest.TestCase):
    def test_recovers_one_missing_symbol_at_every_body_position(self) -> None:
        token = "cashuBABCDpqrs0123"
        frame = encode_frame(token)
        for index in range(HEADER_SYMBOLS, len(frame) * 4):
            with self.subTest(symbol_index=index):
                snapshot = _snapshot_from_exact_frame(
                    0, partial_frame(frame, missing=(index,)), len(frame)
                )
                self.assertTrue(snapshot.complete)
                self.assertEqual(snapshot.token, token)
                self.assertEqual(snapshot.resolved_symbols, len(frame) * 4)
                self.assertEqual(snapshot.recovered_symbol_indices, (index,))

    def test_recovery_refuses_missing_header_multiple_erasures_and_conflicts(self) -> None:
        frame = encode_frame("cashuBproof")
        cases = (
            ((0,), ()),
            ((HEADER_SYMBOLS - 1,), ()),
            ((HEADER_SYMBOLS, HEADER_SYMBOLS + 1), ()),
            ((HEADER_SYMBOLS,), (HEADER_SYMBOLS + 1,)),
            ((), (HEADER_SYMBOLS,)),
        )
        for missing, conflicting in cases:
            with self.subTest(missing=missing, conflicting=conflicting):
                snapshot = _snapshot_from_exact_frame(
                    0, partial_frame(frame, missing, conflicting), len(frame)
                )
                self.assertFalse(snapshot.complete)
                self.assertIsNone(snapshot.token)
                self.assertEqual(snapshot.recovered_symbol_indices, ())

    def test_recovery_requires_crc_and_exact_length(self) -> None:
        frame = bytearray(encode_frame("cashuBproof"))
        frame[6] ^= 0x80  # Corrupt the received CRC; no candidate may pass.
        snapshot = _snapshot_from_exact_frame(
            0, partial_frame(bytes(frame), missing=(HEADER_SYMBOLS,)), len(frame)
        )
        self.assertFalse(snapshot.complete)
        self.assertIsNone(snapshot.token)
        valid_frame = encode_frame("cashuBproof")
        snapshot = _snapshot_from_exact_frame(
            0, partial_frame(valid_frame, missing=(HEADER_SYMBOLS,)), len(valid_frame) + 1
        )
        self.assertFalse(snapshot.complete)
        self.assertIsNone(snapshot.token)

    def test_fetch_recovers_missing_report_with_valid_received_header(self) -> None:
        token = "cashuBproof"
        frame = encode_frame(token)
        missing_index = HEADER_SYMBOLS + 3

        class FakeAccount:
            def fetch_location_history(self, keys):
                reports = reports_for(keys, frame)
                for key in keys:
                    if key.symbol_index == missing_index:
                        reports[key] = []
                return reports

        with patch("receiver.find_my_receiver._save_session"):
            snapshot = fetch_message_snapshot(
                FakeAccount(), 0, MODEM_ID, 100, Path("unused")
            )
        self.assertTrue(snapshot.complete)
        self.assertEqual(snapshot.token, token)
        self.assertEqual(snapshot.recovered_symbol_indices, (missing_index,))

    def test_display_identifies_crc_recovery(self) -> None:
        frame = encode_frame("cashuBproof")
        snapshot = _snapshot_from_exact_frame(
            0, partial_frame(frame, missing=(HEADER_SYMBOLS,)), len(frame)
        )
        output = io.StringIO()
        display = WatchDisplay(MODEM_ID, (0,), 60, plain=True, stream=output)
        display.render({0: snapshot})
        self.assertIn("1 symbol recovered via CRC", output.getvalue())
        self.assertIn("1 symbol recovered via CRC", display._completion_lines(snapshot)[0])

    def test_account_closes_on_the_loop_that_created_it(self) -> None:
        loop = asyncio.new_event_loop()

        class FakeAccount:
            _evt_loop = loop

            def __init__(self):
                self.closed_on = None

            async def close(self):
                self.closed_on = asyncio.get_running_loop()

        account = FakeAccount()
        try:
            _close_account(account)
            self.assertIs(account.closed_on, loop)
            self.assertFalse(asyncio.all_tasks(loop))
        finally:
            loop.close()

    def test_decodes_complete_and_conflicting_two_bit_symbols(self) -> None:
        data = b"FMN1"
        symbols = bytes_to_symbols(data)
        keys = make_candidate_keys(9, MODEM_ID, 0, len(symbols))
        reports = reports_for(keys, data)
        decoded = decode_reports(keys, reports, 0, len(symbols))

        self.assertTrue(decoded.complete)
        self.assertEqual(decoded.to_bytes(), data)
        self.assertEqual(decoded.resolved_symbols, len(symbols))

        wanted_zero = symbols[0]
        conflicting_value = (wanted_zero + 1) % 4
        reports[keys[conflicting_value]] = [object()]  # A second value for symbol zero.
        conflicting = decode_reports(keys, reports, 0, len(symbols))
        self.assertFalse(conflicting.complete)
        self.assertTrue(conflicting.rendered.startswith("!"))
        self.assertEqual(conflicting.conflicting_symbols, 1)

    def test_fetches_header_then_exact_frame(self) -> None:
        frame = encode_frame("cashuBproof")

        class FakeAccount:
            def __init__(self):
                self.batch_sizes = []

            def fetch_location_history(self, keys):
                self.batch_sizes.append(len(keys))
                return reports_for(keys, frame)

        account = FakeAccount()
        with patch("receiver.find_my_receiver._save_session"):
            snapshot = fetch_message_snapshot(
                account,
                message_id=5,
                modem_id=MODEM_ID,
                max_token_bytes=100,
                state_dir=Path("unused"),
            )

        self.assertTrue(snapshot.complete)
        self.assertEqual(snapshot.token, "cashuBproof")
        self.assertEqual(account.batch_sizes[0], HEADER_SYMBOLS * 4)
        exact_candidate_count = len(frame) * 4 * 4
        self.assertEqual(
            account.batch_sizes[1:],
            [
                min(MAX_KEYS_PER_FETCH, exact_candidate_count),
                exact_candidate_count - MAX_KEYS_PER_FETCH,
            ],
        )

    def test_partial_header_does_not_fetch_untrusted_length(self) -> None:
        frame = encode_frame("cashuBproof")

        class FakeAccount:
            def __init__(self):
                self.calls = 0

            def fetch_location_history(self, keys):
                self.calls += 1
                return reports_for(keys, frame, visible_symbols=3)

        account = FakeAccount()
        with patch("receiver.find_my_receiver._save_session"):
            snapshot = fetch_message_snapshot(
                account,
                message_id=6,
                modem_id=MODEM_ID,
                max_token_bytes=100,
                state_dir=Path("unused"),
            )

        self.assertEqual(snapshot.phase, "header-partial")
        self.assertEqual(snapshot.resolved_symbols, 3)
        self.assertEqual(account.calls, 1)

    def test_known_length_queries_body_before_header_is_complete(self) -> None:
        frame = encode_frame("cashuBproof")

        class FakeAccount:
            def __init__(self):
                self.batch_sizes = []

            def fetch_location_history(self, keys):
                self.batch_sizes.append(len(keys))
                return reports_for(keys, frame, visible_symbols=3)

        account = FakeAccount()
        with patch("receiver.find_my_receiver._save_session"):
            snapshot = fetch_message_snapshot(
                account,
                message_id=6,
                modem_id=MODEM_ID,
                max_token_bytes=100,
                state_dir=Path("unused"),
                expected_token_bytes=len("cashuBproof"),
            )

        self.assertEqual(snapshot.phase, "frame-partial")
        self.assertEqual(snapshot.resolved_symbols, 3)
        self.assertEqual(snapshot.total_symbols, len(frame) * 4)
        self.assertGreater(len(account.batch_sizes), 1)
        self.assertEqual(sum(account.batch_sizes), len(frame) * 4 * 4)

    def test_known_length_still_requires_valid_exact_frame(self) -> None:
        frame = encode_frame("cashuBproof")

        class FakeAccount:
            def fetch_location_history(self, keys):
                return reports_for(keys, frame)

        with patch("receiver.find_my_receiver._save_session"):
            snapshot = fetch_message_snapshot(
                FakeAccount(),
                message_id=6,
                modem_id=MODEM_ID,
                max_token_bytes=100,
                state_dir=Path("unused"),
                expected_token_bytes=len("cashuBproof"),
            )
        self.assertTrue(snapshot.complete)
        self.assertEqual(snapshot.token, "cashuBproof")

    def test_fetch_batches_candidate_sets(self) -> None:
        class FakeAccount:
            def __init__(self):
                self.batch_sizes = []

            def fetch_location_history(self, keys):
                self.batch_sizes.append(len(keys))
                return {key: [] for key in keys}

        keys = make_candidate_keys(8, MODEM_ID, 0, 81)  # 324 candidates.
        account = FakeAccount()
        with patch("receiver.find_my_receiver._save_session"):
            fetched = fetch_reports_batched(account, keys, Path("unused"))

        self.assertEqual(account.batch_sizes, [MAX_KEYS_PER_FETCH, 44])
        self.assertEqual(len(fetched), len(keys))

    def test_tracked_message_range_wraps_without_reordering(self) -> None:
        self.assertEqual(message_id_sequence(7, 4), (7, 8, 9, 10))
        self.assertEqual(
            message_id_sequence(0xFFFFFFFE, 4),
            (0xFFFFFFFE, 0xFFFFFFFF, 0, 1),
        )

    def test_plain_display_prints_only_changes_and_token_once(self) -> None:
        output = io.StringIO()
        display = WatchDisplay(
            MODEM_ID,
            (7,),
            60,
            plain=True,
            stream=output,
            width=100,
        )
        waiting = MessageSnapshot(
            message_id=7,
            phase="waiting",
            resolved_symbols=0,
            total_symbols=40,
            report_count=0,
            candidate_hits=0,
            rendered_symbols="",
        )
        complete = MessageSnapshot(
            message_id=7,
            phase="complete",
            resolved_symbols=48,
            total_symbols=48,
            report_count=48,
            candidate_hits=48,
            rendered_symbols="",
            token="cashuBproof",
        )

        display.render({7: waiting})
        display.render({7: waiting})
        display.render({7: waiting}, fetch_error="network unavailable")
        display.render({7: waiting}, fetch_error="network unavailable")
        display.render({7: complete})
        display.render({7: complete})

        rendered = output.getvalue()
        self.assertEqual(rendered.count("message 7 waiting"), 1)
        self.assertEqual(rendered.count("message 7 verified"), 1)
        self.assertEqual(rendered.count("token[7]: cashuBproof"), 1)
        self.assertEqual(rendered.count("backend error — network unavailable"), 1)

    def test_tty_display_updates_rows_in_place_without_wrapping(self) -> None:
        class TtyBuffer(io.StringIO):
            def isatty(self):
                return True

        output = TtyBuffer()
        with patch.dict("os.environ", {"TERM": "xterm-256color"}, clear=False):
            display = WatchDisplay(
                MODEM_ID,
                (7, 8),
                60,
                no_color=True,
                stream=output,
                width=84,
            )
        waiting = {
            message_id: MessageSnapshot(
                message_id=message_id,
                phase="waiting",
                resolved_symbols=0,
                total_symbols=40,
                report_count=0,
                candidate_hits=0,
                rendered_symbols="",
            )
            for message_id in (7, 8)
        }
        receiving = dict(waiting)
        receiving[8] = MessageSnapshot(
            message_id=8,
            phase="frame-partial",
            resolved_symbols=964,
            total_symbols=1580,
            report_count=431,
            candidate_hits=964,
            rendered_symbols="",
            expected_frame_bytes=395,
        )

        display.render(waiting)
        display.render(receiving, checked_at=datetime_for_test())

        rendered = output.getvalue()
        self.assertIn("\033[7F\033[J", rendered)
        final_dashboard = rendered.split("\033[J")[-1]
        ansi_escape = re.compile(r"\033\[[0-9;]*m")
        for line in final_dashboard.splitlines():
            self.assertLessEqual(len(ansi_escape.sub("", line)), 84)
        self.assertIn("#8", final_dashboard)
        self.assertIn("receiving", final_dashboard)

    def test_watch_tracks_randomly_completed_id_and_stops_refetching_it(self) -> None:
        class TtyBuffer(io.StringIO):
            def isatty(self):
                return True

        output = TtyBuffer()
        args = SimpleNamespace(
            message_id=7,
            count=3,
            modem_id=MODEM_ID,
            max_token_bytes=100,
            state_dir=Path("unused"),
            poll_seconds=60,
            plain=False,
            no_color=True,
        )

        def result(_account, message_id, *_args, **_kwargs):
            if message_id == 8:
                return MessageSnapshot(
                    message_id=8,
                    phase="complete",
                    resolved_symbols=48,
                    total_symbols=48,
                    report_count=48,
                    candidate_hits=48,
                    rendered_symbols="",
                    token="cashuBproof",
                )
            return MessageSnapshot(
                message_id=message_id,
                phase="waiting",
                resolved_symbols=0,
                total_symbols=40,
                report_count=0,
                candidate_hits=0,
                rendered_symbols="",
            )

        with patch.dict("os.environ", {"TERM": "xterm-256color"}, clear=False), \
             patch("sys.stdout", output), \
             patch(
                 "receiver.find_my_receiver.fetch_message_snapshot",
                 side_effect=result,
             ) as fetch, \
             patch("receiver.find_my_receiver.time.sleep", side_effect=[None, KeyboardInterrupt]):
            with self.assertRaises(KeyboardInterrupt):
                _run_watch(object(), args)

        self.assertEqual(
            [call.args[1] for call in fetch.call_args_list],
            [7, 8, 9, 7, 9],
        )
        rendered = output.getvalue()
        self.assertEqual(rendered.count("token[8]: cashuBproof"), 1)
        self.assertIn("IDs 7–9 (3 tracked)", rendered)

    def test_small_dashboard_prioritizes_ids_with_reports(self) -> None:
        snapshots = {
            message_id: MessageSnapshot(
                message_id=message_id,
                phase="frame-partial" if message_id >= 2 else "waiting",
                resolved_symbols=100 if message_id >= 2 else 0,
                total_symbols=200 if message_id >= 2 else 40,
                report_count=10 if message_id >= 2 else 0,
                candidate_hits=10 if message_id >= 2 else 0,
                rendered_symbols="",
            )
            for message_id in range(4)
        }
        display = WatchDisplay(
            MODEM_ID,
            tuple(snapshots),
            60,
            plain=True,
            no_color=True,
            stream=io.StringIO(),
            width=80,
            height=8,
        )

        lines = display._dashboard_lines(snapshots, datetime_for_test(), None)

        self.assertEqual(len(lines), 8)
        joined = "\n".join(lines)
        self.assertIn("#2", joined)
        self.assertIn("#3", joined)
        self.assertNotIn("#0", joined)
        self.assertIn("2 quiet IDs hidden", joined)


def datetime_for_test():
    from datetime import datetime, timezone

    return datetime(2026, 8, 4, 12, 34, 56, tzinfo=timezone.utc)


if __name__ == "__main__":
    unittest.main()
