#!/usr/bin/env python3
# Derived from positive-security/send-my's maintained esp-find-my receiver.
# SPDX-License-Identifier: AGPL-3.0-only
"""Fetch and reconstruct framed Cashu tokens relayed through Find My."""

from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import logging
import os
import shutil
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Mapping, MutableMapping, Sequence

try:
    from .find_my_protocol import (
        HEADER_SIZE,
        SYMBOLS_PER_BYTE,
        UINT32_MAX,
        FrameError,
        candidate_key_bytes,
        decode_frame,
        decode_header,
        symbols_to_bytes,
    )
except ImportError:  # Direct ``python receiver/find_my_receiver.py`` execution.
    from find_my_protocol import (
        HEADER_SIZE,
        SYMBOLS_PER_BYTE,
        UINT32_MAX,
        FrameError,
        candidate_key_bytes,
        decode_frame,
        decode_header,
        symbols_to_bytes,
    )

try:
    from findmy import (
        AppleAccount,
        HasPublicKey,
        LocalAnisetteProvider,
        LoginState,
        SmsSecondFactorMethod,
        TrustedDeviceSecondFactorMethod,
    )
except ModuleNotFoundError as exc:  # Unit tests/protocol use need no Apple dependency.
    _FINDMY_IMPORT_ERROR: ModuleNotFoundError | None = exc

    class HasPublicKey:  # type: ignore[no-redef]
        pass

    AppleAccount = object  # type: ignore[misc,assignment]
    LocalAnisetteProvider = object  # type: ignore[misc,assignment]

    class LoginState:  # type: ignore[no-redef]
        LOGGED_IN = "logged-in"
        REQUIRE_2FA = "require-2fa"

    class SmsSecondFactorMethod:  # type: ignore[no-redef]
        pass

    class TrustedDeviceSecondFactorMethod:  # type: ignore[no-redef]
        pass
else:
    _FINDMY_IMPORT_ERROR = None


DEFAULT_MODEM_ID = 0xBD3BB756
DEFAULT_STATE_DIR = Path.home() / ".find-my-nuts"
DEFAULT_POLL_SECONDS = 60
DEFAULT_MAX_TOKEN_BYTES = 4096
DEFAULT_WATCH_MESSAGES = 16
MAX_TRACKED_MESSAGES = 64
MAX_KEYS_PER_FETCH = 280
HEADER_SYMBOLS = HEADER_SIZE * SYMBOLS_PER_BYTE
CONFLICT = -1


@dataclass(frozen=True, eq=False)
class FindMySymbolKey(HasPublicKey):
    """One Find My public-key candidate for a 2-bit value."""

    symbol_index: int
    symbol_value: int
    valid_counter: int
    _key: bytes

    @property
    def adv_key_bytes(self) -> bytes:
        return self._key


@dataclass(frozen=True)
class DecodedReports:
    symbols: tuple[int | None, ...]
    rendered: str
    resolved_symbols: int
    report_count: int
    candidate_hits: int
    conflicting_symbols: int

    @property
    def complete(self) -> bool:
        return self.resolved_symbols == len(self.symbols)

    @property
    def has_reports(self) -> bool:
        return self.candidate_hits > 0

    def to_bytes(self) -> bytes:
        if not self.complete:
            raise ValueError("symbol set is incomplete or conflicting")
        return symbols_to_bytes(tuple(int(symbol) for symbol in self.symbols))


@dataclass(frozen=True)
class MessageSnapshot:
    message_id: int
    phase: str
    resolved_symbols: int
    total_symbols: int
    report_count: int
    candidate_hits: int
    rendered_symbols: str
    expected_frame_bytes: int | None = None
    token: str | None = None
    error: str | None = None
    conflicting_symbols: int = 0
    recovered_symbol_indices: tuple[int, ...] = ()

    @property
    def complete(self) -> bool:
        return self.phase == "complete"

    @property
    def has_reports(self) -> bool:
        return self.candidate_hits > 0


KeyCache = MutableMapping[tuple[int, int, int, int], list[FindMySymbolKey]]


def _require_findmy() -> None:
    if _FINDMY_IMPORT_ERROR is not None:
        raise RuntimeError(
            "FindMy.py is required for backend access; install receiver/requirements.txt"
        ) from _FINDMY_IMPORT_ERROR


def _u32(value: int, name: str) -> int:
    if not 0 <= value <= UINT32_MAX:
        raise argparse.ArgumentTypeError(f"{name} must fit in an unsigned 32-bit integer")
    return value


def parse_modem_id(value: str) -> int:
    compact = value.strip().lower().replace("0x", "").replace(":", "").replace(" ", "")
    try:
        return _u32(int(compact, 16), "modem ID")
    except ValueError as exc:
        raise argparse.ArgumentTypeError("modem ID must be hexadecimal") from exc


def parse_message_id(value: str) -> int:
    try:
        parsed = int(value, 16) if value.lower().startswith("0x") else int(value, 10)
        return _u32(parsed, "message ID")
    except ValueError as exc:
        raise argparse.ArgumentTypeError("message ID must be decimal or start with 0x") from exc


def parse_poll_seconds(value: str) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("poll seconds must be an integer") from exc
    if not 30 <= parsed <= 3600:
        raise argparse.ArgumentTypeError("poll seconds must be between 30 and 3600")
    return parsed


def parse_max_token_bytes(value: str) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("max token bytes must be an integer") from exc
    if not 6 <= parsed <= 65535:
        raise argparse.ArgumentTypeError("max token bytes must be between 6 and 65535")
    return parsed


def parse_message_count(value: str) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("message count must be an integer") from exc
    if not 1 <= parsed <= MAX_TRACKED_MESSAGES:
        raise argparse.ArgumentTypeError(
            f"message count must be between 1 and {MAX_TRACKED_MESSAGES}"
        )
    return parsed


def make_candidate_keys(
    message_id: int,
    modem_id: int,
    start_symbol: int,
    symbol_count: int,
) -> list[FindMySymbolKey]:
    keys: list[FindMySymbolKey] = []
    if symbol_count < 0 or start_symbol < 0 or start_symbol + symbol_count > UINT32_MAX + 1:
        raise ValueError("symbol range must fit in unsigned 32-bit indices")
    for symbol_index in range(start_symbol, start_symbol + symbol_count):
        for symbol_value in range(4):
            key, counter = candidate_key_bytes(
                symbol_index,
                message_id,
                modem_id,
                symbol_value,
            )
            keys.append(
                FindMySymbolKey(
                    symbol_index=symbol_index,
                    symbol_value=symbol_value,
                    valid_counter=counter,
                    _key=key,
                )
            )
    return keys


def get_candidate_keys(
    cache: KeyCache,
    message_id: int,
    modem_id: int,
    start_symbol: int,
    symbol_count: int,
) -> list[FindMySymbolKey]:
    cache_key = (message_id, modem_id, start_symbol, symbol_count)
    if cache_key not in cache:
        cache[cache_key] = make_candidate_keys(
            message_id,
            modem_id,
            start_symbol,
            symbol_count,
        )
    return cache[cache_key]


def decode_reports(
    keys: Sequence[FindMySymbolKey],
    reports: Mapping[HasPublicKey, Sequence[object]],
    start_symbol: int,
    symbol_count: int,
) -> DecodedReports:
    observed: dict[int, set[int]] = {}
    report_count = 0
    candidate_hits = 0

    for key in keys:
        key_reports = reports.get(key, ())
        if not key_reports:
            continue
        candidate_hits += 1
        report_count += len(key_reports)
        observed.setdefault(key.symbol_index, set()).add(key.symbol_value)

    decoded: list[int | None] = []
    rendered: list[str] = []
    resolved = 0
    conflicts = 0
    for symbol_index in range(start_symbol, start_symbol + symbol_count):
        values = observed.get(symbol_index, set())
        if len(values) == 1:
            value = next(iter(values))
            decoded.append(value)
            rendered.append(str(value))
            resolved += 1
        elif len(values) > 1:
            decoded.append(CONFLICT)
            rendered.append("!")
            conflicts += 1
        else:
            decoded.append(None)
            rendered.append("?")

    grouped = " ".join(
        "".join(rendered[start : start + SYMBOLS_PER_BYTE])
        for start in range(0, len(rendered), SYMBOLS_PER_BYTE)
    )
    return DecodedReports(
        symbols=tuple(decoded),
        rendered=grouped,
        resolved_symbols=resolved,
        report_count=report_count,
        candidate_hits=candidate_hits,
        conflicting_symbols=conflicts,
    )


def _method_label(method: object) -> str:
    if isinstance(method, TrustedDeviceSecondFactorMethod):
        return "trusted Apple device"
    if isinstance(method, SmsSecondFactorMethod):
        return f"SMS to {method.phone_number}"
    return type(method).__name__


def _complete_two_factor(account: AppleAccount):
    methods = list(account.get_2fa_methods())
    if not methods:
        raise RuntimeError("Apple requested 2FA but returned no supported challenge methods")
    print("Two-factor authentication is required:")
    for number, method in enumerate(methods, start=1):
        print(f"  {number}. {_method_label(method)}")
    while True:
        choice = input(f"Choose a method [1-{len(methods)}]: ").strip()
        try:
            method = methods[int(choice) - 1]
        except (ValueError, IndexError):
            print("Enter one of the listed numbers.")
            continue
        break
    method.request()
    return method.submit(input("Apple verification code: ").strip())


def _save_session(account: AppleAccount, path: Path) -> None:
    state = account.to_json()
    account_state = state.get("account")
    if isinstance(account_state, dict):
        account_state["password"] = None

    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix="account.", suffix=".tmp", dir=path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(state, handle, indent=2)
            handle.write("\n")
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, path)
        os.chmod(path, 0o600)
    finally:
        temporary_path.unlink(missing_ok=True)


def get_account(state_dir: Path, reset_session: bool) -> AppleAccount:
    _require_findmy()
    state_dir = state_dir.expanduser()
    state_path = state_dir / "account.json"
    libs_path = state_dir / "anisette_libs.bin"
    if reset_session:
        state_path.unlink(missing_ok=True)
    if state_path.exists():
        account = AppleAccount.from_json(state_path, anisette_libs_path=libs_path)
        if account.login_state != LoginState.LOGGED_IN:
            raise RuntimeError(
                f"saved session is incomplete; rerun with --reset-session ({state_path})"
            )
        _save_session(account, state_path)
        print(f"Using saved Apple session from {state_path}")
        return account

    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(state_dir, 0o700)
    account = AppleAccount(LocalAnisetteProvider(libs_path=libs_path))
    username = input("Apple Account email: ").strip()
    password = getpass.getpass("Apple Account password (not saved): ")
    state = account.login(username, password)
    if state == LoginState.REQUIRE_2FA:
        state = _complete_two_factor(account)
    if state != LoginState.LOGGED_IN:
        raise RuntimeError(f"login did not complete (state: {state})")
    _save_session(account, state_path)
    print(f"Saved a password-free session to {state_path}")
    return account


def fetch_reports_batched(
    account: AppleAccount,
    keys: Sequence[FindMySymbolKey],
    state_dir: Path,
) -> Mapping[HasPublicKey, Sequence[object]]:
    fetched: dict[HasPublicKey, Sequence[object]] = {}
    for start in range(0, len(keys), MAX_KEYS_PER_FETCH):
        fetched.update(account.fetch_location_history(keys[start : start + MAX_KEYS_PER_FETCH]))
    _save_session(account, state_dir.expanduser() / "account.json")
    return fetched


def fetch_message_snapshot(
    account: AppleAccount,
    message_id: int,
    modem_id: int,
    max_token_bytes: int,
    state_dir: Path,
    key_cache: KeyCache | None = None,
    expected_token_bytes: int | None = None,
) -> MessageSnapshot:
    """Fetch and validate one message, using a known length when supplied."""
    cache: KeyCache = key_cache if key_cache is not None else {}
    if expected_token_bytes is not None:
        if not 6 <= expected_token_bytes <= max_token_bytes:
            return MessageSnapshot(
                message_id=message_id,
                phase="invalid",
                resolved_symbols=0,
                total_symbols=HEADER_SYMBOLS,
                report_count=0,
                candidate_hits=0,
                rendered_symbols="",
                error=(
                    f"expected token length {expected_token_bytes} is outside "
                    f"the allowed range 6..{max_token_bytes}"
                ),
            )
        # A locally known outbox length is trusted only as a query bound. The
        # recovered FMN1 header, CRC, ASCII and cashuB prefix are still all
        # validated below before a token is returned.
        expected_frame_bytes = HEADER_SIZE + expected_token_bytes
        total_symbols = expected_frame_bytes * SYMBOLS_PER_BYTE
        frame_keys = get_candidate_keys(cache, message_id, modem_id, 0, total_symbols)
        frame_reports = fetch_reports_batched(account, frame_keys, state_dir)
        frame_decoded = decode_reports(frame_keys, frame_reports, 0, total_symbols)
        return _snapshot_from_exact_frame(
            message_id, frame_decoded, expected_frame_bytes
        )

    header_keys = get_candidate_keys(cache, message_id, modem_id, 0, HEADER_SYMBOLS)
    header_reports = fetch_reports_batched(account, header_keys, state_dir)
    header_decoded = decode_reports(header_keys, header_reports, 0, HEADER_SYMBOLS)
    if not header_decoded.complete:
        phase = "header-partial" if header_decoded.has_reports else "waiting"
        return MessageSnapshot(
            message_id=message_id,
            phase=phase,
            resolved_symbols=header_decoded.resolved_symbols,
            total_symbols=HEADER_SYMBOLS,
            report_count=header_decoded.report_count,
            candidate_hits=header_decoded.candidate_hits,
            rendered_symbols=header_decoded.rendered,
            conflicting_symbols=header_decoded.conflicting_symbols,
        )

    try:
        header = decode_header(header_decoded.to_bytes())
    except (FrameError, ValueError) as exc:
        return MessageSnapshot(
            message_id=message_id,
            phase="invalid",
            resolved_symbols=HEADER_SYMBOLS,
            total_symbols=HEADER_SYMBOLS,
            report_count=header_decoded.report_count,
            candidate_hits=header_decoded.candidate_hits,
            rendered_symbols=header_decoded.rendered,
            error=str(exc),
        )
    if header.token_length > max_token_bytes:
        return MessageSnapshot(
            message_id=message_id,
            phase="invalid",
            resolved_symbols=HEADER_SYMBOLS,
            total_symbols=HEADER_SYMBOLS,
            report_count=header_decoded.report_count,
            candidate_hits=header_decoded.candidate_hits,
            rendered_symbols=header_decoded.rendered,
            expected_frame_bytes=header.frame_length,
            error=(
                f"header token length {header.token_length} exceeds configured maximum "
                f"{max_token_bytes}"
            ),
        )

    total_symbols = header.frame_length * SYMBOLS_PER_BYTE
    frame_keys = get_candidate_keys(cache, message_id, modem_id, 0, total_symbols)
    frame_reports = fetch_reports_batched(account, frame_keys, state_dir)
    frame_decoded = decode_reports(frame_keys, frame_reports, 0, total_symbols)
    return _snapshot_from_exact_frame(message_id, frame_decoded, header.frame_length)


def _snapshot_from_exact_frame(
    message_id: int,
    frame_decoded: DecodedReports,
    expected_frame_bytes: int,
) -> MessageSnapshot:
    total_symbols = expected_frame_bytes * SYMBOLS_PER_BYTE
    if not frame_decoded.complete:
        # The CRC covers the token body. With one absent 2-bit symbol, try
        # all four values and accept only one fully valid frame. Never infer
        # header fields or choose between conflicting reports.
        missing = tuple(
            index for index, symbol in enumerate(frame_decoded.symbols)
            if symbol is None
        )
        if (
            len(frame_decoded.symbols) == total_symbols
            and not frame_decoded.conflicting_symbols
            and len(missing) == 1
            and missing[0] >= HEADER_SYMBOLS
        ):
            symbols = list(frame_decoded.symbols)
            valid_tokens: list[str] = []
            for value in range(4):
                symbols[missing[0]] = value
                try:
                    candidate = symbols_to_bytes(tuple(int(symbol) for symbol in symbols))
                    valid_tokens.append(decode_frame(candidate))
                except (FrameError, ValueError):
                    continue
            if len(valid_tokens) == 1:
                return MessageSnapshot(
                    message_id=message_id,
                    phase="complete",
                    resolved_symbols=total_symbols,
                    total_symbols=total_symbols,
                    report_count=frame_decoded.report_count,
                    candidate_hits=frame_decoded.candidate_hits,
                    rendered_symbols=frame_decoded.rendered,
                    expected_frame_bytes=expected_frame_bytes,
                    token=valid_tokens[0],
                    recovered_symbol_indices=missing,
                )
        return MessageSnapshot(
            message_id=message_id,
            phase="frame-partial" if frame_decoded.has_reports else "waiting",
            resolved_symbols=frame_decoded.resolved_symbols,
            total_symbols=total_symbols,
            report_count=frame_decoded.report_count,
            candidate_hits=frame_decoded.candidate_hits,
            rendered_symbols=frame_decoded.rendered,
            expected_frame_bytes=expected_frame_bytes,
            conflicting_symbols=frame_decoded.conflicting_symbols,
        )

    try:
        token = decode_frame(frame_decoded.to_bytes())
    except (FrameError, ValueError) as exc:
        return MessageSnapshot(
            message_id=message_id,
            phase="invalid",
            resolved_symbols=total_symbols,
            total_symbols=total_symbols,
            report_count=frame_decoded.report_count,
            candidate_hits=frame_decoded.candidate_hits,
            rendered_symbols=frame_decoded.rendered,
            expected_frame_bytes=expected_frame_bytes,
            error=str(exc),
        )
    return MessageSnapshot(
        message_id=message_id,
        phase="complete",
        resolved_symbols=total_symbols,
        total_symbols=total_symbols,
        report_count=frame_decoded.report_count,
        candidate_hits=frame_decoded.candidate_hits,
        rendered_symbols=frame_decoded.rendered,
        expected_frame_bytes=expected_frame_bytes,
        token=token,
    )


def message_id_sequence(first_message_id: int, count: int) -> tuple[int, ...]:
    """Return a consecutive tracked ID range with unsigned-32-bit wrapping."""
    if not 1 <= count <= MAX_TRACKED_MESSAGES:
        raise ValueError(
            f"message count must be between 1 and {MAX_TRACKED_MESSAGES}"
        )
    return tuple((first_message_id + offset) & UINT32_MAX for offset in range(count))


def _timestamp() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _waiting_snapshot(
    message_id: int,
    expected_token_bytes: int | None = None,
) -> MessageSnapshot:
    total_symbols = (
        (HEADER_SIZE + expected_token_bytes) * SYMBOLS_PER_BYTE
        if expected_token_bytes is not None else HEADER_SYMBOLS
    )
    return MessageSnapshot(
        message_id=message_id,
        phase="waiting",
        resolved_symbols=0,
        total_symbols=total_symbols,
        report_count=0,
        candidate_hits=0,
        rendered_symbols="",
    )


def _state_label(snapshot: MessageSnapshot) -> str:
    return {
        "waiting": "waiting",
        "header-partial": "header",
        "frame-partial": "receiving",
        "complete": "verified",
        "invalid": "invalid",
    }.get(snapshot.phase, snapshot.phase)


def _snapshot_signature(snapshot: MessageSnapshot) -> tuple[object, ...]:
    return (
        snapshot.phase,
        snapshot.resolved_symbols,
        snapshot.total_symbols,
        snapshot.report_count,
        snapshot.conflicting_symbols,
        snapshot.error,
        snapshot.token,
        snapshot.recovered_symbol_indices,
    )


def _print_snapshot_plain(snapshot: MessageSnapshot, stream=None) -> None:
    output = stream if stream is not None else sys.stdout
    percent = (
        snapshot.resolved_symbols * 100 // snapshot.total_symbols
        if snapshot.total_symbols else 0
    )
    detail = (
        f"{snapshot.resolved_symbols}/{snapshot.total_symbols} symbols "
        f"({percent}%), {snapshot.report_count} reports"
    )
    if snapshot.conflicting_symbols:
        detail += f", {snapshot.conflicting_symbols} conflicts"
    if snapshot.recovered_symbol_indices:
        detail += ", 1 symbol recovered via CRC"
    if snapshot.complete:
        print(
            f"[{_timestamp()}] message {snapshot.message_id} verified — {detail}",
            file=output,
            flush=True,
        )
        print(
            f"token[{snapshot.message_id}]: {snapshot.token}",
            file=output,
            flush=True,
        )
    elif snapshot.error:
        print(
            f"[{_timestamp()}] message {snapshot.message_id} invalid — {detail}: "
            f"{snapshot.error}",
            file=output,
            flush=True,
        )
    else:
        print(
            f"[{_timestamp()}] message {snapshot.message_id} "
            f"{_state_label(snapshot)} — {detail}",
            file=output,
            flush=True,
        )


class WatchDisplay:
    """A stable TTY dashboard with a meaningful append-only plain fallback."""

    _RESET = "\033[0m"
    _BOLD = "\033[1m"
    _DIM = "\033[2m"
    _RED = "\033[31m"
    _YELLOW = "\033[33m"
    _GREEN = "\033[32m"
    _CYAN = "\033[36m"

    def __init__(
        self,
        modem_id: int,
        message_ids: Sequence[int],
        poll_seconds: int,
        *,
        plain: bool = False,
        no_color: bool = False,
        stream=None,
        width: int | None = None,
        height: int | None = None,
    ) -> None:
        self.stream = stream if stream is not None else sys.stdout
        is_tty = bool(getattr(self.stream, "isatty", lambda: False)())
        self.interactive = (
            is_tty and not plain and os.environ.get("TERM", "") != "dumb"
        )
        self.color = (
            self.interactive and not no_color and "NO_COLOR" not in os.environ
        )
        terminal_size = shutil.get_terminal_size((100, 24))
        terminal_width = width or terminal_size.columns
        self.width = max(36, min(120, terminal_width))
        self.height = max(8, height or terminal_size.lines)
        self.modem_id = modem_id
        self.message_ids = tuple(message_ids)
        self.poll_seconds = poll_seconds
        self._rendered_lines = 0
        self._last_states: dict[int, tuple[object, ...]] = {}
        self._announced_tokens: set[int] = set()
        encoding = getattr(self.stream, "encoding", None) or "utf-8"
        try:
            "─█░✓…".encode(encoding)
        except (LookupError, UnicodeEncodeError):
            self.rule_char = "-"
            self.full_char = "#"
            self.empty_char = "."
            self.check_char = "+"
            self.ellipsis = "..."
        else:
            self.rule_char = "─"
            self.full_char = "█"
            self.empty_char = "░"
            self.check_char = "✓"
            self.ellipsis = "…"

    def _paint(self, text: str, code: str) -> str:
        return f"{code}{text}{self._RESET}" if self.color else text

    def _fit(self, text: str) -> str:
        if len(text) <= self.width:
            return text
        if self.width <= 3:
            return text[: self.width]
        return text[: self.width - len(self.ellipsis)] + self.ellipsis

    def _phase_color(self, snapshot: MessageSnapshot) -> str:
        if snapshot.conflicting_symbols:
            return self._RED
        if snapshot.phase == "complete":
            return self._GREEN
        if snapshot.phase == "invalid":
            return self._RED
        if snapshot.phase == "frame-partial":
            return self._CYAN
        if snapshot.phase == "header-partial":
            return self._YELLOW
        return self._DIM

    def _row(self, snapshot: MessageSnapshot) -> str:
        percent = (
            snapshot.resolved_symbols * 100 // snapshot.total_symbols
            if snapshot.total_symbols else 0
        )
        state = _state_label(snapshot)
        message = f"#{snapshot.message_id}"
        if snapshot.error:
            detail = snapshot.error
        elif snapshot.conflicting_symbols:
            detail = f"{snapshot.conflicting_symbols} conflicting symbols"
        elif snapshot.complete:
            detail = "token ready"
        elif not snapshot.has_reports:
            detail = "no reports yet"
        else:
            detail = ""
        if self.width >= 78:
            bar_width = min(18, max(10, self.width - 78))
            filled = bar_width * percent // 100
            bar = self.full_char * filled + self.empty_char * (bar_width - filled)
            prefix = f" {message:>11}  "
            state_field = f"{state:<10}"
            suffix = (
                f" [{bar}] {percent:>3}%  "
                f"{snapshot.resolved_symbols:>4}/{snapshot.total_symbols:<4}  "
                f"{snapshot.report_count:>5} reports"
            )
            remaining = self.width - len(prefix) - len(state_field) - len(suffix)
            if detail and remaining >= 4:
                suffix += "  " + detail[: max(0, remaining - 2)]
            return prefix + self._paint(state_field, self._phase_color(snapshot)) + suffix

        plain = (
            f" {message:>11}  {state:<10} {percent:>3}%  "
            f"{snapshot.resolved_symbols}/{snapshot.total_symbols}"
        )
        if snapshot.error:
            plain += f"  {snapshot.error}"
        elif snapshot.conflicting_symbols:
            noun = "conflict" if snapshot.conflicting_symbols == 1 else "conflicts"
            plain += f"  ! {snapshot.conflicting_symbols} {noun}"
        else:
            plain += f"  {snapshot.report_count} reports"
        fitted = self._fit(plain)
        marker = f"{state:<10}"
        return fitted.replace(
            marker,
            self._paint(marker, self._phase_color(snapshot)),
            1,
        )

    def _dashboard_lines(
        self,
        snapshots: Mapping[int, MessageSnapshot],
        checked_at: datetime | None,
        fetch_error: str | None,
        activity: str | None = None,
    ) -> list[str]:
        first_id = self.message_ids[0]
        last_id = self.message_ids[-1]
        id_scope = str(first_id) if len(self.message_ids) == 1 else f"{first_id}–{last_id}"
        title = self._paint("FIND MY NUTS", self._BOLD) + "  /  RECEIVER"
        meta = (
            f"Modem {self.modem_id:08X}  ·  IDs {id_scope} "
            f"({len(self.message_ids)} tracked)  ·  every {self.poll_seconds}s"
        )
        lines = [title, self._fit(meta), self.rule_char * self.width]
        visible_ids = list(self.message_ids)
        hidden_count = 0
        hidden_active = False
        if len(visible_ids) + 5 > self.height:
            row_capacity = max(1, self.height - 6)
            active_ids = [
                message_id for message_id in self.message_ids
                if snapshots[message_id].has_reports
                or snapshots[message_id].error
            ]
            quiet_ids = [
                message_id for message_id in self.message_ids
                if message_id not in active_ids
            ]
            visible_ids = (active_ids + quiet_ids)[:row_capacity]
            hidden_count = len(self.message_ids) - len(visible_ids)
            hidden_active = any(
                snapshots[message_id].has_reports or snapshots[message_id].error
                for message_id in self.message_ids
                if message_id not in visible_ids
            )
        lines.extend(self._row(snapshots[message_id]) for message_id in visible_ids)
        if hidden_count:
            kind = "messages" if hidden_active else "quiet IDs"
            hidden = (
                f"… {hidden_count} {kind} hidden to fit this terminal; "
                "use --plain to list every change"
            )
            lines.append(self._paint(self._fit(hidden), self._DIM))
        lines.append(self.rule_char * self.width)
        if fetch_error:
            footer = f"Backend error: {fetch_error} · retrying in {self.poll_seconds}s"
            lines.append(self._paint(self._fit(footer), self._RED))
        elif checked_at is None:
            lines.append(
                self._paint(
                    self._fit(activity or "Preparing first report query…"),
                    self._DIM,
                )
            )
        else:
            checked_time = checked_at.astimezone().strftime("%H:%M:%S")
            if self.width < 70:
                footer = (
                    f"Checked {checked_time}  ·  next ~{self.poll_seconds}s  ·  "
                    "Ctrl-C stop"
                )
            else:
                footer = (
                    f"Last check {checked_time}  ·  next poll in ~{self.poll_seconds}s  ·  "
                    "Ctrl-C to stop"
                )
            lines.append(self._paint(self._fit(footer), self._DIM))
        return lines

    def _clear_dashboard(self) -> None:
        if self.interactive and self._rendered_lines:
            self.stream.write(f"\033[{self._rendered_lines}F\033[J")

    def _completion_lines(self, snapshot: MessageSnapshot) -> tuple[str, str]:
        token = snapshot.token or ""
        heading = (
            f"{self.check_char} Recovered message {snapshot.message_id} — "
            f"verified {len(token)}-byte cashuB token"
        )
        if snapshot.recovered_symbol_indices:
            heading += " (1 symbol recovered via CRC)"
        return self._paint(heading, self._GREEN), f"token[{snapshot.message_id}]: {token}"

    def render(
        self,
        snapshots: Mapping[int, MessageSnapshot],
        *,
        checked_at: datetime | None = None,
        fetch_error: str | None = None,
        activity: str | None = None,
    ) -> None:
        completions = [
            snapshots[message_id]
            for message_id in self.message_ids
            if snapshots[message_id].complete
            and message_id not in self._announced_tokens
        ]
        if self.interactive:
            self._clear_dashboard()
            for snapshot in completions:
                heading, token_line = self._completion_lines(snapshot)
                print(heading, file=self.stream)
                print(token_line, file=self.stream)
                print(file=self.stream)
                self._announced_tokens.add(snapshot.message_id)
            lines = self._dashboard_lines(
                snapshots,
                checked_at,
                fetch_error,
                activity,
            )
            self.stream.write("\n".join(lines) + "\n")
            self.stream.flush()
            self._rendered_lines = len(lines)
            return

        for message_id in self.message_ids:
            snapshot = snapshots[message_id]
            signature = _snapshot_signature(snapshot)
            if self._last_states.get(message_id) != signature:
                _print_snapshot_plain(snapshot, self.stream)
                self._last_states[message_id] = signature
                if snapshot.complete:
                    self._announced_tokens.add(message_id)
        if fetch_error:
            error_signature = (fetch_error,)
            if self._last_states.get(-1) != error_signature:
                print(
                    f"[{_timestamp()}] backend error — {fetch_error}; retrying",
                    file=self.stream,
                    flush=True,
                )
                self._last_states[-1] = error_signature
        else:
            self._last_states.pop(-1, None)


def _run_once(account: AppleAccount, args: argparse.Namespace) -> int:
    count = args.count if args.count is not None else 1
    message_ids = message_id_sequence(args.message_id, count)
    key_cache: dict[tuple[int, int, int, int], list[FindMySymbolKey]] = {}
    for message_id in message_ids:
        snapshot = fetch_message_snapshot(
            account,
            message_id,
            args.modem_id,
            args.max_token_bytes,
            args.state_dir,
            key_cache,
            getattr(args, "token_bytes", None),
        )
        _print_snapshot_plain(snapshot)
    return 0


def _run_watch(account: AppleAccount, args: argparse.Namespace) -> int:
    expected_token_bytes = getattr(args, "token_bytes", None)
    count = args.count if args.count is not None else (
        1 if expected_token_bytes is not None else DEFAULT_WATCH_MESSAGES
    )
    message_ids = message_id_sequence(args.message_id, count)
    key_cache: dict[tuple[int, int, int, int], list[FindMySymbolKey]] = {}
    snapshots = {
        message_id: _waiting_snapshot(message_id, expected_token_bytes)
        for message_id in message_ids
    }
    display = WatchDisplay(
        args.modem_id,
        message_ids,
        args.poll_seconds,
        plain=args.plain,
        no_color=args.no_color,
    )
    display.render(snapshots)
    while True:
        fetch_error: str | None = None
        try:
            for position, message_id in enumerate(message_ids, start=1):
                # Message IDs and bytes are immutable. Once validation succeeds,
                # preserve the verified result and stop spending backend calls on it.
                if snapshots[message_id].complete:
                    continue
                display.render(
                    snapshots,
                    activity=(
                        f"Checking message #{message_id}  ·  "
                        f"{position}/{len(message_ids)}"
                    ),
                )
                snapshots[message_id] = fetch_message_snapshot(
                    account,
                    message_id,
                    args.modem_id,
                    args.max_token_bytes,
                    args.state_dir,
                    key_cache,
                    expected_token_bytes,
                )
        except Exception as exc:
            fetch_error = f"{type(exc).__name__}: {exc}"
        display.render(
            snapshots,
            checked_at=datetime.now().astimezone(),
            fetch_error=fetch_error,
        )
        completed_ids = {
            message_id for message_id, snapshot in snapshots.items()
            if snapshot.complete
        }
        if completed_ids:
            # Verified messages are immutable and no longer fetched. Their
            # thousands of derived frame candidates can be released too.
            key_cache = {
                cache_key: keys
                for cache_key, keys in key_cache.items()
                if cache_key[0] not in completed_ids
            }
        time.sleep(args.poll_seconds)


def _close_account(account: AppleAccount) -> None:
    close_result = account.close()
    if not asyncio.iscoroutine(close_result):
        return

    # FindMy.py's synchronous AppleAccount owns the event loop used to create
    # its aiohttp session. Closing it through asyncio.run() creates a different
    # loop, leaving connector cleanup pending (and sometimes raising a
    # cross-loop Future error). The library does not expose a synchronous close
    # wrapper, so finish the coroutine on the same loop used by all of its
    # synchronous request methods. FindMy 0.10.1 is pinned in requirements.txt.
    account_loop = getattr(account, "_evt_loop", None)
    if account_loop is None or account_loop.is_closed():
        asyncio.run(close_result)
        return
    if account_loop.is_running():
        raise RuntimeError("Find My account event loop is unexpectedly still running")
    account_loop.run_until_complete(close_result)
    # Give aiohttp's connector-close callbacks one final turn before process
    # teardown so an ordinary one-shot query exits without pending-task noise.
    account_loop.run_until_complete(asyncio.sleep(0))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Fetch framed cashuB tokens from Apple's Find My backend."
    )
    parser.add_argument(
        "--modem-id",
        type=parse_modem_id,
        default=DEFAULT_MODEM_ID,
        help="four-byte hexadecimal modem ID (default: BD3BB756)",
    )
    parser.add_argument(
        "--message-id",
        type=parse_message_id,
        required=True,
        help="decimal message ID from the wallet (0x... is also accepted)",
    )
    parser.add_argument(
        "--count",
        type=parse_message_count,
        default=None,
        help=(
            "number of consecutive message IDs to track "
            f"(default: 1 once, {DEFAULT_WATCH_MESSAGES} with --watch, "
            "1 with --watch plus --token-bytes)"
        ),
    )
    parser.add_argument(
        "--max-token-bytes",
        type=parse_max_token_bytes,
        default=DEFAULT_MAX_TOKEN_BYTES,
        help=f"safety limit read from the header (default: {DEFAULT_MAX_TOKEN_BYTES})",
    )
    parser.add_argument(
        "--token-bytes",
        type=parse_max_token_bytes,
        default=None,
        help=(
            "known token length from 'findmy list'; query the complete frame "
            "immediately instead of waiting for a complete header"
        ),
    )
    parser.add_argument(
        "--watch",
        action="store_true",
        help="poll continuously and update one stable row per tracked ID",
    )
    parser.add_argument(
        "--poll-seconds",
        type=parse_poll_seconds,
        default=DEFAULT_POLL_SECONDS,
        help=f"watch polling interval (default: {DEFAULT_POLL_SECONDS})",
    )
    parser.add_argument(
        "--state-dir",
        type=Path,
        default=DEFAULT_STATE_DIR,
        help=f"private session directory (default: {DEFAULT_STATE_DIR})",
    )
    parser.add_argument(
        "--reset-session",
        action="store_true",
        help="discard the saved session and perform Apple sign-in again",
    )
    parser.add_argument(
        "--plain",
        action="store_true",
        help="disable in-place updates and print only meaningful state changes",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="disable ANSI colors (also honored through NO_COLOR)",
    )
    parser.add_argument("--verbose", action="store_true")
    return parser


def run(args: argparse.Namespace) -> int:
    if args.verbose and args.watch and not args.plain:
        # Diagnostic log lines and cursor-addressed dashboards cannot safely
        # share a terminal. Plain mode keeps every backend log and state change
        # ordered and readable.
        args.plain = True
        print(
            "Verbose diagnostics enabled; using plain watch output.",
            file=sys.stderr,
        )
    logging.basicConfig(level=logging.INFO if args.verbose else logging.ERROR)
    account = get_account(args.state_dir, args.reset_session)
    try:
        return _run_watch(account, args) if args.watch else _run_once(account, args)
    finally:
        _close_account(account)


def main() -> int:
    try:
        return run(build_parser().parse_args())
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        print(
            "Use --verbose for diagnostics; use --reset-session if login expired.",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
