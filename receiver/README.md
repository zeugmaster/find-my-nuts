# Find My Cashu receiver

For the September 2026 Heltec attempt, run `./receiver/watch_heltec.sh 0` from
the repository root before the first button activation. It explicitly uses
the firmware profile's fresh modem ID **57A030B3** and tracks one message.
After `findmy list`, supply both values as
`./receiver/watch_heltec.sh MESSAGE_ID TOKEN_BYTES` to query the full frame
immediately. See [the Heltec workflow](../docs/HELTEC_V3.md).

This command-line receiver reconstructs the small `cashuB` bearer tokens sent
by find-my-nuts through Apple's Find My network. It generates the same candidate
P-224 public keys as the firmware, fetches matching reports with FindMy.py, and
validates the framed token before printing it.

> **Warning:** a Cashu token is bearer ecash. Anyone who reconstructs the
> token can redeem it. Find My transport is public, unauthenticated, and has no
> delivery acknowledgement. The CRC detects damaged/incomplete data; it does
> not provide encryption, authentication, or ownership. Use only negligible
> proof-of-concept amounts.

The exact wire format is documented in
[`docs/FIND_MY_PROTOCOL.md`](../docs/FIND_MY_PROTOCOL.md).

## Set up

Use a current Python 3 installation and create a dedicated environment from the
repository root:

```sh
python3 -m venv receiver/.venv
receiver/.venv/bin/python -m pip install -r receiver/requirements.txt
```

Backend access uses `FindMy==0.10.1`. On the first run the receiver prompts for
an Apple Account password and a supported two-factor method. It saves a reusable
password-free session under `~/.find-my-nuts` by default. The directory is mode
`0700` and `account.json` is mode `0600`; the session remains sensitive even
though the password is removed.

FindMy.py uses an unofficial Apple backend interface and may stop working when
that interface changes. Use only an account and devices you control or are
authorized to test.

## Receive a token

On the wallet console, `findmy list` shows message IDs and exact token lengths,
while `findmy status` shows the public modem ID and armed message. Query one
message once with:

```sh
receiver/.venv/bin/python receiver/find_my_receiver.py --message-id 12
```

The main receiver and original T-Display profile default to public modem ID
`BD3BB756`; the Heltec profile uses `57A030B3`. Always supply the wallet's ID explicitly
when it differs:

```sh
receiver/.venv/bin/python receiver/find_my_receiver.py \
  --modem-id BD3BB756 --message-id 0 --token-bytes 385
```

Reports arrive opportunistically and partial results are normal. For a focused
deployment, arm one outbox entry and watch that exact ID. Supplying the token
length from `findmy list` queries the whole frame immediately instead of
waiting for a perfect header:

```sh
receiver/.venv/bin/python receiver/find_my_receiver.py \
  --modem-id BD3BB756 --message-id 0 --token-bytes 385 --watch
```

With `--token-bytes`, watch mode defaults to one ID. Without it, the default
watch count remains 16 for legacy/diagnostic range scans. A message ID cannot
be discovered without first deriving and querying its candidate keys.

On an interactive terminal, watch mode keeps one row per ID and redraws those
rows in place. Routine polls do not add lines to scrollback:

```text
FIND MY NUTS  /  RECEIVER
Modem BD3BB756  ·  IDs 0–4 (5 tracked)  ·  every 60s
──────────────────────────────────────────────────────────────────────────────
          #0  waiting    [░░░░░░░░░░]   0%     0/40       0 reports
          #1  header     [███████░░░]  72%    29/40      14 reports
          #2  receiving  [██████░░░░]  61%   964/1580   482 reports
          #3  verified   [██████████] 100%  1580/1580   790 reports  token ready
          #4  invalid    [██████████] 100%    40/40      20 reports  bad frame magic
──────────────────────────────────────────────────────────────────────────────
Last check 12:34:56  ·  next poll in ~60s  ·  Ctrl-C to stop
```

When a frame becomes complete, its fully validated token is printed exactly
once above the live rows so it remains in scrollback and can be copied. The
dashboard continues tracking every other ID. `Ctrl-C` stops it. Redirected
output automatically becomes append-only and prints only meaningful changes;
`--plain` forces that behavior in a terminal.

The display states map to protocol phases as follows: `waiting` means no header
reports, `header` is a partial 10-byte header, `receiving` is a partial exact
frame, `verified` passed length/CRC/ASCII/`cashuB` checks, and `invalid` failed
validation. Conflicting symbols are called out explicitly.

If exactly one body symbol has no report and the full header is available,
the receiver tries its four possible values. It accepts a recovery only when
exactly one candidate passes length, CRC, ASCII, and `cashuB` checks, and marks
the output `1 symbol recovered via CRC`. Missing header symbols, multiple
missing symbols, and conflicting reports still require more reception.

## CLI options

| Option | Meaning |
| --- | --- |
| `--message-id ID` | Required unsigned 32-bit message ID. Decimal is the default; a value beginning with `0x` is hexadecimal. |
| `--count N` | Track `N` consecutive IDs beginning at `--message-id`, wrapping at 32 bits. Default: 1 for a single query, 16 with `--watch`; maximum: 64. |
| `--modem-id HEX` | Four-byte public modem ID in hexadecimal. Optional `0x`, colons, and spaces are accepted. Default: `BD3BB756`. |
| `--max-token-bytes N` | Safety cap applied after decoding the header, from 6 through 65535. Default: 4096. This does not change the transmitted frame. |
| `--token-bytes N` | Exact immutable token length from `findmy list`. Queries the complete frame from the first poll but still requires valid FMN1 length, CRC, ASCII, and `cashuB` framing. Watch mode defaults to one ID when supplied. |
| `--watch` | Poll continuously and update one stable row per tracked ID. Without it, query the selected range once. |
| `--poll-seconds N` | Watch interval from 30 through 3600 seconds. Default: 60. |
| `--state-dir PATH` | Private account session and Anisette library directory. Default: `~/.find-my-nuts`. |
| `--reset-session` | Delete `account.json` and perform interactive sign-in again. |
| `--plain` | Disable in-place rows and emit only meaningful state changes. Non-TTY output uses this automatically. |
| `--no-color` | Disable ANSI color. Setting `NO_COLOR` has the same effect. |
| `--verbose` | Enable FindMy.py diagnostic logging. Watch mode automatically becomes plain so log lines cannot corrupt the in-place display. |
| `-h`, `--help` | Show the generated command help. |

The receiver default allows frames up to 4096 token bytes, while the firmware's
default `FIND_MY_MAX_TOKEN_BYTES` is 1536. The lower firmware limit wins for new
outbox entries.

## Retrieval and timing

Normally the receiver first asks for the fixed 10-byte header: 40 symbols and
160 candidate keys. Only after the magic and length are complete does it
generate candidate keys for the exact frame. `--token-bytes N` safely skips
that discovery delay when the exact length is already known. Backend requests
are split into batches of at most 280 keys.

With the firmware defaults, each frame byte takes four symbols and the first 40
symbols are sent eight times. One pass for an `N`-byte token takes approximately:

```text
[4 × (10 + N) + 280] × 1.6 seconds
```

A 385-byte token therefore uses 1,860 scheduled transmissions and needs about
49 minutes 36 seconds per pass, plus GAP setup and relay/backend delay. The
sender repeats the same immutable frame indefinitely with a newly randomized
body-symbol order until paused. Nearby participating Apple devices and backend
processing can add substantial delay, and some symbols may never be reported;
historical reports continue to contribute on every pass.

## Handling recovered tokens

- Treat terminal output, screenshots, scrollback, and copied tokens as money.
- Verify/redeem the token before assuming any local pass count means delivery.
- The wallet retains completed outbox records because it cannot know whether a
  receiver obtained every symbol. Back up or redeem a token before using
  `findmy forget <message_id> CONFIRM`.
- Never publish real tokens in bug reports or test fixtures.

## License and provenance

The receiver is derived from the maintained receiver in
`positive-security/send-my` / the local `esp-find-my` reference, itself based on
OpenHaystack. The adapted receiver and transport are marked
`SPDX-License-Identifier: AGPL-3.0-only`; see the repository `LICENSE`.
FindMy.py is an external dependency with its own license and terms.
