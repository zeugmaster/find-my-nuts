# Find My Nuts protocol

This document specifies the byte framing and 2-bit Find My modem used by the
find-my-nuts proof of concept. Multi-byte integers are unsigned and big-endian
unless stated otherwise.

## Security model

This is a public, unauthenticated bearer-token transport. It does not encrypt
the payload or prove who transmitted it. The modem ID and message ID are public
routing fields. CRC-32 detects accidental corruption and incomplete/conflicting
reports, but it is not a cryptographic authenticator.

A valid `cashuB` string can be spent by whoever learns it. Implementations and
operators should use only negligible values, must not treat local transmission
completion as delivery, and must not reuse a message ID for different bytes.

## FMN1 frame

One message is an exact byte string:

| Offset | Size | Field | Encoding |
| ---: | ---: | --- | --- |
| 0 | 4 | Magic | ASCII `FMN1` (`46 4d 4e 31`) |
| 4 | 2 | Token length `N` | Unsigned 16-bit big-endian length of the token only |
| 6 | 4 | Token CRC | IEEE CRC-32 of the `N` token bytes |
| 10 | `N` | Token | Full ASCII string beginning with `cashuB` |

The total frame length is exactly `10 + N` bytes. Receivers reject trailing or
missing bytes. The CRC is the common reflected IEEE CRC-32 used by Python's
`binascii.crc32`/`zlib.crc32`: polynomial `0xEDB88320`, initial value
`0xFFFFFFFF`, and final XOR `0xFFFFFFFF`.

The length and CRC cover the token as transmitted, including its `cashuB`
prefix. They do not cover the 10-byte header.

## Two-bit symbols

Each frame byte is split into four symbols, most-significant pair first:

```text
symbol_index = 4 × byte_index + pair_index
symbol_value = (frame[byte_index] >> (6 - 2 × pair_index)) & 0x03
pair_index   = 0, 1, 2, 3
```

Thus the pairs are bits `7:6`, `5:4`, `3:2`, and `1:0`. For example, byte
`0x1B` (`00 01 10 11`) becomes symbols `0, 1, 2, 3`.

There are four candidate values for every symbol. A receiver generates all
four possible keys and determines the value from the candidate(s) that have
reports. One source byte therefore requires 4 symbols × 4 candidates = 16
candidate keys. Missing candidates render as `?`; reports for multiple values
at one index are a conflict rendered as `!`.

The receiver can recover exactly one missing body symbol by testing its four
values against a fully received header and accepting only one candidate that
passes all frame checks. It labels this as CRC recovery. It does not infer
header fields or resolve conflicting reports. This bounded recovery adds no
authentication; it uses the existing CRC as redundancy for a known erasure.

## Candidate public-key layout

Each candidate is a deterministic 28-byte x-coordinate for NIST P-224
(`secp224r1`):

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 2 | Constant magic `BA BE` |
| 2 | 4 | Symbol index |
| 6 | 4 | Message ID |
| 10 | 4 | Public modem ID |
| 14 | 4 | Validity counter |
| 18 | 9 | Zero padding |
| 27 | 1 | Symbol value, restricted to `0..3` |

For each `(symbol index, message ID, modem ID, symbol value)` tuple, generation
starts with validity counter zero and increments until compressed point
`02 || x-coordinate` is a valid `secp224r1` public point. This search is
deterministic, so transmitter and receiver arrive at the same 28 bytes without
sharing a key list.

The component fallback modem ID is `0x4E555453`, the ASCII bytes `NUTS`. It is
configurable and is not a credential; the checked-in deployment configuration
currently overrides it with the fresh namespace `0xBD3BB756`. The caller
supplies the 32-bit message ID. Different frame contents must use different
IDs; replaying the same immutable frame with the same ID is intentional
retransmission.

## Offline Finding advertisement mapping

For a valid x-coordinate `X[0..27]`, the transmitter constructs a random-static
BLE address and the Apple Offline Finding manufacturer payload as follows:

```text
address[0]   = X[0] | 0xC0
address[1:6] = X[1:6]

payload[0:7]   = 1e ff 4c 00 12 19 00
payload[7:29]  = X[6:28]
payload[29]    = X[0] >> 6
payload[30]    = 00
```

The advertisement is non-connectable, uses all BLE advertising channels, and
contains no token bytes directly. The candidate public key is the carrier.

## Receiver sequence

Receivers must not trust a token length from a partial header.

1. Generate candidates for exactly 10 header bytes: 40 symbols and 160 keys.
2. Fetch reports until all header symbols resolve without conflict.
3. Require magic `FMN1`, parse `N`, and apply a local maximum-length policy.
4. Generate candidates for exactly `4 × (10 + N)` symbols.
5. Fetch in backend-safe batches (the supplied receiver uses at most 280 keys
   per request) until the exact frame resolves.
6. Verify exact length, CRC-32, ASCII encoding, and the `cashuB` prefix before
   returning the token.

When the operator independently obtains the exact immutable token length from
`findmy list`, the receiver may generate all `4 × (10 + N)` candidates on its
first poll. It must still apply every exact-length, magic, CRC, ASCII, and
`cashuB` validation above; the supplied receiver enables this mode with
`--token-bytes N`.

The focused firmware binds one message ID and repeats it indefinitely. The
recommended receiver invocation therefore tracks only that ID. Watch mode can
still query a fixed consecutive range when diagnosing legacy or unknown
outbox entries; ranges wrap modulo `2^32`.

## Advertising time

Let:

- `N` be the token length in bytes;
- `D` be the configured symbol dwell in seconds;
- `R` be the number of copies of each 40-symbol FMN1 header per pass.

Ignoring GAP reconfiguration overhead, nominal airtime is:

```text
unique symbols         = 4 × (10 + N)
transmissions per pass = 4 × (10 + N) + 40 × (R - 1)
time per pass          = transmissions per pass × D
```

Defaults are a 1.0-second advertising interval, 1.6-second symbol dwell, and
eight header copies. The 40 header symbols appear at eight evenly distributed
points in a pass. Every body symbol appears exactly once in a randomized affine
permutation; a new permutation is chosen for every pass. Passes repeat without
a fixed limit until the operator pauses the sender. The dwell should be at
least the advertising interval so that the controller has an opportunity to
emit every scheduled symbol.

| Token bytes | Unique symbols | Transmissions/pass | Nominal pass at 1.6 s |
| ---: | ---: | ---: | ---: |
| 100 | 440 | 720 | 19 min 12 s |
| 250 | 1,040 | 1,320 | 35 min 12 s |
| 385 | 1,580 | 1,860 | 49 min 36 s |
| 500 | 2,040 | 2,320 | 1 h 1 min 52 s |

Actual completion takes longer because every symbol changes BLE address and
payload, and Find My relay/backend delivery is opportunistic. Seeing no report
does not prove that a symbol was not advertised.

## Persistence and retransmission

Session activation binds exactly one active message at a time. If an earlier
active message is incomplete, it is resumed. Otherwise an existing queued
one-proof token is selected uniformly at random. Only when there is no queued
token does the wallet use unbiased reservoir sampling to choose one eligible
proof uniformly by proof count across all loaded mints. It reserves a message
ID and stores the immutable one-proof token in NVS before durably removing that
proof from the spendable wallet and making the message eligible for
transmission.

The active message ID is itself durable. The worker cannot switch to another
queued token before the active token completes, even if an older message is
manually requeued while a pass is running. Every reboot forces the sender gate
closed; a reboot while sending changes the item back to `queued`, retains its
active ID, and requires a new activation to resume. Cancellation and transient
BLE errors likewise retain the same bytes and ID.

A successful full pass increments `passes_completed`, persists the counter, and
immediately schedules the same immutable active message again with a new body
permutation. It does not mark the message delivered, clear the active ID, or
select another proof: Find My provides no delivery acknowledgement. If no
eligible proof can be selected initially, the recovery outbox is full, or a
persistence operation fails, the session durably pauses instead of deleting a
recovery copy. `findmy arm <message_id>` resets the selected entry's pass count,
makes it the durable active ID, and deliberately leaves the sender paused for
battery deployment. Manual resend likewise retains the immutable bytes and ID
and remains paused until activation, allowing reports from every historical
and future pass in that namespace to contribute to reconstruction.

## License and provenance

The modem and receiver are derived from `positive-security/send-my` and
OpenHaystack through the maintained local `esp-find-my` reference. Adapted
transport/receiver sources carry `SPDX-License-Identifier: AGPL-3.0-only`; the
repository includes the AGPLv3 text in `LICENSE`.

The vendored micro-ecc sources used for P-224 validation retain Kenneth
MacKay's BSD 2-Clause notices and have their separate license at
`components/find_my_transport/third_party/micro-ecc/LICENSE`. FindMy.py is an
external runtime dependency with its own license.
