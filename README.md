# find-my-nuts

`find-my-nuts` is a proof-of-concept Cashu wallet for the Heltec WiFi LoRa 32
V3 (ESP32-S3) and original 1.14-inch LILYGO/TTGO T-Display (classic ESP32).
It keeps Nucula's UART mint/wallet console and adds a durable outbound Find My
transport with board-specific displays, battery sensing, and button controls.

**Current Heltec attempt:** follow [docs/HELTEC_V3.md](docs/HELTEC_V3.md).
Use `./scripts/heltec.sh console` to mint, hold PRG for one second and release
to start/pause transmission, and run `./receiver/watch_heltec.sh 0` on the Mac.
This profile uses the fresh modem ID **57A030B3**. The T-Display pinout and its
historical BD3BB756 namespace below remain available in the original profile.

The intended demo is a set of negligible one-unit bearer proofs:

```text
find-my-nuts> invoice 5
# pay the printed Lightning invoice
find-my-nuts> claim <quote_id> d=1x5
find-my-nuts> findmy resume
```

The claim asks the mint for exactly five amount-1 proofs and keeps them in the
wallet. GPIO35 (or `findmy resume`) selects exactly one eligible proof,
serializes it as its own complete Cashu V4 (`cashuB`) token, durably removes
only that proof from the spendable wallet, and repeatedly airs that same
immutable message until it is paused. It never advances to a second proof
without a new explicit selection. `d=1-1-1-1-1` is equivalent.

> **This broadcasts public bearer ecash.** Anyone who reconstructs a token can
> redeem it first. The transport is not encrypted or authenticated, CRC is only
> an integrity check, and a completed local transmission is not a delivery
> acknowledgement. Use giveaway amounts you are prepared to lose.

## Project separation

This directory is an independent Git worktree on branch
`feat/find-my-nuts-ttgo`, cloned from Nucula revision `85ac407`. Its upstream is
named `nucula-upstream`; the original `embedded/nucula` and `esp-find-my`
working trees are not build inputs and are not modified by this project.

The concerns are separated as follows:

- `main/wallet.*` and the existing Cashu files retain the Nucula wallet.
- `main/board_tdisplay.*`, `main/display.*`, and `main/ui.*` own this board.
- `main/proof_distribution.*` parses and validates exact mint outputs.
- `main/find_my_wallet.*` transfers proof ownership into the durable outbox.
- `main/find_my_outbox.*` owns NVS persistence, retries, and message IDs.
- `components/find_my_transport/` owns BLE Offline Finding advertisements.
- `receiver/` is a separate host-side reconstruction tool.

See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for provenance and license
boundaries.

## Supported hardware

The Heltec profile targets the WiFi LoRa 32 V3 family: ESP32-S3FN8, 8 MiB
flash, SSD1306 128×64 OLED, UART0 GPIO43/44, and the GPIO0 PRG button. Battery
sensing uses GPIO1 and automatically detects GPIO37's enable polarity.
See the [Heltec pinout and workflow](docs/HELTEC_V3.md) for this board.

The original profile targets the LILYGO/TTGO T-Display with a classic dual-core
ESP32, 16 MiB flash, no PSRAM, and a 240×135 ST7789 panel. It is not configured
for T-Display-S3, T-Display-S3 AMOLED, or newer variants.

| Function | GPIO | Notes |
| --- | ---: | --- |
| TFT MOSI | 19 | SPI |
| TFT SCLK | 18 | SPI at 40 MHz |
| TFT CS | 5 |  |
| TFT DC | 16 |  |
| TFT reset | 23 |  |
| Backlight | 4 | Active high |
| Display button | 0 | Active low; toggles panel/backlight; do not hold while resetting |
| Dispersion button | 35 | Active low, input only; starts/pauses the focused transmission |
| Battery/USB ADC | 34 | ADC1 input through the board's nominal 2:1 divider |
| ADC enable | 14 | Driven high only while sampling the power rail |
| Console TX/RX | 1 / 3 | UART0 through the USB serial bridge, 115200 baud |

The GPIO0 button toggles panel sleep and backlight together. When Find My is
off, the physical-only GPIO35 button starts or resumes one focused proof.
Pressing it during transmission pauses that proof. Using GPIO35 prevents USB
serial control-line pulses on GPIO0 from authorizing bearer-token broadcasts.
Each button is independently debounced and rearms after release. Every boot
starts with transmission off; an armed or interrupted message remains bound to
the next activation, but never resumes automatically. Each completed pass is
followed by another pass over the same immutable proof, using a fresh symbol
order. Wallet, Wi-Fi, and Find My tasks continue while the display is off.
The home-screen footer shows `USB` while externally powered, or a small battery
gauge and approximate percentage while running from its LiPo. The estimate uses
the ESP32's calibrated ADC reference when available; it is not a fuel gauge and
cannot distinguish charging from charge-complete on this board.
The console `status` command includes the sensed voltage and whether ADC
calibration was available.

The dispersion gate is independent of Wi-Fi association state. While a
manually authorized message is being sent, an existing Wi-Fi connection is
left intact, but new reconnect scans are deferred and ESP32 radio coexistence
prefers BLE. Balanced coexistence and reconnect attempts resume when dispersion
is paused, the wallet has no eligible proof, or the recovery outbox is full. A
transport error retains the exact token and message ID for retry. A Wi-Fi scan
already in flight when dispersion begins is tolerated by coexistence; it cannot
change the active-proof authorization or proof state.

There is deliberately no NFC, keypad, or external I²C dependency in this
variant.

## Build and flash

ESP-IDF 5.5.1 is the tested toolchain. From this directory, after activating
that ESP-IDF environment:

For Heltec, use `./scripts/heltec.sh build` and `./scripts/heltec.sh flash`.
Those helpers select the ESP32-S3 profile and a separate build/config, with
fresh NVS above the previously installed Bitle firmware's storage. They
preserve that wallet NVS on subsequent flashes. For the original T-Display:

```sh
git submodule update --init --recursive
cp main/wifi_config.example.h main/wifi_config.h
# Edit wifi_config.h; it is ignored by Git.

idf.py set-target esp32
idf.py build
idf.py -p /dev/cu.usbserial-XXXXXXXX flash monitor
```

On Linux the port is commonly `/dev/ttyUSB0`. On macOS, locate it with:

```sh
ls /dev/cu.usbserial-* /dev/cu.wchusbserial-* 2>/dev/null
```

The default build selects 16 MiB DIO flash, a 4 MiB application partition,
Wi-Fi station mode, BLE-only Bluedroid, and radio coexistence. Wi-Fi's RX fast
path stays in flash to leave enough classic-ESP32 IRAM for simultaneous BLE.

A normal `idf.py flash` preserves NVS. Only use `idf.py erase-flash` when you
intend to destroy the wallet seed, proofs, mint configuration, and every
outbox recovery token. Changing from an unrelated partition layout may require
that one-time destructive erase.

## Console workflow

Open the monitor at 115200 baud and press Enter if the prompt is not already
visible:

```text
find-my-nuts> mint add https://your-mint.example
find-my-nuts> invoice 5
pay this invoice:
lnbc...
quote: <quote_id>
```

`mint add` also accepts a bare hostname and canonicalizes it to HTTPS before
storing it. For example, `mint add mint.example` stores
`https://mint.example`. Use an explicit `http://` only for a trusted local
development mint; other schemes and malformed origins are rejected. Adding a
mint is transactional and requires Wi-Fi: both `/v1/keysets` and `/v1/keys`
must return a usable active keyset before the mint is retained. A failure rolls
back the new slot and its partial NVS data.

After paying, mint a chosen proof distribution into the wallet:

```text
find-my-nuts> claim <quote_id> d=1x5
```

Distribution grammar is intentionally strict:

- `d=1-1-1-1-1` requests explicit denominations in that order.
- `d=1x5` repeats denomination 1 five times.
- `d=1x2-2-4x2` mixes both forms and totals 12.
- Every amount must be supported by the active mint keyset.
- The sum must exactly equal the quote's currently claimable amount.
- The default cap is 32 outputs.

Without `d=`, Nucula's normal binary split is used. All newly minted proofs
remain spendable until a later Find My activation selects one of them.

Useful sender commands:

```text
findmy status
findmy list
findmy arm <message_id>
findmy pause
findmy resume
findmy resend <message_id>
findmy token <message_id>
findmy forget <message_id> CONFIRM
```

`findmy arm <message_id>` durably chooses an existing outbox entry while keeping
the radio off; this is the safest preparation before unplugging USB. GPIO35 and
`findmy resume` then start the same focused transmission. If an armed or
interrupted message exists, they resume it; otherwise they use unbiased
reservoir sampling to choose one eligible proof uniformly by proof count.
Every pass repeats the same message: the 40 header symbols are each aired eight
times and the remaining symbols are each aired once in a freshly randomized
order. `findmy pause` (or GPIO35 during a pass) pauses cooperatively; the next
activation uses identical token bytes and the same message ID. The sender
safely pauses if no eligible proof remains, the recovery outbox is full, or
persistence fails. It never selects a second proof during an active session.

The outbox stores the full token before removing its proof from the spendable
wallet. A reset between those steps is reconciled at boot. Interrupted sends
resume with the same immutable bytes and message ID. Completed entries remain
stored because Find My cannot acknowledge reception; `forget` is accepted only
for a completed entry and permanently deletes the device's recovery copy.

Other inherited console commands include `status`, `balance`, `unit`, `mint`,
`invoice`, `claim`, `melt`, `receive`, `stickup`, `seed`, `heap`, `tasks`,
`selftest`, and `reboot`. Run `help` for their current syntax.

## Receive through Find My

Session activation prints the selected message ID, and `findmy status` shows
the durable active one. This repository's current deployment and receiver use
the fresh public namespace `BD3BB756`. Always use the value printed by
`findmy status` if the firmware configuration changes.

Set up the host receiver and watch only the armed message. Supplying the token
length printed by `findmy list` lets the receiver query every frame symbol from
its first poll, even before all 40 header symbols have arrived.

```sh
python3 -m venv receiver/.venv
receiver/.venv/bin/python -m pip install -r receiver/requirements.txt
receiver/.venv/bin/python receiver/find_my_receiver.py \
  --modem-id <modem_id> --message-id <armed_message_id> \
  --token-bytes <token_bytes> --watch
```

Apple Account access and two-factor authentication are handled interactively
by FindMy.py. Detailed operational guidance is in
[receiver/README.md](receiver/README.md); the exact frame and key derivation are
specified in [docs/FIND_MY_PROTOCOL.md](docs/FIND_MY_PROTOCOL.md).

Transmission is intentionally slow. A pass contains four symbols per frame
byte, plus 280 extra header transmissions from the eight-copy header policy.
At the 1.6-second dwell, a 250-byte token takes about 35 minutes per pass. The
observed 385-byte one-proof tokens use 1,860 transmissions and take about
49 minutes 36 seconds per pass. Passes continue with fresh body-symbol orders
until GPIO35 or `findmy pause` stops them. Find My relay/backend delays are
additional, and missing reports are normal.

## Proof-of-concept limitations

- Find My uses an unofficial Apple backend path and can change or stop working.
- Anyone with the modem/message IDs can query the same public candidates.
- There is no receiver acknowledgement, access control, secrecy, or anti-replay.
- Only outbound one-proof dissemination was added; the board does not receive
  Cashu over BLE.
- Do not use this as a savings wallet or with meaningful value.

## Verification

The project includes host tests for framing, candidate generation, exact-length
retrieval, report decoding, and watch progression. Firmware `selftest` covers
proof-distribution parsing, active-message binding, unbiased-random mapping,
and exact retransmission-schedule coverage. The firmware also cross-builds the
exact ESP32 target. See the handoff/build output for the specific revision's
results.
