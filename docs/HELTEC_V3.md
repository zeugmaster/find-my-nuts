# Heltec WiFi LoRa 32 V3 transmission attempt

The board connected on 2026-09-30 is a Heltec WiFi LoRa 32 V3 family board.
Its previous Bitle firmware identified `board=heltec-v3` and initialized an
SSD1306 OLED. The ROM/esptool probe independently confirmed ESP32-S3 QFN56
revision 0.2, embedded GD 8 MiB flash, 40 MHz crystal, and base MAC
`9c:13:9e:9f:b4:40`. USB identifies as a Silicon Labs CP2102, VID/PID
`10C4:EA60`, serial `0001`, at `/dev/cu.usbserial-0001`.
The PCB subrevision (V3/V3.1/V3.2) is not exposed by those identifiers.
After flashing, GPIO37 was detected active-high, consistent with the V3.2
sensing circuit; this is an inference rather than a readout of the PCB label.

## Verified on 2026-09-30

- Both ESP32-S3 Heltec and original ESP32 T-Display profiles build successfully.
- Firmware was flashed with hash verification and booted from the new layout.
- OLED initialization and framebuffer writes succeeded; `status` reports 128×64, on.
- Battery measured 3.63 V / approximately 25% at the latest check, with curve-fitting calibration.
- Sender is started and paused, wallet reconciled, with an empty 0/16 outbox.
- On-device crypto, Cashu format, proof-policy and transmission-schedule self-tests passed.
- All 17 host receiver tests passed. Saved Apple authentication and a live
  query for modem 57A030B3 / message 0 worked, with no reports before transmission.
- Wi-Fi credentials were updated in the ignored `main/wifi_config.h` and
  reflashed. The board reports connected to the configured `w3.hub Guests`
  network; the console is ready and transmission remains paused.

## Pins and behavior

| Function | GPIO | Behavior |
| --- | ---: | --- |
| PRG/user button | 0 | Active low; short press toggles OLED; hold at least 1 second, then release to start/pause Find My |
| RST button | EN | Hardware reset; every boot starts with Find My off |
| OLED SDA/SCL | 17 / 18 | SSD1306, 128×64, I2C address 0x3C, 100 kHz |
| OLED reset | 21 | Active low |
| Vext enable | 36 | Active low; supplies OLED |
| Battery ADC | 1 | ADC1 channel 0, nominal 4.9:1 divider |
| Battery divider control | 37 | Auto-detected: low enables V3/V3.1; high enables V3.2; disabled between samples |
| Console TX/RX | 43 / 44 | UART0 through CP2102 at 115200 baud |
| SX1262 reset / CS | 12 / 8 | Held low / high; LoRa stays inactive |

The OLED shows sender state/progress, spendable balance, focused message ID,
Wi-Fi state, button hint, and a battery gauge with approximate percentage.
Voltage comes from the ESP32-S3 curve-fitting ADC calibration when available.
This is a voltage estimate, not a fuel gauge; the board does not expose a
readable USB/charging/full indicator. With an implausible
measurement, the footer shows `PWR?` rather than a fabricated percentage.

GPIO0 is also connected to the boot/USB auto-reset circuit. Firmware debounces
the button, suppresses a button held at startup, and requires a one-second
hold followed by release for a send action. Do not hold PRG while resetting or
plugging in USB: that enters the ROM download mode. Ordinary short USB control
pulses cannot authorize transmission. Short presses during a transmission only
toggle the OLED; wallet and radio keep running with the screen off.

Sources:

- [Heltec V3 datasheet and pinout](https://resource.heltec.cn/download/WiFi_LoRa_32_V3/HTIT-WB32LA_V3%28Rev1.1%29.pdf)
- [Heltec schematics, V3.1/V3.2 pin maps and datasheets](https://resource.heltec.cn/download/WiFi_LoRa_32_V3/)
- [Meshtastic Heltec V3 pin definitions](https://github.com/meshtastic/firmware/blob/develop/variants/esp32s3/heltec_v3/variant.h)

The revision's enable polarity is detected by sampling GPIO37 low and high
after allowing each measurement to settle. `status` prints the detected level.
The hardware family identification is confirmed; the subrevision inferred
from the sensing circuit should be checked against the PCB label if needed.

## Build, flash and console

Use ESP-IDF 5.5.1. The board profile lives in `sdkconfig.heltec.defaults`;
`build-heltec` and `sdkconfig.heltec` are separate from the existing ESP32
T-Display build. Helpers activate the local IDF environment automatically:

```sh
./scripts/heltec.sh build
./scripts/heltec.sh flash
./scripts/heltec.sh console
```

An optional second argument overrides `/dev/cu.usbserial-0001`. Set `IDF_PATH`
if ESP-IDF is not installed at `~/Developer/esp/esp-idf`. The flash helper uses
115200 baud, since faster bulk flash reads were unreliable on this USB link.

The Heltec profile uses `partitions.heltec.csv`, with a 4 MiB application at
0x10000 and fresh 256 KiB wallet NVS at 0x500000. The backup confirmed that
this NVS/PHY region was erased, while the 7 MiB region contained older data.
This avoids treating the
previous firmware's NVS at 0x9000 or old app bytes as Cashu wallet storage.
Subsequent ordinary flashes preserve the wallet. Never run `erase-flash` on
a funded device. A full pre-installation flash backup is kept locally in
`.local/backups/heltec-v3-before-find-my-nuts-20260930.bin`, excluded from Git.

## Mint and receive

The new public modem ID is **57A030B3**. The fresh outbox starts at message ID
0, but always confirm the focused ID with `findmy status` and the exact token
length with `findmy list`.

```text
find-my-nuts> status
find-my-nuts> mint add https://YOUR-MINT
find-my-nuts> invoice 1
# Pay the invoice, then use the printed quote ID:
find-my-nuts> claim QUOTE_ID d=1x1
```

On the Mac, start the receiver before pressing the button:

```sh
./receiver/watch_heltec.sh 0
```

Hold PRG for at least one second and release. One eligible proof moves into
the durable outbox and repeats until the same gesture pauses it. The console
prints its message ID. Once `findmy list` shows the token size, restart the
watch with both values to query the complete frame immediately:

```sh
./receiver/watch_heltec.sh MESSAGE_ID TOKEN_BYTES
```

The helper explicitly selects the Heltec namespace and tracks exactly one
ID. The main receiver's historical default remains BD3BB756 for the T-Display.
No token size is assumed. The saved Apple session is reused from
`~/.find-my-nuts`, and the receiver prints a token only after frame validation.
An empty fresh query before the button press is expected. A 385-byte token
takes about 49 minutes 36 seconds per sender pass; Find My relay delay comes
in addition. Test with a negligible amount because this is public bearer ecash.
