# find-my-nuts

A proof-of-concept ESP32 Cashu wallet that broadcasts ecash tokens over Apple's
Find My network. Built on Nucula, with a Python receiver to reconstruct tokens.

Supports the **Heltec WiFi LoRa 32 V3** (ESP32-S3) and the original
**1.14-inch LILYGO/TTGO T-Display** (ESP32).

> Broadcast tokens are public bearer ecash: anyone who recovers one can spend it.
> Use only giveaway amounts. Delivery is slow, unofficial, and not guaranteed.

## Quick start (Heltec V3)

Install ESP-IDF 5.5.1; set `IDF_PATH` if it is outside `~/Developer/esp/esp-idf`.

```sh
git submodule update --init --recursive
cp main/wifi_config.example.h main/wifi_config.h
# Edit main/wifi_config.h with your Wi-Fi credentials (ignored by Git).
./scripts/heltec.sh build
./scripts/heltec.sh flash
./scripts/heltec.sh console
```

In the device console:

```text
mint add https://your-mint.example
invoice 5
# Pay the invoice, then use its quote ID:
claim <quote_id> d=1x5
findmy resume
```

One proof moves into a durable outbox and repeats until `findmy pause`.
On Heltec, holding PRG for one second and releasing also starts/pauses sending.
Every boot starts with transmission off. Never erase flash on a funded device.

## Guides

- [Heltec setup, controls, and flashing](docs/HELTEC_V3.md)
- [Receiver setup and usage](receiver/README.md) — requires an Apple Account and 2FA.
- [Transport protocol](docs/FIND_MY_PROTOCOL.md)
- [Third-party notices and license boundaries](THIRD_PARTY_NOTICES.md)
