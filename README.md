# ESP32-S3 Pi-hole (SD-backed DNS Sinkhole) for Waveshare boards

Turn a **Waveshare ESP32-S3** dev board into a **network-wide ad/tracker blocker**
(Pi-hole style) that stores its blocklist on the **microSD card you expanded the
board with** instead of limited on-chip flash/PSRAM.

- **DNS sinkhole** on UDP/TCP port 53 (RFC 1035 query parsing).
- **Blocklist = a file on the SD card** (`/sdcard/blocklist.bin`): sorted
  5-byte FNV-1a domain hashes, binary-searched. Size is bounded only by your SD
  card — a 2 GB card holds ~400k domains, a 32 GB card ~6.7 million.
- **Suffix matching**: `ads.a.b.com` is blocked if `b.com` is listed.
- **Fail-open**: if the SD card or blocklist is missing, all queries are forwarded
  upstream so the LAN never loses DNS.
- Simple web dashboard at the device IP (`/stats` JSON).

## Hardware

Any Waveshare ESP32-S3 board with an SD card slot. Verified SD wiring
(from Waveshare's own `SDMMC_Test` example, 1-bit SD_MMC mode):

| Signal | GPIO |
|--------|------|
| CLK    | 14   |
| CMD    | 17   |
| D0     | 16   |

> Power the SD card from **3.3 V** — it is not 5 V tolerant.

## Sources & credits

- Blocklist hashing/lookup algorithm: [`M-Abozaid/esp32-c3-adblock`](https://github.com/M-Abozaid/esp32-c3-adblock)
  (40-bit FNV-1a hashes in flash, binary-searched — we moved the file to SD).
- ESP32-S3 DNS sinkhole architecture / fail-open design: [`aguilerasmiguel/esphole`](https://github.com/aguilerasmiguel/esphole).
- SD card pinout: Waveshare `ESP32-S3-Touch-LCD-1.85C` `04_SDMMC_Test` example.

## Build & flash (PlatformIO)

```bash
cd esp32s3-pihole
cp src/secrets.example.h src/secrets.h      # edit WiFi SSID/PASS
pio run -t upload                           # flash firmware
pio device monitor                          # watch boot logs
```

Set the right `board =` in `platformio.ini` for your exact module
(e.g. `esp32-s3-zero`, `esp32-s3-devkitc-1`, etc.).

## Prepare the SD card blocklist

```bash
# default daily-driver list (~140k domains, social keeps working)
python3 tools/build_blocklist.py blocklist.bin

# aggressive (~500k, also blocks social/messaging)
python3 tools/build_blocklist.py blocklist.bin \
  https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social/hosts \
  https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/ultimate.txt
```

Copy the resulting `blocklist.bin` to the **root of the microSD card** (the
firmware mounts it at `/sdcard/blocklist.bin`). Insert the card, power the board.

The serial monitor will print how many hashes were loaded from the card.

## Deploy

1. Flash firmware, insert SD card with `blocklist.bin`, power on.
2. Board connects to WiFi; serial shows its IP (e.g. `192.168.1.42`).
3. In your router's DHCP settings, set the DNS server to that IP for all clients
   (or manually set DNS on each device).
4. Open `http://<device-ip>/` to see live blocked/allowed stats.

## How it uses your expanded SD card

The firmware never loads the full list into RAM. Each DNS query does a handful of
`seek()` + `read(5 bytes)` calls against `/sdcard/blocklist.bin` (binary search).
That is why a large SD card is a feature, not waste: you can drop the biggest
blocklists (StevenBlack + Hagezi Ultimate + more) with zero RAM pressure.

## Files

```
esp32s3-pihole/
├── platformio.ini            # build config
├── src/
│   ├── main.cpp              # DNS sinkhole + SD-card blocklist loader
│   └── secrets.example.h     # WiFi template (copy to secrets.h)
├── tools/
│   └── build_blocklist.py    # hosts -> sorted 5-byte hash file for the SD card
└── data/                     # working dir for build artifacts
```
