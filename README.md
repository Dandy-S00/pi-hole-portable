# ESP32-S3 Pi-hole (SD-backed DNS Sinkhole) for Waveshare boards

[![Build firmware](https://github.com/Dandy-S00/pi-hole-portable/actions/workflows/build.yml/badge.svg)](https://github.com/Dandy-S00/pi-hole-portable/actions/workflows/build.yml)

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

## Architecture

```mermaid
flowchart LR
    subgraph LAN["Your LAN"]
        C1["Phone / Laptop"]
        C2["Smart TV"]
        C3["IoT devices"]
        R["Router (DHCP)<br/>DNS = ESP32-S3 IP"]
    end

    subgraph BOARD["Waveshare ESP32-S3 + microSD"]
        DNS["DNS Sinkhole<br/>UDP/TCP :53"]
        BL["Blocklist lookup<br/>binary search<br/>/sdcard/blocklist.bin"]
        SD[(("microSD card<br/>(expanded storage)<br/>sorted 5-byte<br/>FNV-1a hashes"))]
        UP["Forward to<br/>upstream resolver"]
    end

    NET["Internet<br/>(Quad9 9.9.9.9)"]

    C1 --> R
    C2 --> R
    C3 --> R
    R -->|DNS query| DNS
    DNS -->|hash domain + suffix| BL
    BL -->|seek+read 5 bytes| SD
    SD -->|hit = blocked| DNS
    DNS -->|reply 0.0.0.0| R
    BL -->|miss = allowed| UP
    UP --> NET
    NET -->|real answer| DNS
    DNS -->|reply| R

    style SD fill:#1f6f43,stroke:#2ecc71,color:#fff
    style DNS fill:#0b3d5c,stroke:#3498db,color:#fff
    style BL fill:#3a2d5c,stroke:#9b59b6,color:#fff
    style UP fill:#5c3a0b,stroke:#e67e22,color:#fff
```

Every DNS query on the LAN is intercepted by the ESP32-S3. The domain (and each
parent suffix) is hashed with FNV-1a and binary-searched against `blocklist.bin` on
the SD card. A **hit** → answer `0.0.0.0` (sinkholed). A **miss** → forward to the
upstream resolver and relay the real answer. See [`docs/architecture.md`](docs/architecture.md)
for the source of this diagram.

## Build firmware in CI (GitHub Actions)

Pushing to `main` automatically builds `firmware.bin` via PlatformIO. The build
matrix uploads the `.bin` as a downloadable artifact — so you don't need
PlatformIO installed locally to flash.

- **Download the built firmware:** repo → *Actions* → latest run → *Artifacts*
  (`esp32s3-pihole-firmware-...`).
- **Flash it:** `esptool.py write_flash 0x0 firmware.bin` (or use the ESP Web
  Flasher with the artifact).
- **Different board?** run the workflow manually (`workflow_dispatch`) and set the
  `board` input (e.g. `esp32-s3-zero`).

> The CI build uses `board = esp32-s3-devkitc-1` by default; change it in
> `platformio.ini` or pass the `board` input.

## Files

```
esp32s3-pihole/
├── platformio.ini            # build config
├── .github/workflows/
│   └── build.yml             # CI: builds firmware.bin on push/PR
├── src/
│   ├── main.cpp              # DNS sinkhole + SD-card blocklist loader
│   └── secrets.example.h     # WiFi template (copy to secrets.h)
├── tools/
│   └── build_blocklist.py    # hosts -> sorted 5-byte hash file for the SD card
├── docs/
│   └── architecture.md       # Mermaid diagram source
└── data/                     # working dir for build artifacts
```
