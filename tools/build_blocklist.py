#!/usr/bin/env python3
"""
Build a Pi-hole-style blocklist as a sorted file of 5-byte (40-bit) FNV-1a
domain hashes, ready to drop on the ESP32-S3's microSD card as /sdcard/blocklist.bin.

Because the firmware binary-searches this FILE directly from the SD card, the
blocklist size is bounded only by your SD card capacity -- not by flash/PSRAM.
A 2 GB card holds ~400k hashes; a 32 GB card ~6.7 million. Use the big card
you expanded the board with.

HASH_BYTES MUST match src/main.cpp (5).

Usage:
  python3 build_blocklist.py [out.bin] [source ...]

  source = local file or URL. With no sources given, downloads a balanced
  daily-driver set (StevenBlack base + Hagezi Light) ~= 140k domains:
  blocks ads/trackers/malware but leaves WhatsApp/social working.

  Aggressive (~500k, also blocks social/messaging):
    python3 build_blocklist.py blocklist.bin \\
      https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social/hosts \\
      https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/ultimate.txt

Then copy out.bin to the SD card root as:  blocklist.bin
(and the firmware mounts it at /sdcard/blocklist.bin)
"""
import sys, os, math, urllib.request

HASH_BYTES = 5
MASK = (1 << (HASH_BYTES * 8)) - 1
FNV_OFFSET = 0xcbf29ce484222325
FNV_PRIME  = 0x100000001b3
U64 = (1 << 64) - 1

DEFAULT_SOURCES = [
    'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
    'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/light.txt',
]

def fnv(b: bytes) -> int:
    h = FNV_OFFSET
    for c in b:
        h = ((h ^ c) * FNV_PRIME) & U64
    return h & MASK

def norm(d: str) -> str:
    d = d.strip().lower().lstrip('*').lstrip('.').rstrip('.')
    return d[4:] if d.startswith('www.') else d

def read_source(src: str) -> str:
    if os.path.exists(src):
        return open(src, errors='ignore').read()
    print(f'  downloading {src} ...', file=sys.stderr)
    return urllib.request.urlopen(src, timeout=180).read().decode('utf-8', 'ignore')

def main():
    args = sys.argv[1:]
    out = args[0] if args else 'blocklist.bin'
    sources = args[1:] if len(args) > 1 else DEFAULT_SOURCES

    domains = set()
    for src in sources:
        try:
            data = read_source(src)
        except Exception as e:
            print(f'  !! skipped {src}: {e}', file=sys.stderr)
            continue
        for line in data.splitlines():
            line = line.split('#', 1)[0].strip()
            if not line or line[0] in '!/':
                continue
            parts = line.split()
            d = (parts[1] if len(parts) >= 2 and parts[0] in ('0.0.0.0','127.0.0.1','::1','::')
                 else parts[0] if len(parts) == 1 else None)
            if d:
                d = norm(d)
                if '.' in d and ' ' not in d:
                    domains.add(d)

    hashes = sorted(fnv(d.encode()) for d in domains)
    uniq = sorted(set(hashes))
    collisions = len(hashes) - len(uniq)
    with open(out, 'wb') as f:
        for h in uniq:
            f.write(h.to_bytes(HASH_BYTES, 'little'))

    n, size = len(uniq), len(uniq) * HASH_BYTES
    print(f'source domains   : {len(domains):,}')
    print(f'hash entries     : {n:,}  ({HASH_BYTES}-byte / {HASH_BYTES*8}-bit)')
    print(f'collisions       : {collisions}  (domains sharing a hash -> minor over-block)')
    print(f'bin blob         : {size:,} bytes ({size/1024/1024:.2f} MB) -> {out}')
    print(f'lookup           : ~{math.ceil(math.log2(max(n,2)))} reads/query (SD card seeks)')
    print(f'\nNext: copy {out} onto the microSD card as  blocklist.bin  (root dir).')

if __name__ == '__main__':
    main()
