/*
 * ESP32-S3 Pi-hole (DNS sinkhole) for Waveshare ESP32-S3 boards with SD card.
 *
 * Design (adapted from M-Abozaid/esp32-c3-adblock + aguilerasmiguel/esphole):
 *   - DNS server on port 53 (UDP), RFC 1035 style query parsing.
 *   - Blocklist = sorted 5-byte (40-bit) FNV-1a domain hashes, binary-searched
 *     directly from a FILE on the microSD card -> /sdcard/blocklist.bin
 *   - This means the blocklist size is bounded only by your SD card, not by
 *     flash/PSRAM. A 32 GB card holds ~6 million hashes; even a 2 GB card
 *     holds ~400k. You expanded the board's storage with a big SD card -> use it.
 *   - Suffix matching (test "ads.example.com" against "example.com" too).
 *   - Fail-open: if SD/blocklist unavailable, everything is forwarded upstream
 *     so the LAN never loses DNS.
 *   - Optional simple web UI to see stats (blocked/allowed counts).
 *
 * Hardware: any Waveshare ESP32-S3 board that exposes an SD card.
 * SD wiring (1-bit SD_MMC, verified on Waveshare ESP32-S3 examples):
 *   CLK = GPIO 14, CMD = GPIO 17, D0 = GPIO 16
 *   (power the SD card from 3.3V; it is NOT 5V tolerant)
 *
 * Build: PlatformIO (see platformio.ini). WiFi creds in src/secrets.h
 *        (copy src/secrets.example.h).
 */

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <SD_MMC.h>
#include <WebServer.h>
#include <Preferences.h>
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "secrets.h"

// ---------------- config ----------------
static const IPAddress UPSTREAM(9, 9, 9, 9);   // Quad9 (no blocking)
static const uint16_t DNS_PORT = 53;
static const char* BLOCKLIST_PATH = "/sdcard/blocklist.bin";  // <-- on the SD card
static const int HASH_BYTES = 5;
static const uint64_t HASH_MASK = (1ULL << (HASH_BYTES * 8)) - 1;

// SD_MMC 1-bit pins for Waveshare ESP32-S3 boards
static const int SD_CLK = 14;
static const int SD_CMD = 17;
static const int SD_D0  = 16;

// ---------------- globals ----------------
WiFiUDP dnsServer, upstreamCli;
WebServer web(80);

File blocklist;                 // open handle to /sdcard/blocklist.bin
uint32_t numHashes = 0;         // number of 5-byte entries on the card
uint32_t totalBlocked = 0, totalAllowed = 0;
uint8_t buf[600];

Preferences prefs;

// ---------------- hashing / matching ----------------
static uint64_t fnv40(const char* s, size_t n) {
  uint64_t h = 0xcbf29ce484222325ULL;
  for (size_t i = 0; i < n; i++) { h ^= (uint8_t)s[i]; h *= 0x100000001b3ULL; }
  return h & HASH_MASK;
}

// Binary search the blocklist FILE on the SD card.
static bool inBlocklistFile(uint64_t h) {
  if (!blocklist || numHashes == 0) return false;
  int32_t lo = 0, hi = (int32_t)numHashes - 1;
  uint8_t b[HASH_BYTES];
  while (lo <= hi) {
    int32_t mid = (lo + hi) >> 1;
    blocklist.seek((uint32_t)mid * HASH_BYTES);
    if (blocklist.read(b, HASH_BYTES) != HASH_BYTES) return false;
    uint64_t v = 0;
    for (int k = 0; k < HASH_BYTES; k++) v |= (uint64_t)b[k] << (8 * k);
    if (v < h) lo = mid + 1;
    else if (v > h) hi = mid - 1;
    else return true;
  }
  return false;
}

// Test the full domain and each parent suffix (ads.a.b.com -> a.b.com -> b.com)
static bool isBlocked(const char* domain) {
  const char* p = domain;
  while (p && *p) {
    uint64_t h = fnv40(p, strlen(p));
    if (inBlocklistFile(h)) return true;
    const char* dot = strchr(p, '.');
    if (!dot) break;
    const char* next = dot + 1;
    if (!strchr(next, '.')) break;  // stop before TLD
    p = next;
  }
  return false;
}

// ---------------- DNS ----------------
static size_t parseQuery(const uint8_t* pkt, int len, char* out, uint16_t* qtype, int* qend) {
  if (len < 13) return 0;
  int i = 12; size_t o = 0;
  while (i < len) {
    uint8_t l = pkt[i++];
    if (l == 0) break;
    if (l & 0xC0) return 0;
    if (o + l + 1 >= 250 || i + l > len) return 0;
    if (o) out[o++] = '.';
    for (uint8_t k = 0; k < l; k++) out[o++] = tolower(pkt[i++]);
  }
  out[o] = 0;
  if (i + 4 > len) return 0;
  *qtype = (pkt[i] << 8) | pkt[i + 1];
  *qend = i + 4;
  if (o > 4 && strncmp(out, "www.", 4) == 0) { memmove(out, out + 4, o - 3); o -= 4; }
  return o;
}

static int buildBlocked(int qend, uint16_t qtype) {
  buf[2] = 0x81; buf[3] = 0x80; buf[6] = 0; buf[7] = (qtype == 1) ? 1 : 0;
  buf[8] = 0; buf[9] = 0; buf[10] = 0; buf[11] = 0;
  if (qtype != 1) return qend;
  const uint8_t ans[] = {0xC0,0x0C, 0,1, 0,1, 0,0,1,0x2C, 0,4, 0,0,0,0};
  memcpy(buf + qend, ans, sizeof(ans));
  return qend + sizeof(ans);
}

static int forwardUpstream(int qlen) {
  upstreamCli.beginPacket(UPSTREAM, 53);
  upstreamCli.write(buf, qlen);
  upstreamCli.endPacket();
  uint32_t t0 = millis();
  while (millis() - t0 < 1500) {
    int sz = upstreamCli.parsePacket();
    if (sz > 0) return upstreamCli.read(buf, sizeof(buf));
    delay(1);
  }
  return 0;
}

static void handleDns() {
  for (int budget = 0; budget < 16; budget++) {
    int sz = dnsServer.parsePacket();
    if (sz <= 0) break;
    IPAddress cip = dnsServer.remoteIP();
    uint16_t cport = dnsServer.remotePort();
    int qlen = dnsServer.read(buf, sizeof(buf));
    if (qlen < 13) continue;
    char domain[256];
    uint16_t qtype = 0;
    int qend = qlen;
    size_t dl = parseQuery(buf, qlen, domain, &qtype, &qend);
    bool blocked = dl && numHashes && isBlocked(domain);
    int rlen;
    if (blocked) { rlen = buildBlocked(qend, qtype); totalBlocked++; }
    else         { rlen = forwardUpstream(qlen);     totalAllowed++; }
    if (rlen > 0) {
      dnsServer.beginPacket(cip, cport);
      dnsServer.write(buf, rlen);
      dnsServer.endPacket();
    }
  }
}

// ---------------- web stats ----------------
static void handleStats() {
  String j = "{\"ip\":\"" + WiFi.localIP().toString() + "\",";
  j += "\"blocked\":" + String(totalBlocked) + ",";
  j += "\"allowed\":" + String(totalAllowed) + ",";
  j += "\"domains\":" + String(numHashes) + ",";
  j += "\"sd_mounted\":" + String(SD_MMC.begin("/sdcard", true) ? "true" : "false");
  j += "}";
  web.send(200, "application/json", j);
}

static void handleRoot() {
  String html = "<html><head><meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>ESP32-S3 Pi-hole</title></head><body style='font-family:sans-serif;background:#111;color:#eee'>"
    "<h1>ESP32-S3 Pi-hole (SD-backed)</h1>"
    "<p>Blocklist lives on the microSD card: <code>/sdcard/blocklist.bin</code></p>"
    "<p>Point your router's DNS at this device's IP: <b>" + WiFi.localIP().toString() + "</b></p>"
    "<pre id='s'>loading...</pre>"
    "<script>fetch('/stats').then(r=>r.json()).then(d=>{"
    "document.getElementById('s').textContent="
    "'Blocked: '+d.blockeded+'\\nAllowed: '+d.allowed+'\\nDomains on SD: '+d.domains+'\\nSD mounted: '+d.sd_mounted;"
    "}).catch(e=>document.getElementById('s').textContent='err '+e);</script>"
    "</body></html>";
  web.send(200, "text/html", html);
}

// ---------------- setup ----------------
void setup() {
  Serial.begin(115200);
  delay(500);
  Serial.println("\nESP32-S3 Pi-hole (SD-backed) booting...");

  // --- mount SD card (holds the blocklist) ---
  if (!SD_MMC.setPins(SD_CLK, SD_CMD, SD_D0)) {
    Serial.println("SD_MMC setPins failed!");
  }
  if (!SD_MMC.begin("/sdcard", true)) {   // true = 1-bit mode
    Serial.println("SD card mount FAILED - will run fail-open (no blocking).");
  } else {
    uint8_t t = SD_MMC.cardType();
    Serial.printf("SD card mounted. Type=%d, size=%llu MB\n", t, SD_MMC.cardSize()/(1024*1024));
    // open blocklist read-only
    if (SD_MMC.exists(BLOCKLIST_PATH)) {
      blocklist = SD_MMC.open(BLOCKLIST_PATH, FILE_READ);
      numHashes = blocklist.size() / HASH_BYTES;
      Serial.printf("Blocklist loaded: %u hashes (%u bytes) from SD card\n", numHashes, (uint32_t)blocklist.size());
    } else {
      Serial.printf("WARN: %s not found on SD card. Fail-open (no blocking) until you add it.\n", BLOCKLIST_PATH);
    }
  }

  // --- WiFi ---
  prefs.begin("wifi", true);
  String ssid = prefs.getString("ssid", WIFI_SSID);
  String pass = prefs.getString("pass", WIFI_PASS);
  prefs.end();

  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid.c_str(), pass.c_str());
  Serial.printf("Connecting to %s ...\n", ssid.c_str());
  int tries = 0;
  while (WiFi.status() != WL_CONNECTED && tries < 30) {
    delay(1000); Serial.print("."); tries++;
  }
  if (WiFi.status() == WL_CONNECTED) {
    Serial.printf("\nWiFi up: %s\n", WiFi.localIP().toString().c_str());
  } else {
    Serial.println("\nWiFi FAILED - check secrets.h");
    return;
  }

  dnsServer.begin(DNS_PORT);
  upstreamCli.begin(53);
  web.on("/", handleRoot);
  web.on("/stats", handleStats);
  web.begin();
  Serial.printf("DNS sinkhole live on %s:53\n", WiFi.localIP().toString().c_str());
  Serial.println("Configure your router DHCP to hand out this IP as DNS.");
}

void loop() {
  handleDns();
  web.handleClient();
  delay(1);
}
