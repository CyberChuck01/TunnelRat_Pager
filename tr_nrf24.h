// ===========================================================================
//  tr_nrf24.h  —  Tunnel R.A.T. // T-Pager  —  nRF24L01+ wardrive sensor
//  Device: LILYGO T-LoRa Pager + HW-237 nRF24L01+PA+LNA on the 12-pin header
//
//  RECEIVE-ONLY. The radio never transmits, so the PA stage never fires.
//
//  Two kinds of observation, logged separately and never mixed up:
//   1) "activity"  — Received-Power-Detector (RPD) sweep of channels 0..125.
//                    RPD only says "something above about -64 dBm was on this
//                    channel". It is NOT a device detection: Wi-Fi, BLE
//                    (including this Pager's own Wi-Fi/BLE scans), microwaves
//                    etc. all light it up.
//   2) "esb"       — Enhanced ShockBurst frames found with the 2-byte
//                    "promiscuous" address trick (Goodspeed 2011, as used by
//                    Bastille's nrf-research-firmware) and confirmed by the
//                    ESB CRC-16 in software. Only the 5-byte device address,
//                    channel, data rate and payload LENGTH are reported.
//                    Payload bytes are never stored (they can be keystrokes).
//
//  Limits: detects 5-byte-address / 16-bit-CRC ESB at 2M/1M/250k. Many
//  Si24R1/BK242x "nRF24" clones ignore the 2-byte address mode, in which case
//  only the activity sweep produces data.
//
//  Self-contained register driver (no RF24 library needed). All SPI traffic
//  goes through the lock/unlock callbacks so it shares the Pager's SPI bus
//  (display, SD, LoRa and NFC are all on SCK35/MOSI34/MISO33).
// ===========================================================================
#pragma once
#include <Arduino.h>
#include <SPI.h>
#include "config.h"

namespace nrf {

// ---- public types -----------------------------------------------------------
enum Rate : uint8_t { RATE_2M = 0, RATE_1M = 1, RATE_250K = 2 };
inline const char *rateName(uint8_t r) { return r == RATE_2M ? "2M" : r == RATE_1M ? "1M" : "250K"; }

struct EsbHit {
  uint8_t  addr[5];      // MSB first, as sent on air
  uint8_t  channel;      // 0..125  (freq = 2400 + channel MHz)
  uint8_t  rate;         // Rate
  uint8_t  payloadLen;   // bytes, from the ESB packet-control field
  uint16_t frames;       // CRC-valid frames seen from this address so far
  bool     strong;       // RPD set while receiving: signal above about -64 dBm
};

struct Activity {
  uint32_t windowMs;     // length of the window this summary covers
  uint16_t sweeps;       // full 0..125 sweeps done in the window
  uint8_t  n;            // number of active channels listed below
  uint8_t  ch[126];
  uint16_t hits[126];
};

typedef bool (*LockFn)();
typedef void (*UnlockFn)();
typedef void (*HitFn)(const EsbHit &);
typedef void (*ActFn)(const Activity &);

// ---- registers / commands ---------------------------------------------------
enum : uint8_t {
  R_CONFIG = 0x00, R_EN_AA = 0x01, R_EN_RXADDR = 0x02, R_SETUP_AW = 0x03,
  R_SETUP_RETR = 0x04, R_RF_CH = 0x05, R_RF_SETUP = 0x06, R_STATUS = 0x07,
  R_RPD = 0x09, R_RX_ADDR_P0 = 0x0A, R_RX_PW_P0 = 0x11, R_FIFO_STATUS = 0x17,
  R_DYNPD = 0x1C, R_FEATURE = 0x1D,
  C_R_RX_PAYLOAD = 0x61, C_FLUSH_TX = 0xE1, C_FLUSH_RX = 0xE2, C_NOP = 0xFF
};

// ---- state ------------------------------------------------------------------
static SPIClass *s_spi = nullptr;
static LockFn    s_lock = nullptr;
static UnlockFn  s_unlock = nullptr;
static bool      s_pinsReady = false, s_present = false, s_running = false;
static uint8_t   s_rates[3]; static uint8_t s_rateCount = 0, s_rateIdx = 0;
static uint8_t   s_ch = TR_NRF24_CH_MIN;
static uint32_t  s_lastHop = 0, s_lastSweep = 0, s_windowStart = 0;
static uint16_t  s_sweeps = 0;
static uint16_t  s_hits[126];
static uint8_t   s_lastActive = 0;
static uint32_t  s_frames = 0, s_crcOk = 0, s_confirmed = 0, s_busErrors = 0;

struct Track { uint8_t addr[5]; uint8_t used; uint16_t frames; uint32_t first, last, logged; };
static Track s_track[32];

// ---- low level --------------------------------------------------------------
inline void ce(bool on) { digitalWrite(TR_NRF24_CE_PIN, on ? HIGH : LOW); }

static bool busBegin() {
  if (!s_spi) return false;
  if (s_lock && !s_lock()) { s_busErrors++; return false; }
  s_spi->beginTransaction(SPISettings(TR_NRF24_SPI_HZ, MSBFIRST, SPI_MODE0));
  digitalWrite(TR_NRF24_CSN_PIN, LOW);
  return true;
}
static void busEnd() {
  digitalWrite(TR_NRF24_CSN_PIN, HIGH);
  s_spi->endTransaction();
  if (s_unlock) s_unlock();
}
static uint8_t rreg(uint8_t r) {
  if (!busBegin()) return 0xFF;
  s_spi->transfer(0x00 | (r & 0x1F));
  uint8_t v = s_spi->transfer(C_NOP);
  busEnd();
  return v;
}
static void wreg(uint8_t r, uint8_t v) {
  if (!busBegin()) return;
  s_spi->transfer(0x20 | (r & 0x1F));
  s_spi->transfer(v);
  busEnd();
}
static void wregn(uint8_t r, const uint8_t *b, uint8_t n) {
  if (!busBegin()) return;
  s_spi->transfer(0x20 | (r & 0x1F));
  for (uint8_t i = 0; i < n; i++) s_spi->transfer(b[i]);
  busEnd();
}
static void cmd(uint8_t c) {
  if (!busBegin()) return;
  s_spi->transfer(c);
  busEnd();
}
static bool readPayload(uint8_t *b, uint8_t n) {
  if (!busBegin()) return false;
  s_spi->transfer(C_R_RX_PAYLOAD);
  for (uint8_t i = 0; i < n; i++) b[i] = s_spi->transfer(C_NOP);
  busEnd();
  return true;
}

// Park the module off the shared bus. Safe to call before anything else is
// initialised and safe with nothing connected. Call EARLY in setup().
inline void parkPins() {
  pinMode(TR_NRF24_CSN_PIN, OUTPUT); digitalWrite(TR_NRF24_CSN_PIN, HIGH);
  pinMode(TR_NRF24_CE_PIN, OUTPUT);  digitalWrite(TR_NRF24_CE_PIN, LOW);
  s_pinsReady = true;
}

inline void attach(SPIClass *spi, LockFn lock, UnlockFn unlock) {
  s_spi = spi; s_lock = lock; s_unlock = unlock;
  if (!s_pinsReady) parkPins();
}

// Register read-back test. A missing module (MISO floating / held) cannot
// echo two different values back from two different registers.
inline bool probe() {
  if (!s_spi || s_running) return s_present;
  ce(false);
  wreg(R_CONFIG, 0x70);                       // powered down, IRQs masked
  wreg(R_SETUP_AW, 0x01); uint8_t a = rreg(R_SETUP_AW) & 0x03;
  wreg(R_SETUP_AW, 0x03); uint8_t b = rreg(R_SETUP_AW) & 0x03;
  wreg(R_RF_CH, 0x2A);    uint8_t c = rreg(R_RF_CH);
  wreg(R_RF_CH, 0x4C);    uint8_t d = rreg(R_RF_CH);
  s_present = (a == 0x01 && b == 0x03 && c == 0x2A && d == 0x4C);
  return s_present;
}

static uint8_t rateBits(uint8_t r) { return r == RATE_2M ? 0x08 : r == RATE_250K ? 0x20 : 0x00; }

static void setChannel(uint8_t c) { ce(false); wreg(R_RF_CH, c); ce(true); }

// Promiscuous receive: 2-byte address 0x00AA (noise + preamble), no CRC,
// no auto-ack, fixed 32-byte payload. The real ESB frame (address, packet
// control field, payload, CRC) then lands in the payload buffer.
static void configureRx() {
  ce(false);
  wreg(R_CONFIG, 0x70 | 0x02 | 0x01);         // IRQs masked, CRC off, PWR_UP, PRIM_RX
  delay(5);                                    // crystal start-up (Tpd2stby)
  wreg(R_EN_AA, 0x00);
  wreg(R_EN_RXADDR, 0x01);
  wreg(R_SETUP_AW, 0x00);                      // 2-byte address (nRF24L01+ only)
  wreg(R_SETUP_RETR, 0x00);
  const uint8_t promisc[2] = {0xAA, 0x00};     // LSByte first -> 0x00AA on air
  wregn(R_RX_ADDR_P0, promisc, 2);
  wreg(R_RX_PW_P0, 32);
  wreg(R_DYNPD, 0x00);
  wreg(R_FEATURE, 0x00);
  wreg(R_RF_SETUP, rateBits(s_rates[s_rateIdx]) | 0x06);
  wreg(R_STATUS, 0x70);
  cmd(C_FLUSH_RX);
  cmd(C_FLUSH_TX);
  setChannel(s_ch);
}

inline void start() {
  if (!s_present && !probe()) return;
  s_rateCount = 0;
  if (TR_NRF24_RATES & 0x01) s_rates[s_rateCount++] = RATE_2M;
  if (TR_NRF24_RATES & 0x02) s_rates[s_rateCount++] = RATE_1M;
  if (TR_NRF24_RATES & 0x04) s_rates[s_rateCount++] = RATE_250K;
  if (!s_rateCount) s_rates[s_rateCount++] = RATE_2M;
  s_rateIdx = 0; s_ch = TR_NRF24_CH_MIN;
  memset(s_hits, 0, sizeof s_hits); s_sweeps = 0;
  memset(s_track, 0, sizeof s_track);
  uint32_t now = millis();
  s_lastHop = now; s_lastSweep = now; s_windowStart = now;
  configureRx();
  s_running = true;
}

inline void stop() {
  if (!s_spi) return;
  ce(false);
  if (s_present) wreg(R_CONFIG, 0x70);          // PWR_UP=0 -> ~1 uA standby
  s_running = false;
}

// ---- ESB decode -------------------------------------------------------------
static uint16_t crcUpdate(uint16_t crc, uint8_t byte, uint8_t bits) {
  crc ^= (uint16_t)byte << 8;
  while (bits--) crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x1021) : (uint16_t)(crc << 1);
  return crc;
}

// Returns true and fills addr/len when buf holds a CRC-valid ESB frame
// (tries the 0xAA and 0x55 preamble alignments).
static bool esbDecode(const uint8_t *raw, uint8_t *addr, uint8_t *len) {
  uint8_t p[32];
  memcpy(p, raw, 32);
  for (int pass = 0; pass < 2; pass++) {
    if (pass == 1) {                            // shift right one bit for the 0x55 preamble case
      for (int x = 31; x >= 0; x--)
        p[x] = (uint8_t)((x > 0 ? (p[x - 1] & 0x01) << 7 : 0) | (p[x] >> 1));
    }
    uint8_t L = p[5] >> 2;                      // 6-bit payload length from the PCF
    if (L > 32 - 9) continue;
    uint16_t given = (uint16_t)(((p[6 + L] & 0x7F) << 9) | (p[7 + L] << 1) | (p[8 + L] >> 7));
    uint16_t crc = 0xFFFF;
    for (int x = 0; x < 6 + L; x++) crc = crcUpdate(crc, p[x], 8);
    crc = crcUpdate(crc, p[6 + L] & 0x80, 1);   // 9th PCF bit (NO_ACK)
    if (crc != given) continue;
    // Reject addresses that are just noise floor / preamble patterns.
    bool junk = true;
    for (int i = 0; i < 5; i++)
      if (p[i] != 0x00 && p[i] != 0xFF && p[i] != 0x55 && p[i] != 0xAA) { junk = false; break; }
    if (junk) continue;
    memcpy(addr, p, 5); *len = L;
    return true;
  }
  return false;
}

// Random noise passes a 16-bit CRC about once every 32k tries, so an address
// is only reported after a 2nd CRC-valid frame within 10 s.
static void trackFrame(const uint8_t *addr, uint8_t len, bool strong, uint32_t now, HitFn onHit) {
  s_crcOk++;
  int idx = -1, freeIdx = -1, oldest = 0;
  for (int i = 0; i < 32; i++) {
    if (s_track[i].used && memcmp(s_track[i].addr, addr, 5) == 0) { idx = i; break; }
    if (!s_track[i].used) { if (freeIdx < 0) freeIdx = i; }
    else if (now - s_track[i].last > now - s_track[oldest].last) oldest = i;
  }
  if (idx < 0) {
    idx = freeIdx >= 0 ? freeIdx : oldest;
    memset(&s_track[idx], 0, sizeof(Track));
    memcpy(s_track[idx].addr, addr, 5);
    s_track[idx].used = 1; s_track[idx].first = now;
  }
  Track &t = s_track[idx];
  if (!t.logged && t.frames && now - t.last > 10000) { t.frames = 0; t.first = now; }
  if (t.frames < 0xFFFF) t.frames++;
  t.last = now;
  if (t.frames >= 2 && (!t.logged || now - t.logged >= TR_NRF24_RELOG_MS)) {
    t.logged = now; s_confirmed++;
    if (onHit) {
      EsbHit h; memcpy(h.addr, addr, 5);
      h.channel = s_ch; h.rate = s_rates[s_rateIdx]; h.payloadLen = len;
      h.frames = t.frames; h.strong = strong;
      onHit(h);
    }
  }
}

// ---- RPD activity sweep -----------------------------------------------------
static void sweep() {
  for (uint8_t c = 0; c < 126; c++) {
    ce(false); wreg(R_RF_CH, c); ce(true);
    delayMicroseconds(TR_NRF24_RPD_US);         // >=170 us: RX settle + RPD integration
    if (rreg(R_RPD) & 0x01) s_hits[c]++;
  }
  ce(false);
  cmd(C_FLUSH_RX);                              // drop junk captured on other channels
  wreg(R_STATUS, 0x70);
  setChannel(s_ch);
  s_sweeps++;
}

static void emitWindow(uint32_t now, ActFn onAct) {
  static Activity a;                            // ~400 bytes, keep off the stack
  a.windowMs = now - s_windowStart; a.sweeps = s_sweeps; a.n = 0;
  uint16_t thr = (uint16_t)((s_sweeps * (uint32_t)TR_NRF24_ACTIVE_PCT + 99) / 100);
  if (thr < 1) thr = 1;
  for (uint8_t c = 0; c < 126; c++)
    if (s_hits[c] >= thr) { a.ch[a.n] = c; a.hits[a.n] = s_hits[c]; a.n++; }
  s_lastActive = a.n;
  if (s_sweeps && onAct) onAct(a);
  memset(s_hits, 0, sizeof s_hits); s_sweeps = 0; s_windowStart = now;
}

// ---- main tick (call from loop() while running) -----------------------------
inline void tick(HitFn onHit, ActFn onAct) {
  if (!s_running) return;
  uint32_t now = millis();

  // 1) drain the 3-deep RX FIFO
  for (int k = 0; k < 3; k++) {
    uint8_t fifo = rreg(R_FIFO_STATUS);
    if (fifo == 0xFF || (fifo & 0x01)) break;   // bus error or RX_EMPTY
    uint8_t raw[32];
    if (!readPayload(raw, 32)) break;
    bool strong = rreg(R_RPD) & 0x01;
    wreg(R_STATUS, 0x40);                       // clear RX_DR
    s_frames++;
    uint8_t addr[5], len;
    if (esbDecode(raw, addr, &len)) trackFrame(addr, len, strong, now, onHit);
  }

  // 2) hop; after a full channel cycle move to the next data rate
  if (now - s_lastHop >= TR_NRF24_DWELL_MS) {
    s_lastHop = now;
    if (++s_ch > TR_NRF24_CH_MAX) {
      s_ch = TR_NRF24_CH_MIN;
      if (s_rateCount > 1) {
        s_rateIdx = (s_rateIdx + 1) % s_rateCount;
        ce(false); wreg(R_RF_SETUP, rateBits(s_rates[s_rateIdx]) | 0x06);
      }
    }
    setChannel(s_ch);
  }

  // 3) periodic RPD sweep (~25 ms blocking)
  if (TR_NRF24_SWEEP_MS > 0 && now - s_lastSweep >= TR_NRF24_SWEEP_MS) {
    s_lastSweep = now;
    sweep();
  }

  // 4) activity summary window
  if (now - s_windowStart >= TR_NRF24_WINDOW_MS) emitWindow(now, onAct);
}

// ---- status -----------------------------------------------------------------
// ---- standalone scan + radar helpers (used by the nRF24 scan+radar mode) ----
// Radio must already be in RX (call start() first). Both are blocking and take
// the SPI lock per register op, so they're safe against the display.

// One full 0..125 RPD pass: out[c] = 1 if carrier-detect fired on channel c. ~25 ms.
inline void sweepRaw(uint8_t out[126]) {
  for (uint8_t c = 0; c < 126; c++) {
    ce(false); wreg(R_RF_CH, c); ce(true);
    delayMicroseconds(TR_NRF24_RPD_US);
    out[c] = (rreg(R_RPD) & 0x01) ? 1 : 0;
  }
  ce(false); cmd(C_FLUSH_RX); wreg(R_STATUS, 0x70);
  setChannel(s_ch);
}

// Park on one channel and count RPD hits over `samples` reads (radar homing).
// Returns 0..samples.
inline uint16_t rpdOn(uint8_t ch, uint16_t samples) {
  ce(false); wreg(R_RF_CH, ch); ce(true);
  uint16_t hits = 0;
  for (uint16_t i = 0; i < samples; i++) {
    delayMicroseconds(TR_NRF24_RPD_US);
    if (rreg(R_RPD) & 0x01) hits++;
  }
  ce(false); cmd(C_FLUSH_RX); wreg(R_STATUS, 0x70);
  setChannel(s_ch);
  return hits;
}

inline bool     present()      { return s_present; }
inline bool     running()      { return s_running; }
inline uint8_t  channel()      { return s_ch; }
inline uint8_t  activeCount()  { return s_lastActive; }
inline uint32_t frames()       { return s_frames; }
inline uint32_t crcValid()     { return s_crcOk; }
inline uint32_t confirmed()    { return s_confirmed; }
inline uint32_t busErrors()    { return s_busErrors; }

} // namespace nrf
