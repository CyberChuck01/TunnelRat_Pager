// ===========================================================================
//  tr_cc1101.h  —  Tunnel R.A.T. // T-Pager  —  CC1101 sub-GHz wardrive sensor
//  Device: LILYGO T-LoRa Pager + external CC1101 module on the 12-pin header
//
//  RECEIVE-ONLY activity survey. Steps through a list of common sub-GHz
//  frequencies (garage/gate remotes, car fobs, sensors, ISM) and reads the
//  CC1101's live RSSI on each. Once per window it reports, per frequency,
//  how many sweeps were above the threshold and the strongest level seen.
//  This is signal ACTIVITY, not decoded devices.
//
//  Shares the header "radio slot" with the nRF24: CSN on GPIO44 (header RX).
//  GDO0 goes to header GPIO9 (NOT GPIO43 — that pin is the nRF24's CE output
//  and would fight the CC1101's GDO0 output).
// ===========================================================================
#pragma once
#include <Arduino.h>
#include <SPI.h>
#include <RadioLib.h>
#include "config.h"

namespace cc {

struct Activity {
  uint32_t windowMs;
  uint16_t sweeps;
  uint8_t  n;                       // active frequencies listed below
  float    freq[16];
  uint16_t hits[16];
  float    maxRssi[16];
};
typedef void (*ActFn)(const Activity &);
typedef bool (*LockFn)();
typedef void (*UnlockFn)();

static const float s_freqs[] = { TR_CC1101_FREQS };
static const uint8_t s_nFreq = (uint8_t)(sizeof(s_freqs) / sizeof(s_freqs[0]) > 16 ? 16 : sizeof(s_freqs) / sizeof(s_freqs[0]));

static Module  *s_mod = nullptr;
static CC1101  *s_radio = nullptr;
static LockFn   s_lock = nullptr;
static UnlockFn s_unlock = nullptr;
static bool     s_present = false, s_running = false;
static uint32_t s_lastSweep = 0, s_windowStart = 0;
static uint16_t s_sweeps = 0;
static uint16_t s_hits[16];
static float    s_max[16];
static float    s_lastRssi[16];
static uint8_t  s_lastActive = 0;

static bool lock()   { return s_lock ? s_lock() : true; }
static void unlock() { if (s_unlock) s_unlock(); }

inline void attach(LockFn l, UnlockFn u) {
  s_lock = l; s_unlock = u;
  if (!s_mod) {
    s_mod = new Module(TR_CC1101_CSN_PIN, TR_CC1101_GDO0_PIN, RADIOLIB_NC, RADIOLIB_NC, SPI);
    s_radio = new CC1101(s_mod);
  }
}

// RadioLib begin() resets the chip and checks its VERSION register.
// ~100 ms when nothing is attached. Call only when the slot is idle.
inline bool probe() {
  if (!s_radio || s_running) return s_present;
  if (!lock()) return s_present;
  int16_t st = s_radio->begin(433.92, 4.8, 5.0, TR_CC1101_RXBW_KHZ, 10, 16);
  if (st == RADIOLIB_ERR_NONE) s_radio->sleep();
  unlock();
  s_present = (st == RADIOLIB_ERR_NONE);
  return s_present;
}

inline void start() {
  if (!s_present) return;
  memset(s_hits, 0, sizeof s_hits); s_sweeps = 0;
  for (uint8_t i = 0; i < 16; i++) { s_max[i] = -200; s_lastRssi[i] = -200; }
  s_windowStart = s_lastSweep = millis();
  if (lock()) { s_radio->standby(); unlock(); }
  s_running = true;
}

inline void stop() {
  if (s_present && s_radio && lock()) { s_radio->standby(); s_radio->sleep(); unlock(); }
  s_running = false;
}

static void sweep() {
  for (uint8_t i = 0; i < s_nFreq; i++) {
    if (!lock()) return;
    s_radio->standby();
    float rssi = -200;
    if (s_radio->setFrequency(s_freqs[i]) == RADIOLIB_ERR_NONE && s_radio->receiveDirect() == RADIOLIB_ERR_NONE) {
      delayMicroseconds(TR_CC1101_SETTLE_US);   // RX settle + RSSI integration
      rssi = s_radio->getRSSI();                // live register read in direct mode
    }
    unlock();
    s_lastRssi[i] = rssi;
    if (rssi > s_max[i]) s_max[i] = rssi;
    if (rssi >= TR_CC1101_RSSI_DBM) s_hits[i]++;
  }
  if (lock()) { s_radio->standby(); unlock(); }
  s_sweeps++;
}

static void emitWindow(uint32_t now, ActFn onAct) {
  static Activity a;
  a.windowMs = now - s_windowStart; a.sweeps = s_sweeps; a.n = 0;
  for (uint8_t i = 0; i < s_nFreq; i++)
    if (s_hits[i]) { a.freq[a.n] = s_freqs[i]; a.hits[a.n] = s_hits[i]; a.maxRssi[a.n] = s_max[i]; a.n++; }
  s_lastActive = a.n;
  if (s_sweeps && onAct) onAct(a);
  memset(s_hits, 0, sizeof s_hits); s_sweeps = 0; s_windowStart = now;
  for (uint8_t i = 0; i < 16; i++) s_max[i] = -200;
}

inline void tick(ActFn onAct) {
  if (!s_running) return;
  uint32_t now = millis();
  if (now - s_lastSweep >= TR_CC1101_SWEEP_MS) { s_lastSweep = now; sweep(); }
  if (now - s_windowStart >= TR_CC1101_WINDOW_MS) emitWindow(now, onAct);
}

inline bool    present()     { return s_present; }
inline bool    running()     { return s_running; }
inline uint8_t activeCount() { return s_lastActive; }

// ---- standalone scan + radar helpers (used by the CC1101 scan+radar mode) ---
inline uint8_t freqCount()        { return s_nFreq; }
inline float   freqMHz(uint8_t i) { return i < s_nFreq ? s_freqs[i] : 0.0f; }

// Sweep the whole list once -> out[i] = live RSSI dBm (or -200). out >= freqCount().
inline void sweepRssi(float *out){
  for(uint8_t i=0;i<s_nFreq;i++){
    float rssi=-200;
    if(lock()){
      s_radio->standby();
      if(s_radio->setFrequency(s_freqs[i])==RADIOLIB_ERR_NONE && s_radio->receiveDirect()==RADIOLIB_ERR_NONE){
        delayMicroseconds(TR_CC1101_SETTLE_US); rssi=s_radio->getRSSI();
      }
      unlock();
    }
    out[i]=rssi; s_lastRssi[i]=rssi;
  }
  if(lock()){ s_radio->standby(); unlock(); }
}

// Park on one frequency and read its RSSI (radar homing).
inline float rssiAt(float mhz){
  float rssi=-200;
  if(lock()){
    s_radio->standby();
    if(s_radio->setFrequency(mhz)==RADIOLIB_ERR_NONE && s_radio->receiveDirect()==RADIOLIB_ERR_NONE){
      delayMicroseconds(TR_CC1101_SETTLE_US); rssi=s_radio->getRSSI();
    }
    unlock();
  }
  return rssi;
}

} // namespace cc
