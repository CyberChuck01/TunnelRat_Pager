// ===========================================================================
//  tr_nfc.h  —  Tunnel R.A.T. // T-Pager  —  NFC wardrive sensor
//  Device: LILYGO T-LoRa Pager (built-in ST25R3916 reader)
//
//  Uses LilyGoLib's LilyGoNfcService (reader mode). One record per tag tap:
//  UID, technology, tag/card type, whether it carries NDEF and which KINDS of
//  NDEF records (text/URI/wifi/...). Record CONTENTS are never logged — no
//  Wi-Fi passwords, no URLs, no payment-card data (no APDUs are sent beyond
//  the library's standard NDEF detection).
//
//  NFC range is a few centimetres: this logs tags you tap, not tags you
//  drive past.
//
//  Needs a LilyGoLib new enough to ship nfc/LilyGoNfcService.h. With an older
//  LilyGoLib this compiles to stubs and the NFC checkbox shows "needs
//  newer LilyGoLib".
// ===========================================================================
#pragma once
#include <LilyGoLib.h>
#include "config.h"

#if TR_NFC_ENABLE && defined(USING_ST25R3916) && __has_include("nfc/LilyGoNfcService.h")
#include "nfc/LilyGoNfcService.h"
#define TR_NFC_AVAILABLE 1
#else
#define TR_NFC_AVAILABLE 0
#endif

namespace trnfc {

struct Tag {
  char uid[49];          // "04:A2:..." as reported by the library
  char tech[16];         // NFC-A / NFC-B / NFC-F / NFC-V ...
  char tagType[12];      // T2T / T4T / ...
  char cardType[32];     // e.g. "NTAG215", "MIFARE Classic 1K"
  bool hasNdef;
  uint8_t records;       // number of NDEF records
  char recordKinds[64];  // "uri|text" — kinds only, never contents
};
typedef void (*TagFn)(const Tag &);

#if TR_NFC_AVAILABLE

static TagFn s_cb = nullptr;
static bool  s_running = false, s_pending = false;
static Tag   s_tag;
static uint32_t s_tags = 0;

static void copyStr(char *dst, size_t cap, const char *src) {
  if (!cap) return;
  size_t i = 0;
  for (; src && src[i] && i + 1 < cap; i++) dst[i] = (src[i] == ',' || src[i] == '"' || src[i] < 0x20) ? ' ' : src[i];
  dst[i] = 0;
}

static void fillBase(const LilyGoNfcReaderResult &r) {
  copyStr(s_tag.uid, sizeof s_tag.uid, r.uidText);
  copyStr(s_tag.tech, sizeof s_tag.tech, r.technology);
  copyStr(s_tag.tagType, sizeof s_tag.tagType, r.tagType);
  copyStr(s_tag.cardType, sizeof s_tag.cardType, r.cardType);
  s_tag.hasNdef = false; s_tag.records = 0; s_tag.recordKinds[0] = 0;
}

static void fillNdef(const LilyGoNfcReaderResult &r) {
  s_tag.hasNdef = r.hasNdef;
  s_tag.records = r.recordCount;
  size_t p = 0; s_tag.recordKinds[0] = 0;
  for (uint8_t i = 0; i < r.recordCount && i < LILYGO_NFC_MAX_RECORDS; i++) {
    const char *k = lilygoNfcRecordKindName(r.records[i].kind);
    int n = snprintf(s_tag.recordKinds + p, sizeof(s_tag.recordKinds) - p, "%s%s", p ? "|" : "", k ? k : "?");
    if (n < 0 || p + (size_t)n >= sizeof(s_tag.recordKinds)) break;
    p += (size_t)n;
  }
}

static void emit() {
  s_pending = false;
  if (!s_tag.uid[0]) return;
  s_tags++;
  if (s_cb) s_cb(s_tag);
}

// Called from LilyGoNfc.loop() -> always on the Arduino loop task.
static void onEvent(LilyGoNfcEvent e, const LilyGoNfcReaderResult &r, void *) {
  switch (e) {
    case LILYGO_NFC_EVENT_CARD_DETECTED:
      fillBase(r); s_pending = true; break;
    case LILYGO_NFC_EVENT_NDEF_READ:
    case LILYGO_NFC_EVENT_NDEF_UNSUPPORTED:
    case LILYGO_NFC_EVENT_NDEF_ERROR:
      if (s_pending) { if (!s_tag.uid[0]) fillBase(r); fillNdef(r); emit(); }
      break;
    case LILYGO_NFC_EVENT_CARD_RELEASED:
      if (s_pending) emit();
      break;
    default: break;
  }
}

inline bool available() { return true; }
inline bool running()   { return s_running; }
inline uint32_t tags()  { return s_tags; }

inline bool start(TagFn cb) {
  s_cb = cb;
  if (s_running) return true;
  instance.powerControl(POWER_NFC, true);
  s_pending = false;
  s_running = LilyGoNfc.beginReader(onEvent, nullptr);
  if (!s_running) instance.powerControl(POWER_NFC, false);
  return s_running;
}
inline void stop() {
  if (s_running) { LilyGoNfc.stop(); instance.powerControl(POWER_NFC, false); }
  s_running = false; s_pending = false;
}
inline void tick() { if (s_running) LilyGoNfc.loop(); }

#else   // ---- stubs: NFC disabled or LilyGoLib too old ----------------------

inline bool available() { return false; }
inline bool running()   { return false; }
inline uint32_t tags()  { return 0; }
inline bool start(TagFn) { return false; }
inline void stop() {}
inline void tick() {}

#endif

} // namespace trnfc
