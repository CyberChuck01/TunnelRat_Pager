// ===========================================================================
//  tr_platform.h — Tunnel R.A.T. // T-Pager — board glue shared by the sketch
//  Device: LILYGO T-LoRa Pager
//
//  Lives in a .h on purpose: the Arduino IDE auto-generates prototypes for
//  every function in the .ino and mangles templates / types declared later
//  in the file. Headers are left alone.
// ===========================================================================
#pragma once
#include <LilyGoLib.h>
#include "freertos/FreeRTOS.h"

// LilyGoLib's display mutex doubles as the shared-SPI lock (display, SD, LoRa,
// NFC and the nRF24 all sit on SCK35/MOSI34/MISO33). Detected at compile time
// so an older LilyGoLib without lockSPI() still builds.
template<typename T> auto tr_lock_impl(T &t, int) -> decltype(t.lockSPI(TickType_t(0)), bool()) {
  return t.lockSPI(pdMS_TO_TICKS(250));
}
template<typename T> bool tr_lock_impl(T &, long) { return true; }
template<typename T> auto tr_unlock_impl(T &t, int) -> decltype(t.unlockSPI(), void()) { t.unlockSPI(); }
template<typename T> void tr_unlock_impl(T &, long) {}

// XL9555 expander write (the header pin labelled "CE" = XL9555 IO9).
template<typename T> auto tr_exp_write_impl(T &t, uint8_t pin, uint8_t v, int)
    -> decltype(t.io.digitalWrite(pin, v), void()) { t.io.digitalWrite(pin, v); }
template<typename T> void tr_exp_write_impl(T &, uint8_t, uint8_t, long) {}

inline bool tr_spi_lock()   { return tr_lock_impl(instance, 0); }
inline void tr_spi_unlock() { tr_unlock_impl(instance, 0); }
inline void tr_expander_write(uint8_t pin, uint8_t v) { tr_exp_write_impl(instance, pin, v, 0); }

// GPS object type (works with both the old TinyGPSPlus-derived GPS class and
// the newer LilyGoLib GPS class).
using TrGps = decltype(instance.gps);

// One GPS/time snapshot, stamped on every sensor record.
struct GpsSnap {
  bool valid = false, alt_valid = false, utc_valid = false, hdop_valid = false;
  double lat = 0, lon = 0, alt = 0, hdop = 0;
  char utc[25] = "";
};

inline void gps_snapshot(GpsSnap &o) {
  if (!g_gpsOn) {                 // GPS logging disabled: never stamp a location
    o.valid = o.alt_valid = o.hdop_valid = o.utc_valid = false;
    o.utc[0] = 0;
    return;
  }
  auto &gps = instance.gps;
  o.valid = gps.location.isValid() && gps.location.age() < 5000;
  o.alt_valid = o.valid && gps.altitude.isValid() && gps.altitude.age() < 5000;
  o.hdop_valid = o.valid && gps.hdop.isValid() && gps.hdop.age() < 5000;
  if (o.valid) { o.lat = gps.location.lat(); o.lon = gps.location.lng(); }
  if (o.alt_valid) o.alt = gps.altitude.meters();
  if (o.hdop_valid) o.hdop = gps.hdop.hdop();
  o.utc_valid = gps.date.isValid() && gps.time.isValid() && gps.date.age() < 5000 &&
                gps.time.age() < 5000 && gps.date.year() >= 2020;
  if (o.utc_valid)
    snprintf(o.utc, sizeof(o.utc), "%04d-%02d-%02dT%02d:%02d:%02dZ", gps.date.year(), gps.date.month(),
             gps.date.day(), gps.time.hour(), gps.time.minute(), gps.time.second());
  else o.utc[0] = 0;
}
