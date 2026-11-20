// ===========================================================================
//  tr_rf_wifibt.h  —  Tunnel R.A.T. // T-Pager  —  WiFi & BT scan + radar
//
//  Built-in radios, receive-only. Both bands report real dBm RSSI, so the
//  radar gives smooth hot/cold homing (blip tightens toward center as the
//  signal strengthens).
//    SCAN  : a selectable list of nearby APs / BLE devices with live RSSI.
//    HUNT  : tap a row (touch) or "Hunt loudest" (wheel) to lock a target.
//    RADAR : homes on the locked target.
//            WiFi  -> promiscuous sniff of the AP's channel (beacon RSSI).
//            BT    -> locked device's advertisement RSSI.
//
//  One implementation (rfwb::) parameterised by band; wifiradar:: / btradar::
//  are thin wrappers the launcher calls. Only one is ever active at a time.
// ===========================================================================
#pragma once
#include "config.h"
#include <lvgl.h>
#include <math.h>
#include <string.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <NimBLEDevice.h>
#include <string>
#include "tr_radar.h"

namespace rfwb {

enum Band { BAND_WIFI, BAND_BT };

struct Dev { char label[40]; char addr[18]; uint8_t mac[6]; uint8_t ch; int rssi; };

static Band s_band = BAND_WIFI;
static bool s_radar = false;
static lv_obj_t *s_sView=nullptr, *s_rView=nullptr, *s_list=nullptr, *s_scanStat=nullptr;
static lv_obj_t *s_blip=nullptr, *s_lockLbl=nullptr, *s_actLbl=nullptr;
static Dev  s_dev[32]; static int s_devN=0;
static uint8_t s_lockMac[6]={0}; static uint8_t s_lockCh=1; static char s_lockAddr[18]="";
static char s_lockLabel[40]="";
static volatile int s_rssiRaw=-100;          // latest RSSI of the locked target
static float s_rssiEma=-100, s_angle=0;
static uint32_t s_lastScan=0, s_lastList=0, s_lastRad=0;
static bool s_wifiScanRunning=false, s_btScanning=false;

// forward decls (used by lambdas / helpers before their definitions)
static void showRadar(bool on);
static void lockDevice(int i);

static float rssiRatio(float dbm){ float r=(dbm+90.0f)/60.0f; if(r<0)r=0; if(r>1)r=1; return r; }

// ---------- WiFi ------------------------------------------------------------
static void wifiSniff(void *buf, wifi_promiscuous_pkt_type_t type){
  const wifi_promiscuous_pkt_t *p=(const wifi_promiscuous_pkt_t*)buf;
  const uint8_t *a2=p->payload+10;           // transmitter addr (AP for beacons)
  for(int i=0;i<6;i++) if(a2[i]!=s_lockMac[i]) return;
  s_rssiRaw=p->rx_ctrl.rssi;
}
static void wifiHuntStart(){
  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(wifiSniff);
  esp_wifi_set_channel(s_lockCh, WIFI_SECOND_CHAN_NONE);
  esp_wifi_set_promiscuous(true);
}
static void wifiHuntStop(){ esp_wifi_set_promiscuous(false); }

static void wifiScanKick(){
  if(s_wifiScanRunning) return;
  WiFi.scanNetworks(true,true);              // async, include hidden
  s_wifiScanRunning=true;
}
static bool wifiScanPoll(){                  // true when a fresh result was loaded
  int n=WiFi.scanComplete();
  if(n<0) return false;
  s_devN=0;
  for(int i=0;i<n && s_devN<32;i++){
    Dev &d=s_dev[s_devN];
    const uint8_t *b=WiFi.BSSID(i); if(b) memcpy(d.mac,b,6); else memset(d.mac,0,6);
    d.ch=(uint8_t)WiFi.channel(i); d.rssi=WiFi.RSSI(i); d.addr[0]=0;
    String ss=WiFi.SSID(i);
    snprintf(d.label,sizeof d.label,"%-16.16s %ddBm c%u", ss.length()?ss.c_str():"(hidden)", d.rssi, d.ch);
    s_devN++;
  }
  WiFi.scanDelete();
  s_wifiScanRunning=false;
  return true;
}

// ---------- BT (BLE) --------------------------------------------------------
class BtCB : public NimBLEScanCallbacks {
  void onResult(const NimBLEAdvertisedDevice *d) override {
    char as[18]; { std::string s=d->getAddress().toString(); strncpy(as,s.c_str(),17); as[17]=0; }
    int rssi=d->getRSSI();
    if(s_radar){ if(strcmp(as,s_lockAddr)==0) s_rssiRaw=rssi; return; }
    for(int i=0;i<s_devN;i++) if(strcmp(s_dev[i].addr,as)==0){ s_dev[i].rssi=rssi; return; }
    if(s_devN<32){
      Dev &dv=s_dev[s_devN]; strncpy(dv.addr,as,17); dv.addr[17]=0; dv.rssi=rssi;
      memset(dv.mac,0,6); dv.ch=0;
      snprintf(dv.label,sizeof dv.label,"%-13.13s %ddBm %s",
               d->haveName()? d->getName().c_str():"(no name)", rssi, as);
      s_devN++;
    }
  }
};
static BtCB s_btcb;
static NimBLEScan *s_scan=nullptr;

static void btScanStart(){
  NimBLEDevice::init("TR");                   // no-op if already initialised
  s_scan=NimBLEDevice::getScan();
  s_scan->setScanCallbacks(&s_btcb,false);
  s_scan->setActiveScan(true); s_scan->setInterval(100); s_scan->setWindow(90);
  s_scan->start(0,false);
  s_btScanning=true;
}
static void btScanStop(){ if(s_scan && s_scan->isScanning()) s_scan->stop(); s_btScanning=false; }

// ---------- target selection ------------------------------------------------
static void lockDevice(int i){
  if(i<0||i>=s_devN) return;
  memcpy(s_lockMac,s_dev[i].mac,6); s_lockCh=s_dev[i].ch;
  strncpy(s_lockAddr,s_dev[i].addr,17); s_lockAddr[17]=0;
  strncpy(s_lockLabel,s_dev[i].label,sizeof s_lockLabel-1); s_lockLabel[sizeof s_lockLabel-1]=0;
  s_rssiRaw=-100; s_rssiEma=-100;
  if(s_band==BAND_WIFI) wifiHuntStart();       // BT keeps scanning; cb filters the lock
  if(s_lockLbl) lv_label_set_text(s_lockLbl,s_lockLabel);
  showRadar(true);
}
static void huntStrongest(){
  int best=-1000, bi=-1;
  for(int i=0;i<s_devN;i++) if(s_dev[i].rssi>best){ best=s_dev[i].rssi; bi=i; }
  if(bi>=0) lockDevice(bi);
}

static void rebuildList(){
  if(!s_list) return;
  lv_obj_clean(s_list);
  for(int i=0;i<s_devN;i++){
    lv_obj_t *btn=lv_list_add_button(s_list,NULL,s_dev[i].label);
    lv_obj_set_style_bg_color(btn,lv_color_hex(0x0E120E),0);
    lv_obj_set_style_text_color(btn,lv_color_hex(TR_THEME_GREEN),0);
    lv_obj_add_event_cb(btn,[](lv_event_t*e){ lockDevice((int)(intptr_t)lv_event_get_user_data(e)); },
                        LV_EVENT_CLICKED,(void*)(intptr_t)i);
  }
}

static void showRadar(bool on){
  s_radar=on;
  if(s_sView){ if(on) lv_obj_add_flag(s_sView,LV_OBJ_FLAG_HIDDEN); else lv_obj_clear_flag(s_sView,LV_OBJ_FLAG_HIDDEN); }
  if(s_rView){ if(on) lv_obj_clear_flag(s_rView,LV_OBJ_FLAG_HIDDEN); else lv_obj_add_flag(s_rView,LV_OBJ_FLAG_HIDDEN); }
  if(!on && s_band==BAND_WIFI){ wifiHuntStop(); s_lastScan=0; }   // re-scan on return
}

// ---------- UI --------------------------------------------------------------
static void buildImpl(lv_obj_t *parent, Band band){
  s_band=band; s_devN=0; s_radar=false; s_rssiRaw=-100; s_rssiEma=-100;
  const char *title = (band==BAND_WIFI)? "WiFi  scanning" : "BT  scanning";

  if(band==BAND_WIFI){ WiFi.mode(WIFI_STA); WiFi.disconnect(false); wifiScanKick(); }
  else              { btScanStart(); }

  // SCAN view
  s_sView=lv_obj_create(parent); lv_obj_remove_style_all(s_sView);
  lv_obj_set_size(s_sView,lv_pct(100),lv_pct(100)); lv_obj_set_style_bg_opa(s_sView,LV_OPA_TRANSP,0);

  lv_obj_t *t=lv_label_create(s_sView); lv_label_set_text(t,title);
  lv_obj_align(t,LV_ALIGN_TOP_LEFT,0,0); lv_obj_set_style_text_color(t,lv_color_hex(TR_THEME_GREEN),0);

  s_scanStat=lv_label_create(s_sView);
  lv_obj_set_style_text_color(s_scanStat,lv_color_hex(0x8B949E),0);
  lv_obj_align(s_scanStat,LV_ALIGN_TOP_RIGHT,0,0); lv_label_set_text(s_scanStat,"...");

  lv_obj_t *hb=lv_button_create(s_sView); lv_obj_set_size(hb,130,28);
  lv_obj_align(hb,LV_ALIGN_TOP_MID,0,18); lv_obj_set_style_bg_color(hb,lv_color_hex(0x1C6B34),0);
  lv_obj_t *hl=lv_label_create(hb); lv_label_set_text(hl,LV_SYMBOL_GPS " Hunt loudest"); lv_obj_center(hl);
  lv_obj_add_event_cb(hb,[](lv_event_t*){ huntStrongest(); },LV_EVENT_CLICKED,nullptr);

  s_list=lv_list_create(s_sView);
  lv_obj_set_size(s_list,lv_pct(100),lv_pct(60)); lv_obj_align(s_list,LV_ALIGN_BOTTOM_MID,0,0);
  lv_obj_set_style_bg_color(s_list,lv_color_hex(0x0E120E),0);

  // RADAR view (hidden until a lock)
  s_rView=lv_obj_create(parent); lv_obj_remove_style_all(s_rView);
  lv_obj_set_size(s_rView,lv_pct(100),lv_pct(100)); lv_obj_set_style_bg_opa(s_rView,LV_OPA_TRANSP,0);
  lv_obj_add_flag(s_rView,LV_OBJ_FLAG_HIDDEN);

  radarui::build(s_rView);
  s_lockLbl=lv_label_create(s_rView); lv_obj_set_style_text_color(s_lockLbl,lv_color_hex(TR_THEME_GREEN),0);
  lv_label_set_long_mode(s_lockLbl,LV_LABEL_LONG_WRAP); lv_obj_set_width(s_lockLbl,180);
  lv_obj_align(s_lockLbl,LV_ALIGN_TOP_LEFT,4,2); lv_label_set_text(s_lockLbl,"(locked target)");

  lv_obj_t *sb=lv_button_create(s_rView); lv_obj_set_size(sb,110,28);
  lv_obj_align(sb,LV_ALIGN_BOTTOM_RIGHT,-6,-6); lv_obj_set_style_bg_color(sb,lv_color_hex(0x173017),0);
  lv_obj_t *sl=lv_label_create(sb); lv_label_set_text(sl,LV_SYMBOL_LEFT " SCAN"); lv_obj_center(sl);
  lv_obj_add_event_cb(sb,[](lv_event_t*){ showRadar(false); },LV_EVENT_CLICKED,nullptr);

  showRadar(false);
}

static void loopImpl(){
  uint32_t now=millis();
  if(!s_radar){
    if(s_band==BAND_WIFI){
      if(wifiScanPoll()) rebuildList();
      if(!s_wifiScanRunning && now-s_lastScan>1500){ s_lastScan=now; wifiScanKick(); }
    } else {
      if(now-s_lastList>600){ s_lastList=now; rebuildList(); }
    }
    if(s_scanStat) lv_label_set_text_fmt(s_scanStat,"%d found",s_devN);
    return;
  }
  // radar
  if(now-s_lastRad<100) return; s_lastRad=now;
  float dbm=(float)s_rssiRaw;
  s_rssiEma = (s_rssiEma<=-100)? dbm : s_rssiEma*0.6f + dbm*0.4f;
  float ratio=rssiRatio(s_rssiEma);
  char buf[16]; snprintf(buf,sizeof buf,"%d dBm",(int)s_rssiEma);
  radarui::update(ratio, buf);
}

static void leaveImpl(){
  if(s_band==BAND_WIFI){ wifiHuntStop(); WiFi.scanDelete(); s_wifiScanRunning=false; }
  else                 { btScanStop(); }
  radarui::reset();
  s_sView=s_rView=s_list=s_scanStat=s_blip=s_lockLbl=s_actLbl=nullptr;
  s_radar=false; s_devN=0;
}

} // namespace rfwb

// ---- launcher-facing wrappers (one active at a time) -----------------------
namespace wifiradar {
  inline void buildUI(lv_obj_t *p){ rfwb::buildImpl(p, rfwb::BAND_WIFI); }
  inline void loop(){ rfwb::loopImpl(); }
  inline void leave(){ rfwb::leaveImpl(); }
}
namespace btradar {
  inline void buildUI(lv_obj_t *p){ rfwb::buildImpl(p, rfwb::BAND_BT); }
  inline void loop(){ rfwb::loopImpl(); }
  inline void leave(){ rfwb::leaveImpl(); }
}
