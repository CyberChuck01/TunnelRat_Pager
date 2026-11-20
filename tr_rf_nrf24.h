// ===========================================================================
//  tr_rf_nrf24.h  —  Tunnel R.A.T. // T-Pager  —  nRF24 scan + radar (standalone)
//
//  Needs an nRF24 (HW-237) on the header slot. Receive-only.
//   SCAN  : live 2.4 GHz RPD activity spectrum across channels 2..84.
//   HUNT  : locks the strongest active channel and switches to RADAR.
//   RADAR : homes on the locked channel's activity (nRF24 has no true RSSI,
//           so the blip tracks carrier-detect density: busier = nearer center).
//
//  Uses the existing nrf:: backend (tr_nrf24.h) + its sweepRaw()/rpdOn() helpers.
//  All RPD reads are SPI-locked inside nrf::, so they never fight the display.
// ===========================================================================
#pragma once
#include "config.h"
#include <lvgl.h>
#include <math.h>
#include "tr_nrf24.h"
#include "tr_radar.h"

namespace nrfscan {

#if TR_NRF24_ENABLE
static const int   CH_LO = TR_NRF24_CH_MIN;         // 2
static const int   CH_HI = TR_NRF24_CH_MAX;         // 84
static const int   NBINS = (CH_HI - CH_LO + 2) / 2; // 2 channels per bar

static lv_obj_t *s_sView=nullptr, *s_rView=nullptr;
static lv_obj_t *s_bar[64]={nullptr};
static lv_obj_t *s_scanStat=nullptr, *s_blip=nullptr, *s_lockLbl=nullptr, *s_actLbl=nullptr;
static bool  s_radar=false;
static int   s_lockCh=CH_LO, s_strongCh=CH_LO;
static float s_acc[126]={0};        // per-channel EMA activity 0..1 (scan)
static float s_radAct=0;            // locked-channel activity EMA 0..1 (radar)
static float s_angle=0;
static uint32_t s_lastScan=0, s_lastRad=0;

static void showRadar(bool on){
  s_radar=on;
  if(s_sView){ if(on) lv_obj_add_flag(s_sView,LV_OBJ_FLAG_HIDDEN); else lv_obj_clear_flag(s_sView,LV_OBJ_FLAG_HIDDEN); }
  if(s_rView){ if(on) lv_obj_clear_flag(s_rView,LV_OBJ_FLAG_HIDDEN); else lv_obj_add_flag(s_rView,LV_OBJ_FLAG_HIDDEN); }
}

static void hunt(){
  s_lockCh=s_strongCh; s_radAct=0;
  if(s_lockLbl) lv_label_set_text_fmt(s_lockLbl,"ch %d\n%d MHz",s_lockCh,2400+s_lockCh);
  showRadar(true);
}

// ---- UI --------------------------------------------------------------------
inline void buildUI(lv_obj_t *parent){
  if(!nrf::present() && !nrf::probe()){
    lv_obj_t*l=lv_label_create(parent);
    lv_label_set_long_mode(l,LV_LABEL_LONG_WRAP); lv_obj_set_width(l,lv_pct(96));
    lv_label_set_text(l,"No nRF24 detected.\nAttach an nRF24 (HW-237) to the header slot, then re-open.");
    lv_obj_set_style_text_color(l,lv_color_hex(0xFF5252),0);
    return;
  }
  nrf::start();
  for(int i=0;i<126;i++) s_acc[i]=0;

  // ---- SCAN view ----
  s_sView=lv_obj_create(parent);
  lv_obj_remove_style_all(s_sView);
  lv_obj_set_size(s_sView,lv_pct(100),lv_pct(100));
  lv_obj_set_style_bg_opa(s_sView,LV_OPA_TRANSP,0);

  lv_obj_t*t=lv_label_create(s_sView);
  lv_label_set_text(t,"nRF24  2.4 GHz  scanning"); lv_obj_align(t,LV_ALIGN_TOP_LEFT,0,0);
  lv_obj_set_style_text_color(t,lv_color_hex(TR_THEME_GREEN),0);

  s_scanStat=lv_label_create(s_sView);
  lv_obj_set_style_text_color(s_scanStat,lv_color_hex(0x8B949E),0);
  lv_obj_align(s_scanStat,LV_ALIGN_TOP_RIGHT,0,0);
  lv_label_set_text(s_scanStat,"...");

  lv_obj_t*b=lv_button_create(s_sView); lv_obj_set_size(b,110,30);
  lv_obj_align(b,LV_ALIGN_TOP_MID,0,20); lv_obj_set_style_bg_color(b,lv_color_hex(0x1C6B34),0);
  lv_obj_t*bl=lv_label_create(b); lv_label_set_text(bl,LV_SYMBOL_GPS " HUNT"); lv_obj_center(bl);
  lv_obj_add_event_cb(b,[](lv_event_t*){ hunt(); },LV_EVENT_CLICKED,nullptr);

  lv_obj_t*box=lv_obj_create(s_sView);
  lv_obj_remove_style_all(box);
  lv_obj_set_size(box,lv_pct(100),lv_pct(55));
  lv_obj_align(box,LV_ALIGN_BOTTOM_MID,0,0);
  lv_obj_set_flex_flow(box,LV_FLEX_FLOW_ROW);
  lv_obj_set_flex_align(box,LV_FLEX_ALIGN_SPACE_EVENLY,LV_FLEX_ALIGN_END,LV_FLEX_ALIGN_END);
  lv_obj_set_style_bg_color(box,lv_color_hex(0x0E120E),0);
  lv_obj_set_style_bg_opa(box,LV_OPA_COVER,0);
  for(int i=0;i<NBINS && i<64;i++){
    lv_obj_t*bar=lv_obj_create(box);
    lv_obj_remove_style_all(bar);
    lv_obj_set_width(bar,7); lv_obj_set_height(bar,2);
    lv_obj_set_style_bg_color(bar,lv_color_hex(TR_THEME_GREEN),0);
    lv_obj_set_style_bg_opa(bar,LV_OPA_COVER,0);
    s_bar[i]=bar;
  }

  // ---- RADAR view (hidden until HUNT) ----
  s_rView=lv_obj_create(parent);
  lv_obj_remove_style_all(s_rView);
  lv_obj_set_size(s_rView,lv_pct(100),lv_pct(100));
  lv_obj_set_style_bg_opa(s_rView,LV_OPA_TRANSP,0);
  lv_obj_add_flag(s_rView,LV_OBJ_FLAG_HIDDEN);

  radarui::build(s_rView);
  s_lockLbl=lv_label_create(s_rView);
  lv_obj_set_style_text_color(s_lockLbl,lv_color_hex(TR_THEME_GREEN),0);
  lv_obj_align(s_lockLbl,LV_ALIGN_TOP_LEFT,4,2);
  lv_label_set_text_fmt(s_lockLbl,"ch %d / %d MHz",s_lockCh,2400+s_lockCh);

  lv_obj_t*sb=lv_button_create(s_rView); lv_obj_set_size(sb,110,30);
  lv_obj_align(sb,LV_ALIGN_BOTTOM_RIGHT,-6,-6); lv_obj_set_style_bg_color(sb,lv_color_hex(0x173017),0);
  lv_obj_t*sl=lv_label_create(sb); lv_label_set_text(sl,LV_SYMBOL_LEFT " SCAN"); lv_obj_center(sl);
  lv_obj_add_event_cb(sb,[](lv_event_t*){ showRadar(false); },LV_EVENT_CLICKED,nullptr);

  showRadar(false);
}

inline void loop(){
  if(!nrf::present()) return;
  uint32_t now=millis();

  if(!s_radar){
    if(now-s_lastScan < 120) return; s_lastScan=now;
    uint8_t raw[126]; nrf::sweepRaw(raw);
    float best=0; int bestCh=CH_LO;
    for(int c=0;c<126;c++){
      s_acc[c]=s_acc[c]*0.6f + (raw[c]?1.0f:0.0f)*0.4f;
      if(c>=CH_LO && c<=CH_HI && s_acc[c]>best){ best=s_acc[c]; bestCh=c; }
    }
    s_strongCh=bestCh;
    for(int i=0;i<NBINS && i<64;i++){
      int c0=CH_LO+2*i; float v=s_acc[c0]; if(c0+1<=CH_HI && s_acc[c0+1]>v) v=s_acc[c0+1];
      int h=2+(int)(v*100.0f); if(h>100)h=100;
      if(s_bar[i]) lv_obj_set_height(s_bar[i],h);
    }
    if(s_scanStat) lv_label_set_text_fmt(s_scanStat,"peak ch%d  %d%%",s_strongCh,(int)(best*100));
    return;
  }

  // radar
  if(now-s_lastRad < 100) return; s_lastRad=now;
  uint16_t hits=nrf::rpdOn((uint8_t)s_lockCh,64);
  float ratio=hits/64.0f; if(ratio>1)ratio=1;
  s_radAct=s_radAct*0.5f + ratio*0.5f;
  char buf[16]; snprintf(buf,sizeof buf,"%d%%",(int)(s_radAct*100));
  radarui::update(s_radAct, buf);
}

inline void leave(){
  nrf::stop();
  radarui::reset();
  s_sView=s_rView=s_blip=s_scanStat=s_lockLbl=s_actLbl=nullptr;
  for(int i=0;i<64;i++) s_bar[i]=nullptr;
  s_radar=false;
}

#else  // nRF24 disabled at compile time
inline void buildUI(lv_obj_t *parent){
  lv_obj_t*l=lv_label_create(parent);
  lv_label_set_text(l,"nRF24 support is off (set TR_NRF24_ENABLE 1).");
}
inline void loop(){}
inline void leave(){}
#endif

} // namespace nrfscan
