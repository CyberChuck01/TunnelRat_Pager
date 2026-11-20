// ===========================================================================
//  tr_rf_cc1101.h  —  Tunnel R.A.T. // T-Pager  —  CC1101 sub-GHz scan + radar
//
//  Needs a CC1101 on the header slot. Receive-only. CC1101 reports real dBm,
//  so the radar gives smooth hot/cold homing — the sub-GHz fox-hunt.
//    SCAN  : sweeps the frequency list (config TR_CC1101_FREQS) reading live
//            RSSI on each; lists freq + dBm, peak called out.
//    HUNT  : tap a frequency (touch) or "Hunt loudest" (wheel) to lock it.
//    RADAR : homes on the locked frequency's RSSI (full-screen pulse radar).
// ===========================================================================
#pragma once
#include "config.h"
#include <lvgl.h>
#include <stdio.h>
#include "tr_cc1101.h"
#include "tr_radar.h"

namespace ccradar {

static lv_obj_t *s_sView=nullptr, *s_rView=nullptr, *s_list=nullptr, *s_scanStat=nullptr, *s_lockLbl=nullptr;
static bool  s_radar=false;
static float s_rssi[16];
static int   s_strong=0;
static float s_lockFreq=433.92f, s_rssiEma=-120.0f;
static uint32_t s_lastScan=0, s_lastRad=0;

static void showRadar(bool on);
static void lockIdx(int i);

// format a MHz value without %f (avoids float-printf dependence)
static void fmtMHz(char *b,int n,float f){
  int w=(int)f; int fr=(int)((f-(float)w)*100.0f+0.5f);
  if(fr>=100){ w++; fr-=100; }
  snprintf(b,n,"%d.%02d",w,fr);
}

static void lockIdx(int i){
  if(i<0||i>=(int)cc::freqCount()) return;
  s_lockFreq=cc::freqMHz(i); s_rssiEma=-120.0f;
  if(s_lockLbl){ char m[12]; fmtMHz(m,sizeof m,s_lockFreq); lv_label_set_text_fmt(s_lockLbl,"%s MHz",m); }
  showRadar(true);
}
static void huntStrongest(){ lockIdx(s_strong); }

static void rebuildList(){
  if(!s_list) return;
  lv_obj_clean(s_list);
  for(int i=0;i<(int)cc::freqCount();i++){
    char m[12]; fmtMHz(m,sizeof m,cc::freqMHz(i));
    char row[48]; snprintf(row,sizeof row,"%s MHz    %d dBm",m,(int)s_rssi[i]);
    lv_obj_t *btn=lv_list_add_button(s_list,NULL,row);
    lv_obj_set_style_bg_color(btn,lv_color_hex(0x0E120E),0);
    lv_obj_set_style_text_color(btn,lv_color_hex(TR_THEME_GREEN),0);
    lv_obj_add_event_cb(btn,[](lv_event_t*e){ lockIdx((int)(intptr_t)lv_event_get_user_data(e)); },
                        LV_EVENT_CLICKED,(void*)(intptr_t)i);
  }
}

static void showRadar(bool on){
  s_radar=on;
  if(s_sView){ if(on) lv_obj_add_flag(s_sView,LV_OBJ_FLAG_HIDDEN); else lv_obj_clear_flag(s_sView,LV_OBJ_FLAG_HIDDEN); }
  if(s_rView){ if(on) lv_obj_clear_flag(s_rView,LV_OBJ_FLAG_HIDDEN); else lv_obj_add_flag(s_rView,LV_OBJ_FLAG_HIDDEN); }
}

inline void buildUI(lv_obj_t *parent){
  if(!cc::present() && !cc::probe()){
    lv_obj_t*l=lv_label_create(parent);
    lv_label_set_long_mode(l,LV_LABEL_LONG_WRAP); lv_obj_set_width(l,lv_pct(96));
    lv_label_set_text(l,"No CC1101 detected.\nAttach a CC1101 to the header slot (GDO0 to GPIO9), then re-open.");
    lv_obj_set_style_text_color(l,lv_color_hex(0xFF5252),0);
    return;
  }
  cc::start();
  for(int i=0;i<16;i++) s_rssi[i]=-120.0f;

  // SCAN view
  s_sView=lv_obj_create(parent); lv_obj_remove_style_all(s_sView);
  lv_obj_set_size(s_sView,lv_pct(100),lv_pct(100)); lv_obj_set_style_bg_opa(s_sView,LV_OPA_TRANSP,0);

  lv_obj_t *t=lv_label_create(s_sView); lv_label_set_text(t,"CC1101  sub-GHz scanning");
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
  s_lockLbl=lv_label_create(s_rView);
  lv_obj_set_style_text_color(s_lockLbl,lv_color_hex(TR_THEME_GREEN),0);
  lv_obj_align(s_lockLbl,LV_ALIGN_TOP_LEFT,4,2); lv_label_set_text(s_lockLbl,"(locked freq)");

  lv_obj_t *sb=lv_button_create(s_rView); lv_obj_set_size(sb,110,28);
  lv_obj_align(sb,LV_ALIGN_BOTTOM_RIGHT,-6,-6); lv_obj_set_style_bg_color(sb,lv_color_hex(0x173017),0);
  lv_obj_t *sl=lv_label_create(sb); lv_label_set_text(sl,LV_SYMBOL_LEFT " SCAN"); lv_obj_center(sl);
  lv_obj_add_event_cb(sb,[](lv_event_t*){ showRadar(false); },LV_EVENT_CLICKED,nullptr);

  showRadar(false);
}

inline void loop(){
  if(!cc::present()) return;
  uint32_t now=millis();
  if(!s_radar){
    if(now-s_lastScan<400) return; s_lastScan=now;
    cc::sweepRssi(s_rssi);
    float best=-999; int bi=0;
    for(int i=0;i<(int)cc::freqCount();i++) if(s_rssi[i]>best){ best=s_rssi[i]; bi=i; }
    s_strong=bi; rebuildList();
    if(s_scanStat){ char m[12]; fmtMHz(m,sizeof m,cc::freqMHz(bi)); lv_label_set_text_fmt(s_scanStat,"peak %s  %ddBm",m,(int)best); }
    return;
  }
  if(now-s_lastRad<120) return; s_lastRad=now;
  float dbm=cc::rssiAt(s_lockFreq);
  s_rssiEma = (s_rssiEma<=-120.0f)? dbm : s_rssiEma*0.6f + dbm*0.4f;
  float ratio=(s_rssiEma+110.0f)/80.0f; if(ratio<0)ratio=0; if(ratio>1)ratio=1;  // ~-110..-30 dBm
  char buf[16]; snprintf(buf,sizeof buf,"%d dBm",(int)s_rssiEma);
  radarui::update(ratio, buf);
}

inline void leave(){
  cc::stop(); radarui::reset();
  s_sView=s_rView=s_list=s_scanStat=s_lockLbl=nullptr; s_radar=false;
}

} // namespace ccradar
