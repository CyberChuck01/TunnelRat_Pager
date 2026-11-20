// ===========================================================================
//  tr_radar.h  —  Tunnel R.A.T. // T-Pager  —  shared full-screen pulse radar
//
//  One radar widget used by every band (nRF24 / WiFi / BT). Instead of a blip
//  that scatters around, the signal drives a PULSE:
//    - sonar-style ping rings expand from the center; stronger signal = faster,
//      brighter pings.
//    - a center dot whose size + brightness track the signal (more intense dot
//      = more intense signal).
//  Fills the whole screen. Only one radar is live at a time, so the state is
//  shared/static here. The caller passes intensity 0..1 each tick + a readout.
// ===========================================================================
#pragma once
#include "config.h"
#include <lvgl.h>
#include <math.h>

// ===========================================================================
//  radaraudio  —  the "getting warmer" fox-hunt ping
//
//  A background task owns the I2S codec and does the BLOCKING writes on its own
//  core, so the radar UI loop never stalls. The UI only publishes a shared
//  intensity (0..1); the task turns that into pings whose PITCH and REPETITION
//  RATE both rise with signal strength (closer = higher + faster). It self-
//  gates on update-recency, so it's silent on the scan view and only pings
//  while the radar view is live.
//
//  Threading: all codec I2C (open / close / setVolume) happens on the MAIN
//  thread (start()/stop() are called from the LVGL context) so it can't race
//  the keypad/touch on the shared I2C bus. The task touches only I2S (write()).
// ===========================================================================
namespace radaraudio {

static const uint32_t SR=16000;                 // 16 kHz, mono, 16-bit
static const int      FRAME=160;                // 10 ms per write
static volatile float    s_inten=0.0f;
static volatile uint32_t s_lastUpd=0;
static volatile bool     s_run=false;
static TaskHandle_t      s_task=nullptr;

static void task(void*){
  float phase=0.0f; int pingPos=0; uint32_t sinceGap=0;
  static int16_t buf[FRAME];
  while(s_run){
    float inten=s_inten; if(inten<0)inten=0; if(inten>1)inten=1;
    bool active = g_radarAudioOn && (millis()-s_lastUpd < 250);   // radar view live?
    float gapSec = 0.52f - inten*0.45f; if(gapSec<0.05f) gapSec=0.05f; // faster when hot
    uint32_t gapSamp=(uint32_t)(gapSec*SR);
    int   pingLen=(int)(0.040f*SR);             // 40 ms ping
    int   fade   =(int)(0.006f*SR);             // 6 ms attack/decay
    float freq   = 560.0f + inten*1650.0f;      // higher pitch when hot
    float amp    = 0.35f + inten*0.55f;         // and louder
    for(int i=0;i<FRAME;i++){
      int16_t s=0;
      if(active && pingPos>0){
        int elapsed=pingLen-pingPos; float env=1.0f;
        if(elapsed<fade)      env=(float)elapsed/fade;    // attack
        else if(pingPos<fade) env=(float)pingPos/fade;    // decay
        s=(int16_t)(amp*env*30000.0f*sinf(phase));
        phase+=6.2831853f*freq/SR; if(phase>6.2831853f) phase-=6.2831853f;
        pingPos--;
      } else if(active){
        if(++sinceGap>=gapSamp){ sinceGap=0; pingPos=pingLen; phase=0.0f; }
      } else { sinceGap=0; pingPos=0; }
      buf[i]=s;
    }
    instance.codec.write((uint8_t*)buf,sizeof buf);        // I2S only, blocks ~10 ms here
  }
  s_task=nullptr;
  vTaskDelete(nullptr);
}

inline void start(){
  if(s_task || !g_radarAudioOn) return;
  if(instance.codec.open(16,1,SR)!=0) return;
  instance.codec.setVolume(82);
  s_run=true; s_inten=0.0f; s_lastUpd=0;
  if(xTaskCreatePinnedToCore(task,"radarping",4096,nullptr,2,&s_task,0)!=pdPASS){
    s_run=false; s_task=nullptr; instance.codec.close();
  }
}
inline void stop(){
  if(!s_task) return;
  s_run=false;
  for(int i=0;i<40 && s_task;i++) delay(5);    // let the task finish its current frame
  instance.codec.close();
}
inline void setIntensity(float v){ s_inten=v; s_lastUpd=millis(); }

} // namespace radaraudio

namespace radarui {

static lv_obj_t *s_cont=nullptr, *s_ping[3]={nullptr,nullptr,nullptr}, *s_dot=nullptr, *s_read=nullptr;
static float s_phase[3]={0.0f,0.34f,0.67f};
static float s_dotPhase=0.0f;
static const int S_MAXR=95;                 // max ping radius (fills the ~198px height)

inline void build(lv_obj_t *parent){
  s_cont=lv_obj_create(parent); lv_obj_remove_style_all(s_cont);
  lv_obj_set_size(s_cont,lv_pct(100),lv_pct(100));
  lv_obj_set_style_bg_opa(s_cont,LV_OPA_TRANSP,0);
  lv_obj_clear_flag(s_cont,LV_OBJ_FLAG_SCROLLABLE);

  // dim static backdrop rings
  const int rings[4]={60,110,160,190};
  for(int i=0;i<4;i++){
    lv_obj_t *r=lv_obj_create(s_cont); lv_obj_remove_style_all(r);
    lv_obj_set_size(r,rings[i],rings[i]); lv_obj_center(r);
    lv_obj_set_style_radius(r,LV_RADIUS_CIRCLE,0);
    lv_obj_set_style_border_color(r,lv_color_hex(0x2A2A2A),0);
    lv_obj_set_style_border_width(r,1,0);
    lv_obj_set_style_bg_opa(r,LV_OPA_TRANSP,0);
  }
  // expanding ping rings (the pulse)
  for(int i=0;i<3;i++){
    lv_obj_t *p=lv_obj_create(s_cont); lv_obj_remove_style_all(p);
    lv_obj_set_size(p,2,2); lv_obj_center(p);
    lv_obj_set_style_radius(p,LV_RADIUS_CIRCLE,0);
    lv_obj_set_style_border_color(p,lv_color_hex(TR_THEME_GREEN),0);
    lv_obj_set_style_border_width(p,2,0);
    lv_obj_set_style_border_opa(p,0,0);
    lv_obj_set_style_bg_opa(p,LV_OPA_TRANSP,0);
    s_ping[i]=p;
  }
  // center dot (intensity = signal)
  s_dot=lv_obj_create(s_cont); lv_obj_remove_style_all(s_dot);
  lv_obj_set_size(s_dot,10,10); lv_obj_center(s_dot);
  lv_obj_set_style_radius(s_dot,LV_RADIUS_CIRCLE,0);
  lv_obj_set_style_bg_color(s_dot,lv_color_hex(TR_THEME_GREEN),0);
  lv_obj_set_style_bg_opa(s_dot,80,0);

  // big readout, top-center
  s_read=lv_label_create(s_cont);
  lv_obj_set_style_text_color(s_read,lv_color_hex(TR_THEME_GREEN),0);
  lv_obj_align(s_read,LV_ALIGN_TOP_MID,0,2);
  lv_label_set_text(s_read,"--");

  s_phase[0]=0.0f; s_phase[1]=0.34f; s_phase[2]=0.67f; s_dotPhase=0.0f;

  radaraudio::start();                    // fox-hunt ping follows this radar
}

// intensity 0..1 ; readout text may be nullptr to leave it unchanged
inline void update(float intensity, const char *text){
  if(intensity<0)intensity=0; if(intensity>1)intensity=1;
  radaraudio::setIntensity(intensity);    // drive the "getting warmer" tone
  for(int i=0;i<3;i++){
    s_phase[i]+=0.012f+intensity*0.045f;      // stronger signal -> faster pings
    if(s_phase[i]>1.0f) s_phase[i]-=1.0f;
    if(!s_ping[i]) continue;
    int d=(int)(s_phase[i]*2*S_MAXR);
    lv_obj_set_size(s_ping[i],d,d); lv_obj_center(s_ping[i]);
    int op=(int)((1.0f-s_phase[i])*(40.0f+intensity*215.0f));
    if(op<0)op=0; if(op>255)op=255;
    lv_obj_set_style_border_opa(s_ping[i],(lv_opa_t)op,0);
  }
  s_dotPhase+=0.25f; if(s_dotPhase>6.2832f) s_dotPhase-=6.2832f;
  int base=8+(int)(intensity*24.0f);
  int dd=base+(int)(3.0f*sinf(s_dotPhase));
  if(s_dot){
    lv_obj_set_size(s_dot,dd,dd); lv_obj_center(s_dot);
    int op=70+(int)(intensity*185.0f); if(op>255)op=255;
    lv_obj_set_style_bg_opa(s_dot,(lv_opa_t)op,0);
  }
  if(s_read && text) lv_label_set_text(s_read,text);
}

inline void reset(){
  radaraudio::stop();                     // silence the ping when the radar closes
  s_cont=s_dot=s_read=nullptr; s_ping[0]=s_ping[1]=s_ping[2]=nullptr;
  s_phase[0]=0.0f; s_phase[1]=0.34f; s_phase[2]=0.67f; s_dotPhase=0.0f;
}

} // namespace radarui
