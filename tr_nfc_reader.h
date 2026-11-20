// ===========================================================================
//  tr_nfc.h  —  Tunnel R.A.T. // T-Pager  —  NFC Reader + Writer
//  READ : shows tag UID + NDEF record (text / URL / WiFi).
//  WRITE: type text or a URL, then tap a writable tag (NTAG / Type 2/4/5)
//         to write an NDEF record to it.
//
//  Uses LilyGoLib's global NFCReader (RfalNfcClass) + the RFAL NdefClass, plus
//  the example helpers app_nfc.cpp/.h (beginNFC / loopNFCReader) for discovery.
//
//  NOTE (write): the write happens on the tag the read loop just activated.
//  Blank/unformatted tags may fail detect — use an NDEF-formatted tag. First
//  pass; may need tuning on real hardware.
// ===========================================================================
#pragma once
#include "config.h"
#include <lvgl.h>

#if defined(USING_ST25R3916)
#include "app_nfc.h"
#include "ndef_class.h"

namespace nfc {

static lv_obj_t *s_lbl=nullptr, *s_ta=nullptr, *s_status=nullptr;
static char s_uid[48]="", s_ndef[160]="";

// ---- write state ----------------------------------------------------------
static uint8_t  s_wbuf[256];
static uint32_t s_wlen=0;
static bool     s_wpend=false;
static NdefClass *s_ndefWriter=nullptr;

// Build a single-record NDEF message (short record).
static uint32_t buildText(uint8_t*o,const char*t){
  uint8_t tl=strlen(t); if(tl>200)tl=200;
  uint32_t n=0;
  o[n++]=0xD1;                 // MB|ME|SR, TNF=well-known
  o[n++]=0x01;                 // type length
  o[n++]=(uint8_t)(3+tl);      // payload = status(1) + "en"(2) + text
  o[n++]='T';
  o[n++]=0x02;                 // UTF-8, language length 2
  o[n++]='e'; o[n++]='n';
  memcpy(o+n,t,tl); n+=tl;
  return n;
}
static uint32_t buildUri(uint8_t*o,const char*u){
  uint8_t ul=strlen(u); if(ul>200)ul=200;
  uint32_t n=0;
  o[n++]=0xD1;
  o[n++]=0x01;
  o[n++]=(uint8_t)(1+ul);      // payload = prefix(1) + uri
  o[n++]='U';
  o[n++]=0x00;                 // prefix 0x00 = none (full URI in the string)
  memcpy(o+n,u,ul); n+=ul;
  return n;
}

static void armWrite(bool uri){
  const char *txt=lv_textarea_get_text(s_ta);
  if(!txt || !txt[0]){ if(s_status) lv_label_set_text(s_status,"type something first"); return; }
  s_wlen = uri ? buildUri(s_wbuf,txt) : buildText(s_wbuf,txt);
  s_wpend = true;
  if(s_status) lv_label_set_text(s_status,"WRITE ARMED — hold a writable tag...");
}

// ---- read (NDEF callbacks) ------------------------------------------------
static void onNotify(){}
static void onNdef(ndefTypeId id, void *data){
  switch(id){
    case NDEF_TYPE_RTD_TEXT:{ ndefRtdText*t=(ndefRtdText*)data;
      snprintf(s_ndef,sizeof s_ndef,"TEXT: %.120s",(const char*)t->bufSentence.buffer);} break;
    case NDEF_TYPE_RTD_URI:{ ndefRtdUri*u=(ndefRtdUri*)data;
      snprintf(s_ndef,sizeof s_ndef,"URL: %.40s%.80s",(const char*)u->bufProtocol.buffer,(const char*)u->bufUriString.buffer);} break;
    case NDEF_TYPE_MEDIA_WIFI:{ ndefTypeWifi*w=(ndefTypeWifi*)data;
      snprintf(s_ndef,sizeof s_ndef,"WiFi SSID: %.*s",(int)w->bufNetworkSSID.length,(const char*)w->bufNetworkSSID.buffer);} break;
    default: break;
  }
}

static void renderRead(){
  if(!s_lbl) return;
  if(s_uid[0]) lv_label_set_text_fmt(s_lbl,"UID: %s   %s", s_uid, s_ndef);
  else         lv_label_set_text(s_lbl,"NFC — tap a tag to read, or type below + Write");
}

// ---- UI -------------------------------------------------------------------
static void mkBtn(lv_obj_t*p,const char*t,int x,int y,lv_event_cb_t cb){
  lv_obj_t*b=lv_btn_create(p); lv_obj_set_size(b,110,28);
  lv_obj_align(b,LV_ALIGN_TOP_LEFT,x,y); lv_obj_set_style_bg_color(b,lv_color_hex(0x173017),0);
  lv_obj_t*l=lv_label_create(b); lv_label_set_text(l,t); lv_obj_center(l);
  lv_obj_add_event_cb(b,cb,LV_EVENT_CLICKED,NULL);
}

inline void buildUI(lv_obj_t *parent){
  s_uid[0]=0; s_ndef[0]=0; s_wpend=false;

  s_lbl=lv_label_create(parent);
  lv_label_set_long_mode(s_lbl,LV_LABEL_LONG_WRAP); lv_obj_set_width(s_lbl,lv_pct(96));
  lv_obj_set_style_text_color(s_lbl,lv_color_hex(TR_THEME_GREEN),0);
  lv_obj_align(s_lbl,LV_ALIGN_TOP_LEFT,0,0);
  renderRead();

  s_ta=lv_textarea_create(parent);
  lv_textarea_set_one_line(s_ta,true);
  lv_textarea_set_placeholder_text(s_ta,"text or https://... to write");
  lv_obj_set_width(s_ta,lv_pct(96)); lv_obj_align(s_ta,LV_ALIGN_TOP_LEFT,0,34);

  mkBtn(parent,"Write Text",0,  70,[](lv_event_t*){ armWrite(false); });
  mkBtn(parent,"Write URL", 120,70,[](lv_event_t*){ armWrite(true); });

  s_status=lv_label_create(parent);
  lv_obj_set_width(s_status,lv_pct(96)); lv_obj_align(s_status,LV_ALIGN_TOP_LEFT,0,104);
  lv_obj_set_style_text_color(s_status,lv_color_hex(0x8B949E),0);
  lv_label_set_text(s_status,"");

  static bool started=false;
  if(!started){
    instance.powerControl(POWER_NFC, true);   // LilyGoLib's begin() powered the NFC field OFF
    beginNFC(onNotify,onNdef);
    started=true;
  }
}

inline void loop(){
  loopNFCReader();
  rfalNfcDevice *dev=nullptr;
  if(NFCReader.rfalNfcGetActiveDevice(&dev)==ST_ERR_NONE && dev && dev->nfcidLen){
    int n=0; for(int i=0;i<dev->nfcidLen && n<44;i++) n+=snprintf(s_uid+n,sizeof s_uid-n,"%02X",dev->nfcid[i]);
    if(s_wpend){
      if(!s_ndefWriter) s_ndefWriter=new NdefClass(&NFCReader);
      ndefInfo info; ReturnCode e;
      e=s_ndefWriter->ndefPollerContextInitialization(dev);
      if(e==ST_ERR_NONE) e=s_ndefWriter->ndefPollerNdefDetect(&info);
      if(e==ST_ERR_NONE) e=s_ndefWriter->ndefPollerWriteRawMessage(s_wbuf,s_wlen);
      if(s_status) lv_label_set_text(s_status, e==ST_ERR_NONE ? "WRITE OK" : "write failed (tag writable/formatted?)");
      s_wpend=false;
    }
  }
  renderRead();
}

inline void leave(){}

} // namespace nfc

#else   // ---- NFC not available in this build ----
namespace nfc {
  inline void buildUI(lv_obj_t *p){ lv_obj_t*l=lv_label_create(p);
    lv_label_set_text(l,"NFC not available in this build."); }
  inline void loop(){}
  inline void leave(){}
}
#endif
