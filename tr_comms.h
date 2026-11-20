// ===========================================================================
//  tr_comms.h  —  Tunnel R.A.T. // T-Pager  —  Comms (encrypted DM)
//  WiFi-direct messaging over ESP-NOW (optionally Long-Range), end-to-end
//  encrypted with the vault's Curve25519 keypair: ECDH -> SHA-256 -> AES-256-GCM.
//  Only the intended recipient (matching key) can read a message.
//
//  Needs the Contacts vault UNLOCKED (that's where your keypair + contact
//  public keys live). Pick a contact, type, Send. Messages addressed to you
//  are decrypted and shown; everyone else's broadcast just fails the tag.
//
//  Packet: [senderPub 32][targetId 4][iv 12][tag 16][ciphertext N]  (<=250B)
//  v1 transport = ESP-NOW. LoRa-mesh transport is a later addition.
//  Needs TWO devices running this firmware to actually exchange messages.
// ===========================================================================
#pragma once
#include "config.h"
#include <lvgl.h>
#include <WiFi.h>
#include <esp_now.h>
#include <esp_wifi.h>
#include "esp_random.h"
#include "tr_contacts.h"

#if TR_VAULT_ENABLE
#include <SHA256.h>
#include <GCM.h>
#include <AES.h>
#include <Curve25519.h>
#endif

namespace comms {

static lv_obj_t *s_log=nullptr, *s_ta=nullptr, *s_dd=nullptr, *s_status=nullptr;
static bool s_up=false;
static const uint8_t BCAST[6]={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};

// rx packet handed from the ESP-NOW callback to loop() (LVGL + crypto on main task)
static volatile bool s_rxPend=false;
static uint8_t s_rxBuf[260];
static volatile int  s_rxLen=0;

static void addLog(const char*who,const char*msg){
  if(!s_log) return;
  char row[210]; snprintf(row,sizeof row,"%s: %.170s",who,msg);
  if(lv_obj_get_child_cnt(s_log)>40) lv_obj_del(lv_obj_get_child(s_log,0));
  lv_obj_t*it=lv_list_add_text(s_log,row);
  lv_obj_set_style_text_color(it, strcmp(who,"me")==0?lv_color_hex(TR_THEME_GREEN):lv_color_hex(0x40C4FF),0);
}

#if TR_VAULT_ENABLE
static void deriveKey(const uint8_t *theirPub, uint8_t *key32){
  uint8_t shared[32]; memcpy(shared,theirPub,32);
  uint8_t priv[32];   memcpy(priv,contacts::myPriv(),32);
  Curve25519::dh2(shared,priv);                 // shared = ECDH secret
  SHA256 h; h.reset(); h.update(shared,32); h.finalize(key32,32);
}

// Keep the callback light: copy the packet, decrypt in loop().
static void onRecv(const esp_now_recv_info_t *info, const uint8_t *data, int len){
  (void)info;
  if(s_rxPend) return;
  if(len<64 || len>(int)sizeof s_rxBuf) return;
  memcpy(s_rxBuf,data,len); s_rxLen=len; s_rxPend=true;
}

static void processRx(){
  int len=s_rxLen; const uint8_t*d=s_rxBuf;
  const uint8_t*spub=d, *tid=d+32, *iv=d+36, *tag=d+48, *ct=d+64;
  if(memcmp(tid,contacts::myPub(),4)!=0) return;  // not addressed to me
  int clen=len-64; if(clen<0||clen>200) return;
  uint8_t key[32]; deriveKey(spub,key);
  uint8_t pt[201];
  GCM<AES256> gcm; gcm.setKey(key,32); gcm.setIV(iv,12);
  gcm.decrypt(pt,ct,clen);
  if(!gcm.checkTag(tag,16)) return;               // wrong key / tampered
  pt[clen]=0;
  char who[18]; snprintf(who,sizeof who,"!%02x%02x%02x%02x",spub[0],spub[1],spub[2],spub[3]);
  addLog(who,(char*)pt);
}

static void sendMsg(){
  if(!contacts::isUnlocked()){ if(s_status)lv_label_set_text(s_status,"unlock the vault first"); return; }
  int idx = s_dd ? (int)lv_dropdown_get_selected(s_dd) : -1;
  const uint8_t*tpub=contacts::contactPub(idx);
  if(!tpub){ if(s_status)lv_label_set_text(s_status,"add a contact (with pubkey) in Contacts"); return; }
  const char*txt=lv_textarea_get_text(s_ta);
  if(!txt||!txt[0]) return;
  uint8_t key[32]; deriveKey(tpub,key);
  int mlen=strlen(txt); if(mlen>180)mlen=180;
  uint8_t pkt[64+200]; int n=0;
  memcpy(pkt+n,contacts::myPub(),32); n+=32;
  memcpy(pkt+n,tpub,4); n+=4;                      // target id = first 4 of their pub
  uint8_t iv[12]; esp_fill_random(iv,12); memcpy(pkt+n,iv,12); n+=12;
  uint8_t*tagp=pkt+n; n+=16;
  GCM<AES256> gcm; gcm.setKey(key,32); gcm.setIV(iv,12);
  gcm.encrypt(pkt+n,(const uint8_t*)txt,mlen); gcm.computeTag(tagp,16); n+=mlen;
  esp_now_send(BCAST,pkt,n);
  addLog("me",txt);
  lv_textarea_set_text(s_ta,"");
  if(s_status)lv_label_set_text(s_status,"sent (encrypted)");
}
#endif  // TR_VAULT_ENABLE

static void espnowUp(){
  if(s_up) return;
  WiFi.mode(WIFI_STA); WiFi.disconnect(false);
  esp_wifi_set_channel(TR_ESPNOW_CHAN, WIFI_SECOND_CHAN_NONE);
#if TR_ESPNOW_LR
  esp_wifi_set_protocol(WIFI_IF_STA,
    WIFI_PROTOCOL_11B|WIFI_PROTOCOL_11G|WIFI_PROTOCOL_11N|WIFI_PROTOCOL_LR);
#endif
  if(esp_now_init()!=ESP_OK) return;
#if TR_VAULT_ENABLE
  esp_now_register_recv_cb(onRecv);
#endif
  esp_now_peer_info_t p={}; memcpy(p.peer_addr,BCAST,6);
  p.channel=TR_ESPNOW_CHAN; p.ifidx=WIFI_IF_STA; p.encrypt=false;
  esp_now_add_peer(&p);
  s_up=true;
}
static void espnowDown(){ if(s_up){ esp_now_deinit(); s_up=false; } }

// ---- UI -------------------------------------------------------------------
inline void buildUI(lv_obj_t*parent){
#if TR_VAULT_ENABLE
  if(!contacts::isUnlocked()){
    lv_obj_t*l=lv_label_create(parent);
    lv_label_set_long_mode(l,LV_LABEL_LONG_WRAP); lv_obj_set_width(l,lv_pct(96));
    lv_label_set_text(l,"Comms needs the vault unlocked.\nOpen Contacts, unlock, then come back here.");
    lv_obj_set_style_text_color(l,lv_color_hex(0xFF5252),0);
    return;
  }

  s_dd=lv_dropdown_create(parent);
  { String opts; int c=contacts::contactCount();
    if(c==0) opts="(no contacts yet)";
    else for(int i=0;i<c;i++){ if(i)opts+="\n"; opts+=contacts::contactName(i); }
    lv_dropdown_set_options(s_dd,opts.c_str()); }
  lv_obj_set_width(s_dd,lv_pct(58)); lv_obj_align(s_dd,LV_ALIGN_TOP_LEFT,0,0);

  s_status=lv_label_create(parent);
  lv_obj_set_style_text_color(s_status,lv_color_hex(0x8B949E),0);
  lv_obj_align(s_status,LV_ALIGN_TOP_RIGHT,0,6);
  lv_label_set_text_fmt(s_status,"me %s",contacts::myNodeId().c_str());

  s_ta=lv_textarea_create(parent);
  lv_textarea_set_one_line(s_ta,true); lv_textarea_set_placeholder_text(s_ta,"message");
  lv_obj_set_width(s_ta,lv_pct(72)); lv_obj_align(s_ta,LV_ALIGN_TOP_LEFT,0,42);

  lv_obj_t*b=lv_btn_create(parent); lv_obj_set_size(b,92,32);
  lv_obj_align(b,LV_ALIGN_TOP_RIGHT,0,42); lv_obj_set_style_bg_color(b,lv_color_hex(0x173017),0);
  lv_obj_t*bl=lv_label_create(b); lv_label_set_text(bl,"Send"); lv_obj_center(bl);
  lv_obj_add_event_cb(b,[](lv_event_t*){ sendMsg(); },LV_EVENT_CLICKED,NULL);

  s_log=lv_list_create(parent);
  lv_obj_set_size(s_log,lv_pct(100),lv_pct(54));
  lv_obj_align(s_log,LV_ALIGN_BOTTOM_MID,0,0);
  lv_obj_set_style_bg_color(s_log,lv_color_hex(0x0E120E),0);

  espnowUp();
#else
  lv_obj_t*l=lv_label_create(parent);
  lv_label_set_text(l,"Comms needs the vault (set TR_VAULT_ENABLE 1).");
#endif
}

inline void loop(){
#if TR_VAULT_ENABLE
  if(s_rxPend){ processRx(); s_rxPend=false; }
#endif
}

inline void leave(){ espnowDown(); }

} // namespace comms
