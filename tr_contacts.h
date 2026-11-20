// ===========================================================================
//  tr_contacts.h  —  Tunnel R.A.T. // T-Pager  —  Encrypted contacts vault
//  "In case lost": contacts + your message keypair live in an AES-256-GCM
//  vault on the microSD, unlocked by a passphrase (PBKDF2-HMAC-SHA256).
//  A lost/stolen Pager leaks nothing without the passphrase.
//
//  Stores per contact: name, mesh node ID (!xxxxxxxx), ESP-NOW MAC, X25519
//  public key. Your own X25519 keypair is generated on vault creation and
//  stored inside the same vault. The DM send/receive that USES these keys
//  lands in the Comms phase; this module is the key store + at-rest crypto.
//
//  Crypto: the "Crypto" library by Rhys Weatherley (Library Manager → "Crypto").
//  Self-contained, no mbedTLS/ESP-IDF headers needed. Provides AES-256-GCM,
//  SHA-256/HMAC (for PBKDF2) and Curve25519 (X25519).
// ===========================================================================
#pragma once
#include "config.h"
#include <lvgl.h>

#if !TR_VAULT_ENABLE
// -------- Vault disabled: stubs so the firmware compiles with no crypto lib ---
namespace contacts {
  inline void buildUI(lv_obj_t *parent){
    lv_obj_t *l = lv_label_create(parent);
    lv_label_set_text(l,
      "Contacts vault is OFF.\n\n"
      "To enable:\n"
      "1) Library Manager -> install \"Crypto\" (Rhys Weatherley)\n"
      "2) set TR_VAULT_ENABLE 1 in config.h\n"
      "3) re-flash");
    lv_obj_set_width(l, lv_pct(96));
    lv_obj_align(l, LV_ALIGN_TOP_LEFT, 0, 0);
  }
  inline lv_obj_t *inputField(){ return nullptr; }
  inline void leave(){}
  inline bool isUnlocked(){ return false; }
  inline const uint8_t* myPriv(){ return nullptr; }
  inline const uint8_t* myPub(){ return nullptr; }
  inline String myNodeId(){ return String(""); }
  inline int contactCount(){ return 0; }
  inline const char* contactName(int){ return ""; }
  inline const uint8_t* contactPub(int){ return nullptr; }
}
#else
// -------- Vault enabled: real encrypted store (needs the Crypto library) ------
#include <SD.h>
#include <ArduinoJson.h>
#include <vector>
#include "esp_random.h"

#include <Crypto.h>
#include <AES.h>
#include <GCM.h>
#include <SHA256.h>
#include <Curve25519.h>

namespace contacts {

struct Contact { String name, nodeid, mac; uint8_t pub[32]; };

static bool    s_unlocked = false;
static uint8_t s_priv[32], s_pub[32];     // our X25519 keypair (valid when unlocked)
static String  s_nodeid;                  // our mesh id, derived from pub
static std::vector<Contact> s_contacts;
static uint8_t s_fails = 0;
static String  s_pass;                    // held only while unlocked (for re-saves)
static void (*s_refreshNavigation)() = nullptr;
void setNavigationCallback(void (*fn)()){ s_refreshNavigation=fn; }

static lv_obj_t *s_root = nullptr, *s_ta = nullptr, *s_info = nullptr, *s_list = nullptr;

// ---- hex helpers ----------------------------------------------------------
static String toHex(const uint8_t *b, size_t n){
  static const char *h = "0123456789abcdef"; String s; s.reserve(n*2);
  for (size_t i=0;i<n;i++){ s += h[b[i]>>4]; s += h[b[i]&0xF]; } return s;
}
static bool fromHex(const String &s, uint8_t *out, size_t n){
  if (s.length() != n*2) return false;
  auto v=[&](char c)->int{ if(c>='0'&&c<='9')return c-'0'; c|=0x20; if(c>='a'&&c<='f')return c-'a'+10; return -1; };
  for (size_t i=0;i<n;i++){ int hi=v(s[i*2]),lo=v(s[i*2+1]); if(hi<0||lo<0)return false; out[i]=(hi<<4)|lo; }
  return true;
}

// ---- crypto ---------------------------------------------------------------
// PBKDF2-HMAC-SHA256, one 32-byte output block.
static void pbkdf2(const uint8_t *pass, size_t plen, const uint8_t *salt, size_t slen,
                   uint32_t iters, uint8_t out[32]){
  SHA256 sha; uint8_t U[32], T[32];
  const uint8_t ib[4] = {0,0,0,1};                // block index 1
  sha.resetHMAC(pass, plen); sha.update(salt, slen); sha.update(ib, 4);
  sha.finalizeHMAC(pass, plen, U, 32);
  memcpy(T, U, 32);
  for (uint32_t i=1;i<iters;i++){
    sha.resetHMAC(pass, plen); sha.update(U, 32); sha.finalizeHMAC(pass, plen, U, 32);
    for (int j=0;j<32;j++) T[j]^=U[j];
  }
  memcpy(out, T, 32);
}
static void kdf(const String &pass, const uint8_t *salt, uint8_t *key32){
  pbkdf2((const uint8_t*)pass.c_str(), pass.length(), salt, 16, TR_VAULT_PBKDF2_ITERS, key32);
}

static void genKeypair(){
  Curve25519::dh1(s_pub, s_priv);                 // s_priv random+clamped, s_pub = public
  char id[18]; snprintf(id,sizeof id,"!%02x%02x%02x%02x", s_pub[0],s_pub[1],s_pub[2],s_pub[3]);
  s_nodeid = id;
}

// ---- JSON blob ------------------------------------------------------------
static String serialize(){
  DynamicJsonDocument doc(32768);
  doc["priv"]=toHex(s_priv,32); doc["pub"]=toHex(s_pub,32); doc["nodeid"]=s_nodeid;
  JsonArray cs=doc.createNestedArray("contacts");
  for (auto &c : s_contacts){ JsonObject o=cs.createNestedObject();
    o["name"]=c.name; o["nodeid"]=c.nodeid; o["mac"]=c.mac; o["pub"]=toHex(c.pub,32); }
  String out; serializeJson(doc,out); return out;
}
static bool deserialize(const String &json){
  DynamicJsonDocument doc(32768);
  if (deserializeJson(doc,json)) return false;
  if (!doc["contacts"].is<JsonArray>()) return false;
  if (!fromHex(doc["priv"]|"", s_priv,32)) return false;
  if (!fromHex(doc["pub"]|"", s_pub,32)) return false;
  s_nodeid=(const char*)(doc["nodeid"]|"");
  s_contacts.clear();
  for (JsonObject o : doc["contacts"].as<JsonArray>()){
    Contact c; c.name=(const char*)(o["name"]|""); c.nodeid=(const char*)(o["nodeid"]|"");
    c.mac=(const char*)(o["mac"]|""); if (!fromHex(o["pub"]|"", c.pub,32)) return false; s_contacts.push_back(c);
  }
  return s_contacts.size() <= TR_VAULT_MAX_CONTACTS;
}

// ---- vault file: "TRV1" | salt16 | iv12 | tag16 | len4(LE) | ct ------------
static bool saveVault(const String &pass){
  if (!SD.cardType() || !pass.length()) return false;
  uint8_t salt[16], iv[12], key[32], tag[16];
  esp_fill_random(salt,16); esp_fill_random(iv,12);
  kdf(pass,salt,key);
  String pt=serialize(); size_t n=pt.length();
  if (!n || n > 200000) { memset(key,0,sizeof(key)); return false; }
  std::vector<uint8_t> ct(n);
  GCM<AES256> gcm;
  if (!gcm.setKey(key,32) || !gcm.setIV(iv,12)) { memset(key,0,sizeof(key)); return false; }
  gcm.encrypt(ct.data(), (const uint8_t*)pt.c_str(), n);
  gcm.computeTag(tag,16);
  memset(key,0,sizeof(key));
  SD.mkdir(TR_SD_LOG_DIR);
  const char *tmp = "/tunnelrat/contacts.tmp";
  const char *bak = "/tunnelrat/contacts.bak";
  SD.remove(tmp);
  File f=SD.open(tmp, FILE_WRITE);
  if (!f) return false;
  uint32_t len=(uint32_t)n;
  bool ok = f.write((const uint8_t*)"TRV1",4)==4
         && f.write(salt,16)==16 && f.write(iv,12)==12
         && f.write(tag,16)==16 && f.write((const uint8_t*)&len,4)==4
         && f.write(ct.data(),n)==n;
  f.flush(); f.close();
  if (!ok) { SD.remove(tmp); return false; }
  // Keep the last valid vault until the replacement has been written.
  SD.remove(bak);
  bool hadOld = SD.exists(TR_VAULT_FILE);
  if (hadOld && !SD.rename(TR_VAULT_FILE,bak)) { SD.remove(tmp); return false; }
  if (!SD.rename(tmp,TR_VAULT_FILE)) {
    if (hadOld) SD.rename(bak,TR_VAULT_FILE);
    return false;
  }
  // Backup intentionally retained for recovery if media fails later.
  return true;
}

static bool loadVault(const String &pass){
  File f=SD.open(TR_VAULT_FILE, FILE_READ); if(!f) return false;
  uint8_t magic[4],salt[16],iv[12],tag[16],key[32]; uint32_t len=0;
  if (f.read(magic,4)!=4 || memcmp(magic,"TRV1",4)){ f.close(); return false; }
  if (f.read(salt,16)!=16 || f.read(iv,12)!=12 || f.read(tag,16)!=16 || f.read((uint8_t*)&len,4)!=4) { f.close(); return false; }
  if (len==0||len>200000 || f.size() != (size_t)52 + len){ f.close(); return false; }
  std::vector<uint8_t> ct(len), pt(len);
  if (f.read(ct.data(),len)!=(int)len){ f.close(); return false; }
  f.close();
  kdf(pass,salt,key);
  GCM<AES256> gcm;
  if (!gcm.setKey(key,32) || !gcm.setIV(iv,12)) { memset(key,0,sizeof(key)); return false; }
  gcm.decrypt(pt.data(), ct.data(), len);
  bool valid=gcm.checkTag(tag,16);
  memset(key,0,sizeof(key));
  if (!valid) { memset(pt.data(),0,pt.size()); return false; }        // wrong passphrase / tampered
  bool parsed=deserialize(String((const char*)pt.data(), len));
  memset(pt.data(),0,pt.size());
  return parsed;
}

static bool vaultExists(){ return SD.exists(TR_VAULT_FILE); }

// ---- public ops (used by Comms, Phase E) ----------------------------------
bool isUnlocked(){ return s_unlocked; }
const uint8_t* myPriv(){ return s_unlocked ? s_priv : nullptr; }
const uint8_t* myPub(){ return s_unlocked ? s_pub : nullptr; }
String myNodeId(){ return s_nodeid; }
int contactCount(){ return (int)s_contacts.size(); }
const char* contactName(int i){ return (i>=0&&i<(int)s_contacts.size())? s_contacts[i].name.c_str():""; }
const uint8_t* contactPub(int i){ return (i>=0&&i<(int)s_contacts.size())? s_contacts[i].pub : nullptr; }

static void lock(){ s_unlocked=false; memset(s_priv,0,32); memset(s_pub,0,32); s_nodeid=""; s_contacts.clear();
                    for (size_t i=0;i<s_pass.length();i++) s_pass.setCharAt(i,0); s_pass=""; }

// ---- UI -------------------------------------------------------------------
static void rebuild();
static bool s_submitPending = false;

static void addContactFromLine(const String &line){
  int a=line.indexOf('|'), b=line.indexOf('|',a+1), c=line.indexOf('|',b+1);
  if (a<0||b<0||c<0) return;
  Contact k; k.name=line.substring(0,a); k.name.trim();
  k.nodeid=line.substring(a+1,b); k.nodeid.trim();
  k.mac=line.substring(b+1,c); k.mac.trim();
  String ph=line.substring(c+1); ph.trim();
  if (!fromHex(ph,k.pub,32)) return;
  if (s_contacts.size() < TR_VAULT_MAX_CONTACTS) s_contacts.push_back(k);
}

static void submitInput(int phase){
  if (!s_ta || !s_info) return;
  String pass(lv_textarea_get_text(s_ta));
  // 0=create 1=unlock 2=add
  if (phase==0){
    if (pass.length()<12){ lv_label_set_text(s_info,"passphrase too short"); return; }
    genKeypair(); s_contacts.clear();
    if (saveVault(pass)){ s_unlocked=true; s_pass=pass; }
    else { lock(); lv_label_set_text(s_info,"save failed (SD?)"); return; }
  } else if (phase==1){
    if (loadVault(pass)){ s_unlocked=true; s_pass=pass; s_fails=0; }
    else { lock(); s_fails++;
      if (TR_VAULT_WIPE_AFTER_FAILS && s_fails>=TR_VAULT_WIPE_AFTER_FAILS){ SD.remove(TR_VAULT_FILE); lv_label_set_text(s_info,"WIPED after fails"); }
      else lv_label_set_text(s_info,"wrong passphrase"); }
  } else if (phase==2){
    addContactFromLine(pass);
    if (s_pass.length() && !saveVault(s_pass)) { lv_label_set_text(s_info,"Save failed; SD card?"); return; }
  }
  rebuild();
  if (s_refreshNavigation) s_refreshNavigation();
}

// Defer vault work until the input event completes. Rebuilding a screen
// from inside its own KEY/READY callback can delete the active event target.
static void submitDeferred(void *arg){
  int phase = (int)(intptr_t)arg;
  s_submitPending = false;
  Serial.printf("[VAULT] submit phase=%d\n", phase);
  submitInput(phase);
}
static void requestSubmit(int phase){
  if (s_submitPending) return;  // READY and KEY can both fire for one Enter
  s_submitPending = true;
  lv_async_call(submitDeferred, (void*)(intptr_t)phase);
}
static void okCb(lv_event_t *e){
  requestSubmit((int)(intptr_t)lv_event_get_user_data(e));
}
static void textSubmitCb(lv_event_t *e){
  lv_event_code_t code = lv_event_get_code(e);
  // Some LilyGo keyboard revisions send ASCII BS (0x08) rather than
  // LVGL's delete key. LVGL handles LV_KEY_BACKSPACE itself; this is
  // only a fallback for the raw ASCII control code.
  if (code == LV_EVENT_KEY && lv_event_get_key(e) == 0x08 &&
      LV_KEY_BACKSPACE != 0x08 && LV_KEY_DEL != 0x08) {
    lv_textarea_delete_char((lv_obj_t*)lv_event_get_target(e));
    return;
  }
  if (code == LV_EVENT_READY ||
      (code == LV_EVENT_KEY && lv_event_get_key(e) == LV_KEY_ENTER)) {
    requestSubmit((int)(intptr_t)lv_event_get_user_data(e));
  }
}

static void mkBtn(lv_obj_t *p,const char*t,int x,int y,lv_event_cb_t cb,void*ud){
  lv_obj_t *b=lv_button_create(p); lv_obj_set_size(b,96,28);
  lv_obj_align(b,LV_ALIGN_TOP_LEFT,x,y); lv_obj_set_style_bg_color(b,lv_color_hex(0x173017),0);
  lv_obj_t *l=lv_label_create(b); lv_label_set_text(l,t); lv_obj_center(l);
  lv_obj_add_event_cb(b,cb,LV_EVENT_CLICKED,ud);
}

static bool s_resetArm=false;   // two-tap confirm guard for the lock-screen Reset button
static void rebuild(){
  lv_obj_clean(s_root);
  // Opaque black background prevents underlying screen bleed-through.
  lv_obj_set_style_bg_color(s_root, lv_color_hex(0x000000), LV_PART_MAIN);
  lv_obj_set_style_bg_opa(s_root, LV_OPA_COVER, LV_PART_MAIN);
  lv_obj_set_style_border_width(s_root, 0, LV_PART_MAIN);
  s_info=lv_label_create(s_root);
  lv_obj_set_style_text_color(s_info, lv_color_hex(TR_THEME_GREEN), 0);
  lv_obj_align(s_info, LV_ALIGN_TOP_LEFT, 0, 0);

  if (!s_unlocked){
    bool exists=vaultExists();
    s_resetArm=false;   // disarm whenever the lock screen is (re)drawn
    lv_label_set_text(s_info, exists?"Vault locked - enter passphrase":"Create vault - passphrase (12+ chars)");
    s_ta=lv_textarea_create(s_root);
    lv_textarea_set_one_line(s_ta,true); lv_textarea_set_password_mode(s_ta,true);
    lv_textarea_set_password_show_time(s_ta, 0); // never flash typed characters
    lv_obj_set_style_bg_color(s_ta, lv_color_hex(0x000000), LV_PART_MAIN);
    lv_obj_set_style_bg_opa(s_ta, LV_OPA_COVER, LV_PART_MAIN);
    lv_obj_set_style_text_color(s_ta, lv_color_hex(TR_THEME_GREEN), LV_PART_MAIN);
    lv_obj_set_style_border_color(s_ta, lv_color_hex(TR_THEME_GREEN), LV_PART_MAIN);
    lv_obj_set_style_border_width(s_ta, 1, LV_PART_MAIN);
    lv_textarea_set_placeholder_text(s_ta,"passphrase");
    lv_obj_set_width(s_ta, lv_pct(70)); lv_obj_align(s_ta, LV_ALIGN_TOP_LEFT, 0, 22);
    lv_obj_add_event_cb(s_ta, textSubmitCb, LV_EVENT_READY, (void*)(intptr_t)(exists?1:0));
    lv_obj_add_event_cb(s_ta, textSubmitCb, LV_EVENT_KEY, (void*)(intptr_t)(exists?1:0));
    mkBtn(s_root, exists?"Unlock":"Create", 0, 54, okCb, (void*)(intptr_t)(exists?1:0));
    if (exists) mkBtn(s_root, "Reset", 100, 54, [](lv_event_t*){
        if(!s_resetArm){ s_resetArm=true;
          lv_label_set_text(s_info,"Reset ERASES all contacts + your key.\nTap Reset again to confirm."); return; }
        s_resetArm=false; SD.remove(TR_VAULT_FILE); lock(); rebuild();
        if(s_refreshNavigation) s_refreshNavigation();
        lv_label_set_text(s_info,"Vault reset - set a new passphrase"); }, nullptr);
    return;
  }

  lv_label_set_text_fmt(s_info, "Unlocked - %s", s_nodeid.c_str());
  s_ta=lv_textarea_create(s_root);
  lv_textarea_set_one_line(s_ta,true);
  lv_obj_set_width(s_ta, lv_pct(96)); lv_obj_align(s_ta, LV_ALIGN_TOP_LEFT, 0, 86);
  lv_obj_add_event_cb(s_ta, textSubmitCb, LV_EVENT_READY, (void*)(intptr_t)2);
  lv_obj_add_event_cb(s_ta, textSubmitCb, LV_EVENT_KEY, (void*)(intptr_t)2);
  mkBtn(s_root,"My ID",   0, 22, [](lv_event_t*){
      lv_label_set_text_fmt(s_info,"ID %s\npub %s", s_nodeid.c_str(), toHex(s_pub,32).c_str()); },0);
  mkBtn(s_root,"Add",    100,22, [](lv_event_t*){
      lv_label_set_text(s_info,"paste: name | !id | MAC | pubhex, then Save");
      lv_textarea_set_password_mode(s_ta,false);
      lv_textarea_set_placeholder_text(s_ta,"name | !id | AABBCC.. | pubhex");
      lv_group_focus_obj(s_ta);
      },0);
  mkBtn(s_root,"Save",   200,22, okCb, (void*)(intptr_t)2);
  mkBtn(s_root,"Lock",   0, 54, [](lv_event_t*){ lock(); rebuild(); if (s_refreshNavigation) s_refreshNavigation(); },0);

  s_list=lv_list_create(s_root);
  lv_obj_set_size(s_list, lv_pct(100), lv_pct(45));
  lv_obj_align(s_list, LV_ALIGN_BOTTOM_MID, 0, 0);
  lv_obj_set_style_bg_color(s_list, lv_color_hex(0x0E120E), 0);
  for (auto &c : s_contacts){
    char row[80]; snprintf(row,sizeof row,"%s  %s", c.name.c_str(), c.nodeid.c_str());
    lv_list_add_text(s_list, row);
  }
}

lv_obj_t *inputField(){ return s_ta; }

void buildUI(lv_obj_t *parent){ s_root=parent; rebuild(); }
void leave(){ if (TR_VAULT_LOCK_ON_EXIT) lock(); s_root=nullptr; s_ta=nullptr; s_info=nullptr; s_list=nullptr; }

} // namespace contacts
#endif // TR_VAULT_ENABLE
