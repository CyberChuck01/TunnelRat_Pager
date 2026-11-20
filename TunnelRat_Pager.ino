// ===========================================================================
//  Tunnel R.A.T. // T-Pager        (multi-mode build — Wardrive crash fix + nRF24)
//  Device: LILYGO T-LoRa Pager (ESP32-S3, u-blox MIA-M10Q, SX1262/LR1121/CC1101)
//
//  A mode launcher for the Pager. Pick a mode from the home menu; only one
//  owns the radios at a time:
//    • TUNNEL R.A.T. — field wardrive sensor (WiFi/BLE/LoRa-mesh/nRF24,
//        GPS-tagged, SD-first, uploads to the NanoPi) + dashboard remote.
//    • WIFI ATTACKS — Bruce-style: deauth, beacon spam, probe/beacon sniff,
//        karma. (tr_wifi_attacks.h)   AUTHORIZED / OWN-NETWORK ONLY.
//    • CONTACTS — encrypted vault (tr_contacts.h)
//    • (coming) EVIL PORTAL + capture · BLE · NFC + BadUSB · COMMS
//
//  cyberchuck01 · Authorized / own-network use only.
//  --------------------------------------------------------------------------
//  BUILD: Board "LilyGo-T-LoRa-Pager", Board Revision = your radio,
//  USB CDC On Boot: Enabled (required: nRF24 uses GPIO43/44), Partition
//  "16M Flash (3MB APP/9.9MB FATFS)", USB Mode: Hardware CDC and JTAG.
//  LIBS: LilyGoLib + LilyGoLib-ThirdParty (LVGL 9.x / RadioLib / NimBLE 2.x),
//        ArduinoJson, Crypto (vault). nRF24 needs NO extra library.
//
//  THREADING RULE (this build's crash fix): LVGL, SD and SPI-radio calls
//  happen ONLY on the Arduino loop task. Radio callbacks (NimBLE, WiFi)
//  just queue small records; loop() does everything else.
// ===========================================================================

// LilyGoLib first: it puts LilyGoLib's lv_conf.h on the include path before
// any header pulls in lvgl.h.
#include <LilyGoLib.h>
#include "tr_platform.h"
#include "config.h"
#include "tr_wifi_attacks.h"
#include "tr_contacts.h"
#if TR_NRF24_ENABLE
#include "tr_nrf24.h"
#endif
#include "tr_nfc.h"
#if TR_CC1101_ENABLE
#include "tr_cc1101.h"
#endif

#include <LV_Helper.h>
#include <lvgl.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <HTTPClient.h>
#include <NimBLEDevice.h>
#include <ArduinoJson.h>
#include <SD.h>
#include <SPI.h>
#include <RadioLib.h>
#include <vector>
#include "esp_system.h"
#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"

// --- Grafted feature modes (self-contained; after LilyGoLib + system headers) ---
#include "tr_evilportal.h"   // evilportal::  open captive portal + credential capture
#include "tr_ble.h"          // ble::         BLE scan + proximity spam
#include "tr_nfc_reader.h"   // nfc::         NFC read + write (RFAL / app_nfc backend)
#include "tr_comms.h"        // comms::       Curve25519 encrypted DM over ESP-NOW
#include "tr_rf_nrf24.h"     // nrfscan::     nRF24 2.4 GHz scan + radar (standalone)
#include "tr_rf_wifibt.h"    // wifiradar:: / btradar::  WiFi & BT scan + radar
#include "tr_rf_cc1101.h"    // ccradar::     CC1101 sub-GHz scan + radar
#include "tr_mp3.h"          // mp3player::   SD-card MP3 player (minimp3 decoder)
#include "tr_splash_img.h"   // baked tunnel-rat logo (lv_image_dsc_t tr_splash_img)

#if TR_NRF24_ENABLE && defined(ARDUINO_USB_CDC_ON_BOOT) && !ARDUINO_USB_CDC_ON_BOOT
#error "nRF24 uses GPIO43/44 (UART0). Set Tools > USB CDC On Boot: Enabled, or set TR_NRF24_ENABLE 0 in config.h."
#endif

// ===========================================================================
//  BOARD BRING-UP  (verify against your LilyGoLib example)
// ===========================================================================
// Radio is a global RadioLib object (SX1262/LR1121/... per Board Revision),
// brought up by instance.begin(). GPS is instance.gps (TinyGPS-style fields),
// also initialised inside instance.begin().
#define RADIO        radio

// Shared-SPI lock, expander write, GpsSnap/gps_snapshot: see tr_platform.h

// ===========================================================================
//  Modes
// ===========================================================================
enum Mode { MODE_LAUNCHER, MODE_TUNNELRAT, MODE_PAGER_WD, MODE_WIFI_ATTACKS, MODE_CONTACTS,
            MODE_NFC, MODE_EVILPORTAL, MODE_BLE, MODE_COMMS, MODE_NRF24,
            MODE_WIFIRADAR, MODE_BTRADAR, MODE_CC1101, MODE_SETTINGS, MODE_SDEXP, MODE_MP3 };
static Mode g_mode = MODE_LAUNCHER;

static lv_obj_t *g_scr_launcher = nullptr;   // persistent home screen
static lv_obj_t *g_scr_mode     = nullptr;   // current mode's screen (created on enter)

// ===========================================================================
//  Tunnel R.A.T. (wardrive/remote) state
// ===========================================================================
enum Layer { L_WIFI, L_BLE, L_MESH, L_FLOCK, L_AXON, L_MOTOROLA };
const char* LAYER_NAME[] = {"wifi","ble","mesh","flock","axon","motorola"};

struct Sighting {
  uint8_t layer; char mac[18]; char name[33];
  int16_t rssi; int16_t chan; double lat, lon, alt; uint32_t ts; bool gps_valid=false; bool alt_valid=false; bool utc_valid=false; char utc[25]="";
};
struct Counts { uint32_t wifi=0,ble=0,mesh=0,flock=0,axon=0,motorola=0,nrf24=0,nrf24act=0,nfc=0,cc1101=0,
                 wifiWigle=0,bleWigle=0,wifiNoFix=0,bleNoFix=0; } g_count;
struct GpsState { bool valid=false; double lat=0,lon=0,alt=0; uint8_t sats=0; } g_gps;

static volatile bool g_wardriving=false;
bool g_uplink=false, g_sdOk=false;
uint32_t g_lastWifi=0, g_lastBle=0, g_lastUpload=0;
WiFiUDP g_udp;
bool g_trRadios=false;   // are the wardrive radios (BLE/mesh) currently up?
static char g_session[9]="";              // random id per START, stamped on every record
static esp_reset_reason_t g_resetReason = ESP_RST_UNKNOWN;

// UI handles (all nulled in pagerwd_exit / remote_exit before the screen is deleted)
static lv_obj_t *lbl_gps=nullptr, *lbl_uplink=nullptr, *lbl_counts=nullptr, *lbl_status=nullptr;
static lv_obj_t *lbl_wd_state=nullptr, *list_hits=nullptr, *lbl_mesh=nullptr, *lbl_remote=nullptr;
static lv_obj_t *g_tv=nullptr;
static lv_obj_t *wd_checks[5]={nullptr,nullptr,nullptr,nullptr,nullptr};
static lv_obj_t *wd_counters[5]={nullptr,nullptr,nullptr,nullptr,nullptr};
static lv_obj_t *wd_gps=nullptr, *wd_start=nullptr, *wd_stop=nullptr;
static volatile bool wd_enabled[5]={true,true,true,false,false}; // WiFi BLE Mesh nRF24 NFC
static void wd_set_running(bool run);

// shared styles
static lv_style_t st_accent, st_dim;
static lv_group_t *g_nav_group = nullptr;
static lv_obj_t *g_launcher_first = nullptr;
static lv_style_t st_focus;

// Bind LilyGo's LVGL encoder/keyboard input devices to the current screen.
static void nav_bind_inputs() {
  if (!g_nav_group) return;
  lv_indev_t *dev = nullptr;
  while ((dev = lv_indev_get_next(dev)) != nullptr) {
    lv_indev_type_t type = lv_indev_get_type(dev);
    if (type == LV_INDEV_TYPE_ENCODER || type == LV_INDEV_TYPE_KEYPAD)
      lv_indev_set_group(dev, g_nav_group);
  }
}

static void nav_add(lv_obj_t *obj) {
  if (!g_nav_group || !obj) return;
  lv_group_add_obj(g_nav_group, obj);
  lv_obj_add_style(obj, &st_focus, LV_STATE_FOCUSED);
  // Keyboard Enter should select like the encoder press. The keypad delivers
  // the raw char ('\r' = 13), which is NOT LVGL's LV_KEY_ENTER (10), so map it
  // to a click here. Text fields are skipped so typing/Enter still works there.
  lv_obj_add_event_cb(obj, [](lv_event_t *e){
    lv_obj_t *t = (lv_obj_t*)lv_event_get_target(e);
    if (lv_obj_check_type(t, &lv_textarea_class)) return;
    if (lv_event_get_key(e) == 13) lv_obj_send_event(t, LV_EVENT_CLICKED, NULL);
  }, LV_EVENT_KEY, NULL);
}

static void nav_begin_screen() {
  if (g_nav_group) { lv_group_remove_all_objs(g_nav_group); }
  else { g_nav_group = lv_group_create(); }
  nav_bind_inputs();
  lv_group_set_wrap(g_nav_group, true);
}

// Collect clickable widgets for encoder/keyboard navigation on mode screens.
static void nav_collect(lv_obj_t *parent) {
  uint32_t count = lv_obj_get_child_count(parent);
  for (uint32_t i = 0; i < count; ++i) {
    lv_obj_t *child = lv_obj_get_child(parent, i);
    if (lv_obj_has_flag(child, LV_OBJ_FLAG_CLICKABLE) &&
        !lv_obj_has_state(child, LV_STATE_DISABLED)) nav_add(child);
    nav_collect(child);
  }
}


// fwd decls
static void back_to_launcher();
static void enter_mode(Mode m);
static void refresh_remote();
static const char *reset_reason_str(esp_reset_reason_t r);
static bool reset_was_abnormal();

// ---------------------------------------------------------------------------
//  Styles
// ---------------------------------------------------------------------------
static void ui_style_init() {
  lv_style_init(&st_accent);
  lv_style_set_text_color(&st_accent, lv_color_hex(TR_THEME_GREEN));
  lv_style_set_text_font(&st_accent, &lv_font_montserrat_16);
  lv_style_init(&st_focus);
  lv_style_set_outline_color(&st_focus, lv_color_hex(0x00FF66));
  lv_style_set_outline_width(&st_focus, 2);
  lv_style_set_outline_pad(&st_focus, 2);
  lv_style_set_bg_color(&st_focus, lv_color_hex(0x12452A));
  lv_style_init(&st_dim);
  lv_style_set_text_color(&st_dim, lv_color_hex(0x7A8A7A));
  lv_style_set_text_font(&st_dim, &lv_font_montserrat_14);
}

// A small "< back" button pinned to a mode screen's top-right.
// The return to the launcher is deferred with lv_async_call so the mode
// screen (which owns this button) is never deleted inside its own event.
static bool g_backPending = false;
static void back_async(void *) { g_backPending = false; back_to_launcher(); }
static void add_back_button(lv_obj_t *scr) {
  lv_obj_t *b = lv_button_create(scr);
  lv_obj_set_size(b, 40, 22);
  lv_obj_align(b, LV_ALIGN_TOP_RIGHT, -2, -2);
  lv_obj_set_style_bg_color(b, lv_color_hex(0x223322), 0);
  lv_obj_t *l = lv_label_create(b); lv_label_set_text(l, LV_SYMBOL_LEFT); lv_obj_center(l);
  lv_obj_add_event_cb(b, [](lv_event_t*){
    if (!g_backPending) { g_backPending = true; lv_async_call(back_async, nullptr); }
  }, LV_EVENT_CLICKED, NULL);
}

// ===========================================================================
//  LAUNCHER (home menu)
// ===========================================================================
static void launcher_select_cb(lv_event_t *e) {
  Mode m = (Mode)(intptr_t)lv_event_get_user_data(e);
  enter_mode(m);
}

// --- menu organization: top-level folders, each holding related tools -------
enum Cat { CAT_HUNT=0, CAT_ATTACK, CAT_RECON, CAT_NFC, CAT_SECURE, CAT_SYSTEM };
struct Folder { int id; const char *name; const char *txt; };
static const Folder FOLDERS[] = {
  {CAT_HUNT,   "Signal Hunt",      LV_SYMBOL_WIFI     "  Signal Hunt        " LV_SYMBOL_RIGHT},
  {CAT_ATTACK, "Attacks",          LV_SYMBOL_WARNING  "  Attacks            " LV_SYMBOL_RIGHT},
  {CAT_RECON,  "Wardrive + Recon", LV_SYMBOL_GPS      "  Wardrive + Recon   " LV_SYMBOL_RIGHT},
  {CAT_NFC,    "NFC",              LV_SYMBOL_SD_CARD  "  NFC read / write   " LV_SYMBOL_RIGHT},
  {CAT_SECURE, "Comms + Vault",    LV_SYMBOL_CALL     "  Comms + Vault      " LV_SYMBOL_RIGHT},
  {CAT_SYSTEM, "System",           LV_SYMBOL_SETTINGS "  System             " LV_SYMBOL_RIGHT},
};
struct LItem { const char *txt; Mode m; bool on; int cat; };
static const LItem LITEMS[] = {
  // Signal Hunt
  {LV_SYMBOL_WIFI      "  nRF24 - scan + radar",          MODE_NRF24,        true,                 CAT_HUNT},
  {LV_SYMBOL_WIFI      "  WiFi - scan + radar",           MODE_WIFIRADAR,    true,                 CAT_HUNT},
  {LV_SYMBOL_BLUETOOTH " BT - scan + radar",              MODE_BTRADAR,      true,                 CAT_HUNT},
  {LV_SYMBOL_WIFI      "  CC1101 - scan + radar",         MODE_CC1101,       true,                 CAT_HUNT},
  // Attacks
  {LV_SYMBOL_WARNING   "  WiFi Attacks",                  MODE_WIFI_ATTACKS, true,                 CAT_ATTACK},
  {LV_SYMBOL_WIFI      "  Evil Portal + Capture",         MODE_EVILPORTAL,   true,                 CAT_ATTACK},
  {LV_SYMBOL_BLUETOOTH " BLE Tools",                      MODE_BLE,          true,                 CAT_ATTACK},
  // Wardrive + Recon
  {LV_SYMBOL_GPS       "  Pager Wardrive (standalone)",   MODE_PAGER_WD,     true,                 CAT_RECON},
  {LV_SYMBOL_SD_CARD   "  NFC Reader (read + write)",     MODE_NFC,          true,                 CAT_NFC},
  {LV_SYMBOL_WIFI      "  Tunnel R.A.T. Remote (NanoPi)", MODE_TUNNELRAT,    true,                 CAT_RECON},
  // Comms + Vault
  {LV_SYMBOL_CALL      "  Comms (encrypted DM)",          MODE_COMMS,        true,                 CAT_SECURE},
  {LV_SYMBOL_LIST      "  Contacts (encrypted vault)",    MODE_CONTACTS,     (bool)TR_VAULT_ENABLE, CAT_SECURE},
  // System
  {LV_SYMBOL_SETTINGS  " Settings (theme + brightness)",  MODE_SETTINGS,     true,                 CAT_SYSTEM},
  {LV_SYMBOL_DRIVE     "  SD Explorer (file manager)",    MODE_SDEXP,        true,                 CAT_SYSTEM},
  {LV_SYMBOL_AUDIO     "  Music Player (MP3)",            MODE_MP3,          true,                 CAT_SYSTEM},
};

static lv_obj_t *g_launcher_list=nullptr;
static lv_obj_t *g_launcher_title=nullptr;
static char      g_homeTitle[96]="TUNNEL R.A.T. // T-Pager";
static int       g_launchFolder=-1;          // -1 = top level, else a Cat value
static int       g_launchPending=-1;
static bool      g_launchNavPending=false;

static void launcher_fill();
static void launcher_goto(int cat);
static void launcher_folder_cb(lv_event_t *e){ launcher_goto((int)(intptr_t)lv_event_get_user_data(e)); }
static void launcher_back_cb(lv_event_t *){ launcher_goto(-1); }

// Populate the (already-created) list for the current folder. Adds no nav here;
// the caller resets the nav group and collects, same as the SD manager.
static void launcher_fill(){
  if(!g_launcher_list) return;
  lv_obj_clean(g_launcher_list);
  g_launcher_first=nullptr;

  if(g_launchFolder<0){                                   // top level: folders
    if(g_launcher_title) lv_label_set_text(g_launcher_title,g_homeTitle);
    for(auto &f:FOLDERS){
      lv_obj_t *b=lv_list_add_button(g_launcher_list,NULL,f.txt);
      lv_obj_set_style_bg_color(b,lv_color_hex(0x081208),0);
      lv_obj_set_style_text_color(b,lv_color_hex(TR_THEME_GREEN),0);
      lv_obj_add_event_cb(b,launcher_folder_cb,LV_EVENT_CLICKED,(void*)(intptr_t)f.id);
      if(!g_launcher_first) g_launcher_first=b;
    }
  } else {                                                // inside a folder
    const char *fname="";
    for(auto &f:FOLDERS) if(f.id==g_launchFolder) fname=f.name;
    if(g_launcher_title) lv_label_set_text(g_launcher_title,fname);
    lv_obj_t *bk=lv_list_add_button(g_launcher_list,LV_SYMBOL_LEFT," Back");
    lv_obj_set_style_bg_color(bk,lv_color_hex(0x0A0A0A),0);
    lv_obj_set_style_text_color(bk,lv_color_hex(0xB8B8B8),0);
    lv_obj_add_event_cb(bk,launcher_back_cb,LV_EVENT_CLICKED,nullptr);
    g_launcher_first=bk;
    for(auto &it:LITEMS){
      if(it.cat!=g_launchFolder) continue;
      lv_obj_t *b=lv_list_add_button(g_launcher_list,NULL,it.txt);
      lv_obj_set_style_bg_color(b,lv_color_hex(0x081208),0);
      lv_obj_set_style_text_color(b,lv_color_hex(TR_THEME_GREEN),0);
      if(it.on) lv_obj_add_event_cb(b,launcher_select_cb,LV_EVENT_CLICKED,(void*)(intptr_t)it.m);
      else      lv_obj_set_style_text_color(b,lv_color_hex(0x445544),0);
    }
  }
}
static void launcher_refocus(){
  if(!g_scr_launcher) return;
  nav_begin_screen();
  nav_collect(g_scr_launcher);
  if(g_launcher_first) lv_group_focus_obj(g_launcher_first);
  lv_group_set_editing(g_nav_group,false);
}
static void launcher_nav_async(void*){
  g_launchNavPending=false; g_launchFolder=g_launchPending;
  if(!g_scr_launcher||!g_launcher_list) return;
  launcher_fill();
  launcher_refocus();
}
static void launcher_goto(int cat){                       // deferred: never clean the list inside a row's own event
  if(g_launchNavPending) return;
  g_launchPending=cat; g_launchNavPending=true;
  lv_async_call(launcher_nav_async,nullptr);
}

static void build_launcher() {
  g_launcher_first=nullptr;
  g_scr_launcher=lv_obj_create(NULL);
  lv_obj_set_style_bg_color(g_scr_launcher,lv_color_hex(TR_THEME_BG),0);
  lv_obj_set_style_text_color(g_scr_launcher,lv_color_hex(TR_THEME_GREEN),0);

  if(reset_was_abnormal()) snprintf(g_homeTitle,sizeof g_homeTitle,"TUNNEL R.A.T. // T-Pager   (last reset: %s)",reset_reason_str(g_resetReason));
  else                     strcpy(g_homeTitle,"TUNNEL R.A.T. // T-Pager");

  g_launcher_title=lv_label_create(g_scr_launcher);
  lv_label_set_text(g_launcher_title,g_homeTitle);
  lv_obj_add_style(g_launcher_title,&st_accent,0);
  lv_obj_align(g_launcher_title,LV_ALIGN_TOP_MID,0,2);

  g_launcher_list=lv_list_create(g_scr_launcher);
  lv_obj_set_size(g_launcher_list,lv_pct(100),lv_pct(82));
  lv_obj_align(g_launcher_list,LV_ALIGN_BOTTOM_MID,0,0);
  lv_obj_set_style_bg_color(g_launcher_list,lv_color_hex(0x050905),0);

  launcher_fill();                 // builds for current g_launchFolder (-1 on boot)
  nav_begin_screen();
  nav_collect(g_scr_launcher);
  if(g_launcher_first) lv_group_focus_obj(g_launcher_first);
}


// ===========================================================================
//  Shared UI helpers
// ===========================================================================
static lv_obj_t* make_tab_label(lv_obj_t *p, const char *txt) {
  lv_obj_t *l = lv_label_create(p); lv_label_set_text(l, txt);
  lv_obj_add_style(l, &st_dim, 0); lv_obj_set_width(l, lv_pct(100)); return l;
}
static lv_obj_t* make_button(lv_obj_t *parent, const char *txt, uint32_t bg, lv_event_cb_t cb, void *ud) {
  lv_obj_t *b = lv_button_create(parent);
  lv_obj_set_height(b, 32);
  lv_obj_set_flex_grow(b, 1);
  lv_obj_set_style_bg_color(b, lv_color_hex(bg), 0);
  lv_obj_t *l = lv_label_create(b); lv_label_set_text(l, txt); lv_obj_center(l);
  if (cb) lv_obj_add_event_cb(b, cb, LV_EVENT_CLICKED, ud);
  return b;
}
static lv_obj_t* make_row(lv_obj_t *parent, int h) {
  lv_obj_t *r = lv_obj_create(parent);
  lv_obj_set_size(r, lv_pct(100), h);
  lv_obj_set_flex_flow(r, LV_FLEX_FLOW_ROW);
  lv_obj_set_style_pad_all(r, 2, 0);
  lv_obj_set_style_pad_column(r, 4, 0);
  lv_obj_set_style_bg_color(r, lv_color_hex(0x0E190E), 0);
  lv_obj_set_style_border_width(r, 0, 0);
  lv_obj_remove_flag(r, LV_OBJ_FLAG_SCROLLABLE);
  return r;
}

static void ble_scan_tick();
static void mesh_begin();
static void nrf_sensor_start();
static void nrf_sensor_stop();
static void nfc_sensor_start();
static void nfc_sensor_stop();
static void wd_stop_ble_scan();
static void wd_stop_wifi_scan();
static void quick_action_cb(lv_event_t *e);

// ---------------------------------------------------------------------------
//  Header "radio slot": an nRF24 OR a CC1101, detected on entering the mode
// ---------------------------------------------------------------------------
enum HdrKind { HDR_NONE = 0, HDR_NRF24 = 1, HDR_CC1101 = 2 };
static HdrKind g_hdr = HDR_NONE;
static const char *hdr_name(){ return g_hdr==HDR_NRF24?"nRF24":g_hdr==HDR_CC1101?"CC1101":"Header radio"; }
static void hdr_probe(){
  if(g_wardriving) return;
  g_hdr=HDR_NONE;
#if TR_NRF24_ENABLE
  if(nrf::probe()){ g_hdr=HDR_NRF24; return; }
#endif
#if TR_CC1101_ENABLE
  if(cc::probe()) g_hdr=HDR_CC1101;
#endif
}
static void hdr_start(){
  if(g_hdr==HDR_NRF24) nrf_sensor_start();
#if TR_CC1101_ENABLE
  else if(g_hdr==HDR_CC1101) cc::start();
#endif
}
static void hdr_stop(){
  nrf_sensor_stop();
#if TR_CC1101_ENABLE
  cc::stop();
#endif
}
static bool sensor_usable(int i){
  if(i<0||i>4) return false;
  if(i==3) return g_hdr!=HDR_NONE;
  if(i==4) return trnfc::available();
  return true;
}

// ===========================================================================
//  PAGER WARDRIVE — standalone screen (Pager GPS + Pager radios -> SD only)
// ===========================================================================
static lv_obj_t *g_sel = nullptr;      // sensor selection window (overlay)
static lv_obj_t *lbl_sel = nullptr;    // "Sensors: ..." summary line

static void wd_start_cb(lv_event_t *e){ wd_set_running(true); }
static void wd_stop_cb(lv_event_t *e){ wd_set_running(false); }

static void sel_summary(){
  if(!lbl_sel) return;
  char s[96]; size_t p=0; s[0]=0;
  const char *nm[5]={"WiFi","BLE","Mesh",hdr_name(),"NFC"};
  for(int i=0;i<5;i++) if(wd_enabled[i]&&sensor_usable(i)) p+=snprintf(s+p,sizeof(s)-p,"%s%s",p?" + ":"",nm[i]);
  lv_label_set_text_fmt(lbl_sel,"Sensors: %s",p?s:"none selected");
}

static void wd_sensor_cb(lv_event_t *e){
  int i=(int)(intptr_t)lv_event_get_user_data(e);
  if(!sensor_usable(i)||!wd_checks[i]) return;
  wd_enabled[i]=lv_obj_has_state(wd_checks[i],LV_STATE_CHECKED);
  if(g_wardriving){                   // live changes while a session runs
    if(i==0&&!wd_enabled[0])wd_stop_wifi_scan();
    if(i==1){ if(wd_enabled[1])ble_scan_tick(); else wd_stop_ble_scan(); }
    if(i==2&&wd_enabled[2])mesh_begin();
    if(i==3){ if(wd_enabled[3])hdr_start(); else hdr_stop(); }
    if(i==4){ if(wd_enabled[4])nfc_sensor_start(); else nfc_sensor_stop(); }
  }
  sel_summary();
}

static void sel_close_async(void *){
  if(!g_sel) return;
  lv_obj_t *o=g_sel; g_sel=nullptr;
  for(int i=0;i<5;i++) wd_checks[i]=nullptr;
  nav_begin_screen();
  lv_obj_delete(o);
  if(g_scr_mode) nav_collect(g_scr_mode);
  if(wd_start && !lv_obj_has_state(wd_start,LV_STATE_DISABLED)) lv_group_focus_obj(wd_start);
  sel_summary();
}
static void sel_done_cb(lv_event_t *){ lv_async_call(sel_close_async,nullptr); }

static void sel_open_cb(lv_event_t *){
  if(g_sel||!g_scr_mode) return;
  g_sel=lv_obj_create(g_scr_mode);
  lv_obj_set_size(g_sel,lv_pct(100),lv_pct(100));
  lv_obj_align(g_sel,LV_ALIGN_CENTER,0,0);
  lv_obj_set_style_bg_color(g_sel,lv_color_hex(0x050A05),0);
  lv_obj_set_style_bg_opa(g_sel,LV_OPA_COVER,0);
  lv_obj_set_style_border_color(g_sel,lv_color_hex(TR_THEME_GREEN),0);
  lv_obj_set_style_border_width(g_sel,1,0);
  lv_obj_set_flex_flow(g_sel,LV_FLEX_FLOW_COLUMN);
  lv_obj_set_style_pad_row(g_sel,2,0);
  lv_obj_set_style_pad_all(g_sel,6,0);

  lv_obj_t *t=lv_label_create(g_sel);
  lv_label_set_text(t,"SELECT SENSORS TO WARDRIVE");
  lv_obj_add_style(t,&st_accent,0);

  char hdrTxt[48];
  if(g_hdr==HDR_NRF24)       snprintf(hdrTxt,sizeof hdrTxt,"nRF24  (header, 2.4 GHz)");
  else if(g_hdr==HDR_CC1101) snprintf(hdrTxt,sizeof hdrTxt,"CC1101  (header, sub-GHz)");
  else                       snprintf(hdrTxt,sizeof hdrTxt,"nRF24 / CC1101  (none found)");
  const char *nfcTxt = trnfc::available()?"NFC  (tap tags)":(TR_NFC_ENABLE?"NFC  (update LilyGoLib)":"NFC  (off)");
  const char *names[5]={"Wi-Fi","Bluetooth","LoRa Mesh",hdrTxt,nfcTxt};
  const int order[5]={0,1,4,3,2};      // WiFi, BT, NFC, header radio, mesh
  for(int k=0;k<5;k++){
    int i=order[k];
    wd_checks[i]=lv_checkbox_create(g_sel);
    lv_checkbox_set_text(wd_checks[i],names[i]);
    if(!sensor_usable(i)) { wd_enabled[i]=false; lv_obj_add_state(wd_checks[i],LV_STATE_DISABLED); }
    else lv_obj_add_event_cb(wd_checks[i],wd_sensor_cb,LV_EVENT_VALUE_CHANGED,(void*)(intptr_t)i);
    if(wd_enabled[i]) lv_obj_add_state(wd_checks[i],LV_STATE_CHECKED);
  }
  lv_obj_t *done=lv_button_create(g_sel);
  lv_obj_set_size(done,lv_pct(100),32);
  lv_obj_set_style_bg_color(done,lv_color_hex(0x1C6B34),0);
  lv_obj_t *dl=lv_label_create(done); lv_label_set_text(dl,LV_SYMBOL_OK "  DONE"); lv_obj_center(dl);
  lv_obj_add_event_cb(done,sel_done_cb,LV_EVENT_CLICKED,NULL);

  nav_begin_screen();
  nav_collect(g_sel);
  for(int k=0;k<5;k++){ int i=order[k]; if(sensor_usable(i)){ lv_group_focus_obj(wd_checks[i]); break; } }
}

static void build_pagerwd(lv_obj_t *root){
  lv_obj_t *col=lv_obj_create(root);
  lv_obj_set_size(col,lv_pct(100),lv_pct(100));
  lv_obj_set_flex_flow(col,LV_FLEX_FLOW_COLUMN);
  lv_obj_set_style_pad_all(col,4,0);
  lv_obj_set_style_pad_row(col,3,0);
  lv_obj_set_style_bg_color(col,lv_color_hex(TR_THEME_BG),0);
  lv_obj_set_style_bg_opa(col,LV_OPA_COVER,0);
  lv_obj_set_style_border_width(col,0,0);
  lv_obj_set_scroll_dir(col,LV_DIR_VER);

  lbl_wd_state=lv_label_create(col);
  lv_obj_add_style(lbl_wd_state,&st_accent,0);
  lv_label_set_text(lbl_wd_state,g_wardriving?"PAGER WARDRIVE  - RUNNING":"PAGER WARDRIVE  - STOPPED");

  wd_gps=lv_label_create(col);
  lv_label_set_text(wd_gps,"GPS: SEARCHING (scanning still allowed)");
  lv_obj_set_style_text_color(wd_gps,lv_color_hex(0xF0C64B),0);

  lbl_sel=make_tab_label(col,"Sensors: ");
  lv_label_set_long_mode(lbl_sel,LV_LABEL_LONG_DOT);

  lv_obj_t *btns=make_row(col,40);
  make_button(btns,LV_SYMBOL_LIST " SENSORS",0x173017,sel_open_cb,nullptr);
  wd_start=make_button(btns,LV_SYMBOL_PLAY " START",0x1C6B34,wd_start_cb,nullptr);
  wd_stop =make_button(btns,LV_SYMBOL_STOP " STOP & SAVE",0xA52A2A,wd_stop_cb,nullptr);
  if(g_wardriving) lv_obj_add_state(wd_start,LV_STATE_DISABLED);
  else             lv_obj_add_state(wd_stop,LV_STATE_DISABLED);

  lv_obj_t *cnt=make_row(col,46);
  const char *cn[5]={"WiFi","BLE","NFC",hdr_name(),"Mesh"};
  const int   ci[5]={0,1,4,3,2};
  for(int k=0;k<5;k++){
    int i=ci[k];
    wd_counters[i]=lv_label_create(cnt);
    lv_obj_set_flex_grow(wd_counters[i],1);
    lv_obj_add_style(wd_counters[i],&st_accent,0);
    lv_label_set_text_fmt(wd_counters[i],"%s\n%s",cn[k],sensor_usable(i)?"0":"N/A");
  }

  list_hits=lv_list_create(col);
  lv_obj_set_size(list_hits,lv_pct(100),110);
  lv_obj_set_style_bg_color(list_hits,lv_color_hex(0x0E120E),0);
  sel_summary();
}

// ===========================================================================
//  TUNNEL R.A.T. REMOTE — joins the NanoPi AP, drives the NanoPi's wardrive
// ===========================================================================
static lv_obj_t *lbl_nwd=nullptr;   // NanoPi wardrive status/output

// POST a command to the dashboard's key-protected CLI. Returns HTTP code,
// fills out with the "output" field (or the raw body).
static int nanopi_cli(const char *cmd, String &out){
  out="";
  if(!g_uplink){ out="Not connected to the tunnel-rat AP."; return -1; }
  HTTPClient http; String url=String("http://")+TR_NANOPI_HOST+":"+TR_NANOPI_PORT+TR_NANOPI_CLI_PATH;
  http.setConnectTimeout(2000); http.setTimeout(15000);
  http.begin(url); http.addHeader("Content-Type","application/json"); http.addHeader("X-API-Key",TR_API_KEY);
  String body=String("{\"" TR_NANOPI_CLI_FIELD "\":\"")+cmd+"\"}";
  int code=http.POST(body);
  String resp = code>0 ? http.getString() : String("");
  http.end();
  DynamicJsonDocument doc(2048);
  if(resp.length() && deserializeJson(doc,resp)==DeserializationError::Ok && doc["output"].is<const char*>())
    out=(const char*)doc["output"];
  else out=resp;
  if(out.length()>400) out=out.substring(0,400)+"...";
  return code;
}
static void nwd_run(const char *label, const char *cmd){
  if(!lbl_nwd) return;
  lv_label_set_text_fmt(lbl_nwd,"%s: working...",label);
  lv_refr_now(NULL);                         // show "working" before the HTTP call blocks
  String out; int code=nanopi_cli(cmd,out);
  if(!lbl_nwd) return;
  if(code==200) lv_label_set_text_fmt(lbl_nwd,"%s: OK\n%s",label,out.c_str());
  else          lv_label_set_text_fmt(lbl_nwd,"%s: HTTP %d\n%s",label,code,out.c_str());
}
static void nwd_start_cb(lv_event_t*){ nwd_run("START ALL",TR_NANOPI_WD_START); }
static void nwd_stop_cb(lv_event_t*){  nwd_run("STOP ALL",TR_NANOPI_WD_STOP); }
static void nwd_stat_cb(lv_event_t*){  nwd_run("STATUS",TR_NANOPI_WD_STATUS); }

// ---- NanoPi remote tools (NETWORK / OSINT tabs) --------------------------
static lv_obj_t *g_netOut=nullptr, *g_osintOut=nullptr;
static const char *NET_TOOLS[][2]   = {{"LAN Scan","nmap-scan"},{"WiFi Scan","wifi-scan"},{"ARP","arp-table"},
                                       {"Ports","ports"},{"Routes","routes"},{"DNS","dns-test"}};
static const char *OSINT_TOOLS[][2] = {{"Ext IP","myip"},{"Real IP","myip-real"},{"Tor Start","tor-start"},
                                       {"Tor NewID","tor-newid"},{"Tor IP","tor-ip"},{"Tor Stat","tor-status"}};

// Run a dashboard action over /api/remote/run and show its output. Synchronous
// (same pattern as the other remote calls); a scan can take several seconds.
static void remote_tool(const char *action, lv_obj_t *outlbl){
  if(!outlbl) return;
  if(!g_uplink){ lv_label_set_text(outlbl,"Offline - join the " TR_AP_SSID " AP first (see HOME)."); return; }
  lv_label_set_text_fmt(outlbl,"Running: %s ...", action);
  lv_refr_now(NULL);                                 // paint "Running" before the blocking call
  HTTPClient http; String url=String("http://")+TR_NANOPI_HOST+":"+TR_NANOPI_PORT+"/api/remote/run";
  http.setConnectTimeout(2000); http.setTimeout(18000);
  http.begin(url);
  http.addHeader("Content-Type","application/json"); http.addHeader("X-API-Key",TR_API_KEY);
  int code=http.POST(String("{\"action\":\"")+action+"\"}");
  String resp = code>0 ? http.getString() : String("");
  http.end();
  if(code!=200){ lv_label_set_text_fmt(outlbl,"HTTP %d\n%s", code, resp.c_str()); return; }
  DynamicJsonDocument doc(6144);
  if(deserializeJson(doc, resp)!=DeserializationError::Ok){ lv_label_set_text(outlbl, resp.c_str()); return; }
  if(doc["output"].is<const char*>())     lv_label_set_text(outlbl, (const char*)doc["output"]);
  else if(doc["error"].is<const char*>()) lv_label_set_text_fmt(outlbl, "Error: %s", (const char*)doc["error"]);
  else                                    lv_label_set_text(outlbl, resp.c_str());
}
static void net_tool_cb(lv_event_t *e){ remote_tool((const char*)lv_event_get_user_data(e), g_netOut); }
static void osint_tool_cb(lv_event_t *e){ remote_tool((const char*)lv_event_get_user_data(e), g_osintOut); }

static void build_tool_tab(lv_obj_t *tab, bool net){
  lv_obj_set_flex_flow(tab, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_style_pad_row(tab, 4, 0);
  for(int row=0; row<2; row++){
    lv_obj_t *r = make_row(tab, 34);
    for(int c=0;c<3;c++){
      int i=row*3+c;
      const char *lbl = net ? NET_TOOLS[i][0] : OSINT_TOOLS[i][0];
      const char *act = net ? NET_TOOLS[i][1] : OSINT_TOOLS[i][1];
      make_button(r, lbl, 0x173017, net ? net_tool_cb : osint_tool_cb, (void*)act);
    }
  }
  lv_obj_t *out = lv_label_create(tab);
  lv_label_set_long_mode(out, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(out, lv_pct(100));
  lv_obj_add_style(out, &st_dim, 0);
  lv_label_set_text(out, net ? "Tap a network tool. Output appears here."
                             : "Tap an OSINT tool. Output appears here.");
  if(net) g_netOut=out; else g_osintOut=out;
}

static void build_remote(lv_obj_t *root){
  lv_obj_t *tv = lv_tabview_create(root);
  g_tv = tv;
  lv_tabview_set_tab_bar_size(tv, 26);
  lv_obj_set_style_bg_color(tv, lv_color_hex(TR_THEME_BG), 0);
  lv_obj_set_size(tv, lv_pct(100), lv_pct(100));
  lv_obj_t *t_home = lv_tabview_add_tab(tv, "HOME");
  lv_obj_t *t_wd   = lv_tabview_add_tab(tv, "WARDRIVE");
  lv_obj_t *t_net  = lv_tabview_add_tab(tv, "NETWORK");
  lv_obj_t *t_os   = lv_tabview_add_tab(tv, "OSINT");

  lv_obj_set_flex_flow(t_home,LV_FLEX_FLOW_COLUMN);
  lbl_status = lv_label_create(t_home);
  lv_label_set_text(lbl_status, "TUNNEL R.A.T. REMOTE"); lv_obj_add_style(lbl_status, &st_accent, 0);
  lbl_uplink = make_tab_label(t_home, "Uplink: joining " TR_AP_SSID "...");
  lbl_gps    = make_tab_label(t_home, "Pager GPS: no fix");
  lbl_remote = lv_label_create(t_home);
  lv_label_set_long_mode(lbl_remote, LV_LABEL_LONG_WRAP); lv_obj_set_width(lbl_remote, lv_pct(100));
  lv_obj_add_style(lbl_remote, &st_dim, 0);
  lv_label_set_text(lbl_remote, "Base station: connecting...");
  make_tab_label(t_home, "NETWORK + OSINT drive the NanoPi's tools and show output here;\n"
                         "WARDRIVE runs its radios. They work once uplink is CONNECTED.");

  lv_obj_set_flex_flow(t_wd,LV_FLEX_FLOW_COLUMN);
  make_tab_label(t_wd, "Starts/stops every wardrive module on the NanoPi.");
  lv_obj_t *r=make_row(t_wd,40);
  make_button(r,LV_SYMBOL_PLAY " START ALL",0x1C6B34,nwd_start_cb,nullptr);
  make_button(r,LV_SYMBOL_STOP " STOP ALL",0xA52A2A,nwd_stop_cb,nullptr);
  make_button(r,LV_SYMBOL_REFRESH " STATUS",0x173017,nwd_stat_cb,nullptr);
  lbl_nwd = make_tab_label(t_wd, "NanoPi wardrive: press STATUS");
  lv_label_set_long_mode(lbl_nwd, LV_LABEL_LONG_WRAP);

  build_tool_tab(t_net, true);
  build_tool_tab(t_os,  false);
}

static const char *reset_reason_str(esp_reset_reason_t r){
  switch(r){
    case ESP_RST_POWERON:  return "POWERON";
    case ESP_RST_EXT:      return "EXT";
    case ESP_RST_SW:       return "SW";
    case ESP_RST_PANIC:    return "PANIC";
    case ESP_RST_INT_WDT:  return "INT_WDT";
    case ESP_RST_TASK_WDT: return "TASK_WDT";
    case ESP_RST_WDT:      return "WDT";
    case ESP_RST_DEEPSLEEP:return "DEEPSLEEP";
    case ESP_RST_BROWNOUT: return "BROWNOUT";
    case ESP_RST_SDIO:     return "SDIO";
    default:               return "OTHER";
  }
}
static bool reset_was_abnormal(){
  return g_resetReason==ESP_RST_PANIC||g_resetReason==ESP_RST_INT_WDT||g_resetReason==ESP_RST_TASK_WDT||
         g_resetReason==ESP_RST_WDT||g_resetReason==ESP_RST_BROWNOUT;
}

static void ui_refresh_pagerwd() {
  if (g_mode != MODE_PAGER_WD || !wd_gps) return;
  char g[80];
  if (g_gps.valid) snprintf(g,sizeof g,"GPS: LOCKED  %.5f, %.5f  %dsat",g_gps.lat,g_gps.lon,g_gps.sats);
  else             snprintf(g,sizeof g,"GPS: SEARCHING (%d sat) - WiGLE rows wait for a fix",g_gps.sats);
  lv_label_set_text(wd_gps,g);
  lv_obj_set_style_text_color(wd_gps,lv_color_hex(g_gps.valid?0x53F59B:0xF0C64B),0);
  if(wd_counters[0]) lv_label_set_text_fmt(wd_counters[0],"WiFi\n%lu",(unsigned long)g_count.wifi);
  if(wd_counters[1]) lv_label_set_text_fmt(wd_counters[1],"BLE\n%lu",(unsigned long)g_count.ble);
  if(wd_counters[2]) lv_label_set_text_fmt(wd_counters[2],"Mesh\n%lu",(unsigned long)g_count.mesh);
  if(wd_counters[4]&&trnfc::available()) lv_label_set_text_fmt(wd_counters[4],"NFC\n%lu",(unsigned long)g_count.nfc);
  if(wd_counters[3]){
#if TR_NRF24_ENABLE
    if(g_hdr==HDR_NRF24)
      lv_label_set_text_fmt(wd_counters[3],"nRF %uch\n%lu",(unsigned)nrf::activeCount(),(unsigned long)g_count.nrf24);
#endif
#if TR_CC1101_ENABLE
    if(g_hdr==HDR_CC1101)
      lv_label_set_text_fmt(wd_counters[3],"CC1101 %uf\n%lu",(unsigned)cc::activeCount(),(unsigned long)g_count.cc1101);
#endif
  }
}
static void ui_refresh_remote() {
  if (g_mode != MODE_TUNNELRAT || !lbl_uplink) return;
  lv_label_set_text_fmt(lbl_uplink,"Uplink: %s", g_uplink?"CONNECTED to " TR_AP_SSID:"joining " TR_AP_SSID "...");
  if(lbl_gps){
    if(g_gps.valid) lv_label_set_text_fmt(lbl_gps,"Pager GPS: %.5f, %.5f  %dsat  %s",g_gps.lat,g_gps.lon,g_gps.sats,
                                          g_uplink?"-> feeding NanoPi":"(not feeding: offline)");
    else            lv_label_set_text_fmt(lbl_gps,"Pager GPS: searching (%d sat)",g_gps.sats);
  }
  if(lbl_status){
    if(reset_was_abnormal()) lv_label_set_text_fmt(lbl_status,"TUNNEL R.A.T. REMOTE  (last reset: %s)",reset_reason_str(g_resetReason));
  }
}

static void ui_push_row(const char *row, uint32_t color) {
  if (g_mode != MODE_PAGER_WD || !list_hits) return;
  if (lv_obj_get_child_count(list_hits) > 40) lv_obj_delete(lv_obj_get_child(list_hits,0));
  lv_obj_t *it=lv_list_add_text(list_hits,row);
  lv_obj_set_style_text_color(it,lv_color_hex(color),0);
}
static void ui_push_hit(const Sighting &s) {
  char row[80];
  snprintf(row,sizeof row,"%-5s %-16.16s %ddBm",LAYER_NAME[s.layer],s.name[0]?s.name:s.mac,s.rssi);
  ui_push_row(row, s.layer>=L_FLOCK?0xFF5252:s.layer==L_MESH?0x40C4FF:TR_THEME_GREEN);
}

// ===========================================================================
//  GPS snapshot (shared by every sensor record)
// ===========================================================================
// (GpsSnap + gps_snapshot() live in tr_platform.h)

// ===========================================================================
//  Record building (no heap, no ArduinoJson)
// ===========================================================================
// Appends src as JSON string content (no quotes). Returns new length.
static size_t j_esc(char *out, size_t pos, size_t cap, const char *src){
  for(const unsigned char *p=(const unsigned char*)src; *p && pos+7<cap; p++){
    unsigned char c=*p;
    if(c=='"'||c=='\\'){ out[pos++]='\\'; out[pos++]=c; }
    else if(c<0x20){ pos+=snprintf(out+pos,cap-pos,"\\u%04x",c); }
    else out[pos++]=c;
  }
  out[pos]=0; return pos;
}
static size_t j_add(char *out, size_t pos, size_t cap, const char *fmt, ...){
  if(pos>=cap) return pos;
  va_list ap; va_start(ap,fmt); int n=vsnprintf(out+pos,cap-pos,fmt,ap); va_end(ap);
  if(n<0) return pos;
  pos+= (size_t)n; if(pos>=cap) pos=cap-1;
  return pos;
}
// Appends a quoted CSV field: "..." with "" for quotes, CR/LF -> space.
static size_t csv_q(char *out, size_t pos, size_t cap, const char *src){
  if(pos+3>=cap) return pos;
  out[pos++]='"';
  for(const unsigned char *p=(const unsigned char*)(src?src:""); *p && pos+4<cap; p++){
    unsigned char c=*p;
    if(c=='"'){ out[pos++]='"'; out[pos++]='"'; }
    else if(c=='\r'||c=='\n'||c==0x09) out[pos++]=' ';
    else if(c<0x20) continue;
    else out[pos++]=c;
  }
  out[pos++]='"'; out[pos]=0; return pos;
}
// Shared JSON tail: time + GPS fields, identical on every JSONL record.
static size_t j_gps_tail(char *out, size_t pos, size_t cap, const GpsSnap &g, uint32_t ts){
  pos=j_add(out,pos,cap,",\"uptime_ms\":%lu,\"gps_valid\":%s",(unsigned long)ts,g.valid?"true":"false");
  if(g.utc_valid) pos=j_add(out,pos,cap,",\"timestamp_utc\":\"%s\"",g.utc);
  else            pos=j_add(out,pos,cap,",\"timestamp_utc\":null");
  if(g.valid) pos=j_add(out,pos,cap,",\"latitude\":%.7f,\"longitude\":%.7f",g.lat,g.lon);
  else        pos=j_add(out,pos,cap,",\"latitude\":null,\"longitude\":null");
  if(g.alt_valid) pos=j_add(out,pos,cap,",\"altitude_m\":%.1f",g.alt);
  else            pos=j_add(out,pos,cap,",\"altitude_m\":null");
  if(g.hdop_valid) pos=j_add(out,pos,cap,",\"hdop\":%.2f",g.hdop);
  else             pos=j_add(out,pos,cap,",\"hdop\":null");
  pos=j_add(out,pos,cap,",\"session\":\"%s\"}",g_session);
  return pos;
}
static double gps_accuracy_m(const GpsSnap &g){
  double a = g.hdop_valid ? g.hdop*TR_UERE_M : 10.0;
  return a<1.0 ? 1.0 : a;                       // WiGLE downweights 0 m claims
}
// Shared CSV tail for mesh/nfc: gps_valid,latitude,longitude,altitude_m,accuracy_m (blank when unknown)
static size_t csv_gps_tail(char *out, size_t pos, size_t cap, const GpsSnap &g){
  pos=j_add(out,pos,cap,",%d",g.valid?1:0);
  if(g.valid) pos=j_add(out,pos,cap,",%.7f,%.7f",g.lat,g.lon); else pos=j_add(out,pos,cap,",,");
  if(g.alt_valid) pos=j_add(out,pos,cap,",%.1f",g.alt); else pos=j_add(out,pos,cap,",");
  if(g.valid) pos=j_add(out,pos,cap,",%.1f",gps_accuracy_m(g)); else pos=j_add(out,pos,cap,",");
  return pos;
}
// "2026-11-19T04:12:00Z" -> "2026-11-19 04:12:00" (WiGLE FirstSeen)
static void utc_to_wigle(const char *iso, char *out, size_t cap){
  snprintf(out,cap,"%.10s %.8s",iso,iso+11);
}

// ===========================================================================
//  Session folder + per-sensor files, batched SD writer (loop task only)
// ===========================================================================
enum { SDF_RAW=0, SDF_WIFI, SDF_BLE, SDF_MESH, SDF_NRF24, SDF_NFC, SDF_CC1101, SDF_COUNT };
static const char *SDF_NAME[SDF_COUNT]={
  "raw_sightings.jsonl","wifi_wigle.csv","ble_wigle.csv","mesh.csv","nrf24.jsonl","nfc.csv","cc1101.csv" };
static const char WIGLE_HDR[] =
  "WigleWifi-1.6,appRelease=" TR_FW_VERSION ",model=" TR_WIGLE_DEVICE ",release=" TR_FW_VERSION
  ",device=" TR_NODE_NAME ",display=ST7796,board=ESP32-S3,brand=LILYGO,star=Sol,body=3,subBody=0\n"
  "MAC,SSID,AuthMode,FirstSeen,Channel,Frequency,RSSI,CurrentLatitude,CurrentLongitude,"
  "AltitudeMeters,AccuracyMeters,RCOIs,MfgrId,Type\n";
static const char *sdf_header(int f){
  switch(f){
    case SDF_WIFI: case SDF_BLE: return WIGLE_HDR;
    case SDF_MESH: return "timestamp_utc,uptime_ms,session,node_id,rssi_dbm,snr_db,freq_mhz,bw_khz,sf,"
                          "gps_valid,latitude,longitude,altitude_m,accuracy_m\n";
    case SDF_NFC:  return "timestamp_utc,uptime_ms,session,uid,technology,tag_type,card_type,ndef,record_count,"
                          "record_kinds,gps_valid,latitude,longitude,altitude_m,accuracy_m\n";
    case SDF_CC1101: return "timestamp_utc,uptime_ms,session,freq_mhz,active_sweeps,sweeps,max_rssi_dbm,"
                            "gps_valid,latitude,longitude,altitude_m,accuracy_m\n";
    default: return nullptr;
  }
}
static char     g_sessDir[72]="";
static char     g_sessStartUtc[25]="";
static const size_t SD_BUF_CAP=8192;
static char    *g_sdBuf[SDF_COUNT]={nullptr};
static size_t   g_sdLen[SDF_COUNT]={0};
static uint32_t g_sdLastFlush=0, g_sdErrors=0, g_sdDropped=0;

// returns: 1 written, 0 retry later, -1 data dropped
static int sd_flush_one(int f){
  if(!g_sdLen[f]) return 1;
  if(!g_sdOk || !g_sessDir[0]){ g_sdDropped+=g_sdLen[f]; g_sdLen[f]=0; return -1; }
  char path[112]; snprintf(path,sizeof path,"%s/%s",g_sessDir,SDF_NAME[f]);
  if(!tr_spi_lock()){ g_sdErrors++; return 0; }
  File fh=SD.open(path,FILE_APPEND);
  if(!fh){ tr_spi_unlock(); g_sdErrors++; return 0; }
  const char *hdr=sdf_header(f);
  if(hdr && fh.size()==0) fh.print(hdr);        // header once, when the file is new
  size_t w=fh.write((const uint8_t*)g_sdBuf[f],g_sdLen[f]);
  fh.close();
  tr_spi_unlock();
  if(w!=g_sdLen[f]){ g_sdErrors++; g_sdDropped+=g_sdLen[f]-w; }
  g_sdLen[f]=0;          // written (or partially written): never re-write, never duplicate
  return w? 1 : -1;
}
static bool sd_flush_all(){
  bool ok=true;
  for(int f=0;f<SDF_COUNT;f++) if(sd_flush_one(f)!=1) ok=false;
  g_sdLastFlush=millis();
  return ok;
}
static void sd_append(int f, const char *line, size_t n){
  if(!g_sdOk || !n || !g_sessDir[0]) return;
  if(!g_sdBuf[f]){
    g_sdBuf[f]=(char*)heap_caps_malloc(SD_BUF_CAP, MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT);
    if(!g_sdBuf[f]) g_sdBuf[f]=(char*)malloc(SD_BUF_CAP);
    if(!g_sdBuf[f]) { g_sdDropped+=n; return; }
  }
  if(n+1>SD_BUF_CAP){ g_sdDropped+=n; return; }
  if(g_sdLen[f]+n+1>SD_BUF_CAP){
    if(sd_flush_one(f)==0){ g_sdDropped+=g_sdLen[f]; g_sdLen[f]=0; }   // SD stuck: drop, don't block
  }
  memcpy(g_sdBuf[f]+g_sdLen[f],line,n); g_sdLen[f]+=n; g_sdBuf[f][g_sdLen[f]++]='\n';
}

// Creates /tunnelrat/sessions/<UTC>_<id> (or session_<id> without GPS time).
static bool session_open(){
  g_sessDir[0]=0; g_sessStartUtc[0]=0;
  if(!g_sdOk) return false;
  GpsSnap g; gps_snapshot(g);
  char name[40];
  if(g.utc_valid){
    strncpy(g_sessStartUtc,g.utc,sizeof g_sessStartUtc-1);
    // 2026-11-19T04:12:00Z -> 20261119-041200
    snprintf(name,sizeof name,"%.4s%.2s%.2s-%.2s%.2s%.2s_%s",g.utc,g.utc+5,g.utc+8,g.utc+11,g.utc+14,g.utc+17,g_session);
  } else snprintf(name,sizeof name,"session_%s",g_session);
  char dir[72]; snprintf(dir,sizeof dir,"%s/%s",TR_SESSIONS_DIR,name);
  bool ok=false;
  if(tr_spi_lock()){
    SD.mkdir(TR_SD_LOG_DIR); SD.mkdir(TR_SESSIONS_DIR);
    ok = SD.mkdir(dir) || SD.exists(dir);
    tr_spi_unlock();
  }
  if(ok) strncpy(g_sessDir,dir,sizeof g_sessDir-1); else g_sdErrors++;
  return ok;
}

// ===========================================================================
//  Observation pipeline (loop task only)
// ===========================================================================
static bool oui_in(const char *mac,const char *list){char p[7];int j=0;for(int i=0;mac[i]&&j<6;i++)if(mac[i]!=':')p[j++]=toupper(mac[i]);p[6]=0;return strstr(list,p)!=nullptr;}
static uint8_t classify(const char *mac){if(oui_in(mac,TR_OUI_FLOCK))return L_FLOCK;if(oui_in(mac,TR_OUI_AXON))return L_AXON;if(oui_in(mac,TR_OUI_MOTOROLA))return L_MOTOROLA;return 0xFF;}
static void bump(uint8_t l){switch(l){case L_WIFI:g_count.wifi++;break;case L_BLE:g_count.ble++;break;case L_MESH:g_count.mesh++;break;case L_FLOCK:g_count.flock++;break;case L_AXON:g_count.axon++;break;case L_MOTOROLA:g_count.motorola++;break;}}

// Re-observation limiter: fixed 512-slot table, no allocation.
struct SeenEntry { uint32_t h; uint32_t t; };
static SeenEntry g_seen[512];
static bool seen_recently(uint8_t layer, const char *id){
#if TR_REOBSERVE_MS > 0
  uint32_t h=2166136261u; for(const char *p=id;*p;p++){h^=(uint8_t)toupper(*p);h*=16777619u;}
  h^=(uint32_t)layer*0x9E3779B9u; if(!h)h=1;
  uint32_t now=millis(), idx=h&511; int victim=-1; uint32_t worst=0;
  for(int k=0;k<4;k++){
    SeenEntry &e=g_seen[(idx+k)&511];
    if(e.h==h){ if(now-e.t<TR_REOBSERVE_MS) return true; e.t=now; return false; }
    uint32_t age=e.h? now-e.t : 0xFFFFFFFFu;
    if(victim<0||age>=worst){worst=age;victim=(int)((idx+k)&511);}
  }
  g_seen[victim].h=h; g_seen[victim].t=now;
#endif
  return false;
}

// Android-style capability string, the layout WiGLE's own app uploads.
static const char *wifi_auth_str(int enc){
  switch(enc){
    case WIFI_AUTH_OPEN:            return "[ESS]";
    case WIFI_AUTH_WEP:             return "[WEP][ESS]";
    case WIFI_AUTH_WPA_PSK:         return "[WPA-PSK-CCMP+TKIP][ESS]";
    case WIFI_AUTH_WPA2_PSK:        return "[WPA2-PSK-CCMP][ESS]";
    case WIFI_AUTH_WPA_WPA2_PSK:    return "[WPA-PSK-CCMP+TKIP][WPA2-PSK-CCMP+TKIP][ESS]";
    case WIFI_AUTH_WPA2_ENTERPRISE: return "[WPA2-EAP-CCMP][ESS]";
    case WIFI_AUTH_WPA3_PSK:        return "[WPA3-SAE-CCMP][ESS]";
    case WIFI_AUTH_WPA2_WPA3_PSK:   return "[WPA2-PSK-CCMP][WPA3-SAE-CCMP][ESS]";
    case WIFI_AUTH_WAPI_PSK:        return "[WAPI-PSK][ESS]";
    case WIFI_AUTH_OWE:             return "[WPA3-OWE-CCMP][ESS]";
    default:                        return "[UNKNOWN][ESS]";
  }
}
static int wifi_freq_mhz(int ch){ return ch==14 ? 2484 : (ch>=1&&ch<=13) ? 2407+5*ch : (ch>=32 ? 5000+5*ch : 0); }

static void raw_log(const Sighting &s, const GpsSnap &g){
  static char line[512]; size_t p=0; const size_t cap=sizeof line;
  p=j_add(line,p,cap,"{\"layer\":\"%s\",\"mac\":\"",LAYER_NAME[s.layer]);
  p=j_esc(line,p,cap,s.mac);
  p=j_add(line,p,cap,"\",\"name\":\"");
  p=j_esc(line,p,cap,s.name);
  p=j_add(line,p,cap,"\",\"rssi\":%d,\"channel\":%d",s.rssi,s.chan);
  p=j_gps_tail(line,p,cap,g,s.ts);
  sd_append(SDF_RAW,line,p);
}

// WiGLE 1.6 row (wifi_wigle.csv / ble_wigle.csv). Needs a fix + GPS time.
static void wigle_log(bool isWifi, const char *mac, const char *name, const char *auth,
                      int chan, int rssi, int mfg, const GpsSnap &g){
  if(!(g.valid && g.utc_valid)){ if(isWifi) g_count.wifiNoFix++; else g_count.bleNoFix++; return; }
  static char line[400]; size_t p=0; const size_t cap=sizeof line;
  char m[18]; size_t i=0; for(; mac[i] && i<17; i++) m[i]=(char)tolower((unsigned char)mac[i]); m[i]=0;
  char seen[24]; utc_to_wigle(g.utc,seen,sizeof seen);
  p=j_add(line,p,cap,"%s,",m);
  p=csv_q(line,p,cap,name);
  if(isWifi)
    p=j_add(line,p,cap,",%s,%s,%d,%d,%d,%.7f,%.7f,%.1f,%.1f,,,WIFI",
            auth,seen,chan,wifi_freq_mhz(chan),rssi,g.lat,g.lon,g.alt_valid?g.alt:0.0,gps_accuracy_m(g));
  else {
    char mf[8]=""; if(mfg>=0) snprintf(mf,sizeof mf,"%d",mfg);
    p=j_add(line,p,cap,",Misc [LE],%s,0,0,%d,%.7f,%.7f,%.1f,%.1f,,%s,BLE",
            seen,rssi,g.lat,g.lon,g.alt_valid?g.alt:0.0,gps_accuracy_m(g),mf);
  }
  sd_append(isWifi?SDF_WIFI:SDF_BLE,line,p);
  if(isWifi) g_count.wifiWigle++; else g_count.bleWigle++;
}

static void mesh_log(const char *node, int rssi, float snr, const GpsSnap &g){
  static char line[320]; size_t p=0; const size_t cap=sizeof line;
  p=j_add(line,p,cap,"%s,%lu,%s,%s,%d,%.1f,%.3f,%.1f,%d",
          g.utc_valid?g.utc:"",(unsigned long)millis(),g_session,node,rssi,snr,
          (double)TR_MESH_FREQ_MHZ,(double)TR_MESH_BW_KHZ,TR_MESH_SF);
  p=csv_gps_tail(line,p,cap,g);
  sd_append(SDF_MESH,line,p);
}

// mfg: BLE company id or -1;  snr: mesh only (NAN otherwise)
static void add_sighting(uint8_t baseLayer,const char *mac,const char *name,int rssi,int chan,
                         const char *auth,int mfg,float snr){
  Sighting s{}; uint8_t sp=(baseLayer==L_WIFI||baseLayer==L_BLE)?classify(mac):0xFF;
  s.layer=(sp!=0xFF)?sp:baseLayer;
  strncpy(s.mac,mac,sizeof s.mac-1); strncpy(s.name,name?name:"",sizeof s.name-1);
  s.rssi=rssi; s.chan=chan; s.ts=millis();
  GpsSnap g; gps_snapshot(g);
  s.gps_valid=g.valid; s.alt_valid=g.alt_valid; s.utc_valid=g.utc_valid;
  if(g.valid){s.lat=g.lat;s.lon=g.lon;} if(g.alt_valid)s.alt=g.alt;
  if(g.utc_valid)strncpy(s.utc,g.utc,sizeof s.utc-1);
  raw_log(s,g);
  if(baseLayer==L_WIFI)      wigle_log(true, mac,name,auth?auth:"[UNKNOWN][ESS]",chan,rssi,-1,g);
  else if(baseLayer==L_BLE)  wigle_log(false,mac,name,nullptr,0,rssi,mfg,g);
  else if(baseLayer==L_MESH) mesh_log(mac,rssi,isnan(snr)?0.0f:snr,g);
  bump(baseLayer); if(sp!=0xFF)bump(sp); ui_push_hit(s);
}

// ===========================================================================
//  Uplink (NanoPi AP) — scheduled so it never fights the wardrive scan
// ===========================================================================
static uint32_t g_lastJoin=0;
static void uplink_tick(){
  g_uplink=(WiFi.status()==WL_CONNECTED);
#if TR_AUTO_JOIN_NANOPI
  if(g_uplink) return;
  if(WiFi.scanComplete()==WIFI_SCAN_RUNNING) return;      // never interrupt our own scan
  uint32_t now=millis();
  if(g_lastJoin && now-g_lastJoin<TR_RECONNECT_MS) return;
  g_lastJoin=now?now:1;
  WiFi.begin(TR_AP_SSID,TR_AP_PASS);
#endif
}

// Rebuild NMEA (GGA+RMC) from the parsed fix and fire it at gpsd on the NanoPi
// (the GPS class doesn't expose its raw serial, so we reconstruct).
static void nmea_send(TrGps &g){
  if(!g_uplink || !g.location.isValid()) return;
  double la=g.location.lat(); char ns=la<0?'S':'N'; la=fabs(la);
  int lad=(int)la; double lam=(la-lad)*60.0;
  double lo=g.location.lng(); char ew=lo<0?'W':'E'; lo=fabs(lo);
  int lod=(int)lo; double lom=(lo-lod)*60.0;
  int hh=g.time.isValid()?g.time.hour():0, mm=g.time.isValid()?g.time.minute():0, ss=g.time.isValid()?g.time.second():0;
  int dd=g.date.isValid()?g.date.day():1, mo=g.date.isValid()?g.date.month():1, yy=g.date.isValid()?g.date.year()%100:0;
  int sats=g.satellites.isValid()?g.satellites.value():0;
  double alt=g.altitude.isValid()?g.altitude.meters():0;
  char body[110], out[120]; uint8_t ck;
  snprintf(body,sizeof body,"GPGGA,%02d%02d%02d.00,%02d%07.4f,%c,%03d%07.4f,%c,1,%02d,1.0,%.1f,M,0.0,M,,",
           hh,mm,ss,lad,lam,ns,lod,lom,ew,sats,alt);
  ck=0; for(char*p=body;*p;p++) ck^=(uint8_t)*p;
  snprintf(out,sizeof out,"$%s*%02X\r\n",body,ck);
  g_udp.beginPacket(TR_NANOPI_HOST,TR_GPS_UDP_PORT); g_udp.write((uint8_t*)out,strlen(out)); g_udp.endPacket();
  snprintf(body,sizeof body,"GPRMC,%02d%02d%02d.00,A,%02d%07.4f,%c,%03d%07.4f,%c,0.0,0.0,%02d%02d%02d,,,A",
           hh,mm,ss,lad,lam,ns,lod,lom,ew,dd,mo,yy);
  ck=0; for(char*p=body;*p;p++) ck^=(uint8_t)*p;
  snprintf(out,sizeof out,"$%s*%02X\r\n",body,ck);
  g_udp.beginPacket(TR_NANOPI_HOST,TR_GPS_UDP_PORT); g_udp.write((uint8_t*)out,strlen(out)); g_udp.endPacket();
}

static void gps_tick(){
  instance.gps.loop();                        // pump the GPS UART
  auto &g = instance.gps;
  g_gps.sats = g.satellites.isValid()? g.satellites.value() : 0;
  if(g.location.isValid() && g.location.age()<5000){
    g_gps.lat=g.location.lat(); g_gps.lon=g.location.lng();
    g_gps.alt=g.altitude.isValid()?g.altitude.meters():0; g_gps.valid=true;
  } else g_gps.valid=false;
  static uint32_t lastPush=0;
  if(millis()-lastPush>=TR_GPS_PUSH_MS){ lastPush=millis(); nmea_send(g); }
}

// ===========================================================================
//  Wi-Fi sensor
// ===========================================================================
static void wd_stop_wifi_scan(){
  if(WiFi.scanComplete()==WIFI_SCAN_RUNNING) esp_wifi_scan_stop();
  WiFi.scanDelete();
}
static void wifi_scan_tick(){
  int16_t n=WiFi.scanComplete();
  if(n==WIFI_SCAN_RUNNING)return;
  if(n>=0){
    for(int i=0;i<n;i++){
      String b=WiFi.BSSIDstr(i);
      if(seen_recently(L_WIFI,b.c_str())) continue;
      String s=WiFi.SSID(i);
      add_sighting(L_WIFI,b.c_str(),s.c_str(),WiFi.RSSI(i),WiFi.channel(i),
                   wifi_auth_str((int)WiFi.encryptionType(i)),-1,NAN);
    }
    WiFi.scanDelete();
  }
  WiFi.scanNetworks(true,true);
}

// ===========================================================================
//  BLE sensor — NimBLE callback only queues; the loop task does the rest
// ===========================================================================
struct BleRaw { char mac[18]; char name[33]; int16_t rssi; int32_t mfg; };
static QueueHandle_t g_bleQ=nullptr;
static volatile uint32_t g_bleDrops=0;

class BleCB : public NimBLEScanCallbacks {
  void onResult(const NimBLEAdvertisedDevice *d) override {
    // Runs on the NimBLE host task: NO LVGL, NO SD, NO heap-heavy work here.
    if(!g_bleQ || !g_wardriving || !wd_enabled[1]) return;
    BleRaw r;
    const uint8_t *a=d->getAddress().getVal();   // little-endian
    snprintf(r.mac,sizeof r.mac,"%02x:%02x:%02x:%02x:%02x:%02x",a[5],a[4],a[3],a[2],a[1],a[0]);
    r.name[0]=0;
    if(d->haveName()){ std::string nm=d->getName(); strncpy(r.name,nm.c_str(),sizeof r.name-1); r.name[sizeof r.name-1]=0; }
    r.rssi=d->getRSSI();
    r.mfg=-1;                                       // company id from manufacturer data, if any
    if(d->haveManufacturerData()){ std::string md=d->getManufacturerData(); if(md.size()>=2) r.mfg=(uint8_t)md[0]|((uint8_t)md[1]<<8); }
    if(xQueueSend(g_bleQ,&r,0)!=pdTRUE) g_bleDrops++;
  }
};
static BleCB g_bleCB; static NimBLEScan *g_scan=nullptr;
static void wd_stop_ble_scan(){ if(g_scan && g_scan->isScanning())g_scan->stop(); }
static void ble_begin(){
  if(!g_bleQ) g_bleQ=xQueueCreate(TR_BLE_QUEUE_LEN,sizeof(BleRaw));
  if(!g_scan){
    NimBLEDevice::init("");
    g_scan=NimBLEDevice::getScan();
    g_scan->setScanCallbacks(&g_bleCB,false);
    g_scan->setMaxResults(0);       // do NOT keep every advertiser in RAM (old build grew until it crashed)
    g_scan->setActiveScan(true);
    g_scan->setInterval(100); g_scan->setWindow(80);
  }
}
// Finite scans, restarted by the loop: resets the controller's duplicate
// filter so devices still nearby are reported again (rate-limited by
// TR_REOBSERVE_MS).
static void ble_scan_tick(){ if(g_scan&&!g_scan->isScanning())g_scan->start(TR_BLE_SCAN_MS,false,true); }
static void ble_drain(){
  if(!g_bleQ) return;
  BleRaw r; int n=0;
  while(n<24 && xQueueReceive(g_bleQ,&r,0)==pdTRUE){
    n++;
    if(!g_wardriving||!wd_enabled[1]) continue;
    r.mac[sizeof r.mac-1]=0; r.name[sizeof r.name-1]=0;
    if(seen_recently(L_BLE,r.mac)) continue;
    add_sighting(L_BLE,r.mac,r.name,r.rssi,0,nullptr,(int)r.mfg,NAN);
  }
}

// ===========================================================================
//  LoRa mesh sensor (RX only)
// ===========================================================================
static volatile bool g_rxFlag=false;
static void IRAM_ATTR onRxDone(){ g_rxFlag=true; }
static void mesh_begin(){
  if(!tr_spi_lock())return;   // LoRa (SX1262) shares the SPI bus with the display
  RADIO.setFrequency(TR_MESH_FREQ_MHZ); RADIO.setBandwidth(TR_MESH_BW_KHZ);
  RADIO.setSpreadingFactor(TR_MESH_SF); RADIO.setCodingRate(TR_MESH_CR);
  RADIO.setPreambleLength(TR_MESH_PREAMBLE); RADIO.setSyncWord(TR_MESH_SYNCWORD);
#if TR_RADIO_SX1262 || TR_RADIO_LR1121 || TR_RADIO_SX1280
  RADIO.setDio1Action(onRxDone);
#else
  RADIO.setPacketReceivedAction(onRxDone);
#endif
  RADIO.startReceive();
  tr_spi_unlock();
}
static void mesh_tick(){
  if(!g_rxFlag)return; g_rxFlag=false;
  if(!tr_spi_lock())return;   // serialize the LoRa read with the display flush
  uint8_t buf[256]; size_t len=RADIO.getPacketLength(); if(len>sizeof buf) len=sizeof buf;
  int state=RADIO.readData(buf,len);
  int rssi=(int)RADIO.getRSSI(); float snr=RADIO.getSNR();
  RADIO.startReceive();
  tr_spi_unlock();
  if(state==RADIOLIB_ERR_NONE&&len>=16){
    uint32_t from=buf[4]|(buf[5]<<8)|(buf[6]<<16)|((uint32_t)buf[7]<<24);
    char id[18]; snprintf(id,sizeof id,"!%08lx",(unsigned long)from);
    char nm[33]; snprintf(nm,sizeof nm,"meshtastic SF%d",TR_MESH_SF);
    add_sighting(L_MESH,id,nm,rssi,TR_MESH_SF,nullptr,-1,snr);
  } else if(state==RADIOLIB_ERR_NONE){
    char id[18]; snprintf(id,sizeof id,"lora-%d",(int)len); add_sighting(L_MESH,id,"mesh/unknown",rssi,TR_MESH_SF,nullptr,-1,snr);
  }
}

// ===========================================================================
//  nRF24 sensor glue (driver in tr_nrf24.h) — local SD only, not uploaded
// ===========================================================================
#if TR_NRF24_ENABLE
static void nrf_on_hit(const nrf::EsbHit &h){
  GpsSnap g; gps_snapshot(g);
  static char line[512]; size_t p=0; const size_t cap=sizeof line;
  char addr[11]; snprintf(addr,sizeof addr,"%02X%02X%02X%02X%02X",h.addr[0],h.addr[1],h.addr[2],h.addr[3],h.addr[4]);
  p=j_add(line,p,cap,"{\"sensor\":\"nrf24\",\"type\":\"esb\",\"address\":\"%s\",\"channel\":%u,\"freq_mhz\":%u,"
                     "\"rate\":\"%s\",\"payload_len\":%u,\"frames\":%u,\"strong_signal\":%s",
          addr,(unsigned)h.channel,2400u+h.channel,nrf::rateName(h.rate),(unsigned)h.payloadLen,
          (unsigned)h.frames,h.strong?"true":"false");
  p=j_gps_tail(line,p,cap,g,millis());
  sd_append(SDF_NRF24,line,p);
  g_count.nrf24++;
  char row[64]; snprintf(row,sizeof row,"nrf   %s ch%u %s%s",addr,(unsigned)h.channel,nrf::rateName(h.rate),h.strong?" *":"");
  ui_push_row(row,0xD07CFF);
}
static void nrf_on_activity(const nrf::Activity &a){
  if(!a.n) return;                                // nothing above threshold: no line
  GpsSnap g; gps_snapshot(g);
  static char line[1800]; size_t p=0; const size_t cap=sizeof line;
  p=j_add(line,p,cap,"{\"sensor\":\"nrf24\",\"type\":\"activity\",\"note\":\"RPD>-64dBm per channel; not device detections\","
                     "\"window_ms\":%lu,\"sweeps\":%u,\"threshold_pct\":%u,\"active_channels\":%u,\"channels\":[",
          (unsigned long)a.windowMs,(unsigned)a.sweeps,(unsigned)TR_NRF24_ACTIVE_PCT,(unsigned)a.n);
  for(uint8_t i=0;i<a.n;i++) p=j_add(line,p,cap,"%s[%u,%u]",i?",":"",(unsigned)a.ch[i],(unsigned)a.hits[i]);
  p=j_add(line,p,cap,"]");
  p=j_gps_tail(line,p,cap,g,millis());
  sd_append(SDF_NRF24,line,p);
  g_count.nrf24act++;
}
static void nrf_sensor_start(){
  if(!nrf::present()) return;
#if TR_NRF24_SHIELD_RXTX_EXPANDER && defined(EXPANDS_GPIO_EN)
  tr_expander_write((uint8_t)EXPANDS_GPIO_EN, (uint8_t)LOW);   // LilyGo PA shield -> RX
#endif
  nrf::start();
}
static void nrf_sensor_stop(){ nrf::stop(); }
#else
static void nrf_sensor_start(){}
static void nrf_sensor_stop(){}
#endif

// ===========================================================================
//  NFC sensor glue (driver in tr_nfc.h) — one row per tag tap, local SD only
// ===========================================================================
static void nfc_on_tag(const trnfc::Tag &t){
  GpsSnap g; gps_snapshot(g);
  static char line[400]; size_t p=0; const size_t cap=sizeof line;
  p=j_add(line,p,cap,"%s,%lu,%s,%s,%s,%s,%s,%d,%u,%s",
          g.utc_valid?g.utc:"",(unsigned long)millis(),g_session,t.uid,t.tech,t.tagType,t.cardType,
          t.hasNdef?1:0,(unsigned)t.records,t.recordKinds);
  p=csv_gps_tail(line,p,cap,g);
  sd_append(SDF_NFC,line,p);
  g_count.nfc++;
  char row[64]; snprintf(row,sizeof row,"nfc   %.20s %.12s",t.uid,t.cardType[0]?t.cardType:t.tech);
  ui_push_row(row,0xFFC857);
}
static void nfc_sensor_start(){ if(trnfc::available()) trnfc::start(nfc_on_tag); }
static void nfc_sensor_stop(){ trnfc::stop(); }

// ===========================================================================
//  CC1101 sensor glue (driver in tr_cc1101.h) — local SD only
// ===========================================================================
#if TR_CC1101_ENABLE
static void cc_on_activity(const cc::Activity &a){
  if(!a.n) return;
  GpsSnap g; gps_snapshot(g);
  static char line[320];
  int best=0;
  for(uint8_t i=0;i<a.n;i++){
    size_t p=0; const size_t cap=sizeof line;
    p=j_add(line,p,cap,"%s,%lu,%s,%.3f,%u,%u,%.1f",g.utc_valid?g.utc:"",(unsigned long)millis(),g_session,
            (double)a.freq[i],(unsigned)a.hits[i],(unsigned)a.sweeps,(double)a.maxRssi[i]);
    p=csv_gps_tail(line,p,cap,g);
    sd_append(SDF_CC1101,line,p);
    g_count.cc1101++;
    if(a.maxRssi[i]>a.maxRssi[best]) best=i;
  }
  char row[64]; snprintf(row,sizeof row,"sub   %.2fMHz max %ddBm (+%u)",(double)a.freq[best],(int)a.maxRssi[best],(unsigned)(a.n-1));
  ui_push_row(row,0x7CC8FF);
}
#endif

// ===========================================================================
//  REMOTE tab (base-station status + quick actions)
// ===========================================================================
static void refresh_remote(){
  if(g_mode!=MODE_TUNNELRAT||!lbl_remote)return;
  if(!g_tv || lv_tabview_get_tab_active(g_tv)!=0) return;   // only poll while HOME is visible
  if(!g_uplink){lv_label_set_text(lbl_remote,"Base station: offline");return;}
  HTTPClient http; String url=String("http://")+TR_NANOPI_HOST+":"+TR_NANOPI_PORT+"/api/remote/status";
  http.setConnectTimeout(1500); http.setTimeout(2500);
  http.begin(url); http.addHeader("X-API-Key",TR_API_KEY); int code=http.GET();
  if(code==200){DynamicJsonDocument doc(2048);
    if(deserializeJson(doc,http.getString())==DeserializationError::Ok)
      lv_label_set_text_fmt(lbl_remote,"Tunnel R.A.T. base\nCPU %d%% MEM %d%% DISK %d%%\nSDR:%s  Stingray:%s",
        (int)doc["cpu"],(int)doc["memory"],(int)doc["disk"],doc["sdr"]?"yes":"no",(const char*)(doc["stingray"]|"off"));
  } else lv_label_set_text_fmt(lbl_remote,"Base station: HTTP %d",code);
  http.end();
}

static void quick_action_cb(lv_event_t *e){
  const char *action=(const char*)lv_event_get_user_data(e);
  if(!g_uplink||!action)return;
  HTTPClient http; String url=String("http://")+TR_NANOPI_HOST+":"+TR_NANOPI_PORT+"/api/remote/run";
  http.setConnectTimeout(1500); http.setTimeout(2500);
  http.begin(url); http.addHeader("Content-Type","application/json"); http.addHeader("X-API-Key",TR_API_KEY);
  int code=http.POST(String("{\"action\":\"")+action+"\"}"); http.end();
  if(lbl_remote) lv_label_set_text_fmt(lbl_remote,"Sent '%s' -> HTTP %d",action,code);
}

// ===========================================================================
//  PAGER WARDRIVE: START / STOP & SAVE
// ===========================================================================
// Plain-text summary written on STOP & SAVE into the session folder.
static bool session_write_info(){
  if(!g_sdOk || !g_sessDir[0]) return false;
  GpsSnap g; gps_snapshot(g);
  static char buf[1500]; size_t p=0; const size_t cap=sizeof buf;
  p=j_add(buf,p,cap,"Tunnel R.A.T. // T-Pager  PAGER WARDRIVE session %s\n",g_session);
  p=j_add(buf,p,cap,"folder: %s\nstarted_utc: %s\nstopped_utc: %s\n\n",g_sessDir,
          g_sessStartUtc[0]?g_sessStartUtc:"(no GPS time)",g.utc_valid?g.utc:"(no GPS time)");
  p=j_add(buf,p,cap,"wifi_wigle.csv : %lu rows  (%lu WiFi observations, %lu skipped: no GPS fix)\n",
          (unsigned long)g_count.wifiWigle,(unsigned long)g_count.wifi,(unsigned long)g_count.wifiNoFix);
  p=j_add(buf,p,cap,"ble_wigle.csv  : %lu rows  (%lu BLE observations, %lu skipped: no GPS fix)\n",
          (unsigned long)g_count.bleWigle,(unsigned long)g_count.ble,(unsigned long)g_count.bleNoFix);
  p=j_add(buf,p,cap,"nfc.csv        : %lu tag taps\n",(unsigned long)g_count.nfc);
  p=j_add(buf,p,cap,"nrf24.jsonl    : %lu ESB devices, %lu activity windows\n",
          (unsigned long)g_count.nrf24,(unsigned long)g_count.nrf24act);
  p=j_add(buf,p,cap,"cc1101.csv     : %lu active-frequency rows\n",(unsigned long)g_count.cc1101);
  p=j_add(buf,p,cap,"mesh.csv       : %lu rows\n",(unsigned long)g_count.mesh);
  p=j_add(buf,p,cap,"raw_sightings.jsonl : every WiFi/BLE/mesh report incl. no-fix\n\n");
  p=j_add(buf,p,cap,"UPLOAD\n  wigle.net (Uploads page)  : wifi_wigle.csv, ble_wigle.csv\n"
                    "  wdgwars.pl                 : wifi_wigle.csv, ble_wigle.csv (same WiGLE 1.6 format)\n"
                    "  nfc / nrf24 / cc1101 / mesh files : no public upload target - keep / map locally\n");
  p=j_add(buf,p,cap,"\nsd_errors: %lu  bytes_dropped: %lu\n",(unsigned long)g_sdErrors,(unsigned long)g_sdDropped);
  char path[112]; snprintf(path,sizeof path,"%s/session_info.txt",g_sessDir);
  bool ok=false;
  if(tr_spi_lock()){
    File fh=SD.open(path,FILE_WRITE);
    if(fh){ ok = fh.write((const uint8_t*)buf,p)==p; fh.close(); }
    tr_spi_unlock();
  }
  if(!ok) g_sdErrors++;
  return ok;
}

static void sensors_stop_all(){
  g_wardriving=false;
  wd_stop_ble_scan();
  wd_stop_wifi_scan();
  hdr_stop();
  nfc_sensor_stop();
  ble_drain();                     // discard anything still queued (g_wardriving is false)
}

static void wd_set_running(bool run){
  if(run==g_wardriving)return;
  bool any=false; for(int i=0;i<5;i++) if(wd_enabled[i]&&sensor_usable(i)) any=true;
  if(run && !any){
    if(lbl_wd_state) lv_label_set_text(lbl_wd_state,"PAGER WARDRIVE  - pick sensors first (SENSORS)");
    return;
  }
  if(run){
    snprintf(g_session,sizeof g_session,"%08lx",(unsigned long)esp_random());
    memset(g_seen,0,sizeof g_seen);
    g_count=Counts();              // counters are per session; files are never erased
    g_lastWifi=0; g_lastBle=0;
    bool dirOk = g_sdOk && session_open();
    g_wardriving=true;
    if(wd_enabled[0])WiFi.scanNetworks(true,true);
    if(wd_enabled[1])ble_scan_tick();
    if(wd_enabled[2])mesh_begin();
    if(wd_enabled[3])hdr_start();
    if(wd_enabled[4])nfc_sensor_start();
    if(lbl_wd_state){
      if(dirOk)        lv_label_set_text_fmt(lbl_wd_state,"PAGER WARDRIVE  - RUNNING  #%s",g_session);
      else if(!g_sdOk) lv_label_set_text(lbl_wd_state,"PAGER WARDRIVE  - RUNNING, NO SD (not saving)");
      else             lv_label_set_text(lbl_wd_state,"PAGER WARDRIVE  - RUNNING, SD FOLDER ERROR");
    }
    if(wd_start) lv_obj_add_state(wd_start,LV_STATE_DISABLED);
    if(wd_stop)  lv_obj_remove_state(wd_stop,LV_STATE_DISABLED);
    Serial.printf("[WD] START session=%s dir=%s sensors W%d B%d M%d %s%d F%d\n",g_session,g_sessDir,
                  (int)wd_enabled[0],(int)wd_enabled[1],(int)wd_enabled[2],hdr_name(),(int)wd_enabled[3],(int)wd_enabled[4]);
  }else{
    sensors_stop_all();
    bool ok=sd_flush_all();
    if(g_sessDir[0]) ok = session_write_info() && ok;
    if(lbl_wd_state){
      if(!g_sdOk)      lv_label_set_text(lbl_wd_state,"STOPPED - NO SD CARD (not saved)");
      else if(!ok)     lv_label_set_text(lbl_wd_state,"STOPPED - SD WRITE ERROR");
      else             lv_label_set_text_fmt(lbl_wd_state,"SAVED #%s  WiGLE rows W:%lu B:%lu",
                             g_session,(unsigned long)g_count.wifiWigle,(unsigned long)g_count.bleWigle);
    }
    if(wd_start) lv_obj_remove_state(wd_start,LV_STATE_DISABLED);
    if(wd_stop)  lv_obj_add_state(wd_stop,LV_STATE_DISABLED);
    Serial.printf("[WD] STOP session=%s saved=%d sdErr=%lu dropped=%lu\n",g_session,(int)ok,
                  (unsigned long)g_sdErrors,(unsigned long)g_sdDropped);
  }
}

static void diag_tick(){
#if TR_DIAG_SERIAL_MS > 0
  static uint32_t last=0; uint32_t now=millis();
  if(now-last<TR_DIAG_SERIAL_MS) return; last=now;
  Serial.printf("[WD] up=%lus mode=%d run=%d heap=%u min=%u psram=%u bleQ=%u drop=%lu sdErr=%lu hdr=%s",
    (unsigned long)(now/1000),(int)g_mode,(int)g_wardriving,(unsigned)ESP.getFreeHeap(),(unsigned)ESP.getMinFreeHeap(),
    (unsigned)ESP.getFreePsram(),g_bleQ?(unsigned)uxQueueMessagesWaiting(g_bleQ):0u,(unsigned long)g_bleDrops,
    (unsigned long)g_sdErrors,hdr_name());
#if TR_NRF24_ENABLE
  if(g_hdr==HDR_NRF24)
    Serial.printf(" nrf=%d frames=%lu crc=%lu conf=%lu act=%u busErr=%lu",(int)nrf::running(),
      (unsigned long)nrf::frames(),(unsigned long)nrf::crcValid(),(unsigned long)nrf::confirmed(),
      (unsigned)nrf::activeCount(),(unsigned long)nrf::busErrors());
#endif
  Serial.println();
#endif
}

// ---- PAGER WARDRIVE lifecycle ------------------------------------------------
static void pagerwd_enter(){
  WiFi.setAutoReconnect(false);
  WiFi.mode(WIFI_STA); WiFi.disconnect();        // standalone: never joins the NanoPi AP
  WiFi.setSleep(false);
  g_uplink=false; g_lastJoin=0;
  ble_begin(); mesh_begin(); g_trRadios=true;
}
static void pagerwd_exit(){
  sensors_stop_all();
  sd_flush_all();
  // The mode screen is deleted right after this: drop every pointer into it.
  g_sel=nullptr; lbl_sel=nullptr;
  lbl_wd_state=list_hits=nullptr;
  wd_gps=nullptr; wd_start=nullptr; wd_stop=nullptr;
  for(int i=0;i<5;i++){wd_checks[i]=nullptr;wd_counters[i]=nullptr;}
  g_trRadios=false;
}
static void pagerwd_loop(){
  uint32_t now=millis();
  ble_drain();
  if(g_wardriving){
    if(wd_enabled[0] && now-g_lastWifi>=TR_WIFI_SCAN_MS){g_lastWifi=now;wifi_scan_tick();}
    if(wd_enabled[1] && now-g_lastBle>=500){g_lastBle=now;ble_scan_tick();}
    if(wd_enabled[2])mesh_tick();
    if(wd_enabled[3]){
#if TR_NRF24_ENABLE
      if(g_hdr==HDR_NRF24) nrf::tick(nrf_on_hit,nrf_on_activity);
#endif
#if TR_CC1101_ENABLE
      if(g_hdr==HDR_CC1101) cc::tick(cc_on_activity);
#endif
    }
    if(wd_enabled[4])trnfc::tick();
  }
  if(now-g_sdLastFlush>=TR_SD_FLUSH_MS) sd_flush_all();
  static uint32_t lu=0;
  if(now-lu>=500){lu=now;ui_refresh_pagerwd();}
  diag_tick();
}

// ---- TUNNEL R.A.T. REMOTE lifecycle -----------------------------------------
static void remote_enter(){
  WiFi.mode(WIFI_STA); WiFi.setSleep(false);
  WiFi.setAutoReconnect(false);    // joins are scheduled by uplink_tick()
  g_lastJoin=0;
}
static void remote_exit(){
  lbl_gps=lbl_uplink=lbl_status=lbl_remote=lbl_nwd=nullptr;
  g_netOut=g_osintOut=nullptr;
  g_tv=nullptr;
}
static void remote_loop(){
  uint32_t now=millis();
  static uint32_t lu=0,lr=0;
  if(now-lu>=1000){lu=now;ui_refresh_remote();}
  if(now-lr>=6000){lr=now;refresh_remote();}
  diag_tick();
}

// ===========================================================================
//  Mode switching
// ===========================================================================
// ===========================================================================
//  Settings (theme + brightness)  and  SD Explorer
// ===========================================================================
static uint8_t  g_bright = DEVICE_MAX_BRIGHTNESS_LEVEL;
static bool     g_launcherDirty = false;
static lv_obj_t *g_set_title = nullptr;

static void settings_save(){
  if(!g_sdOk) return;
  if(!tr_spi_lock()) return;
  SD.remove(TR_SETTINGS_FILE);
  File f=SD.open(TR_SETTINGS_FILE, FILE_WRITE);
  if(f){ f.printf("accent=%06x\n",(unsigned)(g_accent&0xFFFFFF)); f.printf("bright=%d\n",(int)g_bright); f.printf("audio=%d\n",g_radarAudioOn?1:0); f.close(); }
  tr_spi_unlock();
}
static void settings_load(){
  if(!g_sdOk || !SD.exists(TR_SETTINGS_FILE)) return;
  if(!tr_spi_lock()) return;
  File f=SD.open(TR_SETTINGS_FILE, FILE_READ);
  if(f){
    while(f.available()){
      String ln=f.readStringUntil('\n'); ln.trim();
      if(ln.startsWith("accent=")) g_accent=(uint32_t)strtoul(ln.substring(7).c_str(),nullptr,16);
      else if(ln.startsWith("bright=")){ int b=ln.substring(7).toInt(); if(b<1)b=1; if(b>DEVICE_MAX_BRIGHTNESS_LEVEL)b=DEVICE_MAX_BRIGHTNESS_LEVEL; g_bright=(uint8_t)b; }
      else if(ln.startsWith("audio=")) g_radarAudioOn = (ln.substring(6).toInt()!=0);
    }
    f.close();
  }
  tr_spi_unlock();
  instance.setBrightness(g_bright);
  lv_style_set_text_color(&st_accent, lv_color_hex(g_accent));
}
static void theme_apply(uint32_t color){
  g_accent=color;
  lv_style_set_text_color(&st_accent, lv_color_hex(g_accent));
  g_launcherDirty=true;
  settings_save();
}

static const struct { const char *name; uint32_t col; } THEME_COLORS[] = {
  {"Blue",0x2979FF},{"Purple",0xB388FF},{"Green",0x00FF66},{"Red",0xFF5252},
  {"Cyan",0x00E5FF},{"Amber",0xFFC400},{"White",0xFFFFFF}
};

static void build_settings(lv_obj_t *parent){
  g_set_title=lv_label_create(parent);
  lv_label_set_text(g_set_title,"Settings");
  lv_obj_set_style_text_color(g_set_title,lv_color_hex(g_accent),0);
  lv_obj_align(g_set_title,LV_ALIGN_TOP_LEFT,0,0);

  lv_obj_t *al=lv_label_create(parent); lv_label_set_text(al,"Accent color");
  lv_obj_set_style_text_color(al,lv_color_hex(0x8B949E),0); lv_obj_align(al,LV_ALIGN_TOP_LEFT,0,28);

  lv_obj_t *row=lv_obj_create(parent); lv_obj_remove_style_all(row);
  lv_obj_set_size(row,lv_pct(100),46); lv_obj_align(row,LV_ALIGN_TOP_LEFT,0,48);
  lv_obj_set_flex_flow(row,LV_FLEX_FLOW_ROW);
  lv_obj_set_flex_align(row,LV_FLEX_ALIGN_SPACE_EVENLY,LV_FLEX_ALIGN_CENTER,LV_FLEX_ALIGN_CENTER);
  for(auto &c: THEME_COLORS){
    lv_obj_t *sw=lv_button_create(row); lv_obj_set_size(sw,40,40);
    lv_obj_set_style_radius(sw,LV_RADIUS_CIRCLE,0);
    lv_obj_set_style_bg_color(sw,lv_color_hex(c.col),0);
    lv_obj_set_style_border_color(sw,lv_color_hex(0xFFFFFF),0);
    lv_obj_set_style_border_width(sw, (g_accent==c.col)?3:0, 0);
    lv_obj_add_event_cb(sw,[](lv_event_t*e){
      uint32_t col=(uint32_t)(intptr_t)lv_event_get_user_data(e);
      theme_apply(col);
      if(g_set_title) lv_obj_set_style_text_color(g_set_title,lv_color_hex(col),0);
    },LV_EVENT_CLICKED,(void*)(intptr_t)c.col);
  }

  lv_obj_t *bl=lv_label_create(parent); lv_label_set_text(bl,"Brightness");
  lv_obj_set_style_text_color(bl,lv_color_hex(0x8B949E),0); lv_obj_align(bl,LV_ALIGN_TOP_LEFT,0,104);
  lv_obj_t *sld=lv_slider_create(parent);
  lv_obj_set_width(sld,lv_pct(82)); lv_obj_align(sld,LV_ALIGN_TOP_LEFT,0,128);
  lv_slider_set_range(sld,1,DEVICE_MAX_BRIGHTNESS_LEVEL);
  lv_slider_set_value(sld,g_bright,LV_ANIM_OFF);
  lv_obj_add_event_cb(sld,[](lv_event_t*e){
    int v=(int)lv_slider_get_value((lv_obj_t*)lv_event_get_target(e)); if(v<1)v=1;
    g_bright=(uint8_t)v; instance.setBrightness(g_bright);
  },LV_EVENT_VALUE_CHANGED,nullptr);
  lv_obj_add_event_cb(sld,[](lv_event_t*){ settings_save(); },LV_EVENT_RELEASED,nullptr);

  // Radar "getting warmer" ping on/off (persisted)
  lv_obj_t *pl=lv_label_create(parent); lv_label_set_text(pl,"Radar ping (fox-hunt)");
  lv_obj_set_style_text_color(pl,lv_color_hex(0x8B949E),0); lv_obj_align(pl,LV_ALIGN_TOP_LEFT,0,160);
  lv_obj_t *sw=lv_switch_create(parent);
  lv_obj_align(sw,LV_ALIGN_TOP_LEFT,0,182);
  lv_obj_set_style_bg_color(sw,lv_color_hex(g_accent),LV_PART_INDICATOR|LV_STATE_CHECKED);
  if(g_radarAudioOn) lv_obj_add_state(sw,LV_STATE_CHECKED);
  lv_obj_add_event_cb(sw,[](lv_event_t*e){
    g_radarAudioOn = lv_obj_has_state((lv_obj_t*)lv_event_get_target(e),LV_STATE_CHECKED);
    settings_save();
  },LV_EVENT_VALUE_CHANGED,nullptr);
}

// ======================= SD CARD FILE MANAGER ============================
// A real file manager: browse, open/edit/play, rename, delete (files AND
// folders), make new files/folders. Every screen rebuild is DEFERRED with
// lv_async_call so g_sd_parent is never cleaned inside one of its children's
// own event callbacks (doing so deletes the live widget mid-dispatch -> the
// white-screen crash). All SD access is SPI-locked against the display DMA.
static lv_obj_t *g_sd_parent=nullptr;        // SD mode content sub-container
static char      g_sdPath[160]="/";
static lv_obj_t *g_sd_list=nullptr, *g_sd_path=nullptr, *g_sd_edit=nullptr, *g_sd_name=nullptr;
static lv_obj_t *g_sdFocus=nullptr;          // widget to focus after a deferred rebuild
static char      g_sdNames[48][44];
static uint8_t   g_sdIsDir[48];
static int       g_sdN=0;
static char      g_sdFile[224]="";           // file currently in the editor
static char      g_sdSelName[44]="";         // the item the actions menu acts on
static char      g_sdSelFull[224]="";
static bool      g_sdSelDir=false;
static char      g_sdNamePurpose=0;          // 'f' new file, 'd' new folder, 'r' rename

static void sd_build_browse();
static void sd_build_actions();
static void sd_build_confirm();
static void sd_build_name();
static void sd_open_editor_existing();
static void sd_nav_up();
static void sd_select(int i);
static void sd_name_save();
static void sd_editor_save();

// ---- deferred screen swap ------------------------------------------------
static void (*g_sdNext)()=nullptr;
static void sd_async(void*){
  void(*fn)()=g_sdNext; g_sdNext=nullptr;
  if(!fn || g_mode!=MODE_SDEXP || !g_sd_parent) return;
  fn();                                       // rebuild g_sd_parent (safe here)
  nav_begin_screen();                         // reset nav group, then re-collect
  nav_collect(g_scr_mode);                    // back button + the new widgets
  if(g_sdFocus) lv_group_focus_obj(g_sdFocus);
  lv_group_set_editing(g_nav_group,false);    // wheel navigates; keyboard still types
}
static void sd_go(void(*fn)()){ g_sdNext=fn; lv_async_call(sd_async,nullptr); }

static void sd_join(char*out,int n,const char*dir,const char*name){
  int l=strlen(dir);
  if(l && dir[l-1]=='/') snprintf(out,n,"%s%s",dir,name);
  else                   snprintf(out,n,"%s/%s",dir,name);
}
static bool sd_is_wav(const char*name){ const char*d=strrchr(name,'.'); return d && !strcasecmp(d,".wav"); }
static bool sd_is_mp3(const char*name){ const char*d=strrchr(name,'.'); return d && !strcasecmp(d,".mp3"); }

// recursive delete: a file, or a folder and everything under it
static bool sd_rmrf(const char*path){
  if(!tr_spi_lock()) return false;
  File d=SD.open(path);
  if(!d){ tr_spi_unlock(); return false; }
  if(!d.isDirectory()){ d.close(); bool ok=SD.remove(path); tr_spi_unlock(); return ok; }
  char names[24][44]; int cn=0;
  for(File e=d.openNextFile(); e && cn<24; e=d.openNextFile()){
    const char*nm=e.name(); const char*bb=strrchr(nm,'/'); bb=bb?bb+1:nm;
    strncpy(names[cn],bb,43); names[cn][43]=0; cn++; e.close();
  }
  d.close(); tr_spi_unlock();
  for(int i=0;i<cn;i++){ char ch[224]; sd_join(ch,sizeof ch,path,names[i]); sd_rmrf(ch); }
  if(!tr_spi_lock()) return false;
  bool ok=SD.rmdir(path); tr_spi_unlock();
  return ok;
}

static void sd_play_wav(const char*path){
  if(!g_sdOk) return;
  if(!tr_spi_lock()) return;
  File f=SD.open(path,FILE_READ); size_t len=f?f.size():0;
  if(!f || len<44 || len>4u*1024*1024){ if(f)f.close(); tr_spi_unlock(); return; }
  uint8_t*buf=(uint8_t*)ps_malloc(len);
  if(!buf){ f.close(); tr_spi_unlock(); return; }
  f.read(buf,len); f.close(); tr_spi_unlock();
  instance.codec.setVolume(85);
  instance.codec.playWAV(buf,len);               // blocks for the clip
  free(buf);
}

// ---- actions invoked from the per-item menu ------------------------------
static void sd_act_open(){                     // enter folder
  strncpy(g_sdPath,g_sdSelFull,sizeof g_sdPath-1); g_sdPath[sizeof g_sdPath-1]=0;
  sd_go(sd_build_browse);
}
static void sd_act_delete_now(){               // confirmed delete
  if(g_sdSelDir) sd_rmrf(g_sdSelFull);
  else if(g_sdOk && tr_spi_lock()){ SD.remove(g_sdSelFull); tr_spi_unlock(); }
  sd_go(sd_build_browse);
}
static void sd_name_save(){
  const char*nm = g_sd_name? lv_textarea_get_text(g_sd_name):"";
  if(!nm||!nm[0]){ sd_go(sd_build_browse); return; }
  char path[224]; sd_join(path,sizeof path,g_sdPath,nm);
  if(g_sdOk && tr_spi_lock()){
    if(g_sdNamePurpose=='d')      SD.mkdir(path);
    else if(g_sdNamePurpose=='r') SD.rename(g_sdSelFull,path);
    else { SD.remove(path); File f=SD.open(path,FILE_WRITE); if(f) f.close(); }
    tr_spi_unlock();
  }
  sd_go(sd_build_browse);
}
static void sd_editor_save(){
  const char*txt = g_sd_edit? lv_textarea_get_text(g_sd_edit):"";
  if(g_sdOk && g_sdFile[0] && tr_spi_lock()){
    SD.remove(g_sdFile);
    File f=SD.open(g_sdFile,FILE_WRITE);
    if(f){ f.print(txt); f.close(); }
    tr_spi_unlock();
  }
  sd_go(sd_build_browse);
}
static void sd_select(int i){
  if(i<0||i>=g_sdN) return;
  strncpy(g_sdSelName,g_sdNames[i],sizeof g_sdSelName-1); g_sdSelName[sizeof g_sdSelName-1]=0;
  g_sdSelDir=g_sdIsDir[i];
  sd_join(g_sdSelFull,sizeof g_sdSelFull,g_sdPath,g_sdSelName);
  sd_go(sd_build_actions);
}
static void sd_nav_up(){
  char *s=strrchr(g_sdPath,'/');
  if(!s || s==g_sdPath){ g_sdPath[0]='/'; g_sdPath[1]=0; }
  else *s=0;
  if(!g_sdPath[0]){ g_sdPath[0]='/'; g_sdPath[1]=0; }
  sd_go(sd_build_browse);
}

// ---- screens -------------------------------------------------------------
static void sd_build_browse(){
  if(!g_sd_parent) return;
  lv_obj_clean(g_sd_parent);
  g_sd_edit=nullptr; g_sd_name=nullptr; g_sd_list=nullptr; g_sd_path=nullptr; g_sdFocus=nullptr;

  g_sd_path=lv_label_create(g_sd_parent);
  lv_obj_set_style_text_color(g_sd_path,lv_color_hex(g_accent),0);
  lv_label_set_long_mode(g_sd_path,LV_LABEL_LONG_DOT);
  lv_obj_set_width(g_sd_path,lv_pct(52)); lv_obj_align(g_sd_path,LV_ALIGN_TOP_LEFT,0,3);
  lv_label_set_text(g_sd_path,g_sdPath);

  lv_obj_t*bf=lv_button_create(g_sd_parent); lv_obj_set_size(bf,74,26);
  lv_obj_align(bf,LV_ALIGN_TOP_RIGHT,-80,0); lv_obj_set_style_bg_color(bf,lv_color_hex(0x1C6B34),0);
  { lv_obj_t*l=lv_label_create(bf); lv_label_set_text(l,LV_SYMBOL_PLUS " File"); lv_obj_center(l); }
  lv_obj_add_event_cb(bf,[](lv_event_t*){ g_sdNamePurpose='f'; sd_go(sd_build_name); },LV_EVENT_CLICKED,nullptr);

  lv_obj_t*bd=lv_button_create(g_sd_parent); lv_obj_set_size(bd,74,26);
  lv_obj_align(bd,LV_ALIGN_TOP_RIGHT,0,0); lv_obj_set_style_bg_color(bd,lv_color_hex(0x245A8A),0);
  { lv_obj_t*l=lv_label_create(bd); lv_label_set_text(l,LV_SYMBOL_PLUS " Dir"); lv_obj_center(l); }
  lv_obj_add_event_cb(bd,[](lv_event_t*){ g_sdNamePurpose='d'; sd_go(sd_build_name); },LV_EVENT_CLICKED,nullptr);

  g_sd_list=lv_list_create(g_sd_parent);
  lv_obj_set_size(g_sd_list,lv_pct(100),lv_pct(84)); lv_obj_align(g_sd_list,LV_ALIGN_BOTTOM_MID,0,0);
  lv_obj_set_style_bg_color(g_sd_list,lv_color_hex(0x0E120E),0);

  g_sdN=0;
  if(!g_sdOk){ lv_list_add_text(g_sd_list,"no SD card"); return; }
  if(strcmp(g_sdPath,"/")!=0){
    lv_obj_t *b=lv_list_add_button(g_sd_list,LV_SYMBOL_UP,"..");
    lv_obj_add_event_cb(b,[](lv_event_t*){ sd_nav_up(); },LV_EVENT_CLICKED,nullptr);
    if(!g_sdFocus) g_sdFocus=b;
  }
  if(!tr_spi_lock()) return;
  File dir=SD.open(g_sdPath);
  if(dir && dir.isDirectory()){
    for(File e=dir.openNextFile(); e && g_sdN<48; e=dir.openNextFile()){
      const char *nm=e.name(); const char *base=strrchr(nm,'/'); base=base?base+1:nm;
      strncpy(g_sdNames[g_sdN],base,43); g_sdNames[g_sdN][43]=0;
      g_sdIsDir[g_sdN]=e.isDirectory()?1:0;
      char row[96];
      if(g_sdIsDir[g_sdN])     snprintf(row,sizeof row,LV_SYMBOL_DIRECTORY " %s",base);
      else if(sd_is_wav(base)) snprintf(row,sizeof row,LV_SYMBOL_AUDIO " %s  %lu B",base,(unsigned long)e.size());
      else                     snprintf(row,sizeof row,LV_SYMBOL_FILE " %s  %lu B",base,(unsigned long)e.size());
      lv_obj_t *b=lv_list_add_button(g_sd_list,NULL,row);
      lv_obj_set_style_text_color(b,lv_color_hex(g_sdIsDir[g_sdN]?g_accent:0xB0B0B0),0);
      lv_obj_add_event_cb(b,[](lv_event_t*ev){ sd_select((int)(intptr_t)lv_event_get_user_data(ev)); },
                          LV_EVENT_CLICKED,(void*)(intptr_t)g_sdN);
      if(!g_sdFocus) g_sdFocus=b;
      e.close(); g_sdN++;
    }
  } else lv_list_add_text(g_sd_list,"(cannot open folder)");
  if(dir) dir.close();
  tr_spi_unlock();
}

static void sd_build_actions(){
  if(!g_sd_parent) return;
  lv_obj_clean(g_sd_parent);
  g_sd_edit=nullptr; g_sd_name=nullptr; g_sd_list=nullptr; g_sd_path=nullptr; g_sdFocus=nullptr;

  lv_obj_t*t=lv_label_create(g_sd_parent);
  lv_label_set_long_mode(t,LV_LABEL_LONG_DOT); lv_obj_set_width(t,lv_pct(100));
  lv_obj_set_style_text_color(t,lv_color_hex(g_accent),0); lv_obj_align(t,LV_ALIGN_TOP_LEFT,0,0);
  lv_label_set_text_fmt(t,"%s %s", g_sdSelDir?LV_SYMBOL_DIRECTORY:LV_SYMBOL_FILE, g_sdSelName);

  lv_obj_t*col=lv_obj_create(g_sd_parent); lv_obj_remove_style_all(col);
  lv_obj_set_size(col,lv_pct(100),lv_pct(82)); lv_obj_align(col,LV_ALIGN_BOTTOM_MID,0,0);
  lv_obj_set_flex_flow(col,LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(col,LV_FLEX_ALIGN_START,LV_FLEX_ALIGN_CENTER,LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_row(col,7,0);

  const char*prim;
  if(g_sdSelDir)                  prim=LV_SYMBOL_RIGHT " Open";
  else if(sd_is_wav(g_sdSelName)) prim=LV_SYMBOL_PLAY " Play";
  else if(sd_is_mp3(g_sdSelName)) prim=LV_SYMBOL_PLAY " Play";
  else                            prim=LV_SYMBOL_EDIT " Edit";
  lv_obj_t*bp=lv_button_create(col); lv_obj_set_size(bp,lv_pct(94),30);
  lv_obj_set_style_bg_color(bp,lv_color_hex(0x1C6B34),0);
  { lv_obj_t*l=lv_label_create(bp); lv_label_set_text(l,prim); lv_obj_center(l); }
  lv_obj_add_event_cb(bp,[](lv_event_t*){
     if(g_sdSelDir) sd_act_open();
     else if(sd_is_wav(g_sdSelName)) sd_play_wav(g_sdSelFull);
     else if(sd_is_mp3(g_sdSelName)) mp3player::play(g_sdSelFull,g_sdSelName);
     else { strncpy(g_sdFile,g_sdSelFull,sizeof g_sdFile-1); g_sdFile[sizeof g_sdFile-1]=0; sd_go(sd_open_editor_existing); }
  },LV_EVENT_CLICKED,nullptr);
  g_sdFocus=bp;

  lv_obj_t*br=lv_button_create(col); lv_obj_set_size(br,lv_pct(94),30);
  lv_obj_set_style_bg_color(br,lv_color_hex(0x245A8A),0);
  { lv_obj_t*l=lv_label_create(br); lv_label_set_text(l,LV_SYMBOL_EDIT " Rename"); lv_obj_center(l); }
  lv_obj_add_event_cb(br,[](lv_event_t*){ g_sdNamePurpose='r'; sd_go(sd_build_name); },LV_EVENT_CLICKED,nullptr);

  lv_obj_t*bx=lv_button_create(col); lv_obj_set_size(bx,lv_pct(94),30);
  lv_obj_set_style_bg_color(bx,lv_color_hex(0x7A1F1F),0);
  { lv_obj_t*l=lv_label_create(bx); lv_label_set_text(l,LV_SYMBOL_TRASH " Delete"); lv_obj_center(l); }
  lv_obj_add_event_cb(bx,[](lv_event_t*){ sd_go(sd_build_confirm); },LV_EVENT_CLICKED,nullptr);

  lv_obj_t*bb=lv_button_create(col); lv_obj_set_size(bb,lv_pct(94),30);
  lv_obj_set_style_bg_color(bb,lv_color_hex(0x2A2A2A),0);
  { lv_obj_t*l=lv_label_create(bb); lv_label_set_text(l,LV_SYMBOL_LEFT " Back"); lv_obj_center(l); }
  lv_obj_add_event_cb(bb,[](lv_event_t*){ sd_go(sd_build_browse); },LV_EVENT_CLICKED,nullptr);
}

static void sd_build_confirm(){
  if(!g_sd_parent) return;
  lv_obj_clean(g_sd_parent);
  g_sd_edit=nullptr; g_sd_name=nullptr; g_sd_list=nullptr; g_sd_path=nullptr; g_sdFocus=nullptr;

  lv_obj_t*q=lv_label_create(g_sd_parent);
  lv_label_set_long_mode(q,LV_LABEL_LONG_WRAP); lv_obj_set_width(q,lv_pct(100));
  lv_obj_set_style_text_color(q,lv_color_hex(0xFFFFFF),0); lv_obj_align(q,LV_ALIGN_TOP_LEFT,0,0);
  lv_label_set_text_fmt(q,"Delete %s%s? This cannot be undone.", g_sdSelDir?"folder and all contents: ":"", g_sdSelName);

  lv_obj_t*yes=lv_button_create(g_sd_parent); lv_obj_set_size(yes,lv_pct(94),32);
  lv_obj_align(yes,LV_ALIGN_BOTTOM_MID,0,-40); lv_obj_set_style_bg_color(yes,lv_color_hex(0x7A1F1F),0);
  { lv_obj_t*l=lv_label_create(yes); lv_label_set_text(l,LV_SYMBOL_TRASH " Delete"); lv_obj_center(l); }
  lv_obj_add_event_cb(yes,[](lv_event_t*){ sd_act_delete_now(); },LV_EVENT_CLICKED,nullptr);

  lv_obj_t*no=lv_button_create(g_sd_parent); lv_obj_set_size(no,lv_pct(94),32);
  lv_obj_align(no,LV_ALIGN_BOTTOM_MID,0,-4); lv_obj_set_style_bg_color(no,lv_color_hex(0x173017),0);
  { lv_obj_t*l=lv_label_create(no); lv_label_set_text(l,LV_SYMBOL_LEFT " Cancel"); lv_obj_center(l); }
  lv_obj_add_event_cb(no,[](lv_event_t*){ sd_go(sd_build_actions); },LV_EVENT_CLICKED,nullptr);
  g_sdFocus=no;
}

static void sd_build_name(){
  if(!g_sd_parent) return;
  lv_obj_clean(g_sd_parent);
  g_sd_edit=nullptr; g_sd_list=nullptr; g_sd_path=nullptr; g_sd_name=nullptr; g_sdFocus=nullptr;

  lv_obj_t*t=lv_label_create(g_sd_parent);
  lv_obj_set_style_text_color(t,lv_color_hex(g_accent),0); lv_obj_align(t,LV_ALIGN_TOP_LEFT,0,0);
  lv_label_set_text(t, g_sdNamePurpose=='d'?"New folder name:" : g_sdNamePurpose=='r'?"Rename to:" : "New file name:");

  g_sd_name=lv_textarea_create(g_sd_parent);
  lv_textarea_set_one_line(g_sd_name,true);
  lv_obj_set_width(g_sd_name,lv_pct(100)); lv_obj_align(g_sd_name,LV_ALIGN_TOP_LEFT,0,22);
  lv_obj_set_style_bg_color(g_sd_name,lv_color_hex(0x0E120E),0);
  lv_obj_set_style_text_color(g_sd_name,lv_color_hex(0xE0E0E0),0);
  if(g_sdNamePurpose=='r')      lv_textarea_set_text(g_sd_name,g_sdSelName);
  else if(g_sdNamePurpose=='f') lv_textarea_set_placeholder_text(g_sd_name,"notes.txt");
  else                          lv_textarea_set_placeholder_text(g_sd_name,"folder");

  lv_obj_t*br=lv_obj_create(g_sd_parent); lv_obj_remove_style_all(br);
  lv_obj_set_size(br,lv_pct(100),34); lv_obj_align(br,LV_ALIGN_BOTTOM_MID,0,0);
  lv_obj_set_flex_flow(br,LV_FLEX_FLOW_ROW);
  lv_obj_set_flex_align(br,LV_FLEX_ALIGN_SPACE_EVENLY,LV_FLEX_ALIGN_CENTER,LV_FLEX_ALIGN_CENTER);
  lv_obj_t*bs=lv_button_create(br); lv_obj_set_size(bs,110,30); lv_obj_set_style_bg_color(bs,lv_color_hex(0x1C6B34),0);
  { lv_obj_t*l=lv_label_create(bs); lv_label_set_text(l,LV_SYMBOL_OK " Save"); lv_obj_center(l); }
  lv_obj_add_event_cb(bs,[](lv_event_t*){ sd_name_save(); },LV_EVENT_CLICKED,nullptr);
  lv_obj_t*bc=lv_button_create(br); lv_obj_set_size(bc,110,30); lv_obj_set_style_bg_color(bc,lv_color_hex(0x2A2A2A),0);
  { lv_obj_t*l=lv_label_create(bc); lv_label_set_text(l,LV_SYMBOL_LEFT " Cancel"); lv_obj_center(l); }
  lv_obj_add_event_cb(bc,[](lv_event_t*){ sd_go(g_sdNamePurpose=='r'?sd_build_actions:sd_build_browse); },LV_EVENT_CLICKED,nullptr);
  g_sdFocus=g_sd_name;
}

static void sd_open_editor_existing(){
  if(!g_sd_parent) return;
  lv_obj_clean(g_sd_parent);
  g_sd_list=nullptr; g_sd_path=nullptr; g_sd_name=nullptr; g_sd_edit=nullptr; g_sdFocus=nullptr;

  lv_obj_t*lbl=lv_label_create(g_sd_parent);
  lv_obj_set_style_text_color(lbl,lv_color_hex(g_accent),0);
  lv_label_set_long_mode(lbl,LV_LABEL_LONG_DOT); lv_obj_set_width(lbl,lv_pct(100));
  lv_obj_align(lbl,LV_ALIGN_TOP_LEFT,0,0);
  const char*base=strrchr(g_sdFile,'/'); lv_label_set_text(lbl,base?base+1:g_sdFile);

  g_sd_edit=lv_textarea_create(g_sd_parent);
  lv_obj_set_size(g_sd_edit,lv_pct(100),lv_pct(66)); lv_obj_align(g_sd_edit,LV_ALIGN_TOP_LEFT,0,22);
  lv_obj_set_style_bg_color(g_sd_edit,lv_color_hex(0x0E120E),0);
  lv_obj_set_style_text_color(g_sd_edit,lv_color_hex(0xD0D0D0),0);
  if(g_sdOk && g_sdFile[0] && tr_spi_lock()){
    File f=SD.open(g_sdFile,FILE_READ);
    if(f){ size_t n=f.size(); if(n>8000)n=8000; static char cbuf[8001]; size_t r=f.read((uint8_t*)cbuf,n); cbuf[r]=0; lv_textarea_set_text(g_sd_edit,cbuf); f.close(); }
    tr_spi_unlock();
  }

  lv_obj_t*br=lv_obj_create(g_sd_parent); lv_obj_remove_style_all(br);
  lv_obj_set_size(br,lv_pct(100),34); lv_obj_align(br,LV_ALIGN_BOTTOM_MID,0,0);
  lv_obj_set_flex_flow(br,LV_FLEX_FLOW_ROW);
  lv_obj_set_flex_align(br,LV_FLEX_ALIGN_SPACE_EVENLY,LV_FLEX_ALIGN_CENTER,LV_FLEX_ALIGN_CENTER);
  lv_obj_t*bs=lv_button_create(br); lv_obj_set_size(bs,110,30); lv_obj_set_style_bg_color(bs,lv_color_hex(0x1C6B34),0);
  { lv_obj_t*l=lv_label_create(bs); lv_label_set_text(l,LV_SYMBOL_OK " Save"); lv_obj_center(l); }
  lv_obj_add_event_cb(bs,[](lv_event_t*){ sd_editor_save(); },LV_EVENT_CLICKED,nullptr);
  lv_obj_t*bc=lv_button_create(br); lv_obj_set_size(bc,110,30); lv_obj_set_style_bg_color(bc,lv_color_hex(0x2A2A2A),0);
  { lv_obj_t*l=lv_label_create(bc); lv_label_set_text(l,LV_SYMBOL_LEFT " Cancel"); lv_obj_center(l); }
  lv_obj_add_event_cb(bc,[](lv_event_t*){ sd_go(sd_build_browse); },LV_EVENT_CLICKED,nullptr);
  g_sdFocus=g_sd_edit;
}

static void build_sdexp(lv_obj_t *parent){
  lv_obj_t*cont=lv_obj_create(parent); lv_obj_remove_style_all(cont);
  lv_obj_set_size(cont,lv_pct(100),lv_pct(100)); lv_obj_set_style_bg_opa(cont,LV_OPA_TRANSP,0);
  lv_obj_set_style_pad_top(cont,24,0);                 // room for the back button
  g_sd_parent=cont; strcpy(g_sdPath,"/");
  g_sd_list=nullptr; g_sd_path=nullptr; g_sd_edit=nullptr; g_sd_name=nullptr; g_sdFocus=nullptr;
  g_sdNext=nullptr;
  sd_build_browse();                                   // first build is safe (not in an event)
}

// ======================= MUSIC PLAYER (MP3) =============================
// Browser + transport over the mp3player engine (tr_mp3.h). The engine streams
// on a background core; this UI only issues main-thread commands and polls
// state each loop. No screen rebuilds happen inside events, so no deferral.
static char g_mp3Paths[48][224];
static char g_mp3Disp[48][48];
static int  g_mp3Count=0;
static int  g_mp3Sel=-1;
static lv_obj_t *g_mp3Now=nullptr,*g_mp3Time=nullptr,*g_mp3Bar=nullptr,*g_mp3PlayLbl=nullptr;

static bool mp3_is(const char*name){ const char*d=strrchr(name,'.'); return d && !strcasecmp(d,".mp3"); }

// scan one directory for .mp3 files (caller already holds the SPI lock)
static void mp3_add(const char*dir){
  File d=SD.open(dir);
  if(d && d.isDirectory()){
    for(File e=d.openNextFile(); e && g_mp3Count<48; e=d.openNextFile()){
      if(!e.isDirectory()){
        const char*nm=e.name(); const char*base=strrchr(nm,'/'); base=base?base+1:nm;
        if(mp3_is(base)){
          int l=strlen(dir);
          snprintf(g_mp3Paths[g_mp3Count],224,"%s%s%s",dir,(l&&dir[l-1]=='/')?"":"/",base);
          strncpy(g_mp3Disp[g_mp3Count],base,47); g_mp3Disp[g_mp3Count][47]=0;
          g_mp3Count++;
        }
      }
      e.close();
    }
  }
  if(d) d.close();
}
static void mp3_scan(){
  g_mp3Count=0;
  if(!g_sdOk || !tr_spi_lock()) return;
  mp3_add("/"); mp3_add("/music"); mp3_add("/Music"); mp3_add("/audio");
  tr_spi_unlock();
}
static void mp3_playIndex(int i){
  if(i<0||i>=g_mp3Count) return;
  g_mp3Sel=i;
  mp3player::play(g_mp3Paths[i], g_mp3Disp[i]);
  if(g_mp3Now) lv_label_set_text(g_mp3Now, g_mp3Disp[i]);
}

static void build_mp3(lv_obj_t *parent){
  lv_obj_t*cont=lv_obj_create(parent); lv_obj_remove_style_all(cont);
  lv_obj_set_size(cont,lv_pct(100),lv_pct(100)); lv_obj_set_style_bg_opa(cont,LV_OPA_TRANSP,0);
  lv_obj_set_style_pad_top(cont,24,0);                 // room for the back button
  lv_obj_clear_flag(cont,LV_OBJ_FLAG_SCROLLABLE);

  g_mp3Now=lv_label_create(cont);
  lv_label_set_long_mode(g_mp3Now,LV_LABEL_LONG_DOT);
  lv_obj_set_style_text_color(g_mp3Now,lv_color_hex(g_accent),0);
  lv_obj_set_width(g_mp3Now,lv_pct(70)); lv_obj_align(g_mp3Now,LV_ALIGN_TOP_LEFT,0,0);
  lv_label_set_text(g_mp3Now,"-- select a track --");

  g_mp3Time=lv_label_create(cont);
  lv_obj_set_style_text_color(g_mp3Time,lv_color_hex(0xB0B0B0),0);
  lv_obj_align(g_mp3Time,LV_ALIGN_TOP_RIGHT,0,0); lv_label_set_text(g_mp3Time,"0:00");

  g_mp3Bar=lv_bar_create(cont);
  lv_obj_set_size(g_mp3Bar,lv_pct(100),6); lv_obj_align(g_mp3Bar,LV_ALIGN_TOP_LEFT,0,20);
  lv_bar_set_range(g_mp3Bar,0,100); lv_bar_set_value(g_mp3Bar,0,LV_ANIM_OFF);
  lv_obj_set_style_bg_color(g_mp3Bar,lv_color_hex(0x202820),LV_PART_MAIN);
  lv_obj_set_style_bg_color(g_mp3Bar,lv_color_hex(g_accent),LV_PART_INDICATOR);

  lv_obj_t*bar=lv_obj_create(cont); lv_obj_remove_style_all(bar);
  lv_obj_set_size(bar,lv_pct(100),34); lv_obj_align(bar,LV_ALIGN_TOP_LEFT,0,32);
  lv_obj_set_flex_flow(bar,LV_FLEX_FLOW_ROW);
  lv_obj_set_flex_align(bar,LV_FLEX_ALIGN_SPACE_EVENLY,LV_FLEX_ALIGN_CENTER,LV_FLEX_ALIGN_CENTER);
  struct Btn { const char*txt; uint32_t col; void(*cb)(lv_event_t*); };
  static const Btn btns[] = {
    {LV_SYMBOL_PREV,  0x243040, [](lv_event_t*){ mp3_playIndex(g_mp3Sel-1); }},
    {LV_SYMBOL_PLAY,  0x1C6B34, [](lv_event_t*){ if(mp3player::isActive()) mp3player::togglePause(); else mp3_playIndex(g_mp3Sel<0?0:g_mp3Sel); }},
    {LV_SYMBOL_STOP,  0x7A1F1F, [](lv_event_t*){ mp3player::stop(); }},
    {LV_SYMBOL_NEXT,  0x243040, [](lv_event_t*){ mp3_playIndex(g_mp3Sel+1); }},
    {LV_SYMBOL_VOLUME_MID,0x243040,[](lv_event_t*){ mp3player::volDown(); }},
    {LV_SYMBOL_VOLUME_MAX,0x243040,[](lv_event_t*){ mp3player::volUp(); }},
  };
  for(int i=0;i<6;i++){
    lv_obj_t*b=lv_button_create(bar); lv_obj_set_size(b,64,30);
    lv_obj_set_style_bg_color(b,lv_color_hex(btns[i].col),0);
    lv_obj_t*l=lv_label_create(b); lv_label_set_text(l,btns[i].txt); lv_obj_center(l);
    lv_obj_add_event_cb(b,btns[i].cb,LV_EVENT_CLICKED,nullptr);
    if(i==1) g_mp3PlayLbl=l;                            // remember play/pause glyph
  }

  mp3_scan();
  lv_obj_t*list=lv_list_create(cont);
  lv_obj_set_size(list,lv_pct(100),lv_pct(58)); lv_obj_align(list,LV_ALIGN_BOTTOM_MID,0,0);
  lv_obj_set_style_bg_color(list,lv_color_hex(0x0E120E),0);
  if(g_mp3Count==0){ lv_list_add_text(list,"no .mp3 found  (put files on SD, or in /music)"); }
  else for(int i=0;i<g_mp3Count;i++){
    lv_obj_t*b=lv_list_add_button(list,LV_SYMBOL_AUDIO,g_mp3Disp[i]);
    lv_obj_set_style_text_color(b,lv_color_hex(0xC8C8C8),0);
    lv_obj_add_event_cb(b,[](lv_event_t*e){ mp3_playIndex((int)(intptr_t)lv_event_get_user_data(e)); },
                        LV_EVENT_CLICKED,(void*)(intptr_t)i);
  }
}

static void mp3_loop(){
  mp3player::service();
  if(g_mp3Time){ uint32_t s=mp3player::elapsedSec(); char t[12];
    snprintf(t,sizeof t,"%lu:%02lu",(unsigned long)(s/60),(unsigned long)(s%60)); lv_label_set_text(g_mp3Time,t); }
  if(g_mp3Bar) lv_bar_set_value(g_mp3Bar, mp3player::progressPct(), LV_ANIM_OFF);
  if(g_mp3PlayLbl) lv_label_set_text(g_mp3PlayLbl,
      (mp3player::isActive() && !mp3player::isPaused())? LV_SYMBOL_PAUSE : LV_SYMBOL_PLAY);
}
static void mp3_leave(){
  mp3player::stop();
  g_mp3Now=g_mp3Time=g_mp3Bar=g_mp3PlayLbl=nullptr;
}

static void enter_mode(Mode m){
  if(m==MODE_LAUNCHER){back_to_launcher();return;}
  if(m!=MODE_MP3) mp3player::stop();             // free the codec for whatever this mode needs
  nav_begin_screen();
  g_scr_mode=lv_obj_create(NULL);
  lv_obj_set_style_bg_color(g_scr_mode,lv_color_hex(TR_THEME_BG),0);
  lv_obj_set_style_text_color(g_scr_mode,lv_color_hex(TR_THEME_GREEN),0);
  if(m==MODE_PAGER_WD){
    hdr_probe();                  // nRF24 or CC1101 on the header; re-checked on every entry
    build_pagerwd(g_scr_mode);
  }
  else if(m==MODE_TUNNELRAT){ build_remote(g_scr_mode); }
  else if(m==MODE_WIFI_ATTACKS){ atk::buildUI(g_scr_mode); }
  else if(m==MODE_SETTINGS){ build_settings(g_scr_mode); }
  else if(m==MODE_SDEXP){ build_sdexp(g_scr_mode); }
  else if(m==MODE_MP3){ build_mp3(g_scr_mode); }
  else if(m==MODE_CONTACTS){
    lv_obj_t *vaultPanel = lv_obj_create(g_scr_mode);
    lv_obj_set_size(vaultPanel, lv_pct(100), lv_pct(88));
    lv_obj_align(vaultPanel, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_set_style_bg_color(vaultPanel, lv_color_hex(0x000000), LV_PART_MAIN);
    lv_obj_set_style_bg_opa(vaultPanel, LV_OPA_COVER, LV_PART_MAIN);
    lv_obj_set_style_border_width(vaultPanel, 0, LV_PART_MAIN);
    contacts::buildUI(vaultPanel);
    contacts::setNavigationCallback([](){
      nav_begin_screen();
      nav_collect(g_scr_mode);
      // Physical keyboard sends keys to the focused LVGL widget.
      // Focus the vault textarea rather than the Back/Create buttons.
      if (!contacts::isUnlocked() && contacts::inputField()) {
        // Focus the passphrase field so the keyboard types into it, but keep
        // the group out of edit mode so the wheel still navigates to the buttons.
        lv_group_focus_obj(contacts::inputField());
        lv_group_set_editing(g_nav_group, false);
      } else if (lv_group_get_obj_count(g_nav_group)) {
        // Unlocked: start on a button so the encoder can navigate the vault.
        lv_group_focus_obj(lv_group_get_focused(g_nav_group));
        lv_group_set_editing(g_nav_group, false);
      }
    });
  }
  else if(m==MODE_NFC||m==MODE_EVILPORTAL||m==MODE_BLE||m==MODE_COMMS||m==MODE_NRF24||m==MODE_WIFIRADAR||m==MODE_BTRADAR||m==MODE_CC1101){
    // These module screens were designed with a reserved top strip for the
    // back button, so build them into a padded content area (as in the Comms build).
    lv_obj_t *content=lv_obj_create(g_scr_mode);
    lv_obj_remove_style_all(content);
    lv_obj_set_style_bg_opa(content,LV_OPA_TRANSP,0);
    lv_obj_set_size(content,lv_pct(100),lv_pct(100));
    lv_obj_set_style_pad_top(content,24,0);
    if(m==MODE_NFC)             nfc::buildUI(content);
    else if(m==MODE_EVILPORTAL) evilportal::buildUI(content);
    else if(m==MODE_BLE)        ble::buildUI(content);
    else if(m==MODE_COMMS)      comms::buildUI(content);
    else if(m==MODE_NRF24)      nrfscan::buildUI(content);
    else if(m==MODE_WIFIRADAR)  wifiradar::buildUI(content);
    else if(m==MODE_BTRADAR)    btradar::buildUI(content);
    else                        ccradar::buildUI(content);
  }
  add_back_button(g_scr_mode);
  nav_collect(g_scr_mode);
  lv_screen_load(g_scr_mode);
  if (m == MODE_CONTACTS && contacts::inputField()) {
    lv_group_focus_obj(contacts::inputField());
    lv_group_set_editing(g_nav_group, false);  // wheel navigates; keyboard still types
  }
  else if (g_nav_group && lv_group_get_obj_count(g_nav_group))
    lv_group_focus_obj(lv_group_get_focused(g_nav_group));
  g_mode=m;
  if(m==MODE_PAGER_WD) pagerwd_enter();
  if(m==MODE_TUNNELRAT) remote_enter();
}

static void back_to_launcher(){
  if(g_mode==MODE_PAGER_WD) pagerwd_exit();
  if(g_mode==MODE_TUNNELRAT) remote_exit();
  if(g_mode==MODE_WIFI_ATTACKS) atk::leave();
  if(g_mode==MODE_CONTACTS) contacts::leave();
  if(g_mode==MODE_NFC) nfc::leave();
  if(g_mode==MODE_EVILPORTAL) evilportal::leave();
  if(g_mode==MODE_BLE) ble::leave();
  if(g_mode==MODE_COMMS) comms::leave();
  if(g_mode==MODE_NRF24) nrfscan::leave();
  if(g_mode==MODE_WIFIRADAR) wifiradar::leave();
  if(g_mode==MODE_BTRADAR) btradar::leave();
  if(g_mode==MODE_CC1101) ccradar::leave();
  if(g_mode==MODE_MP3) mp3_leave();
  // Detach focus from soon-to-be-deleted widgets before destroying the mode screen.
  if (g_nav_group) lv_group_remove_all_objs(g_nav_group);
  if(g_launcherDirty){ g_launcherDirty=false; lv_obj_t*oldL=g_scr_launcher; build_launcher(); if(oldL && oldL!=g_scr_launcher) lv_obj_delete(oldL); }
  lv_screen_load(g_scr_launcher);
  if(g_scr_mode){ lv_obj_delete(g_scr_mode); g_scr_mode=nullptr; }
  g_mode=MODE_LAUNCHER;
  nav_collect(g_scr_launcher);
  nav_bind_inputs();
  if (g_launcher_first) lv_group_focus_obj(g_launcher_first);
}

// ===========================================================================
//  setup / loop
// ===========================================================================
static void show_splash(){
  lv_obj_t *scr=lv_obj_create(NULL);
  lv_obj_set_style_bg_color(scr,lv_color_hex(0x000000),0);
  lv_obj_set_style_bg_opa(scr,LV_OPA_COVER,0);
  lv_obj_set_style_border_width(scr,0,0);
  lv_obj_t *gear=lv_image_create(scr);                                // gear ring: fixed silver
  lv_image_set_src(gear,&tr_splash_gear_img);
  lv_obj_set_style_image_recolor(gear,lv_color_hex(0xC4CCD6),0);
  lv_obj_set_style_image_recolor_opa(gear,LV_OPA_COVER,0);
  lv_obj_align(gear,LV_ALIGN_CENTER,0,-10);
  lv_obj_t *img=lv_image_create(scr);                                 // rat: tinted with the theme accent
  lv_image_set_src(img,&tr_splash_rat_img);
  lv_obj_set_style_image_recolor(img,lv_color_hex(g_accent),0);
  lv_obj_set_style_image_recolor_opa(img,LV_OPA_COVER,0);
  lv_obj_align(img,LV_ALIGN_CENTER,0,-10);
  lv_obj_t *cap=lv_label_create(scr);
  lv_label_set_text(cap,"TUNNEL R.A.T.");
  lv_obj_set_style_text_color(cap,lv_color_hex(TR_THEME_GREEN),0);
  lv_obj_align(cap,LV_ALIGN_BOTTOM_MID,0,-6);
  lv_screen_load(scr);
  uint32_t t0=millis();
  while(millis()-t0 < 1900){ lv_timer_handler(); delay(5); }
}

void setup(){
  Serial.begin(115200);
#if TR_NRF24_ENABLE
  nrf::parkPins();     // CSN high / CE low BEFORE the shared SPI bus is used by SD/LoRa/display
#endif
  g_resetReason = esp_reset_reason();

  // --- Board bring-up ---
  instance.begin();                            // powers display/keyboard/encoder/GPS/radio
  beginLvglHelper(instance);                   // wire LVGL to the panel + input devices
  instance.setBrightness(DEVICE_MAX_BRIGHTNESS_LEVEL);

  ui_style_init();

  // radios start idle; each mode brings up what it needs
  WiFi.mode(WIFI_STA); WiFi.disconnect(true);
  g_udp.begin(0);
  // LilyGoLib's instance.begin() already mounted SD on the shared SPI bus.
  // A second SD.begin() re-inits that bus and corrupts the display -> boot loop.
  g_sdOk=(SD.cardType()!=CARD_NONE); if(g_sdOk)SD.mkdir(TR_SD_LOG_DIR);
#if TR_NRF24_ENABLE
  nrf::attach(&SPI, tr_spi_lock, tr_spi_unlock);
#endif
#if TR_CC1101_ENABLE
  cc::attach(tr_spi_lock, tr_spi_unlock);
#endif
  hdr_probe();
  Serial.printf("[BOOT] header radio: %s\n", g_hdr==HDR_NONE ? "none found" : hdr_name());
  Serial.printf("[BOOT] reset reason: %s  SD: %s\n", reset_reason_str(g_resetReason), g_sdOk ? "ok" : "none");

  settings_load();   // restore saved theme + brightness before the splash
  show_splash();
  build_launcher();
  lv_screen_load(g_scr_launcher);

  // Diagnostic: list all LVGL input devices registered by LilyGoLib.
  Serial.println("\n=== TUNNEL R.A.T. INPUT DEBUG ===");
  lv_indev_t *debugDev = nullptr;
  int debugCount = 0;
  while ((debugDev = lv_indev_get_next(debugDev)) != nullptr) {
    Serial.printf("Input %d: type=%d\n", debugCount++,
                  (int)lv_indev_get_type(debugDev));
  }
  Serial.printf("Total LVGL input devices: %d\n", debugCount);
  Serial.println("=== END INPUT DEBUG ===");
}

void loop(){
  lv_timer_handler();
  mp3player::service();          // tidy codec/file if a track finished (any mode)

  switch(g_mode){
    case MODE_PAGER_WD:
      gps_tick();           // Pager GPS -> every record (no NanoPi in this mode)
      pagerwd_loop();
      break;
    case MODE_TUNNELRAT:
      uplink_tick();
      gps_tick();           // Pager GPS -> NanoPi gpsd over UDP
      remote_loop();
      break;
    case MODE_WIFI_ATTACKS:
      atk::tick();
      break;
    case MODE_NFC:        nfc::loop();        break;
    case MODE_EVILPORTAL: evilportal::loop(); break;
    case MODE_BLE:        ble::loop();        break;
    case MODE_COMMS:      comms::loop();      break;
    case MODE_NRF24:      nrfscan::loop();    break;
    case MODE_WIFIRADAR:  wifiradar::loop();  break;
    case MODE_BTRADAR:    btradar::loop();    break;
    case MODE_CC1101:     ccradar::loop();    break;
    case MODE_MP3:        mp3_loop();         break;
    case MODE_LAUNCHER:
    default:
      break;
  }
  delay(3);
}
