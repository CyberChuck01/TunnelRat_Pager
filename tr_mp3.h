// ===========================================================================
//  tr_mp3.h  —  Tunnel R.A.T. // T-Pager  —  SD-card MP3 player
//
//  Streams an MP3 off the SD card to the speaker. A background task does the
//  SD reads (SPI-locked, shared bus with the display), the MP3 decode, and the
//  BLOCKING I2S write, all on its own core, so the UI never stalls. All codec
//  I2C (open / close / setVolume) stays on the MAIN thread: play(), stop() and
//  service() are called from the LVGL context, never from the task, so codec
//  config can't race the keypad / touch on the shared I2C bus.
//
//  Decoder: minimp3 (lieff, public domain / CC0) — a single-header decoder,
//  bundled in minimp3.h. No external library install required.
// ===========================================================================
#pragma once
#include "config.h"
#include <Arduino.h>
#include <FS.h>
#include <SD.h>

#define MINIMP3_IMPLEMENTATION      // emit the decoder here (this header is included once)
#include "minimp3.h"

// tr_spi_lock()/tr_spi_unlock() and the global `instance` are already declared
// (tr_platform.h + LilyGoLib.h are included before this header in the sketch).

namespace mp3player {

static const int IN_CAP = 16 * 1024;            // SD read / decode input buffer
static uint8_t  *s_in  = nullptr;               // PSRAM input (kept compacted)
static int       s_inLen = 0;
static int16_t  *s_pcm = nullptr;               // PSRAM decoded PCM (one frame)
static mp3dec_t  s_dec;
static File      s_file;
static TaskHandle_t s_task = nullptr;

static volatile bool s_run=false;               // task should keep running
static volatile bool s_paused=false;
static volatile bool s_done=false;              // task reached EOF and exited
static volatile bool s_eof=false;               // SD read hit end of file
static volatile bool s_codecOpen=false;
static volatile uint32_t s_rate=44100;
static volatile uint8_t  s_ch=2;
static volatile uint32_t s_played=0;            // PCM frames (per channel) played
static volatile uint32_t s_fileSize=0;
static volatile uint32_t s_bytesRead=0;
static uint8_t s_vol=80;
static char    s_name[64]="";

inline bool ensureBufs(){
  if(!s_in)  s_in =(uint8_t*)ps_malloc(IN_CAP);
  if(!s_pcm) s_pcm=(int16_t*)ps_malloc(MINIMP3_MAX_SAMPLES_PER_FRAME*sizeof(int16_t));
  return s_in && s_pcm;
}

// ---- background decode/playback task (no codec I2C in here) ----------------
static void task(void*){
  mp3dec_frame_info_t info;
  static int16_t silence[256]; memset(silence,0,sizeof silence);
  while(s_run){
    if(s_paused){ instance.codec.write((uint8_t*)silence,sizeof silence); continue; }
    if(!s_eof && s_inLen < 4096){                       // refill from SD
      if(tr_spi_lock()){
        int n=s_file.read(s_in+s_inLen, IN_CAP-s_inLen);
        tr_spi_unlock();
        if(n>0){ s_inLen+=n; s_bytesRead+=n; } else s_eof=true;
      }
    }
    if(s_inLen<=0) break;                               // EOF and drained
    int samples=mp3dec_decode_frame(&s_dec, s_in, s_inLen, s_pcm, &info);
    if(info.frame_bytes>0){
      memmove(s_in, s_in+info.frame_bytes, s_inLen-info.frame_bytes);
      s_inLen-=info.frame_bytes;
    } else {
      if(s_eof) break;                                  // nothing left to feed it
      if(s_inLen>=IN_CAP-16){ memmove(s_in,s_in+1,s_inLen-1); s_inLen-=1; } // resync
      continue;                                         // loop refills
    }
    if(samples>0){
      instance.codec.write((uint8_t*)s_pcm, (size_t)samples*info.channels*2);
      s_played += samples;
    }
  }
  s_done=true;
  s_task=nullptr;
  vTaskDelete(nullptr);
}

// ---- main-thread API -------------------------------------------------------
inline void stop(){
  if(s_task){ s_run=false; for(int i=0;i<60 && s_task;i++) delay(5); }
  s_run=false; s_paused=false; s_done=false;
  if(s_codecOpen){ instance.codec.close(); s_codecOpen=false; }
  if(s_file){ s_file.close(); }
  s_inLen=0; s_eof=false; s_played=0; s_bytesRead=0; s_fileSize=0; s_name[0]=0;
}

inline bool play(const char*path,const char*name){
  stop();                                               // kill any current playback
  if(!path||!path[0]||!ensureBufs()) return false;
  if(!tr_spi_lock()) return false;
  s_file=SD.open(path,FILE_READ);
  if(!s_file){ tr_spi_unlock(); return false; }
  s_fileSize=s_file.size();
  int r=s_file.read(s_in,IN_CAP); s_inLen=(r>0)?r:0;
  s_bytesRead=s_inLen;
  tr_spi_unlock();
  if(s_inLen<=0){ s_file.close(); return false; }

  mp3dec_init(&s_dec);
  mp3dec_frame_info_t info; int samples=0, guard=0;     // find first audio frame (skips ID3)
  while(guard++ < 64){
    samples=mp3dec_decode_frame(&s_dec, s_in, s_inLen, s_pcm, &info);
    if(info.frame_bytes>0){ memmove(s_in,s_in+info.frame_bytes,s_inLen-info.frame_bytes); s_inLen-=info.frame_bytes; }
    else break;
    if(samples>0) break;
  }
  if(samples<=0){ s_file.close(); return false; }       // not a decodable MP3
  s_rate=info.hz; s_ch=info.channels?info.channels:2;
  if(instance.codec.open(16,s_ch,s_rate)!=0){ s_file.close(); return false; }
  instance.codec.setVolume(s_vol);
  s_codecOpen=true;
  instance.codec.write((uint8_t*)s_pcm,(size_t)samples*s_ch*2);   // first frame now
  s_played=samples;
  strncpy(s_name,name?name:"",sizeof s_name-1); s_name[sizeof s_name-1]=0;
  s_eof=false; s_done=false; s_paused=false; s_run=true;
  if(xTaskCreatePinnedToCore(task,"mp3",8192,nullptr,2,&s_task,0)!=pdPASS){
    s_run=false; s_task=nullptr; instance.codec.close(); s_codecOpen=false; s_file.close(); return false;
  }
  return true;
}

// Called from the main loop: when the task finishes on its own (EOF), tidy the
// codec/file here on the main thread (keeps all codec I2C off the task).
inline void service(){
  if(s_done && !s_task){
    if(s_codecOpen){ instance.codec.close(); s_codecOpen=false; }
    if(s_file){ s_file.close(); }
    s_run=false; s_done=false;
  }
}
inline void togglePause(){ if(s_run) s_paused=!s_paused; }
inline bool isActive(){ return s_run && !s_done; }
inline bool isPaused(){ return s_paused; }
inline uint32_t elapsedSec(){ return s_rate? s_played/s_rate : 0; }
inline uint8_t  progressPct(){ return s_fileSize? (uint8_t)((uint64_t)s_bytesRead*100/s_fileSize):0; }
inline const char* trackName(){ return s_name; }
inline uint8_t volume(){ return s_vol; }
inline void setVol(int v){ if(v<0)v=0; if(v>100)v=100; s_vol=(uint8_t)v; if(s_codecOpen) instance.codec.setVolume(s_vol); }
inline void volUp(){ setVol(s_vol+10); }
inline void volDown(){ setVol(s_vol-10); }

} // namespace mp3player
