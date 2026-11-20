// ===========================================================================
// Tunnel R.A.T. // T-Pager  —  config.h
// Device: LILYGO T-LoRa Pager (ESP32-S3, 16MB flash / 8MB PSRAM)
// cyberchuck01 · audit only networks/devices you own or are authorized to test.
// ---------------------------------------------------------------------------
// Edit the values in this file, then flash TunnelRat_Pager.ino.
// ===========================================================================
#pragma once

// ---- Identity -------------------------------------------------------------
// Shown in the UI and attached to every upload so the NanoPi knows which
// field unit a hit came from. Keep it short.
#define TR_NODE_NAME      "pager-01"

// ---- Tunnel R.A.T. base station (NanoPi Zero2) ----------------------------
// The Pager joins the NanoPi's own AP and talks to the dashboard over it.
#define TR_AP_SSID        "tunnel-rat"
#define TR_AP_PASS        "SET_AP_PASSWORD_HERE"  // <-- set to your NanoPi AP password (only needed for Tunnel R.A.T. Remote)
#define TR_NANOPI_HOST    "192.168.50.1"         // NanoPi AP IP (AP_IP in installer)
#define TR_NANOPI_PORT    8080                   // Flask dashboard port
// Must match the dashboard's REMOTE_API_KEY (env TUNNEL_RAT_API_KEY).
// Default install value is "tunnelrat-change-me" — change both.
#define TR_API_KEY        "tunnelrat-change-me"

// ---- Evil Portal (open captive-portal AP + credential capture) ------------
#define TR_PORTAL_SSID    "Free WiFi"            // SSID the open portal broadcasts

// GPS-over-UDP: the Pager fires raw NMEA at the NanoPi, exactly like the
// ESP32-MDK does, so gpsd ingests the Pager's fix (frees a USB port on the hub).
// Must match MDK_GPS_PORT in the installer (default 10110).
#define TR_GPS_UDP_PORT   10110

// ---- What to do when the base station isn't reachable ---------------------
// true  = keep wardriving and log to the SD card locally (standalone mode)
// false = pause uploads but keep the UI/GPS running
#define TR_LOG_TO_SD_WHEN_OFFLINE  true
#define TR_SD_LOG_DIR     "/tunnelrat"           // folder on the microSD

// ---- Radio variant --------------------------------------------------------
// Pick the ONE that matches the LoRa module soldered in your Pager.
// (Set the matching board revision in Arduino IDE too — see the .ino header.)
//   SX1262  : sub-GHz (433/868/915/920)  — most common, DEFAULT
//   LR1121  : sub-GHz + 2.4G
//   CC1101  : sub-GHz (G)FSK/OOK
//   SX1280  : 2.4G only
#define TR_RADIO_SX1262   1
#define TR_RADIO_LR1121   0
#define TR_RADIO_CC1101   0
#define TR_RADIO_SX1280   0

// ---- Mesh listen presets --------------------------------------------------
// The Pager tunes its LoRa radio to a mesh preset and logs any node it hears
// (RSSI/SNR + the UNENCRYPTED Meshtastic sender node-ID). It does NOT join or
// transmit — receive-only wardriving.
//
// Meshtastic US LongFast defaults (change for your region: EU868 = 869.525, etc.)
#define TR_MESH_FREQ_MHZ     906.875     // US LongFast center
#define TR_MESH_BW_KHZ       250.0
#define TR_MESH_SF           11
#define TR_MESH_CR           5           // 4/5
#define TR_MESH_PREAMBLE     16
#define TR_MESH_SYNCWORD     0x2B        // Meshtastic sync word
// How long to sit on the mesh preset each wardrive cycle (ms) before the radio
// is free again. 0 = always listening (mesh only; skips nothing).
#define TR_MESH_DWELL_MS     4000

// ---- Scan cadence ---------------------------------------------------------
#define TR_WIFI_SCAN_MS      8000        // WiFi scan period
#define TR_BLE_SCAN_MS       5000        // BLE scan window
#define TR_UPLOAD_MS         10000       // push buffered sightings this often
#define TR_GPS_PUSH_MS       2000        // push NMEA to the NanoPi this often
#define TR_MAX_BUFFER        120         // max sightings held before a forced flush

// ---- Wardrive stability (crash-fix build) -----------------------------------
// The same WiFi BSSID / BLE MAC is logged again at most this often. Keeps SD
// writes, uploads and the hit list sane in dense areas. 0 = log every report.
#define TR_REOBSERVE_MS      30000
// Joining the NanoPi AP is scheduled, never started while a wardrive WiFi scan
// is running, and WiFi scans pause briefly after each join attempt.
#define TR_AUTO_JOIN_NANOPI  1
#define TR_RECONNECT_MS      45000       // retry joining "tunnel-rat" this often
#define TR_CONNECT_GRACE_MS  8000        // hold WiFi scans this long after a join attempt
// SD writes are batched in RAM and flushed from the main loop only.
// STOP & SAVE (and leaving the mode) always flush.
#define TR_SD_FLUSH_MS       2000
#define TR_BLE_QUEUE_LEN     64          // BLE reports waiting for the main loop
#define TR_DIAG_SERIAL_MS    10000       // [WD] heap/queue line on Serial; 0 = off

// ---- Per-session, per-sensor files ------------------------------------------
// Each START makes  /tunnelrat/sessions/<UTC>_<id>/  containing:
//   wifi_wigle.csv  ble_wigle.csv   WiGLE 1.6 CSV -> wigle.net + wdgwars.pl
//   mesh.csv  nrf24.jsonl  nfc.csv   GPS on every row (blank when no fix)
//   raw_sightings.jsonl              every WiFi/BLE/mesh report, fix or not
//   session_info.txt                 counts + what to upload where (on STOP)
// WiGLE/WDGWars rows are ONLY written with a valid GPS fix + GPS time;
// no-fix observations still go to raw_sightings.jsonl.
#define TR_SESSIONS_DIR      TR_SD_LOG_DIR "/sessions"
#define TR_WIGLE_DEVICE      "LILYGO T-LoRa Pager"
#define TR_FW_VERSION        "TunnelRAT-TPager-2026.11"
#define TR_UERE_M            2.5         // accuracy estimate = HDOP x this (metres)

// ---- NFC (built-in ST25R3916, reader mode, tag taps only) ---------------------
#define TR_NFC_ENABLE        1           // 0 = never touch the NFC chip

// ---- CC1101 (alternative module in the same header "radio slot") ------------
// The slot holds EITHER an nRF24 OR a CC1101; the Pager detects which on
// entering Pager Wardrive. CC1101 wiring (header silkscreen -> module):
//   3.3V->VCC  GND->GND  RX(GPIO44)->CSN  SCK->SCK  MOSI->MOSI(SI)
//   MISO->MISO(SO)  GPIO9->GDO0   GDO2: unconnected.  Not TX/GPIO43.
#define TR_CC1101_ENABLE     1
#define TR_CC1101_CSN_PIN    44
#define TR_CC1101_GDO0_PIN   9
#define TR_CC1101_FREQS      300.0, 303.875, 310.0, 315.0, 318.0, 390.0, 418.0, 433.92, 434.42, 868.35, 915.0
#define TR_CC1101_RXBW_KHZ   135.0
#define TR_CC1101_RSSI_DBM   -80.0       // counts as "active" at or above this
#define TR_CC1101_SETTLE_US  1500
#define TR_CC1101_SWEEP_MS   500         // one pass over the list (~25 ms)
#define TR_CC1101_WINDOW_MS  10000       // one cc1101.csv row per active freq per window

// ---- Tunnel R.A.T. Remote: NanoPi wardrive control ----------------------------
// START ALL / STOP ALL / STATUS run these on the NanoPi through the dashboard's
// key-protected CLI endpoint (the same path the PicoCalc remote uses). Change the
// commands here if your NanoPi starts its modules differently, e.g. chain them:
//   "wardrive-logger.sh start; systemctl start kismet"
#define TR_NANOPI_CLI_PATH   "/api/cli"
#define TR_NANOPI_CLI_FIELD  "cmd"        // JSON field the dashboard reads the command from
#define TR_NANOPI_WD_START   "wardrive-logger.sh start"
#define TR_NANOPI_WD_STOP    "wardrive-logger.sh stop"
#define TR_NANOPI_WD_STATUS  "wardrive-logger.sh status"

// ---- nRF24 (HW-237 nRF24L01+PA+LNA on the 12-pin expansion header) ----------
// RECEIVE-ONLY. Wiring (header silkscreen -> module):  3.3V->VCC  GND->GND
//   TX(GPIO43)->CE   RX(GPIO44)->CSN   SCK->SCK   MOSI->MOSI   MISO->MISO
//   IRQ: leave unconnected.  NOT the header pin labelled "CE" (that is an
//   XL9555 expander line for LilyGo's own PA shield). NEVER use the 5V pin.
// Needs Tools > USB CDC On Boot: Enabled (GPIO43/44 are UART0 otherwise).
#define TR_NRF24_ENABLE      1           // 0 = remove nRF24 support entirely
#define TR_NRF24_CE_PIN      43
#define TR_NRF24_CSN_PIN     44
#define TR_NRF24_SPI_HZ      8000000     // nRF24 max is 10 MHz; long jumpers -> lower
// Drive the header "CE" line (XL9555 IO9) LOW = RX for LilyGo's nRF24 PA
// shield. Harmless for a HW-237, which does not use that pin.
#define TR_NRF24_SHIELD_RXTX_EXPANDER 1
#define TR_NRF24_CH_MIN      2           // ESB hop range (2402..2484 MHz)
#define TR_NRF24_CH_MAX      84
#define TR_NRF24_DWELL_MS    120         // time on each channel listening for ESB
#define TR_NRF24_RATES       0x03        // bit0=2Mbps bit1=1Mbps bit2=250kbps
#define TR_NRF24_SWEEP_MS    1000        // RPD activity sweep 0..125 (~25 ms); 0 = off
#define TR_NRF24_RPD_US      200         // per-channel RPD settle (>=170 us)
#define TR_NRF24_WINDOW_MS   10000       // one activity summary line per window
#define TR_NRF24_ACTIVE_PCT  20          // channel "active" if RPD hit in >= N% of sweeps
#define TR_NRF24_RELOG_MS    30000       // re-log the same ESB address at most this often

// ---- Detection layers (OUI prefixes, upper-case, no colons) ---------------
// These are matched against the first 3 bytes of each WiFi/BLE MAC so the
// NanoPi can map Flock / Axon / police-Motorola gear as their own layers.
// Lists are intentionally short/validated-as-you-go — add prefixes you confirm.
#define TR_OUI_FLOCK      "F09FC2,207693,E0B6F5"   // placeholder — validate!
#define TR_OUI_AXON       "00257F,A4F933"          // placeholder — validate!
#define TR_OUI_MOTOROLA   "001563,00249C,0023FF"   // placeholder — validate!
// (Meshtastic/MeshCore are detected by LoRa framing, not OUI.)

// ---- WiFi Attacks mode (Bruce-style) --------------------------------------
// Authorized / own-network testing only.
// Channels the attack engine hops across (2.4GHz). Trim to your region.
#define TR_ATK_CHANNELS   {1,2,3,4,5,6,7,8,9,10,11}
#define TR_DEAUTH_REASON  7              // 802.11 deauth reason code
#define TR_DEAUTH_BURST   5             // frames per target per tick
// SSIDs the beacon-spam tool broadcasts (rotates through them). Keep it tame.
#define TR_BEACON_SSIDS   {"TunnelRat","FreeWiFi_01","FreeWiFi_02","setup-me","\
guest-net"}
#define TR_BEACON_RANDOM  0             // 1 = random junk SSIDs instead of list

// ---- WiFi-Direct messaging (ESP-NOW, Phase E) -----------------------------
// Peer MAC of the direct receiver (another ESP32 running the matching firmware).
// FF:FF:FF:FF:FF:FF = broadcast to any listener. Set the real MAC for unicast.
#define TR_ESPNOW_PEER    {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}
#define TR_ESPNOW_LR      1             // 1 = enable Long-Range PHY (ESP32<->ESP32)
#define TR_ESPNOW_CHAN    1             // ESP-NOW channel (both ends must match)

// ---- Contacts vault (encrypted, "in case lost") ---------------------------
// Contacts for direct messaging (name + mesh node ID + ESP-NOW MAC + their
// public key) + your own message keypair, encrypted at rest on the microSD
// with AES-256-GCM, key derived from your passphrase via PBKDF2-HMAC-SHA256.
// Set to 1 to turn the Contacts vault ON. Requires the "Crypto" library by
// Rhys Weatherley (Library Manager → search Crypto → the one that lists AES/
// GCM/Curve25519). Left 0 so the firmware compiles with no crypto library.
#define TR_VAULT_ENABLE        1              // 0 = Contacts mode off (compiles clean)
#define TR_VAULT_FILE          "/tunnelrat/contacts.vault"
#define TR_VAULT_PBKDF2_ITERS  120000         // higher = slower to brute force
#define TR_VAULT_LOCK_ON_BOOT  1              // require passphrase after power-up
#define TR_VAULT_LOCK_ON_EXIT  0              // 0 = unlock persists across modes (Comms needs the keys); re-locks on boot or the Lock button
#define TR_VAULT_WIPE_AFTER_FAILS 0           // 0 = off; N = wipe after N bad tries
#define TR_VAULT_MAX_CONTACTS  64

// ---- UI --------------------------------------------------------------------
#include <stdint.h>
static uint32_t g_accent __attribute__((unused)) = 0x00FF66;  // runtime UI accent (Settings > theme)
#define TR_THEME_GREEN    g_accent        // accent is now runtime-themeable
static bool g_radarAudioOn __attribute__((unused)) = true;    // radar "getting warmer" ping (Settings toggle)
static bool g_gpsOn        __attribute__((unused)) = false;   // GPS logging for wardrive: OFF by default (privacy + battery)
#define TR_THEME_BG       0x000000
#define TR_SETTINGS_FILE  "/tunnelrat/settings.txt"
