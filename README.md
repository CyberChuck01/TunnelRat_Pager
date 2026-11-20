# TunnelRat_Pager

Custom Arduino firmware for the **LILYGO T‑LoRa Pager** (ESP32‑S3) — a portable
RF survey, GPS wardriving, and personal‑radio handheld built for **wireless
security education and research on hardware and networks you own or are
explicitly authorized to test**.

It turns the T‑Pager into a self‑contained field instrument with an on‑device
UI: GPS‑tagged radio surveying across several bands, direction‑finding
visualizations, encrypted peer‑to‑peer messaging, an on‑device encrypted
contacts store, an SD‑card file manager, and a music player.

> ⚠️ **Authorized use only.** This project is provided for education and for
> testing on devices and networks that you own or have written permission to
> assess. Radio transmission, spectrum use, and network testing are regulated
> and vary by country. **You are solely responsible** for operating it lawfully
> in your jurisdiction. The authors provide no warranty and accept no liability
> for misuse. If you are unsure whether something is permitted where you are,
> do not do it.

---

## Features

Organized into folders on the home screen:

- **Signal Hunt** — passive survey + on‑screen "radar" direction‑finding for
  2.4 GHz (nRF24), Wi‑Fi, Bluetooth, and sub‑GHz (CC1101). A proximity audio
  tone rises in pitch and rate as a signal gets stronger, for locating your own
  beacons/tags.
- **Wardrive + Recon** — GPS‑tagged logging of Wi‑Fi, BLE, LoRa mesh, and
  nRF24/CC1101 observations to per‑source CSV files for your own mapping
  (e.g. WiGLE‑style surveys of your environment). Also a standalone NFC
  reader and a remote for a companion NanoPi node.
- **Wireless testing utilities** — 802.11 and BLE test tools and a captive‑portal
  / handshake‑capture demo, intended for assessing the security of **your own**
  networks and devices in a lab setting.
- **Comms + Vault** — Curve25519 + AES‑256‑GCM encrypted direct messaging over
  LoRa mesh and ESP‑NOW, plus a passphrase‑locked contacts/keys vault
  (PBKDF2, lock‑on‑boot) so a lost device leaks nothing.
- **System** — theme/brightness settings, an SD‑card file manager
  (browse/edit/rename/delete, new file/folder), and an MP3 player.

## Hardware

- **LILYGO T‑LoRa Pager** (ESP32‑S3, 16 MB flash / 8 MB PSRAM), u‑blox GPS,
  SX1262 LoRa, ST25R3916 NFC, ST7796 display, TCA8418 keyboard, rotary encoder,
  ES‑series I2S audio codec + speaker.
- Optional header radio: **nRF24L01+** or **CC1101**.

## Build

Open the `TunnelRat_Pager/` folder (this repo) in the Arduino IDE.

- **Board:** `LilyGo-T-LoRa-Pager` (install LilyGo's board package).
- **Board Revision:** match your radio.
- **Libraries (pinned — do not auto‑update):**
  - arduino‑esp32 core `4.0.0-alpha1`
  - LilyGoLib `0.2.1`, LilyGo‑display‑library
  - LVGL `9.2.2`
  - RadioLib `7.1.2`
  - NimBLE‑Arduino `2.5.2`
  - SensorLib `0.3.1`, XPowersLib `0.2.9`
  - rweather **Crypto** (vault/messaging)

Put an SD card in for settings, survey logs, and media. Optional folders on the
card: `/music` or `/audio` for the MP3 player.

## Web flasher

A browser‑based installer (no toolchain required, Chrome/Edge over USB) lives
under [`docs/`](docs/) and is published with GitHub Pages:

**→ https://cyberchuck01.github.io/TunnelRat_Pager/docs/**

It flashes a prebuilt binary; see [`docs/README.md`](docs/README.md) for how the
binary is produced and updated.

## Credits & licenses

- MP3 decoding: **minimp3** by lieff — public domain (CC0). Bundled as
  `minimp3.h`.
- Built on LilyGoLib, LVGL, RadioLib, NimBLE‑Arduino, and the rweather Crypto
  library — each under its own license.
- This firmware: see [`LICENSE`](LICENSE) (MIT).
