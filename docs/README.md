# Web flasher

Browser-based installer for TunnelRat_Pager, built on
[ESP Web Tools](https://esphome.github.io/esp-web-tools/). Served via GitHub
Pages from this `docs/` folder at:

**https://cyberchuck01.github.io/TunnelRat_Pager/**

## How the binary is produced

The flasher installs a single merged image: `firmware/firmware.bin`.

It is built from the Arduino IDE output (the firmware itself is not compiled by
GitHub — it uses a pinned alpha core + LilyGo libraries that are set up locally):

1. In the Arduino IDE: **Sketch → Export Compiled Binary**.
2. From the sketch's `build/<board>/` folder, take:
   - `TunnelRat_Pager.ino.bootloader.bin`
   - `TunnelRat_Pager.ino.partitions.bin`
   - `boot_app0.bin` (from the ESP32 core tools)
   - `TunnelRat_Pager.ino.bin` (the app)
3. Merge them into one image for the web flasher:

   ```
   esptool --chip esp32s3 merge_bin -o docs/firmware/firmware.bin \
     --flash_mode dio --flash_freq 80m --flash_size 16MB \
     0x0     TunnelRat_Pager.ino.bootloader.bin \
     0x8000  TunnelRat_Pager.ino.partitions.bin \
     0xe000  boot_app0.bin \
     0x10000 TunnelRat_Pager.ino.bin
   ```

4. Commit the merged `docs/firmware/firmware.bin` and bump `version` in
   `manifest.json`.

(ESP32-S3 flashes the bootloader at offset `0x0`.)
