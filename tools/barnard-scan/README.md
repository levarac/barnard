# `barnard-scan`

macOS BLE scanner for Barnard v2 peripherals. Use it to verify what the
Flutter / React Native example app is broadcasting when you run it on a
phone nearby.

## Setup (one-time)

```bash
cd tools/barnard-scan
python3 -m venv .venv
.venv/bin/pip install bleak
```

macOS will prompt for Bluetooth permission the first time you run Python
against Core Bluetooth. Accept it (System Settings → Privacy & Security →
Bluetooth → Terminal / iTerm).

## Usage

```bash
# Continuous: scan forever, print every peer seen.
.venv/bin/python barnard_scan.py

# One-shot: exit after the first matched peripheral.
.venv/bin/python barnard_scan.py --once

# Longer scan window per cycle (default 8s).
.venv/bin/python barnard_scan.py --timeout 20
```

Example output from a phone running the Flutter example with
`Start Advertise` tapped and no event joined:

```
scanning for service 0000b001-0000-1000-8000-00805f9b34fb (timeout=8.0s, continuous)
[2026-04-21T14:55:12.183+00:00] peer=12:34:56:78:9A:BC name=BND-AB12 rssi=-52
  B002 RPID hex:       01a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6  (version=1, rpi=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6)
  B003 displayId:      60c33b2e   (SHA256(TEK)[0:4])
  B004 EventCodeHash:  (empty — no event joined)
  observer ENIN:       2961234
```

After tapping **Join Event** with `BND` on the phone, B004 will show a
non-empty 8-byte hex, and subsequent B003 reads will correspond to the
post-join TEK.

## What this tool verifies

- v2 GATT service UUID is advertised (`0000B001-...`).
- B002 is exactly 17 bytes (`[formatVersion(1) + RPI(16)]`).
- B003 is exactly 4 bytes.
- B004 is either empty (not joined) or 8 bytes (joined).
- **No writable characteristics** — this scanner never attempts a write.
  If you want to prove writes are rejected, patch in a `write_gatt_char`
  call; the peripheral should respond with `writeNotPermitted`.
