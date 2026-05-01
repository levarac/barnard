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
- `barnard_scan.py` never attempts a write; use `write_reject_test.py`
  (below) if you want to verify write rejection as well.

## Write-rejection test

`write_reject_test.py` scans, reads each characteristic, then tries to
`write_gatt_char` to each. Every write must fail with GATT error 0x03
(`ATT_ERROR_WRITE_NOT_PERMITTED`) — this is the central v2 security
invariant: "TEK never travels on the wire" holds only because no
characteristic accepts a write from a remote central.

```bash
.venv/bin/python write_reject_test.py
```

Expected output:

```
=== Pixel 8a (BND-CD8B) ===
  READ  B002 RPID           : OK, 17 bytes, hex=0166a5cd...
  WRITE B002 RPID           : REJECTED as expected (GATT Protocol Error: Write Not Permitted)
  READ  B003 displayId      : OK, 4 bytes, hex=25fa03e8
  WRITE B003 displayId      : REJECTED as expected (GATT Protocol Error: Write Not Permitted)
  READ  B004 EventCodeHash  : OK, 8 bytes, hex=5673c3e83526634c
  WRITE B004 EventCodeHash  : REJECTED as expected (GATT Protocol Error: Write Not Permitted)
```

Exit code is 0 iff every read succeeded and every write was rejected.
