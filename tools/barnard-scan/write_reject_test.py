#!/usr/bin/env python3
"""Verify the v2 "no writable characteristics" invariant on a real peripheral.

Scans for Barnard v2 peripherals, reads B002/B003/B004 (all should succeed),
then attempts to WRITE to each characteristic (all should fail with GATT
error 0x03 = ATT_ERROR_WRITE_NOT_PERMITTED). This is the single strongest
v2 security invariant because it guarantees "TEK never travels on the wire":
if no write can be accepted, a hostile central cannot inject TEK into a
peer's storage (as v1's B003 allowed).

Verified behaviour (2026-04-21 on Pixel 8a running the Flutter v2 example):

    === Pixel 8a (BND-CD8B) ===
      READ  B002 RPID           : OK, 17 bytes, hex=0166a5cd...
      WRITE B002 RPID           : REJECTED (Write Not Permitted)
      READ  B003 displayId      : OK, 4 bytes, hex=25fa03e8
      WRITE B003 displayId      : REJECTED (Write Not Permitted)
      READ  B004 EventCodeHash  : OK, 8 bytes, hex=5673c3e83526634c
      WRITE B004 EventCodeHash  : REJECTED (Write Not Permitted)

Usage:
  # From tools/barnard-scan/:
  .venv/bin/python write_reject_test.py

Requires the macOS to grant Bluetooth permission to Terminal/iTerm on first
run. See README.md for setup.
"""
from __future__ import annotations

import asyncio
import sys

from bleak import BleakClient, BleakScanner

SERVICE_UUID = "0000b001-0000-1000-8000-00805f9b34fb"
CHARS: dict[str, str] = {
    "B002 RPID": "0000b002-0000-1000-8000-00805f9b34fb",
    "B003 displayId": "0000b003-0000-1000-8000-00805f9b34fb",
    "B004 EventCodeHash": "0000b004-0000-1000-8000-00805f9b34fb",
}


async def _scan(timeout: float = 15.0):
    print(f"scanning for service {SERVICE_UUID} ({timeout:.0f}s)…")
    found = []
    stop = asyncio.Event()

    def _cb(device, adv):
        uuids = {u.lower() for u in (adv.service_uuids or [])}
        if SERVICE_UUID not in uuids:
            return
        if device.address in [d.address for d in found]:
            return
        print(
            f"  found: {device.address} name={adv.local_name or device.name} rssi={adv.rssi}"
        )
        found.append(device)
        # Keep scanning to catch both iOS and Android peers if present.
        if len(found) >= 2:
            stop.set()

    async with BleakScanner(detection_callback=_cb, service_uuids=[SERVICE_UUID]):
        try:
            await asyncio.wait_for(stop.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            pass

    return found


async def _probe(device) -> int:
    print(f"\n=== {device.address} ===")
    any_unexpected = 0
    try:
        async with BleakClient(device, timeout=15.0) as client:
            for label, uuid in CHARS.items():
                # 1. Read — should succeed.
                try:
                    value = bytes(await client.read_gatt_char(uuid))
                    print(
                        f"  READ  {label:20s}: OK, {len(value)} bytes, hex={value.hex()}"
                    )
                except Exception as exc:
                    print(f"  READ  {label:20s}: FAILED ({exc})")

                # 2. Write 4 arbitrary bytes — should be rejected with
                #    ATT_ERROR_WRITE_NOT_PERMITTED (0x03).
                probe = b"\x00\x01\x02\x03"
                try:
                    await client.write_gatt_char(uuid, probe, response=True)
                    print(
                        f"  WRITE {label:20s}: !! UNEXPECTED SUCCESS — v2 requires rejection"
                    )
                    any_unexpected = 1
                except Exception as exc:
                    msg = str(exc)
                    lowered = msg.lower()
                    rejected = (
                        "permit" in lowered
                        or "0x03" in msg
                        or "writenotpermitted" in lowered
                    )
                    label_prefix = (
                        "REJECTED as expected" if rejected else "ERR (unexpected form)"
                    )
                    print(
                        f"  WRITE {label:20s}: {label_prefix} "
                        f"({type(exc).__name__}: {msg[:120]})"
                    )
                    if not rejected:
                        any_unexpected = 1
    except Exception as exc:
        print(f"  connect failed: {exc}")
        return 1
    return any_unexpected


async def _main() -> int:
    devices = await _scan()
    if not devices:
        print("no peripherals found")
        return 1
    overall = 0
    for device in devices:
        overall |= await _probe(device)
    return overall


if __name__ == "__main__":
    sys.exit(asyncio.run(_main()))
