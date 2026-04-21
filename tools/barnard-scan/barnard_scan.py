#!/usr/bin/env python3
"""Barnard v2 BLE scanner/verifier for macOS.

Scans for devices advertising the Barnard v2 service UUID, connects to each,
reads B002 (RPID), B003 (displayId = SHA256(TEK)[0:4]), and B004
(EventCodeHash), and prints the decoded v2 payload. Use this to verify what
a Flutter/RN example app is broadcasting from a phone while running locally.

Wire format (v2):
  B002 RPID        17 B = [formatVersion(1) + RPI(16)]
  B003 displayId    4 B = SHA256(TEK)[0:4]
  B004 EventHash    0 or 8 B

Requires:
  python -m venv .venv && .venv/bin/pip install bleak
  .venv/bin/python barnard_scan.py [--once] [--timeout 8]

macOS needs Terminal → Privacy → Bluetooth permission the first time.
"""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import hashlib
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from bleak import BleakClient, BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

SERVICE_UUID = "0000b001-0000-1000-8000-00805f9b34fb"
RPID_UUID = "0000b002-0000-1000-8000-00805f9b34fb"
DISPLAY_ID_UUID = "0000b003-0000-1000-8000-00805f9b34fb"
EVENT_CODE_HASH_UUID = "0000b004-0000-1000-8000-00805f9b34fb"


def _enin_from_timestamp(ts: datetime) -> int:
    return int(ts.timestamp()) // 600


@dataclass
class ReadResult:
    address: str
    local_name: Optional[str]
    rssi: Optional[int]
    rpid: Optional[bytes]
    display_id: Optional[bytes]
    event_code_hash: Optional[bytes]
    observed_enin: int
    error: Optional[str] = None

    def print(self) -> None:
        ts = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
        header = f"[{ts}] peer={self.address} name={self.local_name or '-'} rssi={self.rssi if self.rssi is not None else '-'}"
        print(header)
        if self.error:
            print(f"  ERROR: {self.error}")
            return

        if self.rpid is None or len(self.rpid) != 17:
            print(f"  B002 RPID:           (missing / unexpected length={len(self.rpid) if self.rpid else 0})")
        else:
            version = self.rpid[0]
            rpi = self.rpid[1:]
            print(f"  B002 RPID hex:       {self.rpid.hex()}  (version={version}, rpi={rpi.hex()})")

        if self.display_id is None:
            print(f"  B003 displayId:      (missing)")
        elif len(self.display_id) != 4:
            print(f"  B003 displayId:      ! unexpected length={len(self.display_id)} hex={self.display_id.hex()}")
        else:
            print(f"  B003 displayId:      {self.display_id.hex()}   (SHA256(TEK)[0:4])")

        if self.event_code_hash is None:
            print(f"  B004 EventCodeHash:  (missing)")
        elif len(self.event_code_hash) == 0:
            print(f"  B004 EventCodeHash:  (empty — no event joined)")
        elif len(self.event_code_hash) == 8:
            print(f"  B004 EventCodeHash:  {self.event_code_hash.hex()}")
        else:
            print(f"  B004 EventCodeHash:  ! unexpected length={len(self.event_code_hash)} hex={self.event_code_hash.hex()}")

        print(f"  observer ENIN:       {self.observed_enin}")


async def _read_once(device: BLEDevice, adv: AdvertisementData) -> ReadResult:
    observed_enin = _enin_from_timestamp(datetime.now(timezone.utc))
    result = ReadResult(
        address=device.address,
        local_name=adv.local_name or device.name,
        rssi=adv.rssi,
        rpid=None,
        display_id=None,
        event_code_hash=None,
        observed_enin=observed_enin,
    )
    try:
        async with BleakClient(device, timeout=15.0) as client:
            # Read order mirrors the v2 central flow: B004 -> B002 -> B003.
            with contextlib.suppress(Exception):
                result.event_code_hash = bytes(await client.read_gatt_char(EVENT_CODE_HASH_UUID))
            with contextlib.suppress(Exception):
                result.rpid = bytes(await client.read_gatt_char(RPID_UUID))
            try:
                result.display_id = bytes(await client.read_gatt_char(DISPLAY_ID_UUID))
            except Exception as exc:  # B003 failure is allowed per v2 policy.
                result.display_id = None
                if result.rpid is None:
                    result.error = f"B002 missing + B003 read failed: {exc}"
                else:
                    # Record B003 failure but don't fail the whole result.
                    print(f"  (B003 read failed: {exc}; per v2 spec, detection would still fire with detectedDisplayId=null)")
    except Exception as exc:
        result.error = f"connect/read failed: {exc}"
    return result


async def _scan_and_read(timeout: float, once: bool) -> None:
    seen: set[str] = set()
    loop = asyncio.get_event_loop()
    queue: asyncio.Queue[tuple[BLEDevice, AdvertisementData]] = asyncio.Queue()

    def _cb(device: BLEDevice, adv: AdvertisementData) -> None:
        uuids = {u.lower() for u in (adv.service_uuids or [])}
        if SERVICE_UUID not in uuids:
            return
        if device.address in seen:
            return
        seen.add(device.address)
        loop.call_soon_threadsafe(queue.put_nowait, (device, adv))

    scanner = BleakScanner(detection_callback=_cb, service_uuids=[SERVICE_UUID])
    print(f"scanning for service {SERVICE_UUID} (timeout={timeout}s{', once' if once else ', continuous'})")
    await scanner.start()
    try:
        while True:
            try:
                device, adv = await asyncio.wait_for(queue.get(), timeout=timeout)
            except asyncio.TimeoutError:
                if once:
                    print("(no matching peripheral seen within timeout)")
                    break
                # Keep scanning forever in continuous mode.
                print(f"(no peers this {timeout}s window; still scanning)")
                continue
            result = await _read_once(device, adv)
            result.print()
            if once:
                break
    finally:
        with contextlib.suppress(Exception):
            await scanner.stop()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Scan for Barnard v2 peripherals and read B002/B003/B004."
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=8.0,
        help="Per-cycle scan timeout in seconds (default 8)",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Exit after the first matched peripheral (otherwise scan forever)",
    )
    args = parser.parse_args(argv)

    try:
        asyncio.run(_scan_and_read(timeout=args.timeout, once=args.once))
    except KeyboardInterrupt:
        print("\ninterrupted")
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
