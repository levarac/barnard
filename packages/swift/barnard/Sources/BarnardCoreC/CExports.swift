// Use of this source code is governed by a BSD-style license.
//
// C ABI surface for BarnardCore (issue #78 follow-through).
//
// Every function here is a thin, allocation-free-at-the-boundary wrapper over
// the deterministic BarnardCore API so that non-Swift hosts (Kotlin/JNI, C,
// Rust, ...) can call the exact same implementation that iOS ships. The same
// purity contract as BarnardCore applies: Swift stdlib only. Callers own all
// buffers; fixed-size outputs are documented per function. Functions return 0
// on success and a negative value on invalid arguments.

import BarnardCore

private func bytes(_ pointer: UnsafePointer<UInt8>?, _ count: Int32) -> [UInt8]? {
  guard count >= 0 else { return nil }
  if count == 0 { return [] }
  guard let pointer else { return nil }
  return Array(UnsafeBufferPointer(start: pointer, count: Int(count)))
}

private func utf8String(_ pointer: UnsafePointer<UInt8>?, _ count: Int32) -> String? {
  guard let raw = bytes(pointer, count) else { return nil }
  return String(decoding: raw, as: UTF8.self)
}

private func write(_ output: [UInt8], _ expectedCount: Int, to pointer: UnsafeMutablePointer<UInt8>) {
  precondition(
    output.count == expectedCount,
    "core output length drifted from the documented C ABI buffer size"
  )
  pointer.update(from: output, count: output.count)
}

/// The C boundary must be total: BarnardCore converts the derived window
/// index with a trapping UInt32 cast, and a Swift trap is an uncatchable
/// process abort for a JNI/C host. These guards mirror the core's own input
/// clamps (see BarnardCoreCrypto.calculateEnin) purely to decide whether the
/// core call is safe; in-domain results come from the core unchanged.
private func eninDomain(
  unixSeconds: Int64,
  mode: Int32,
  eninSeconds: Int64,
  beaconGenesisUnixSeconds: Int64,
  beaconSlotSeconds: Int64
) -> (inDomain: Bool, saturated: UInt32) {
  if mode == 1 {
    let genesis = max(0, beaconGenesisUnixSeconds)
    let slot = max(1, beaconSlotSeconds)
    let elapsed = unixSeconds - genesis
    if elapsed <= 0 { return (true, 0) }
    if elapsed / slot > Int64(UInt32.max) { return (false, UInt32.max) }
    return (true, 0)
  }
  if unixSeconds < 0 { return (false, 0) }
  let effectiveSeconds = min(max(eninSeconds, 12), 3_600)
  if unixSeconds / effectiveSeconds > Int64(UInt32.max) { return (false, UInt32.max) }
  return (true, 0)
}

/// out_tek16: 16 bytes.
@_cdecl("barnard_core_derive_tek_for_event")
public func barnard_core_derive_tek_for_event(
  _ deviceSecret: UnsafePointer<UInt8>?,
  _ deviceSecretLength: Int32,
  _ eventCodeUtf8: UnsafePointer<UInt8>?,
  _ eventCodeLength: Int32,
  _ outTek16: UnsafeMutablePointer<UInt8>?
) -> Int32 {
  guard
    let secret = bytes(deviceSecret, deviceSecretLength),
    let eventCode = utf8String(eventCodeUtf8, eventCodeLength),
    let outTek16
  else { return -1 }
  write(
    BarnardCoreCrypto.deriveTekForEvent(deviceSecret: secret, eventCode: eventCode),
    16,
    to: outTek16
  )
  return 0
}

/// out_tek16: 16 bytes.
@_cdecl("barnard_core_derive_tek_for_anonymous")
public func barnard_core_derive_tek_for_anonymous(
  _ deviceSecret: UnsafePointer<UInt8>?,
  _ deviceSecretLength: Int32,
  _ outTek16: UnsafeMutablePointer<UInt8>?
) -> Int32 {
  guard let secret = bytes(deviceSecret, deviceSecretLength), let outTek16 else {
    return -1
  }
  write(BarnardCoreCrypto.deriveTekForAnonymous(deviceSecret: secret), 16, to: outTek16)
  return 0
}

/// tek16: 16 bytes in. out_rpik16: 16 bytes out.
@_cdecl("barnard_core_derive_rpik")
public func barnard_core_derive_rpik(
  _ tek16: UnsafePointer<UInt8>?,
  _ outRpik16: UnsafeMutablePointer<UInt8>?
) -> Int32 {
  guard let tek = bytes(tek16, 16), let outRpik16 else { return -1 }
  write(BarnardCoreCrypto.deriveRpik(from: tek), 16, to: outRpik16)
  return 0
}

/// rpik16: 16 bytes in. out_rpi16: 16 bytes out.
@_cdecl("barnard_core_generate_rpi")
public func barnard_core_generate_rpi(
  _ rpik16: UnsafePointer<UInt8>?,
  _ enin: UInt32,
  _ outRpi16: UnsafeMutablePointer<UInt8>?
) -> Int32 {
  guard let rpik = bytes(rpik16, 16), let outRpi16 else { return -1 }
  write(BarnardCoreCrypto.generateRpi(rpik: rpik, enin: enin), 16, to: outRpi16)
  return 0
}

/// mode: 1 = beacon slot; any other value is treated as the fixed-length
/// window. Beacon parameters are ignored for the fixed-length mode;
/// enin_seconds is ignored for the beacon-slot mode. This function has no
/// error channel, so out-of-domain timestamps saturate instead of trapping:
/// a negative fixed-length timestamp yields 0 and a window index beyond
/// UINT32_MAX yields UINT32_MAX.
@_cdecl("barnard_core_calculate_enin")
public func barnard_core_calculate_enin(
  _ unixSeconds: Int64,
  _ mode: Int32,
  _ eninSeconds: Int64,
  _ beaconGenesisUnixSeconds: Int64,
  _ beaconSlotSeconds: Int64
) -> UInt32 {
  let domain = eninDomain(
    unixSeconds: unixSeconds,
    mode: mode,
    eninSeconds: eninSeconds,
    beaconGenesisUnixSeconds: beaconGenesisUnixSeconds,
    beaconSlotSeconds: beaconSlotSeconds
  )
  guard domain.inDomain else { return domain.saturated }
  if mode == 1 {
    return BarnardCoreCrypto.calculateEnin(
      unixSeconds: unixSeconds,
      mode: .beaconSlot,
      beaconChain: BarnardCoreBeaconChain(
        chainId: "c-abi",
        genesisUnixSeconds: beaconGenesisUnixSeconds,
        slotSeconds: beaconSlotSeconds
      )
    )
  }
  return BarnardCoreCrypto.calculateEnin(
    unixSeconds: unixSeconds,
    mode: .fixedLength,
    eninSeconds: eninSeconds
  )
}

/// Returns 1 and writes out_enin when the window is stable across both reads,
/// 0 (out_enin untouched) when the window boundary was crossed, negative on
/// invalid arguments — including timestamps outside the representable window
/// domain (negative fixed-length timestamps or window indices beyond
/// UINT32_MAX), which would otherwise trap. mode: 1 = beacon slot; any other
/// value is treated as the fixed-length window.
@_cdecl("barnard_core_stable_read_enin")
public func barnard_core_stable_read_enin(
  _ startedAtUnixSeconds: Int64,
  _ completedAtUnixSeconds: Int64,
  _ mode: Int32,
  _ eninSeconds: Int64,
  _ beaconGenesisUnixSeconds: Int64,
  _ beaconSlotSeconds: Int64,
  _ outEnin: UnsafeMutablePointer<UInt32>?
) -> Int32 {
  guard let outEnin else { return -1 }
  for unixSeconds in [startedAtUnixSeconds, completedAtUnixSeconds]
  where !eninDomain(
    unixSeconds: unixSeconds,
    mode: mode,
    eninSeconds: eninSeconds,
    beaconGenesisUnixSeconds: beaconGenesisUnixSeconds,
    beaconSlotSeconds: beaconSlotSeconds
  ).inDomain {
    return -1
  }
  let coreMode: BarnardCoreEninMode = mode == 1 ? .beaconSlot : .fixedLength
  let chain = BarnardCoreBeaconChain(
    chainId: "c-abi",
    genesisUnixSeconds: beaconGenesisUnixSeconds,
    slotSeconds: beaconSlotSeconds
  )
  guard
    let enin = BarnardCoreCrypto.stableReadEnin(
      startedAtUnixSeconds: startedAtUnixSeconds,
      completedAtUnixSeconds: completedAtUnixSeconds,
      mode: coreMode,
      eninSeconds: eninSeconds,
      beaconChain: chain
    )
  else { return 0 }
  outEnin.pointee = enin
  return 1
}

/// out_hash8: 8 bytes.
@_cdecl("barnard_core_compute_event_code_hash")
public func barnard_core_compute_event_code_hash(
  _ eventCodeUtf8: UnsafePointer<UInt8>?,
  _ eventCodeLength: Int32,
  _ outHash8: UnsafeMutablePointer<UInt8>?
) -> Int32 {
  guard let eventCode = utf8String(eventCodeUtf8, eventCodeLength), let outHash8 else {
    return -1
  }
  write(BarnardCoreCrypto.computeEventCodeHash(eventCode), 8, to: outHash8)
  return 0
}

/// tek16: 16 bytes in. out_display_id4: 4 bytes out.
@_cdecl("barnard_core_display_id4")
public func barnard_core_display_id4(
  _ tek16: UnsafePointer<UInt8>?,
  _ outDisplayId4: UnsafeMutablePointer<UInt8>?
) -> Int32 {
  guard let tek = bytes(tek16, 16), let outDisplayId4 else { return -1 }
  write(BarnardCoreCrypto.displayId4(from: tek), 4, to: outDisplayId4)
  return 0
}

/// out_digest32: 32 bytes.
@_cdecl("barnard_core_sha256")
public func barnard_core_sha256(
  _ input: UnsafePointer<UInt8>?,
  _ inputLength: Int32,
  _ outDigest32: UnsafeMutablePointer<UInt8>?
) -> Int32 {
  guard let raw = bytes(input, inputLength), let outDigest32 else { return -1 }
  write(BarnardCoreCrypto.sha256(raw), 32, to: outDigest32)
  return 0
}

/// out_private_key32: 32 bytes. out_public_key_compressed33: 33 bytes.
@_cdecl("barnard_core_derive_signing_keypair")
public func barnard_core_derive_signing_keypair(
  _ deviceSecret: UnsafePointer<UInt8>?,
  _ deviceSecretLength: Int32,
  _ eventCodeUtf8: UnsafePointer<UInt8>?,
  _ eventCodeLength: Int32,
  _ outPrivateKey32: UnsafeMutablePointer<UInt8>?,
  _ outPublicKeyCompressed33: UnsafeMutablePointer<UInt8>?
) -> Int32 {
  guard
    let secret = bytes(deviceSecret, deviceSecretLength),
    let eventCode = utf8String(eventCodeUtf8, eventCodeLength),
    let outPrivateKey32,
    let outPublicKeyCompressed33
  else { return -1 }
  let keyPair = BarnardCoreSigning.deriveSigningKeyPair(
    deviceSecret: secret,
    eventCode: eventCode
  )
  write(keyPair.privateKey, 32, to: outPrivateKey32)
  write(keyPair.publicKeyCompressed, 33, to: outPublicKeyCompressed33)
  return 0
}

/// private_key32 and message_hash32: 32 bytes in. out_r32/out_s32: 32 bytes
/// out; out_v: recovery id 0-3.
@_cdecl("barnard_core_sign_recoverable")
public func barnard_core_sign_recoverable(
  _ privateKey32: UnsafePointer<UInt8>?,
  _ messageHash32: UnsafePointer<UInt8>?,
  _ outR32: UnsafeMutablePointer<UInt8>?,
  _ outS32: UnsafeMutablePointer<UInt8>?,
  _ outV: UnsafeMutablePointer<Int32>?
) -> Int32 {
  guard
    let privateKey = bytes(privateKey32, 32),
    let messageHash = bytes(messageHash32, 32),
    let outR32,
    let outS32,
    let outV
  else { return -1 }
  let signature = BarnardCoreSigning.signRecoverable(
    privateKey: privateKey,
    messageHash32: messageHash
  )
  write(signature.r, 32, to: outR32)
  write(signature.s, 32, to: outS32)
  outV.pointee = Int32(signature.v)
  return 0
}

/// Returns 1 when the RSSI update should be emitted, else 0.
@_cdecl("barnard_core_should_emit_rssi_update")
public func barnard_core_should_emit_rssi_update(
  _ cachedPeerEnin: UInt32,
  _ currentEnin: UInt32
) -> UInt8 {
  BarnardCoreV2Policy.shouldEmitRssiUpdate(
    cachedPeerEnin: cachedPeerEnin,
    currentEnin: currentEnin
  ) ? 1 : 0
}

/// Returns 1 when the GATT display id should be served, else 0. A NULL
/// event code is treated as absent.
@_cdecl("barnard_core_should_serve_gatt_display_id")
public func barnard_core_should_serve_gatt_display_id(
  _ eventCodeUtf8: UnsafePointer<UInt8>?,
  _ eventCodeLength: Int32
) -> UInt8 {
  let eventCode = utf8String(eventCodeUtf8, eventCodeLength)
  return BarnardCoreV2Policy.shouldServeGattDisplayId(eventCode: eventCode) ? 1 : 0
}
