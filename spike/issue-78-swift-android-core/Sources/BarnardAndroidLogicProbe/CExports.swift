/// A single C-callable shape for the Android/JNI boundary experiment.
///
/// C declaration:
/// `uint8_t barnard_should_emit_rssi_update(uint32_t cached, uint32_t current);`
@c(barnard_should_emit_rssi_update)
public func barnardShouldEmitRssiUpdate(
  _ cachedPeerEnin: UInt32,
  _ currentEnin: UInt32
) -> UInt8 {
  BarnardV2Policy.shouldEmitRssiUpdate(
    cachedPeerEnin: cachedPeerEnin,
    currentEnin: currentEnin
  ) ? 1 : 0
}
