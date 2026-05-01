import Foundation

/// Pure-logic policy decisions for Barnard v2.
///
/// Mirrors `BarnardV2Policy` on the Android side so the same review-fix
/// rules are expressed in the same shape on both platforms.
enum BarnardV2Policy {
  /// B003 displayId may only be served while the peripheral is joined to an event.
  /// Anonymous reads are rejected so the device-secret-derived TEK does not
  /// surface as a stable on-wire displayId.
  static func shouldServeGattDisplayId(eventCode: String?) -> Bool {
    guard let code = eventCode, !code.isEmpty else { return false }
    return true
  }

  /// Cached known-peer RPID is reusable only within the ENIN window in which
  /// it was resolved. After ENIN rotation the SDK must re-read B002/B003.
  struct KnownPeerWindow {
    let enin: UInt32
    func matches(_ currentEnin: UInt32) -> Bool { enin == currentEnin }
  }
}
