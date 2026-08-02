// Use of this source code is governed by a BSD-style license.

import Foundation

/// The unauthenticated, event-scoped hint carried by B005. It contains no
/// device, organizer, or other persistent identifier.
public struct BarnardEventInfo: Equatable {
  public let eventDisplayName: String
  public let eventCodeHash: Data
  /// Reserved for the optional `0x10` census extension. v1 leaves it absent.
  public let census: Data?

  public init(eventDisplayName: String, eventCodeHash: Data, census: Data? = nil) {
    self.eventDisplayName = eventDisplayName
    self.eventCodeHash = eventCodeHash
    self.census = census
  }
}

/// Local-only authorization state for serving B005. Neither flag is encoded
/// in the characteristic value and both deliberately default to `false`.
public struct BarnardEventInfoServePolicy: Equatable {
  public var organizerDesignated: Bool
  public var eventActiveForDiscovery: Bool

  public init(organizerDesignated: Bool = false, eventActiveForDiscovery: Bool = false) {
    self.organizerDesignated = organizerDesignated
    self.eventActiveForDiscovery = eventActiveForDiscovery
  }

  var mayServe: Bool { organizerDesignated && eventActiveForDiscovery }
}

public enum BarnardEventInfoError: Error, Equatable {
  case invalidPayloadLength
  case unsupportedFormatVersion
  case truncatedTlv
  case zeroTlvType
  case unorderedTlvTypes
  case missingDisplayName
  case missingEventCodeHash
  case invalidDisplayName
  case invalidEventCodeHash
  case eventCodeHashMismatch
}

/// B005's pure canonical encoder and strict parser. The encoder intentionally
/// delegates its hash derivation to the existing B004 implementation.
public enum BarnardEventInfoCodec {
  public static let formatVersion: UInt8 = 1
  public static let maximumPayloadBytes = 512
  public static let maximumDisplayNameBytes = 64

  public static func payloadIfServing(
    policy: BarnardEventInfoServePolicy,
    eventCode: String?,
    eventDisplayName: String?,
    b004EventCodeHash: Data
  ) throws -> Data? {
    guard policy.mayServe,
      let eventCode,
      !eventCode.isEmpty,
      let eventDisplayName
    else { return nil }
    return try serialize(
      eventCode: eventCode,
      eventDisplayName: eventDisplayName,
      b004EventCodeHash: b004EventCodeHash
    )
  }

  public static func serialize(
    eventCode: String,
    eventDisplayName: String,
    b004EventCodeHash: Data
  ) throws -> Data {
    let displayNameBytes = try canonicalDisplayNameBytes(eventDisplayName)
    let eventCodeHash = BarnardCrypto.computeEventCodeHash(eventCode)
    guard eventCodeHash.count == 8, eventCodeHash == b004EventCodeHash else {
      throw BarnardEventInfoError.eventCodeHashMismatch
    }

    var payload = Data([formatVersion, 0x01])
    appendLength(displayNameBytes.count, to: &payload)
    payload.append(displayNameBytes)
    payload.append(0x02)
    appendLength(eventCodeHash.count, to: &payload)
    payload.append(eventCodeHash)
    guard (16...maximumPayloadBytes).contains(payload.count) else {
      throw BarnardEventInfoError.invalidPayloadLength
    }
    return payload
  }

  public static func validateEventDisplayName(_ eventDisplayName: String) throws {
    _ = try canonicalDisplayNameBytes(eventDisplayName)
  }

  public static func parse(_ input: Data) throws -> BarnardEventInfo {
    let payload = Data(input)
    guard (16...maximumPayloadBytes).contains(payload.count) else {
      throw BarnardEventInfoError.invalidPayloadLength
    }
    guard payload.first == formatVersion else {
      throw BarnardEventInfoError.unsupportedFormatVersion
    }

    var index = 1
    var previousType = 0
    var displayName: String?
    var eventCodeHash: Data?
    while index < payload.count {
      guard index + 3 <= payload.count else { throw BarnardEventInfoError.truncatedTlv }
      let type = Int(payload[index])
      let length = (Int(payload[index + 1]) << 8) | Int(payload[index + 2])
      index += 3
      guard type != 0 else { throw BarnardEventInfoError.zeroTlvType }
      guard type > previousType else { throw BarnardEventInfoError.unorderedTlvTypes }
      previousType = type
      guard length <= payload.count - index else { throw BarnardEventInfoError.truncatedTlv }
      let value = payload.subdata(in: index..<(index + length))
      index += length

      switch type {
      case 0x01:
        guard displayName == nil else { throw BarnardEventInfoError.unorderedTlvTypes }
        displayName = try validatedDisplayName(value)
      case 0x02:
        guard eventCodeHash == nil, value.count == 8 else {
          throw BarnardEventInfoError.invalidEventCodeHash
        }
        eventCodeHash = value
      default:
        continue // Structurally valid extensions are intentionally ignorable.
      }
    }

    guard index == payload.count else { throw BarnardEventInfoError.truncatedTlv }
    guard let displayName else { throw BarnardEventInfoError.missingDisplayName }
    guard let eventCodeHash else { throw BarnardEventInfoError.missingEventCodeHash }
    return BarnardEventInfo(eventDisplayName: displayName, eventCodeHash: eventCodeHash)
  }

  /// A B005 hint is trustworthy only as an unauthenticated hint when it is
  /// internally consistent with the same Peripheral's B004 response.
  public static func matchesB004(_ info: BarnardEventInfo, b004EventCodeHash: Data) -> Bool {
    !b004EventCodeHash.isEmpty && info.eventCodeHash == b004EventCodeHash
  }

  private static func appendLength(_ length: Int, to payload: inout Data) {
    payload.append(UInt8((length >> 8) & 0xff))
    payload.append(UInt8(length & 0xff))
  }

  private static func canonicalDisplayNameBytes(_ displayName: String) throws -> Data {
    let bytes = Data(displayName.utf8)
    // Swift `String ==` uses canonical equivalence, so compare UTF-8 bytes to
    // detect a decomposed spelling rather than accepting it as NFC.
    guard bytes == Data(displayName.precomposedStringWithCanonicalMapping.utf8) else {
      throw BarnardEventInfoError.invalidDisplayName
    }
    guard (1...maximumDisplayNameBytes).contains(bytes.count), containsOnlyPermittedScalars(displayName) else {
      throw BarnardEventInfoError.invalidDisplayName
    }
    return bytes
  }

  private static func validatedDisplayName(_ bytes: Data) throws -> String {
    guard let displayName = String(data: bytes, encoding: .utf8) else {
      throw BarnardEventInfoError.invalidDisplayName
    }
    _ = try canonicalDisplayNameBytes(displayName)
    return displayName
  }

  private static func containsOnlyPermittedScalars(_ value: String) -> Bool {
    value.unicodeScalars.allSatisfy { scalar in
      scalar.value > 0x1f && scalar.value != 0x7f
    }
  }
}

public struct BarnardEventInfoDiscoveryObservation: Equatable {
  public let additionalNamesOmitted: Bool
  public let additionalEventsOmitted: Bool
}

/// Bounded, observer-local retention for one five-minute discovery session.
public final class BarnardEventInfoDiscoverySession {
  private var startedAt: TimeInterval
  private var namesByHash: [Data: Set<Data>] = [:]
  public private(set) var additionalNamesOmitted = false
  public private(set) var additionalEventsOmitted = false
  public var retainedHashCount: Int { namesByHash.count }

  public init(startedAt: TimeInterval) { self.startedAt = startedAt }

  @discardableResult
  public func observe(_ info: BarnardEventInfo, now: TimeInterval) -> BarnardEventInfoDiscoveryObservation {
    if now - startedAt >= 300 {
      startedAt = now
      namesByHash.removeAll()
      additionalNamesOmitted = false
      additionalEventsOmitted = false
    }
    let name = Data(info.eventDisplayName.utf8)
    if var names = namesByHash[info.eventCodeHash] {
      if !names.contains(name) && names.count >= 4 { additionalNamesOmitted = true }
      else { names.insert(name); namesByHash[info.eventCodeHash] = names }
    } else if namesByHash.count >= 32 {
      additionalEventsOmitted = true
    } else {
      namesByHash[info.eventCodeHash] = [name]
    }
    return BarnardEventInfoDiscoveryObservation(
      additionalNamesOmitted: additionalNamesOmitted,
      additionalEventsOmitted: additionalEventsOmitted
    )
  }
}

/// B005's bounded connection/read retry policy. Semantic unavailability is
/// terminal for the session; transport failures get one retry after 30s.
public final class BarnardEventInfoRetryBudget {
  private var attempts: [UUID: Int] = [:]
  private var retryAfter: [UUID: TimeInterval] = [:]
  private var semanticUnavailable: Set<UUID> = []
  private var lastSeen: [UUID: TimeInterval] = [:]

  public init() {}
  public func canStart(_ peer: UUID, now: TimeInterval) -> Bool {
    prune(now: now)
    lastSeen[peer] = now
    return !semanticUnavailable.contains(peer) && (attempts[peer] ?? 0) < 2 && now >= (retryAfter[peer] ?? 0)
  }
  @discardableResult public func recordRecoverableFailure(_ peer: UUID, now: TimeInterval) -> TimeInterval? {
    prune(now: now)
    lastSeen[peer] = now
    let next = (attempts[peer] ?? 0) + 1
    attempts[peer] = next
    guard next < 2 else { return nil }
    let deadline = now + 30
    retryAfter[peer] = deadline
    return deadline
  }
  public func recordSemanticUnavailable(_ peer: UUID, now: TimeInterval = Date().timeIntervalSince1970) {
    prune(now: now)
    lastSeen[peer] = now
    semanticUnavailable.insert(peer)
  }
  public func clear(_ peer: UUID) {
    attempts.removeValue(forKey: peer)
    retryAfter.removeValue(forKey: peer)
    semanticUnavailable.remove(peer)
    lastSeen.removeValue(forKey: peer)
  }
  public func clearAll() {
    attempts.removeAll()
    retryAfter.removeAll()
    semanticUnavailable.removeAll()
    lastSeen.removeAll()
  }
  private func prune(now: TimeInterval) {
    let stalePeers = lastSeen.compactMap { peer, seenAt in
      now >= seenAt && now - seenAt >= 300 ? peer : nil
    }
    stalePeers.forEach(clear)
  }
}
