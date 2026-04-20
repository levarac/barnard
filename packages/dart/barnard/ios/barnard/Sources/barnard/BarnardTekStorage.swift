// Copyright 2024-2026 The Greeting Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license.

import Foundation

/// A stored TEK entry from GATT exchange.
struct TekEntry: Codable, Equatable {
  /// The 16-byte TEK.
  let tek: Data

  /// The 8-byte EventCodeHash (SHA256(EventCode)[0:8]).
  let eventCodeHash: Data

  /// When the TEK was first exchanged.
  let exchangedAt: Date

  /// When the TEK holder was last seen (RPI resolved).
  var lastSeenAt: Date

  /// Display ID: first 3 bytes of TEK as lowercase hex.
  var displayId: String {
    tek.prefix(3).map { String(format: "%02x", $0) }.joined()
  }

  /// Create from platform channel dictionary.
  static func from(dict: [String: Any]) -> TekEntry? {
    guard
      let tekB64 = dict["tek"] as? String,
      let tekData = Data(base64Encoded: tekB64),
      let hashB64 = dict["eventCodeHash"] as? String,
      let hashData = Data(base64Encoded: hashB64),
      let exchangedAtStr = dict["exchangedAt"] as? String,
      let exchangedAt = ISO8601DateFormatter().date(from: exchangedAtStr),
      let lastSeenAtStr = dict["lastSeenAt"] as? String,
      let lastSeenAt = ISO8601DateFormatter().date(from: lastSeenAtStr)
    else {
      return nil
    }

    return TekEntry(
      tek: tekData,
      eventCodeHash: hashData,
      exchangedAt: exchangedAt,
      lastSeenAt: lastSeenAt
    )
  }

  /// Convert to platform channel dictionary.
  func toDict() -> [String: Any] {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]

    return [
      "tek": tek.base64EncodedString(),
      "eventCodeHash": eventCodeHash.base64EncodedString(),
      "exchangedAt": formatter.string(from: exchangedAt),
      "lastSeenAt": formatter.string(from: lastSeenAt),
      "displayId": displayId,
    ]
  }
}

/// TEK storage configuration.
struct TekStorageConfig {
  /// TTL in seconds (default 24 hours = 86400 seconds).
  let ttlSeconds: Int

  /// Maximum number of stored entries (default 1000).
  let maxEntries: Int

  init(ttlSeconds: Int = 86400, maxEntries: Int = 1000) {
    self.ttlSeconds = ttlSeconds
    self.maxEntries = maxEntries
  }
}

/// Persistent storage for exchanged TEKs.
///
/// Storage is organized by EventCodeHash (base64), with bounded size and TTL.
final class BarnardTekStorage {
  private let storageKeyPrefix = "barnard.tekStorage."
  private let defaults = UserDefaults.standard
  private let config: TekStorageConfig

  init(config: TekStorageConfig = TekStorageConfig()) {
    self.config = config
  }

  // MARK: - Public API

  /// Store a TEK entry for a given event code hash.
  func store(entry: TekEntry) {
    let key = storageKey(for: entry.eventCodeHash)
    var entries = loadEntries(key: key)

    // Check if we already have this TEK
    if let index = entries.firstIndex(where: { $0.tek == entry.tek }) {
      // Update lastSeenAt
      entries[index].lastSeenAt = entry.lastSeenAt
    } else {
      entries.append(entry)
    }

    // Evict expired entries
    let now = Date()
    entries = entries.filter { entry in
      now.timeIntervalSince(entry.lastSeenAt) < Double(config.ttlSeconds)
    }

    // LRU eviction if over capacity
    if entries.count > config.maxEntries {
      entries.sort { $0.lastSeenAt < $1.lastSeenAt }
      entries = Array(entries.suffix(config.maxEntries))
    }

    saveEntries(entries, key: key)
  }

  /// Get all TEK entries for a given event code hash.
  func getEntries(for eventCodeHash: Data) -> [TekEntry] {
    let key = storageKey(for: eventCodeHash)
    var entries = loadEntries(key: key)

    // Filter expired entries
    let now = Date()
    let validEntries = entries.filter { entry in
      now.timeIntervalSince(entry.lastSeenAt) < Double(config.ttlSeconds)
    }

    // Save back if we filtered any
    if validEntries.count != entries.count {
      saveEntries(validEntries, key: key)
    }

    return validEntries
  }

  /// Get all TEKs (as Data) for a given event code hash.
  func getTeks(for eventCodeHash: Data) -> [Data] {
    getEntries(for: eventCodeHash).map(\.tek)
  }

  /// Clear all TEKs for a given event code hash.
  /// Returns the number of entries removed.
  func clear(for eventCodeHash: Data) -> Int {
    let key = storageKey(for: eventCodeHash)
    let entries = loadEntries(key: key)
    let count = entries.count
    defaults.removeObject(forKey: key)
    return count
  }

  /// Clear all stored TEKs across all events.
  /// Returns the total number of entries removed.
  func clearAll() -> Int {
    var total = 0

    // Find all keys with our prefix
    for key in defaults.dictionaryRepresentation().keys {
      if key.hasPrefix(storageKeyPrefix) {
        if let data = defaults.data(forKey: key),
          let entries = try? JSONDecoder().decode([TekEntry].self, from: data)
        {
          total += entries.count
        }
        defaults.removeObject(forKey: key)
      }
    }

    return total
  }

  /// Update lastSeenAt for a TEK if it exists.
  func updateLastSeen(tek: Data, eventCodeHash: Data, at date: Date = Date()) {
    let key = storageKey(for: eventCodeHash)
    var entries = loadEntries(key: key)

    if let index = entries.firstIndex(where: { $0.tek == tek }) {
      entries[index].lastSeenAt = date
      saveEntries(entries, key: key)
    }
  }

  // MARK: - Private

  private func storageKey(for eventCodeHash: Data) -> String {
    storageKeyPrefix + eventCodeHash.base64EncodedString()
  }

  private func loadEntries(key: String) -> [TekEntry] {
    guard let data = defaults.data(forKey: key) else {
      return []
    }

    do {
      return try JSONDecoder().decode([TekEntry].self, from: data)
    } catch {
      // Corrupted data, clear it
      defaults.removeObject(forKey: key)
      return []
    }
  }

  private func saveEntries(_ entries: [TekEntry], key: String) {
    guard !entries.isEmpty else {
      defaults.removeObject(forKey: key)
      return
    }

    do {
      let data = try JSONEncoder().encode(entries)
      defaults.set(data, forKey: key)
    } catch {
      // Encoding failed, don't crash
      print("BarnardTekStorage: Failed to encode entries: \(error)")
    }
  }
}
