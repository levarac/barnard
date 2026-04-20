import Foundation

struct TekEntry: Codable, Equatable {
  let tek: Data
  let eventCodeHash: Data
  let exchangedAt: Date
  var lastSeenAt: Date

  var displayId: String {
    tek.prefix(3).map { String(format: "%02x", $0) }.joined()
  }

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

struct TekStorageConfig {
  let ttlSeconds: Int
  let maxEntries: Int

  init(ttlSeconds: Int = 86400, maxEntries: Int = 1000) {
    self.ttlSeconds = ttlSeconds
    self.maxEntries = maxEntries
  }
}

final class BarnardTekStorage {
  private let storageKeyPrefix = "barnard.tekStorage."
  private let defaults = UserDefaults.standard
  private let config: TekStorageConfig

  init(config: TekStorageConfig = TekStorageConfig()) {
    self.config = config
  }

  func store(entry: TekEntry) {
    let key = storageKey(for: entry.eventCodeHash)
    var entries = loadEntries(key: key)

    if let index = entries.firstIndex(where: { $0.tek == entry.tek }) {
      entries[index].lastSeenAt = entry.lastSeenAt
    } else {
      entries.append(entry)
    }

    let now = Date()
    entries = entries.filter { item in
      now.timeIntervalSince(item.lastSeenAt) < Double(config.ttlSeconds)
    }

    if entries.count > config.maxEntries {
      entries.sort { $0.lastSeenAt < $1.lastSeenAt }
      entries = Array(entries.suffix(config.maxEntries))
    }

    saveEntries(entries, key: key)
  }

  func getEntries(for eventCodeHash: Data) -> [TekEntry] {
    let key = storageKey(for: eventCodeHash)
    let entries = loadEntries(key: key)

    let now = Date()
    let validEntries = entries.filter { item in
      now.timeIntervalSince(item.lastSeenAt) < Double(config.ttlSeconds)
    }

    if validEntries.count != entries.count {
      saveEntries(validEntries, key: key)
    }

    return validEntries
  }

  func getTeks(for eventCodeHash: Data) -> [Data] {
    getEntries(for: eventCodeHash).map(\.tek)
  }

  func clear(for eventCodeHash: Data) -> Int {
    let key = storageKey(for: eventCodeHash)
    let entries = loadEntries(key: key)
    let count = entries.count
    defaults.removeObject(forKey: key)
    return count
  }

  func clearAll() -> Int {
    var total = 0

    for key in defaults.dictionaryRepresentation().keys where key.hasPrefix(storageKeyPrefix) {
      if let data = defaults.data(forKey: key),
        let entries = try? JSONDecoder().decode([TekEntry].self, from: data)
      {
        total += entries.count
      }
      defaults.removeObject(forKey: key)
    }

    return total
  }

  func updateLastSeen(tek: Data, eventCodeHash: Data, at date: Date = Date()) {
    let key = storageKey(for: eventCodeHash)
    var entries = loadEntries(key: key)

    if let index = entries.firstIndex(where: { $0.tek == tek }) {
      entries[index].lastSeenAt = date
      saveEntries(entries, key: key)
    }
  }

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
      print("BarnardTekStorage: Failed to encode entries: \(error)")
    }
  }
}
