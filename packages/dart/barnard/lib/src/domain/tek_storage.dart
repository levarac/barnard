// Copyright 2024-2026 The Greeting Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license.

/// TEK (Temporary Exposure Key) storage data models.
///
/// Storage is implemented per-platform (iOS: UserDefaults, Android: SharedPreferences).
/// This file contains the Dart data models used to communicate with native storage.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:meta/meta.dart';

/// A stored TEK entry from GATT exchange.
@immutable
class TekEntry {
  /// Creates a new TEK entry.
  const TekEntry({
    required this.tek,
    required this.eventCodeHash,
    required this.exchangedAt,
    required this.lastSeenAt,
  });

  /// The 16-byte TEK.
  final Uint8List tek;

  /// The 8-byte EventCodeHash (SHA256(EventCode)[0:8]).
  final Uint8List eventCodeHash;

  /// When the TEK was first exchanged.
  final DateTime exchangedAt;

  /// When the TEK holder was last seen (RPI resolved).
  final DateTime lastSeenAt;

  /// Display ID: first 3 bytes of TEK as lowercase hex.
  String get displayId =>
      tek.sublist(0, 3).map((b) => b.toRadixString(16).padLeft(2, '0')).join();

  /// Create from JSON map (for platform channel).
  factory TekEntry.fromMap(Map<String, dynamic> map) {
    return TekEntry(
      tek: _decodeBase64(map['tek'] as String),
      eventCodeHash: _decodeBase64(map['eventCodeHash'] as String),
      exchangedAt: DateTime.parse(map['exchangedAt'] as String),
      lastSeenAt: DateTime.parse(map['lastSeenAt'] as String),
    );
  }

  /// Convert to JSON map (for platform channel).
  Map<String, dynamic> toMap() => {
    'tek': base64Encode(tek),
    'eventCodeHash': base64Encode(eventCodeHash),
    'exchangedAt': exchangedAt.toUtc().toIso8601String(),
    'lastSeenAt': lastSeenAt.toUtc().toIso8601String(),
    'displayId': displayId,
  };

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is TekEntry &&
          runtimeType == other.runtimeType &&
          _bytesEqual(tek, other.tek);

  @override
  int get hashCode => Object.hashAll(tek);

  @override
  String toString() =>
      'TekEntry(displayId: $displayId, exchangedAt: $exchangedAt)';
}

/// Configuration for TEK storage.
@immutable
class TekStorageConfig {
  /// Creates TEK storage configuration.
  ///
  /// - [ttlSeconds]: Time-to-live for TEK entries (default 24 hours).
  /// - [maxEntries]: Maximum number of entries before LRU eviction (default 1000).
  const TekStorageConfig({this.ttlSeconds = 86400, this.maxEntries = 1000});

  /// TTL in seconds (default 24 hours = 86400 seconds).
  final int ttlSeconds;

  /// Maximum number of stored entries (default 1000).
  final int maxEntries;

  /// Convert to map for platform channel.
  Map<String, dynamic> toMap() => {
    'ttlSeconds': ttlSeconds,
    'maxEntries': maxEntries,
  };

  @override
  String toString() =>
      'TekStorageConfig(ttlSeconds: $ttlSeconds, maxEntries: $maxEntries)';
}

// Helper functions

Uint8List _decodeBase64(String encoded) {
  return base64Decode(encoded);
}

bool _bytesEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
