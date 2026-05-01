import "dart:async";
import "dart:convert";
import "dart:math";
import "dart:typed_data";

import "../../usecase/barnard_client.dart";
import "../../domain/capabilities.dart";
import "../../domain/config.dart";
import "../../domain/crypto.dart";
import "../../domain/events.dart";
import "../../domain/rssi.dart";
import "../../domain/state.dart";
import "../../domain/tek_storage.dart";
import "../../domain/transport.dart";
import "mock_peer.dart";
import "ring_buffer.dart";

class MockBarnardOverrides {
  const MockBarnardOverrides({
    this.rotationSeconds,
    this.minPushIntervalMs,
    this.bufferMaxSamples,
  });

  final int? rotationSeconds;
  final int? minPushIntervalMs;
  final int? bufferMaxSamples;
}

class MockBarnard implements BarnardClient {
  MockBarnard({
    int simulatedPeerCount = 50,
    int tickMs = 200,
    BarnardConfig config = const BarnardConfig(),
    MockBarnardOverrides? overrides,
    Uint8List? deviceSecret,
  }) : _tickMs = tickMs.clamp(50, 2000),
       _random = Random(),
       _config = config,
       _overrides = overrides,
       _deviceSecret = deviceSecret ?? _generateRandomBytes(32) {
    _peers = List<MockPeer>.generate(simulatedPeerCount.clamp(1, 2000), (
      int i,
    ) {
      final int seed = _random.nextInt(1 << 31);
      return MockPeer(id: i, seed: seed, transport: TransportKind.ble);
    });

    _state = _buildState(isScanning: false, isAdvertising: false);
    _events = StreamController<BarnardEvent>.broadcast();
    _debugEvents = StreamController<BarnardDebugEvent>.broadcast();
    _debugBuffer = RingBuffer<BarnardDebugEvent>(2000);

    final int bufferMaxSamples =
        _overrides?.bufferMaxSamples ?? const RssiConfig().bufferMaxSamples;
    _rssiBuffer = RingBuffer<RssiSample>(bufferMaxSamples);

    // Initialize with a deterministic TEK for Anonymous Mode
    _currentTek = BarnardCrypto.deriveTekForAnonymous(_deviceSecret);
  }

  final int _tickMs;
  final Random _random;
  final BarnardConfig _config;
  final MockBarnardOverrides? _overrides;
  final Uint8List _deviceSecret;

  late final List<MockPeer> _peers;

  late BarnardState _state;
  late final StreamController<BarnardEvent> _events;
  late final StreamController<BarnardDebugEvent> _debugEvents;

  late final RingBuffer<BarnardDebugEvent> _debugBuffer;
  late final RingBuffer<RssiSample> _rssiBuffer;

  Timer? _timer;
  bool _disposed = false;

  // Event Mode state
  EventMode _currentMode = EventMode.anonymous;
  String? _currentEventCode;
  late Uint8List _currentTek;
  Uint8List? _currentEventCodeHash;

  // TEK storage: eventCodeHash (base64) -> List<TekEntry>
  final Map<String, List<TekEntry>> _tekStore = <String, List<TekEntry>>{};

  final Map<String, _RssiAgg> _aggByRpidKey = <String, _RssiAgg>{};
  int? _lastWindowIndex;

  int get _maxAggEntries => max(2000, min(10000, _peers.length * 3));

  @override
  BarnardCapabilities get capabilities => BarnardCapabilities(
    supportedTransports: const {TransportKind.ble},
    supportsConnectionlessRpid: true,
    supportsGattFallback: false,
    supportsBackground: false,
    supportsHighRateRssi: true,
    eninMode: _effectiveEninMode,
    eninSeconds: _effectiveEninSeconds,
    beaconChain: _config.beaconChain,
  );

  @override
  BarnardState get state => _state;

  @override
  EventMode get currentMode => _currentMode;

  @override
  String? get currentEventCode => _currentEventCode;

  @override
  String? get myResolvedDisplayId => _tekDisplayId(_currentTek);

  @override
  Stream<BarnardEvent> get events => _events.stream;

  @override
  Stream<BarnardDebugEvent> get debugEvents => _debugEvents.stream;

  @override
  Future<void> startScan([ScanConfig? config]) async {
    _ensureNotDisposed();
    if (_state.isScanning) return;
    _setState(
      _buildState(isScanning: true, isAdvertising: _state.isAdvertising),
      reasonCode: "scan_start",
    );
    _ensureTicker();
  }

  @override
  Future<void> stopScan() async {
    _ensureNotDisposed();
    if (!_state.isScanning) return;
    _setState(
      _buildState(isScanning: false, isAdvertising: _state.isAdvertising),
      reasonCode: "scan_stop",
    );
    _clearAggregation();
    _maybeStopTicker();
  }

  @override
  Future<void> startAdvertise([AdvertiseConfig? config]) async {
    _ensureNotDisposed();
    if (_state.isAdvertising) return;
    _setState(
      _buildState(isScanning: _state.isScanning, isAdvertising: true),
      reasonCode: "advertise_start",
    );
    _ensureTicker();
  }

  @override
  Future<void> stopAdvertise() async {
    _ensureNotDisposed();
    if (!_state.isAdvertising) return;
    _setState(
      _buildState(isScanning: _state.isScanning, isAdvertising: false),
      reasonCode: "advertise_stop",
    );
    _maybeStopTicker();
  }

  @override
  Future<BarnardStartResult> startAuto([AutoConfig? config]) async {
    _ensureNotDisposed();
    final bool wasScanning = _state.isScanning;
    final bool wasAdvertising = _state.isAdvertising;

    await startScan(config?.scan);
    await startAdvertise(config?.advertise);

    return BarnardStartResult(
      scanningStarted: !wasScanning && _state.isScanning,
      advertisingStarted: !wasAdvertising && _state.isAdvertising,
      issues: const <BarnardIssue>[],
    );
  }

  @override
  Future<void> stopAuto() async {
    _ensureNotDisposed();
    await stopScan();
    await stopAdvertise();
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Event Mode APIs
  // ─────────────────────────────────────────────────────────────────────────

  @override
  Future<void> joinEvent(String eventCode) async {
    _ensureNotDisposed();
    if (_currentMode == EventMode.event) {
      throw StateError("Already in Event Mode. Call leaveEvent() first.");
    }

    _currentEventCode = eventCode;
    _currentMode = EventMode.event;

    // Derive TEK from DeviceSecret + EventCode
    _currentTek = BarnardCrypto.deriveTekForEvent(_deviceSecret, eventCode);
    _currentEventCodeHash = BarnardCrypto.computeEventCodeHash(eventCode);

    _emitDebug(DebugLevel.info, "mock_join_event", <String, Object?>{
      "eventCode": eventCode,
      "tekDisplayId": _tekDisplayId(_currentTek),
      "eventCodeHash": base64Encode(_currentEventCodeHash!),
    });
  }

  @override
  Future<void> leaveEvent() async {
    _ensureNotDisposed();
    if (_currentMode == EventMode.anonymous) {
      throw StateError("Not in Event Mode. Call joinEvent() first.");
    }

    final String leftEvent = _currentEventCode!;
    _currentEventCode = null;
    _currentMode = EventMode.anonymous;
    _currentEventCodeHash = null;

    // Generate a deterministic TEK for Anonymous Mode
    _currentTek = BarnardCrypto.deriveTekForAnonymous(_deviceSecret);

    _emitDebug(DebugLevel.info, "mock_leave_event", <String, Object?>{
      "leftEvent": leftEvent,
    });
  }

  @override
  Future<List<TekEntry>> getExchangedTeks(String eventCode) async {
    _ensureNotDisposed();
    final Uint8List hash = BarnardCrypto.computeEventCodeHash(eventCode);
    final String key = base64Encode(hash);
    return List<TekEntry>.unmodifiable(_tekStore[key] ?? const <TekEntry>[]);
  }

  @override
  Future<int> clearTeksForEvent(String eventCode) async {
    _ensureNotDisposed();
    final Uint8List hash = BarnardCrypto.computeEventCodeHash(eventCode);
    final String key = base64Encode(hash);
    final List<TekEntry>? removed = _tekStore.remove(key);
    final int count = removed?.length ?? 0;

    _emitDebug(DebugLevel.info, "mock_clear_teks_for_event", <String, Object?>{
      "eventCode": eventCode,
      "removed": count,
    });

    return count;
  }

  @override
  Future<int> clearAllTeks() async {
    _ensureNotDisposed();
    int total = 0;
    for (final List<TekEntry> entries in _tekStore.values) {
      total += entries.length;
    }
    _tekStore.clear();

    _emitDebug(DebugLevel.info, "mock_clear_all_teks", <String, Object?>{
      "removed": total,
    });

    return total;
  }

  /// Simulates receiving a TEK from another peer (for testing).
  ///
  /// In the real BLE implementation, this happens via GATT exchange.
  void simulateReceivedTek(Uint8List tek, Uint8List eventCodeHash) {
    final String key = base64Encode(eventCodeHash);
    final List<TekEntry> entries = _tekStore.putIfAbsent(
      key,
      () => <TekEntry>[],
    );

    // Check if we already have this TEK
    final String tekB64 = base64Encode(tek);
    final bool alreadyHave = entries.any((e) => base64Encode(e.tek) == tekB64);
    if (alreadyHave) return;

    final DateTime now = DateTime.now();
    entries.add(
      TekEntry(
        tek: Uint8List.fromList(tek),
        eventCodeHash: Uint8List.fromList(eventCodeHash),
        exchangedAt: now,
        lastSeenAt: now,
      ),
    );

    _emitDebug(DebugLevel.info, "mock_tek_received", <String, Object?>{
      "tekDisplayId": _tekDisplayId(tek),
      "eventCodeHashB64": key,
      "totalTeks": entries.length,
    });
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Pull APIs
  // ─────────────────────────────────────────────────────────────────────────

  @override
  List<BarnardDebugEvent> getDebugBuffer({int? limit}) =>
      _debugBuffer.toList(limit: limit);

  @override
  List<RssiSample> getRssiSamples({
    DateTime? since,
    int? limit,
    List<int>? rpidBytes,
  }) {
    final List<RssiSample> all = _rssiBuffer.toList();
    final Uint8List? filterRpid = rpidBytes == null
        ? null
        : Uint8List.fromList(rpidBytes);

    Iterable<RssiSample> filtered = all;
    if (since != null) {
      filtered = filtered.where((RssiSample s) => !s.timestamp.isBefore(since));
    }
    if (filterRpid != null) {
      filtered = filtered.where(
        (RssiSample s) => _bytesEqual(s.rpid, filterRpid),
      );
    }

    final List<RssiSample> out = filtered.toList(growable: false);
    if (limit == null) return out;
    if (limit <= 0) return const <RssiSample>[];
    if (out.length <= limit) return out;
    return out.sublist(out.length - limit);
  }

  @override
  Future<void> dispose() async {
    if (_disposed) return;
    _disposed = true;
    _timer?.cancel();
    _clearAggregation();
    await _events.close();
    await _debugEvents.close();
  }

  void _ensureTicker() {
    _timer ??= Timer.periodic(Duration(milliseconds: _tickMs), (_) => _tick());
  }

  void _maybeStopTicker() {
    if (_state.isScanning || _state.isAdvertising) return;
    _timer?.cancel();
    _timer = null;
  }

  void _tick() {
    if (_disposed) return;
    if (!_state.isScanning) return;

    final DateTime now = DateTime.now();
    final int windowIndex = _calculateEnin(now);
    if (_lastWindowIndex != windowIndex) {
      _lastWindowIndex = windowIndex;
      _clearAggregation();
      _emitDebug(DebugLevel.info, "mock_rotation_window", <String, Object?>{
        "windowIndex": windowIndex,
        "eninMode": _effectiveEninMode.name,
        "eninSeconds": _effectiveEninSeconds,
      });
    }

    final int hits = 1 + _random.nextInt(5);
    for (int i = 0; i < hits; i++) {
      final MockPeer peer = _peers[_random.nextInt(_peers.length)];
      final Uint8List rpid = peer.rpidForWindow(windowIndex);
      final int rssi = peer.nextRssi();

      _rssiBuffer.add(
        RssiSample(
          timestamp: now,
          rpid: rpid,
          rssi: rssi,
          transport: peer.transport,
        ),
      );
      _accumulateAndMaybeEmit(now: now, peer: peer, rpid: rpid, rssi: rssi);
    }
  }

  void _accumulateAndMaybeEmit({
    required DateTime now,
    required MockPeer peer,
    required Uint8List rpid,
    required int rssi,
  }) {
    final String key = _rpidKey(rpid);
    final _RssiAgg agg = _aggByRpidKey.putIfAbsent(key, () => _RssiAgg());
    agg.add(rssi, now: now);
    _evictAggIfNeeded(now);

    final int minIntervalMs =
        (_overrides?.minPushIntervalMs ?? const RssiConfig().minPushIntervalMs)
            .clamp(50, 60 * 1000);
    if (agg.lastEmitAt != null &&
        now.difference(agg.lastEmitAt!).inMilliseconds < minIntervalMs) {
      return;
    }

    final RssiSummary summary = agg.toSummary();
    agg.resetAfterEmit(now);

    final DetectionEvent event = DetectionEvent(
      timestamp: now,
      rpid: rpid,
      rssi: rssi,
      transport: peer.transport,
      formatVersion: 1,
      displayId: _displayId(rpid),
      rssiSummary: summary,
      payloadRaw: null,
      debugLocalName: null,
    );

    _events.add(event);
    _emitDebug(DebugLevel.trace, "mock_detection", <String, Object?>{
      "displayId": event.displayId,
      "rssi": rssi,
      "count": summary.count,
      "min": summary.min,
      "max": summary.max,
      "mean": summary.mean,
    });
  }

  void _setState(BarnardState next, {required String reasonCode}) {
    _state = next;
    final DateTime now = DateTime.now();
    _events.add(
      StateEvent(timestamp: now, state: next, reasonCode: reasonCode),
    );
    _emitDebug(DebugLevel.info, "state", <String, Object?>{
      "isScanning": next.isScanning,
      "isAdvertising": next.isAdvertising,
      "reason": reasonCode,
    });
  }

  void _emitDebug(DebugLevel level, String name, Map<String, Object?> data) {
    final DebugEvent e = DebugEvent(
      timestamp: DateTime.now(),
      level: level,
      name: name,
      data: data,
    );
    _debugBuffer.add(e);
    _debugEvents.add(e);
  }

  void _clearAggregation() {
    _aggByRpidKey.clear();
  }

  void _evictAggIfNeeded(DateTime now) {
    if (_aggByRpidKey.length <= _maxAggEntries) return;

    // Evict the least-recently-seen entries to keep the mock bounded.
    // This is O(n) but only triggers when the map exceeds the cap.
    final List<MapEntry<String, _RssiAgg>> entries = _aggByRpidKey.entries
        .toList(growable: false);
    entries.sort((a, b) {
      final DateTime aSeen =
          a.value.lastSeenAt ?? DateTime.fromMillisecondsSinceEpoch(0);
      final DateTime bSeen =
          b.value.lastSeenAt ?? DateTime.fromMillisecondsSinceEpoch(0);
      return aSeen.compareTo(bSeen);
    });

    final int target = _maxAggEntries;
    final int removeCount = _aggByRpidKey.length - target;
    for (int i = 0; i < removeCount; i++) {
      _aggByRpidKey.remove(entries[i].key);
    }

    _emitDebug(DebugLevel.warn, "mock_agg_eviction", <String, Object?>{
      "removed": removeCount,
      "cap": target,
    });
  }

  void _ensureNotDisposed() {
    if (_disposed) throw StateError("MockBarnard is disposed");
  }

  EninMode get _effectiveEninMode => _overrides?.rotationSeconds == null
      ? _config.eninMode
      : EninMode.fixedLength;

  int get _effectiveEninSeconds {
    final int seconds = _overrides?.rotationSeconds ?? _config.eninSeconds;
    return seconds.clamp(12, 3600);
  }

  int _calculateEnin(DateTime timestamp) {
    return calculateEnin(
      timestamp,
      mode: _effectiveEninMode,
      eninSeconds: _effectiveEninSeconds,
      beaconChain: _config.beaconChain,
    );
  }

  BarnardState _buildState({
    required bool isScanning,
    required bool isAdvertising,
  }) {
    return BarnardState(
      isScanning: isScanning,
      isAdvertising: isAdvertising,
      eninMode: _effectiveEninMode,
      eninSeconds: _effectiveEninSeconds,
      beaconChain: _config.beaconChain,
    );
  }

  static String _displayId(Uint8List rpid) {
    final int take = min(4, rpid.length);
    final String hex = rpid
        .sublist(0, take)
        .map((int b) => b.toRadixString(16).padLeft(2, "0"))
        .join();
    return hex;
  }

  static String _rpidKey(Uint8List rpid) => base64UrlEncode(rpid);

  static bool _bytesEqual(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    for (int i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }

  static Uint8List _generateRandomBytes(int length) {
    final Random random = Random.secure();
    return Uint8List.fromList(
      List<int>.generate(length, (_) => random.nextInt(256)),
    );
  }

  static String _tekDisplayId(Uint8List tek) {
    final int take = min(3, tek.length);
    return tek
        .sublist(0, take)
        .map((int b) => b.toRadixString(16).padLeft(2, "0"))
        .join();
  }
}

class _RssiAgg {
  int _count = 0;
  int _min = 0;
  int _max = 0;
  int _sum = 0;
  DateTime? lastEmitAt;
  DateTime? lastSeenAt;

  void add(int rssi, {required DateTime now}) {
    if (_count == 0) {
      _min = rssi;
      _max = rssi;
    } else {
      if (rssi < _min) _min = rssi;
      if (rssi > _max) _max = rssi;
    }
    _count += 1;
    _sum += rssi;
    lastSeenAt = now;
  }

  RssiSummary toSummary() {
    final double mean = _count == 0 ? 0.0 : _sum / _count;
    return RssiSummary(count: _count, min: _min, max: _max, mean: mean);
  }

  void resetAfterEmit(DateTime emittedAt) {
    _count = 0;
    _min = 0;
    _max = 0;
    _sum = 0;
    lastEmitAt = emittedAt;
  }
}
