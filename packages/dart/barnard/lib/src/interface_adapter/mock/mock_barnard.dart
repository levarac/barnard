import "dart:async";
import "dart:convert";
import "dart:math";
import "dart:typed_data";

import "../../usecase/barnard_client.dart";
import "../../domain/capabilities.dart";
import "../../domain/config.dart";
import "../../domain/crypto.dart";
import "../../domain/events.dart";
import "../../domain/permissions.dart";
import "../../domain/rssi.dart";
import "../../domain/state.dart";
import "../../domain/transport.dart";
import "mock_peer.dart";
import "ring_buffer.dart";

class MockBarnardOverrides {
  const MockBarnardOverrides({
    this.rotationSeconds,
    this.minPushIntervalMs,
    this.bufferMaxSamples,
    this.b004MismatchRate,
    this.b003FailureRate,
  });

  final int? rotationSeconds;
  final int? minPushIntervalMs;
  final int? bufferMaxSamples;

  /// Probability (0.0 .. 1.0) that a simulated B004 read returns a peer
  /// EventCodeHash that does not match this client's current event. Mismatches
  /// gate the exchange before B002/B003 and therefore emit no detection.
  final double? b004MismatchRate;

  /// Probability (0.0 .. 1.0) that a simulated B003 read fails, causing
  /// [DetectionEvent.detectedDisplayId] to be `null`. Defaults to 0.1 (10%).
  final double? b003FailureRate;
}

const BarnardPermissionStatus _grantedPermissionStatus =
    BarnardPermissionStatus(
      platform: "mock",
      permissions: <String, BarnardPermissionDecision>{
        "mock.bluetooth": BarnardPermissionDecision.granted,
      },
      requiredPermissions: <String>["mock.bluetooth"],
      missingPermissions: <String>[],
      requestablePermissions: <String>[],
      blockedPermissions: <String>[],
      canScan: true,
      canAdvertise: true,
    );

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

    _currentEventCode = _normalEventCode(config.eventCode);
    _currentTek = _currentEventCode == null
        ? BarnardCrypto.deriveTekForAnonymous(_deviceSecret)
        : BarnardCrypto.deriveTekForEvent(_deviceSecret, _currentEventCode!);
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

  String? _currentEventCode;
  late Uint8List _currentTek;

  final Map<String, _RssiAgg> _aggByRpidKey = <String, _RssiAgg>{};
  int? _lastWindowIndex;

  int get _maxAggEntries => max(2000, min(10000, _peers.length * 3));

  static String? _normalEventCode(String? eventCode) =>
      eventCode == null || eventCode.isEmpty ? null : eventCode;

  double get _b003FailureRate =>
      (_overrides?.b003FailureRate ?? 0.1).clamp(0.0, 1.0);

  double get _b004MismatchRate =>
      (_overrides?.b004MismatchRate ?? 0.0).clamp(0.0, 1.0);

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
  String? get currentEventCode => _currentEventCode;

  @override
  String get myDisplayId => displayIdFromTek(_currentTek);

  @override
  int get currentEnin => _calculateEnin(DateTime.now());

  @override
  Stream<BarnardEvent> get events => _events.stream;

  @override
  Stream<BarnardDebugEvent> get debugEvents => _debugEvents.stream;

  @override
  Future<BarnardPermissionStatus> getPermissionStatus() async {
    _ensureNotDisposed();
    return _grantedPermissionStatus;
  }

  @override
  Future<BarnardPermissionStatus> requestPermissions() async {
    _ensureNotDisposed();
    return _grantedPermissionStatus;
  }

  @override
  Future<void> openAppSettings() async {
    _ensureNotDisposed();
  }

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

  @override
  Future<void> joinEvent(String eventCode) async {
    _ensureNotDisposed();
    _currentEventCode = eventCode;
    _currentTek = BarnardCrypto.deriveTekForEvent(_deviceSecret, eventCode);

    _emitDebug(DebugLevel.info, "mock_join_event", <String, Object?>{
      "eventCode": eventCode,
      "myDisplayId": myDisplayId,
    });
  }

  @override
  Future<void> leaveEvent() async {
    _ensureNotDisposed();
    final String? leftEvent = _currentEventCode;
    _currentEventCode = null;
    _currentTek = BarnardCrypto.deriveTekForAnonymous(_deviceSecret);

    _emitDebug(DebugLevel.info, "mock_leave_event", <String, Object?>{
      "leftEvent": leftEvent,
    });
  }

  @override
  Future<Uint8List> getCurrentRpi() async {
    _ensureNotDisposed();
    final Uint8List rpik = deriveRpik(_currentTek);
    return generateRpi(rpik, currentEnin);
  }

  @override
  Future<Uint8List> exportCurrentTek() async {
    _ensureNotDisposed();
    // Explicit privacy boundary: returns a defensive copy.
    return Uint8List.fromList(_currentTek);
  }

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
      // Wire-form 17-byte RPID for the detected peer.
      final Uint8List rpidPayload = peer.rpidPayloadForWindow(windowIndex);
      final int rssi = peer.nextRssi();

      _rssiBuffer.add(
        RssiSample(
          timestamp: now,
          rpid: rpidPayload,
          rssi: rssi,
          transport: peer.transport,
        ),
      );
      _accumulateAndMaybeEmit(
        now: now,
        peer: peer,
        rpidPayload: rpidPayload,
        rssi: rssi,
      );
    }
  }

  void _accumulateAndMaybeEmit({
    required DateTime now,
    required MockPeer peer,
    required Uint8List rpidPayload,
    required int rssi,
  }) {
    // Simulate B004 read: EventCodeHash must match before B002/B003 proceed.
    if (_random.nextDouble() < _b004MismatchRate) {
      _emitDebug(DebugLevel.info, "gatt_b004_mismatch", <String, Object?>{
        "peerId": peer.id,
      });
      return;
    }

    final String key = _rpidKey(rpidPayload);
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

    // Capture reporter's own RPID wire form at this observation timestamp.
    final int enin = _calculateEnin(now);
    final Uint8List myRpik = deriveRpik(_currentTek);
    final Uint8List myRpi = generateRpi(myRpik, enin);
    final Uint8List reporterRpid = Uint8List(17);
    reporterRpid[0] = 1; // formatVersion
    reporterRpid.setRange(1, 17, myRpi);

    // Simulate B003 read: peer's TEK -> displayId, with configurable failure.
    final String? detectedDisplayId = _random.nextDouble() < _b003FailureRate
        ? null
        : displayIdFromTek(peer.mockTek);

    if (detectedDisplayId == null) {
      _emitDebug(DebugLevel.warn, "gatt_b003_read_failed", <String, Object?>{
        "peerId": peer.id,
      });
    }

    final DetectionEvent event = DetectionEvent(
      timestamp: now,
      transport: peer.transport,
      formatVersion: 1,
      rpid: rpidPayload,
      reporterRpid: reporterRpid,
      detectedDisplayId: detectedDisplayId,
      rssi: rssi,
      enin: enin,
      rssiSummary: summary,
      payloadRaw: rpidPayload,
      debugLocalName: null,
    );

    _events.add(event);
    _emitDebug(DebugLevel.trace, "mock_detection", <String, Object?>{
      "detectedDisplayId": detectedDisplayId,
      "rssi": rssi,
      "enin": enin,
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
