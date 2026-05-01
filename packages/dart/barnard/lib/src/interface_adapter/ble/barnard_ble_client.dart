import "dart:async";

import "../../domain/capabilities.dart";
import "../../domain/config.dart";
import "../../domain/crypto.dart";
import "../../domain/events.dart";
import "../../domain/hex.dart";
import "../../domain/rssi.dart";
import "../../domain/state.dart";
import "../../domain/transport.dart";
import "../../usecase/barnard_client.dart";
import "package:flutter/services.dart";

class BarnardBleClient implements BarnardClient {
  BarnardBleClient._({
    required BarnardCapabilities capabilities,
    required BarnardState initialState,
    String? initialEventCode,
    required String initialMyDisplayId,
  }) : _capabilities = capabilities,
       _state = initialState,
       _currentEventCode = initialEventCode,
       _myDisplayId = initialMyDisplayId;

  static const MethodChannel _methods = MethodChannel("barnard/methods");
  static const EventChannel _eventsChannel = EventChannel("barnard/events");
  static const EventChannel _debugEventsChannel = EventChannel(
    "barnard/debugEvents",
  );

  final StreamController<BarnardEvent> _eventsController =
      StreamController<BarnardEvent>.broadcast();
  final StreamController<BarnardDebugEvent> _debugEventsController =
      StreamController<BarnardDebugEvent>.broadcast();

  late final StreamSubscription<dynamic> _eventsSub;
  late final StreamSubscription<dynamic> _debugEventsSub;

  final _BoundedBuffer<BarnardDebugEvent> _debugBuffer =
      _BoundedBuffer<BarnardDebugEvent>(2000);
  final _BoundedBuffer<RssiSample> _rssiBuffer = _BoundedBuffer<RssiSample>(
    const RssiConfig().bufferMaxSamples,
  );

  final BarnardCapabilities _capabilities;
  BarnardState _state;
  String? _currentEventCode;
  String _myDisplayId;
  bool _disposed = false;

  static Future<BarnardBleClient> create({
    BarnardConfig config = const BarnardConfig(),
  }) async {
    await _methods.invokeMethod<void>(
      "configure",
      _encodeBarnardConfig(config),
    );

    final Map<Object?, Object?> capsMap =
        (await _methods.invokeMethod<Map<Object?, Object?>>(
          "getCapabilities",
        )) ??
        <Object?, Object?>{};
    final Map<Object?, Object?> stateMap =
        (await _methods.invokeMethod<Map<Object?, Object?>>("getState")) ??
        <Object?, Object?>{};

    String? eventCode;
    try {
      eventCode = await _methods.invokeMethod<String?>("getCurrentEventCode");
    } on MissingPluginException {
      eventCode = null;
    } on PlatformException {
      eventCode = null;
    }

    // myDisplayId is a non-nullable 8-char hex string. A missing/malformed
    // value indicates a native-side protocol error; fail fast.
    final String myDisplayId = _requireDisplayId(
      await _methods.invokeMethod<String>("getMyDisplayId"),
    );

    final BarnardBleClient client = BarnardBleClient._(
      capabilities: _parseCapabilities(capsMap),
      initialState: _parseState(stateMap),
      initialEventCode: eventCode,
      initialMyDisplayId: myDisplayId,
    );
    await client._attachStreams();
    return client;
  }

  Future<void> _attachStreams() async {
    _eventsSub = _eventsChannel.receiveBroadcastStream().listen((dynamic data) {
      final BarnardEvent event = parseBarnardEvent(_expectMap(data));
      if (event is StateEvent) _state = event.state;
      if (event is DetectionEvent) {
        if (!isUsableBleRssi(event.rssi)) return;
        _rssiBuffer.add(
          RssiSample(
            timestamp: event.timestamp,
            rpid: event.rpid,
            rssi: event.rssi,
            transport: event.transport,
          ),
        );
      } else if (event is RssiUpdateEvent && !isUsableBleRssi(event.rssi)) {
        return;
      }
      _eventsController.add(event);
    });

    _debugEventsSub = _debugEventsChannel.receiveBroadcastStream().listen((
      dynamic data,
    ) {
      final BarnardDebugEvent event = _parseDebugEvent(_expectMap(data));
      _debugBuffer.add(event);
      _debugEventsController.add(event);
    });
  }

  @override
  BarnardCapabilities get capabilities => _capabilities;

  @override
  BarnardState get state => _state;

  @override
  String? get currentEventCode => _currentEventCode;

  @override
  String get myDisplayId => _myDisplayId;

  @override
  int get currentEnin {
    // Computed on demand by the native side. The native ENIN uses the
    // device's current time; this getter is synchronous by contract, so we
    // cannot await. The plugin emits ENIN on every detection event — host
    // apps that need fresh ENIN should read it from the latest event. This
    // getter therefore returns an approximation computed in Dart.
    return calculateEnin(
      DateTime.now(),
      mode: _capabilities.eninMode,
      eninSeconds: _capabilities.eninSeconds,
      beaconChain: _capabilities.beaconChain,
    );
  }

  @override
  Stream<BarnardEvent> get events => _eventsController.stream;

  @override
  Stream<BarnardDebugEvent> get debugEvents => _debugEventsController.stream;

  @override
  Future<void> startScan([ScanConfig? config]) async {
    _ensureNotDisposed();
    await _methods.invokeMethod<void>("startScan", _encodeScanConfig(config));
  }

  @override
  Future<void> stopScan() async {
    _ensureNotDisposed();
    await _methods.invokeMethod<void>("stopScan");
  }

  @override
  Future<void> startAdvertise([AdvertiseConfig? config]) async {
    _ensureNotDisposed();
    await _methods.invokeMethod<void>(
      "startAdvertise",
      _encodeAdvertiseConfig(config),
    );
  }

  @override
  Future<void> stopAdvertise() async {
    _ensureNotDisposed();
    await _methods.invokeMethod<void>("stopAdvertise");
  }

  @override
  Future<BarnardStartResult> startAuto([AutoConfig? config]) async {
    _ensureNotDisposed();
    final Map<Object?, Object?>? out = await _methods
        .invokeMethod<Map<Object?, Object?>>(
          "startAuto",
          _encodeAutoConfig(config),
        );
    if (out == null) {
      return const BarnardStartResult(
        scanningStarted: false,
        advertisingStarted: false,
        issues: <BarnardIssue>[],
      );
    }
    return _parseStartResult(out);
  }

  @override
  Future<void> stopAuto() async {
    _ensureNotDisposed();
    await _methods.invokeMethod<void>("stopAuto");
  }

  @override
  Future<void> joinEvent(String eventCode) async {
    _ensureNotDisposed();
    await _methods.invokeMethod<void>("joinEvent", <String, Object?>{
      "eventCode": eventCode,
    });
    _currentEventCode = eventCode;
    // Refresh displayId after TEK change; fail fast on invalid native reply.
    _myDisplayId = _requireDisplayId(
      await _methods.invokeMethod<String>("getMyDisplayId"),
    );
  }

  @override
  Future<void> leaveEvent() async {
    _ensureNotDisposed();
    await _methods.invokeMethod<void>("leaveEvent");
    _currentEventCode = null;
    _myDisplayId = _requireDisplayId(
      await _methods.invokeMethod<String>("getMyDisplayId"),
    );
  }

  @override
  Future<Uint8List> getCurrentRpi() async {
    _ensureNotDisposed();
    final String hex =
        (await _methods.invokeMethod<String>("getCurrentRpi")) ?? "";
    final Uint8List bytes = hexToBytes(hex);
    if (bytes.length != 16) {
      throw StateError(
        "getCurrentRpi: expected 16 bytes from native, got ${bytes.length}",
      );
    }
    return bytes;
  }

  @override
  Future<Uint8List> exportCurrentTek() async {
    _ensureNotDisposed();
    final String hex =
        (await _methods.invokeMethod<String>("exportCurrentTek")) ?? "";
    if (hex.isEmpty) {
      throw StateError(
        "exportCurrentTek: native returned empty TEK — not yet initialized.",
      );
    }
    final Uint8List bytes = hexToBytes(hex);
    if (bytes.length != 16) {
      throw StateError(
        "exportCurrentTek: expected 16 bytes from native, got ${bytes.length}",
      );
    }
    return bytes;
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
    final Uint8List? filterRpid = rpidBytes == null
        ? null
        : Uint8List.fromList(rpidBytes);
    Iterable<RssiSample> samples = _rssiBuffer.toList();
    if (since != null) {
      samples = samples.where((RssiSample s) => !s.timestamp.isBefore(since));
    }
    if (filterRpid != null) {
      samples = samples.where(
        (RssiSample s) => _bytesEqual(s.rpid, filterRpid),
      );
    }
    final List<RssiSample> out = samples.toList(growable: false);
    if (limit == null) return out;
    if (limit <= 0) return const <RssiSample>[];
    if (out.length <= limit) return out;
    return out.sublist(out.length - limit);
  }

  @override
  Future<void> dispose() async {
    if (_disposed) return;
    _disposed = true;
    await _eventsSub.cancel();
    await _debugEventsSub.cancel();
    await _eventsController.close();
    await _debugEventsController.close();
    await _methods.invokeMethod<void>("dispose");
  }

  void _ensureNotDisposed() {
    if (_disposed) throw StateError("BarnardBleClient is disposed");
  }
}

Map<String, Object?> _encodeScanConfig(ScanConfig? config) => <String, Object?>{
  "transport": (config?.transport ?? TransportKind.ble).name,
  "allowDuplicates":
      config?.allowDuplicates ?? const ScanConfig().allowDuplicates,
};

Map<String, Object?> _encodeAdvertiseConfig(AdvertiseConfig? config) =>
    <String, Object?>{
      "transport": (config?.transport ?? TransportKind.ble).name,
      "formatVersion":
          config?.formatVersion ?? const AdvertiseConfig().formatVersion,
    };

Map<String, Object?> _encodeAutoConfig(AutoConfig? config) => <String, Object?>{
  "scan": _encodeScanConfig(config?.scan),
  "advertise": _encodeAdvertiseConfig(config?.advertise),
};

Map<String, Object?> _encodeBarnardConfig(BarnardConfig config) =>
    <String, Object?>{
      "transport": config.transport.name,
      "eventCode": config.eventCode,
      "eninMode": config.eninMode.name,
      "eninSeconds": config.effectiveEninSeconds,
      "beaconChain": <String, Object?>{
        "chainId": config.beaconChain.chainId,
        "genesisUnixSeconds": config.beaconChain.effectiveGenesisUnixSeconds,
        "slotSeconds": config.beaconChain.effectiveSlotSeconds,
      },
    };

BarnardStartResult _parseStartResult(Map<Object?, Object?> map) {
  final bool scanningStarted = map["scanningStarted"] == true;
  final bool advertisingStarted = map["advertisingStarted"] == true;
  final List<BarnardIssue> issues = <BarnardIssue>[];
  final Object? rawIssues = map["issues"];
  if (rawIssues is List) {
    for (final Object? item in rawIssues) {
      if (item is! Map) continue;
      final String? severity = item["severity"] as String?;
      final BarnardIssueSeverity sev = switch (severity) {
        "info" => BarnardIssueSeverity.info,
        "warn" => BarnardIssueSeverity.warn,
        _ => BarnardIssueSeverity.error,
      };
      final String code = (item["code"] as String?) ?? "unknown";
      final String? message = item["message"] as String?;
      issues.add(BarnardIssue(severity: sev, code: code, message: message));
    }
  }
  return BarnardStartResult(
    scanningStarted: scanningStarted,
    advertisingStarted: advertisingStarted,
    issues: issues,
  );
}

BarnardCapabilities _parseCapabilities(Map<Object?, Object?> map) {
  final Object? raw = map["supportedTransports"];
  final List<Object?> transports = raw is List ? raw : const <Object?>["ble"];
  final Set<TransportKind> supportedTransports = transports
      .whereType<String>()
      .map(
        (String s) => TransportKind.values.firstWhere(
          (e) => e.name == s,
          orElse: () => TransportKind.unknown,
        ),
      )
      .toSet();

  return BarnardCapabilities(
    supportedTransports: supportedTransports.isEmpty
        ? <TransportKind>{TransportKind.ble}
        : supportedTransports,
    supportsConnectionlessRpid: map["supportsConnectionlessRpid"] == true,
    supportsGattFallback: map["supportsGattFallback"] == true,
    supportsBackground: map["supportsBackground"] == true,
    supportsHighRateRssi: map["supportsHighRateRssi"] == true,
    eninMode: _parseEninMode(map["eninMode"]),
    eninSeconds: ((map["eninSeconds"] as int?) ?? 600).clamp(12, 3600),
    beaconChain: _parseBeaconChain(map["beaconChain"]),
  );
}

BarnardState _parseState(Map<Object?, Object?> map) {
  final bool isScanning = map["isScanning"] == true;
  final bool isAdvertising = map["isAdvertising"] == true;
  return BarnardState(
    isScanning: isScanning,
    isAdvertising: isAdvertising,
    eninMode: _parseEninMode(map["eninMode"]),
    eninSeconds: ((map["eninSeconds"] as int?) ?? 600).clamp(12, 3600),
    beaconChain: _parseBeaconChain(map["beaconChain"]),
  );
}

EninMode _parseEninMode(Object? value) {
  if (value == "beaconSlot") return EninMode.beaconSlot;
  return EninMode.fixedLength;
}

BeaconChainConfig _parseBeaconChain(Object? value) {
  if (value is! Map) return BeaconChainConfig.ethereumMainnet;
  return BeaconChainConfig(
    chainId:
        (value["chainId"] as String?) ??
        BeaconChainConfig.ethereumMainnet.chainId,
    genesisUnixSeconds:
        (value["genesisUnixSeconds"] as int?) ??
        BeaconChainConfig.ethereumMainnet.genesisUnixSeconds,
    slotSeconds:
        (value["slotSeconds"] as int?) ??
        BeaconChainConfig.ethereumMainnet.slotSeconds,
  );
}

/// Parse a v2 event payload. Byte-valued fields are hex-encoded lowercase.
///
/// Exposed for integration testing and host-app consumers that need to
/// decode method-channel payloads outside of the default stream handler.
BarnardEvent parseBarnardEvent(Map<Object?, Object?> map) {
  final String? type = map["type"] as String?;
  final DateTime ts = DateTime.parse(
    (map["timestamp"] as String?) ?? DateTime.now().toIso8601String(),
  );
  switch (type) {
    case "state":
      final Map<Object?, Object?> state = _expectMap(map["state"]);
      return StateEvent(
        timestamp: ts,
        state: BarnardState(
          isScanning: state["isScanning"] == true,
          isAdvertising: state["isAdvertising"] == true,
          eninMode: _parseEninMode(state["eninMode"]),
          eninSeconds: ((state["eninSeconds"] as int?) ?? 600).clamp(12, 3600),
          beaconChain: _parseBeaconChain(state["beaconChain"]),
        ),
        reasonCode: map["reasonCode"] as String?,
      );
    case "constraint":
      return ConstraintEvent(
        timestamp: ts,
        code: (map["code"] as String?) ?? "unknown",
        message: map["message"] as String?,
        requiredAction: map["requiredAction"] as String?,
      );
    case "error":
      return ErrorEvent(
        timestamp: ts,
        code: (map["code"] as String?) ?? "unknown",
        message: (map["message"] as String?) ?? "unknown",
        recoverable: map["recoverable"] as bool?,
      );
    case "rssi_update":
      final Uint8List rpid = _decodeRpidHex(
        (map["rpid"] as String?) ?? "",
        field: "rpid",
      );
      final Uint8List reporterRpid = _decodeRpidHex(
        (map["reporterRpid"] as String?) ?? "",
        field: "reporterRpid",
      );
      return RssiUpdateEvent(
        timestamp: ts,
        rpid: rpid,
        reporterRpid: reporterRpid,
        enin: (map["enin"] as int?) ?? 0,
        rssi: (map["rssi"] as int?) ?? 0,
        detectedDisplayId: _validateDetectedDisplayId(map["detectedDisplayId"]),
        debugLocalName: map["debugLocalName"] as String?,
      );
    case "detection":
    default:
      final TransportKind transport = TransportKind.values.firstWhere(
        (e) => e.name == (map["transport"] as String?),
        orElse: () => TransportKind.unknown,
      );
      final Uint8List rpid = _decodeRpidHex(
        (map["rpid"] as String?) ?? "",
        field: "rpid",
      );
      final Uint8List reporterRpid = _decodeRpidHex(
        (map["reporterRpid"] as String?) ?? "",
        field: "reporterRpid",
      );
      final String? detectedDisplayId = _validateDetectedDisplayId(
        map["detectedDisplayId"],
      );
      final int rssi = (map["rssi"] as int?) ?? 0;
      final int formatVersion = (map["formatVersion"] as int?) ?? 0;
      final int enin = (map["enin"] as int?) ?? 0;
      final String? payloadRawHex = map["payloadRaw"] as String?;
      final Uint8List? payloadRaw = payloadRawHex == null
          ? null
          : hexToBytes(payloadRawHex);

      final Map<Object?, Object?>? summaryMap = map["rssiSummary"] is Map
          ? map["rssiSummary"] as Map<Object?, Object?>
          : null;
      final RssiSummary? summary = summaryMap == null
          ? null
          : RssiSummary(
              count: (summaryMap["count"] as int?) ?? 0,
              min: (summaryMap["min"] as int?) ?? 0,
              max: (summaryMap["max"] as int?) ?? 0,
              mean: (summaryMap["mean"] as num?)?.toDouble() ?? 0.0,
            );

      final String? debugLocalName = map["debugLocalName"] as String?;

      return DetectionEvent(
        timestamp: ts,
        transport: transport,
        formatVersion: formatVersion,
        rpid: rpid,
        reporterRpid: reporterRpid,
        detectedDisplayId: detectedDisplayId,
        rssi: rssi,
        enin: enin,
        rssiSummary: summary,
        payloadRaw: payloadRaw,
        debugLocalName: debugLocalName,
      );
  }
}

BarnardDebugEvent _parseDebugEvent(Map<Object?, Object?> map) {
  final DateTime ts = DateTime.parse(
    (map["timestamp"] as String?) ?? DateTime.now().toIso8601String(),
  );
  final String? levelStr = map["level"] as String?;
  final DebugLevel level = switch (levelStr) {
    "trace" => DebugLevel.trace,
    "warn" => DebugLevel.warn,
    "error" => DebugLevel.error,
    _ => DebugLevel.info,
  };
  final String name = (map["name"] as String?) ?? "debug";
  final Map<Object?, Object?>? rawData = map["data"] is Map
      ? map["data"] as Map<Object?, Object?>
      : null;
  final Map<String, Object?>? data = rawData?.map(
    (k, v) => MapEntry(k.toString(), v),
  );
  return DebugEvent(timestamp: ts, level: level, name: name, data: data);
}

Map<Object?, Object?> _expectMap(Object? value) {
  if (value is Map<Object?, Object?>) return value;
  if (value is Map) return Map<Object?, Object?>.from(value);
  throw FormatException("Expected map, got ${value.runtimeType}");
}

/// Decode an RPID wire-form hex string and enforce the 17-byte length
/// `[formatVersion(1) + RPI(16)]`. Fails fast on wrong length.
Uint8List _decodeRpidHex(String hex, {required String field}) {
  if (hex.isEmpty) {
    throw FormatException("missing $field in v2 event payload");
  }
  final Uint8List bytes = hexToBytes(hex);
  if (bytes.length != 17) {
    throw FormatException(
      "invalid $field length: expected 17 bytes, got ${bytes.length}",
    );
  }
  return bytes;
}

/// Require a non-null 8-char-lowercase-hex displayId. For myDisplayId we
/// have no null case: it must always be set on the native side.
String _requireDisplayId(String? value) {
  if (value == null) {
    throw StateError(
      "getMyDisplayId returned null — native plugin is not initialized for v2",
    );
  }
  if (!RegExp(r"^[0-9a-f]{8}$").hasMatch(value)) {
    throw StateError(
      "getMyDisplayId returned invalid value '$value' — expected 8 lowercase hex chars",
    );
  }
  return value;
}

/// Validate v2 displayId: 8 lowercase hex chars, or null.
String? _validateDetectedDisplayId(Object? value) {
  if (value == null) return null;
  if (value is! String) {
    throw FormatException(
      "detectedDisplayId must be String, got ${value.runtimeType}",
    );
  }
  if (!RegExp(r"^[0-9a-f]{8}$").hasMatch(value)) {
    throw FormatException(
      "invalid detectedDisplayId: expected 8 lowercase hex chars, got '$value'",
    );
  }
  return value;
}

bool _bytesEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (int i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

class _BoundedBuffer<T> {
  _BoundedBuffer(this._cap) : _items = <T>[];

  final int _cap;
  final List<T> _items;

  void add(T item) {
    _items.add(item);
    final int overflow = _items.length - _cap;
    if (overflow > 0) {
      _items.removeRange(0, overflow);
    }
  }

  List<T> toList({int? limit}) {
    if (limit == null) return List<T>.unmodifiable(_items);
    if (limit <= 0) return List<T>.empty(growable: false);
    if (_items.length <= limit) return List<T>.unmodifiable(_items);
    return List<T>.unmodifiable(_items.sublist(_items.length - limit));
  }
}
