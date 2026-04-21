import "dart:async";
import "dart:convert";
import "dart:io";
import "dart:typed_data";

import "package:barnard/barnard.dart";
import "package:barnard/barnard_ble.dart";
import "package:flutter/material.dart";
import "package:flutter/services.dart" show Clipboard, ClipboardData;
import "package:permission_handler/permission_handler.dart";

void main() => runApp(const MyApp());

class MyApp extends StatefulWidget {
  const MyApp({super.key});

  @override
  State<MyApp> createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  final GlobalKey<ScaffoldMessengerState> _messengerKey =
      GlobalKey<ScaffoldMessengerState>();
  BarnardBleClient? _client;
  StreamSubscription<BarnardEvent>? _eventsSub;
  StreamSubscription<BarnardDebugEvent>? _debugSub;

  final TextEditingController _eventCodeController =
      TextEditingController(text: "BND");

  BarnardState _state = BarnardState.idle;
  final List<BarnardEvent> _events = <BarnardEvent>[];
  final List<BarnardDebugEvent> _debugEvents = <BarnardDebugEvent>[];
  final Map<String, _SeenEntry> _seenById = <String, _SeenEntry>{};
  final _SelfAdvertiseInfo _selfInfo = _SelfAdvertiseInfo();

  bool _busy = false;
  bool _eventsOnlyDetections = false;
  bool _eventsOnlyIssues = false;
  bool _debugOnlyIssues = false;
  bool _debugHideTrace = true;
  String _debugQuery = "";
  Timer? _uiTicker;

  // Monotonic counters. These are "ever-seen" totals and are independent of
  // the 200-entry ring buffer above, so they do not shrink when old
  // DetectionEvents get evicted by high-rate RssiUpdateEvents.
  int _totalEvents = 0;
  int _totalDetections = 0;
  int _totalRssiUpdates = 0;
  int _totalIssues = 0;
  int _totalDebug = 0;
  int _totalDebugIssues = 0;

  // Timeline samples for the fourth tab. Keyed by rpid (17-byte wire form).
  final Map<String, _PeerTrack> _tracks = <String, _PeerTrack>{};
  // Scan-only observations (BLE scan hits not yet resolved to rpid via GATT).
  // Keyed by peripheral id/address (the `id` field of ble_discovery_result
  // debug events). Populated when v2 central sees a peripheral advertise the
  // Barnard service UUID but the follow-up GATT read has not completed.
  final Map<String, _PeerTrack> _scanOnlyTracks = <String, _PeerTrack>{};

  static const Duration _staleAfter = Duration(seconds: 15);
  static const String _serviceUuid = "0000B001-0000-1000-8000-00805F9B34FB";
  static const String _localName = "BNRD";

  @override
  void initState() {
    super.initState();
    _init();
    _uiTicker = Timer.periodic(const Duration(seconds: 1), (_) {
      if (!mounted) return;
      setState(() {});
    });
  }

  @override
  void dispose() {
    _eventsSub?.cancel();
    _debugSub?.cancel();
    _client?.dispose();
    _eventCodeController.dispose();
    _uiTicker?.cancel();
    super.dispose();
  }

  Future<void> _init() async {
    await _ensurePermissions();
    final BarnardBleClient client = await BarnardBleClient.create();

    _eventsSub = client.events.listen((BarnardEvent e) {
      if (!mounted) return;
      setState(() {
        _events.add(e);
        if (_events.length > 200) _events.removeRange(0, _events.length - 200);
        _totalEvents += 1;
        if (e is StateEvent) _state = e.state;
        if (e is DetectionEvent) {
          _totalDetections += 1;
          _updateSeen(e);
          _pushTrackSample(e.rpid, e.timestamp, e.rssi, _TrackKind.detection,
              detectedDisplayId: e.detectedDisplayId);
        }
        if (e is RssiUpdateEvent) {
          _totalRssiUpdates += 1;
          _pushTrackSample(e.rpid, e.timestamp, e.rssi, _TrackKind.rssiUpdate,
              detectedDisplayId: e.detectedDisplayId);
        }
        if (e is ConstraintEvent || e is ErrorEvent) {
          _totalIssues += 1;
        }
      });
    });
    _debugSub = client.debugEvents.listen((BarnardDebugEvent e) {
      if (!mounted) return;
      setState(() {
        _debugEvents.add(e);
        if (_debugEvents.length > 200) {
          _debugEvents.removeRange(0, _debugEvents.length - 200);
        }
        _totalDebug += 1;
        if (e.level == DebugLevel.warn || e.level == DebugLevel.error) {
          _totalDebugIssues += 1;
        }
        _updateSelfInfo(e);
        if (e.name == "ble_discovery_result") {
          _pushScanOnlySample(e);
        }
      });
    });

    setState(() {
      _client = client;
      _state = client.state;
      if (client.currentEventCode != null &&
          client.currentEventCode!.isNotEmpty) {
        _eventCodeController.text = client.currentEventCode!;
      }
    });
  }

  Future<void> _ensurePermissions() async {
    if (!Platform.isAndroid) return;
    await <Permission>[
      Permission.bluetoothScan,
      Permission.bluetoothConnect,
      Permission.bluetoothAdvertise,
    ].request();
  }

  Future<void> _run(
      Future<void> Function(BarnardBleClient client) action) async {
    final BarnardBleClient? client = _client;
    if (client == null) return;
    if (_busy) return;
    setState(() => _busy = true);
    try {
      await action(client);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _ensureEventJoined(BarnardBleClient client) async {
    if (client.currentEventCode != null) return;
    final String code = _eventCodeController.text.trim();
    if (code.isEmpty) return;
    await client.joinEvent(code);
  }

  Future<void> _toggleScan() => _run((c) async {
        if (_state.isScanning) {
          await c.stopScan();
        } else {
          await _ensureEventJoined(c);
          await c.startScan(const ScanConfig(allowDuplicates: true));
        }
      });

  Future<void> _toggleAdvertise() => _run((c) async {
        if (_state.isAdvertising) {
          await c.stopAdvertise();
        } else {
          await _ensureEventJoined(c);
          await c.startAdvertise(const AdvertiseConfig());
        }
      });

  Future<void> _toggleAuto() => _run((c) async {
        if (_state.isScanning || _state.isAdvertising) {
          await c.stopAuto();
        } else {
          await _ensureEventJoined(c);
          await c.startAuto(const AutoConfig());
        }
      });

  Future<void> _exportTek() async {
    final BarnardBleClient? client = _client;
    if (client == null) return;
    try {
      final Uint8List tek = await client.exportCurrentTek();
      final String hex = bytesToHex(tek);
      _messengerKey.currentState?.showSnackBar(SnackBar(
        content: Text("TEK (hex): $hex",
            maxLines: 2, overflow: TextOverflow.ellipsis),
        duration: const Duration(seconds: 8),
        action: SnackBarAction(
          label: "Copy",
          onPressed: () async {
            await _copyToClipboard(hex);
          },
        ),
      ));
    } catch (e, stack) {
      debugPrint("exportCurrentTek failed: $e\n$stack");
      _messengerKey.currentState?.showSnackBar(
        SnackBar(content: Text("exportCurrentTek failed: $e")),
      );
    }
  }

  Future<void> _copyToClipboard(String value) async {
    await Clipboard.setData(ClipboardData(text: value));
    _messengerKey.currentState?.showSnackBar(
      const SnackBar(content: Text("TEK copied to clipboard")),
    );
  }

  void _showMessage(String message) {
    _messengerKey.currentState?.showSnackBar(
      SnackBar(content: Text(message), duration: const Duration(seconds: 2)),
    );
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      scaffoldMessengerKey: _messengerKey,
      theme: ThemeData(
        useMaterial3: true,
        colorSchemeSeed: Colors.deepPurple,
        visualDensity: VisualDensity.compact,
      ),
      home: DefaultTabController(
        length: 4,
        child: Scaffold(
          appBar: AppBar(
            title: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment:
                  Platform.isIOS || Platform.isMacOS
                      ? CrossAxisAlignment.center
                      : CrossAxisAlignment.start,
              children: <Widget>[
                const Text("barnard"),
                Text(
                  "v2 protocol · B003 = SHA256(TEK)[0:4]",
                  style: TextStyle(
                    fontSize: 11,
                    fontWeight: FontWeight.w400,
                    color: Theme.of(context)
                        .colorScheme
                        .onSurfaceVariant
                        .withValues(alpha: 0.8),
                  ),
                ),
              ],
            ),
            bottom: const TabBar(
              isScrollable: true,
              tabs: <Widget>[
                Tab(icon: Icon(Icons.timeline), text: "Timeline"),
                Tab(icon: Icon(Icons.radar), text: "Events"),
                Tab(icon: Icon(Icons.bug_report), text: "Debug"),
                Tab(icon: Icon(Icons.tune), text: "Diagnostics"),
              ],
            ),
          ),
          body: _client == null
              ? const Center(child: CircularProgressIndicator())
              : Column(
                  children: <Widget>[
                    _IdentityCard(
                      state: _state,
                      myDisplayId: _client!.myDisplayId,
                      enin: _client!.currentEnin,
                      eventCode: _client!.currentEventCode,
                    ),
                    _ControlPanel(
                      eventCodeController: _eventCodeController,
                      state: _state,
                      busy: _busy,
                      onToggleScan: _toggleScan,
                      onToggleAdvertise: _toggleAdvertise,
                      onToggleAuto: _toggleAuto,
                      onExportTek: _exportTek,
                    ),
                    const Divider(height: 1),
                    Expanded(
                      child: TabBarView(children: <Widget>[
                        _TimelineTab(
                          tracks: _tracks,
                          scanOnlyTracks: _scanOnlyTracks,
                          totalDetections: _totalDetections,
                          totalRssiUpdates: _totalRssiUpdates,
                          onClear: (_tracks.isEmpty && _scanOnlyTracks.isEmpty)
                              ? null
                              : () => setState(() {
                                    _tracks.clear();
                                    _scanOnlyTracks.clear();
                                  }),
                        ),
                        _EventsTab(
                          events: _events,
                          totalEvents: _totalEvents,
                          totalDetections: _totalDetections,
                          totalRssiUpdates: _totalRssiUpdates,
                          totalIssues: _totalIssues,
                          onlyDetections: _eventsOnlyDetections,
                          onlyIssues: _eventsOnlyIssues,
                          seenById: _seenById,
                          onOnlyDetectionsChanged: (v) =>
                              setState(() => _eventsOnlyDetections = v),
                          onOnlyIssuesChanged: (v) =>
                              setState(() => _eventsOnlyIssues = v),
                          onClear: _events.isEmpty
                              ? null
                              : () => setState(_events.clear),
                        ),
                        _DebugTab(
                          events: _debugEvents,
                          deviceLabel: _selfInfo.localName ?? _localName,
                          onlyIssues: _debugOnlyIssues,
                          hideTrace: _debugHideTrace,
                          query: _debugQuery,
                          onOnlyIssuesChanged: (v) =>
                              setState(() => _debugOnlyIssues = v),
                          onHideTraceChanged: (v) =>
                              setState(() => _debugHideTrace = v),
                          onQueryChanged: (v) =>
                              setState(() => _debugQuery = v.trim()),
                          onClear: _debugEvents.isEmpty
                              ? null
                              : () => setState(_debugEvents.clear),
                          showMessage: _showMessage,
                        ),
                        _DiagnosticsTab(
                          state: _state,
                          selfInfo: _selfInfo,
                          seen: _seenById.values.toList()
                            ..sort((a, b) =>
                                b.lastSeen.compareTo(a.lastSeen)),
                          staleAfter: _staleAfter,
                          serviceUuid: _serviceUuid,
                          defaultLocalName: _localName,
                          totalEvents: _totalEvents,
                          totalDetections: _totalDetections,
                          totalRssiUpdates: _totalRssiUpdates,
                          totalDebug: _totalDebug,
                          debugIssues: _totalDebugIssues,
                        ),
                      ]),
                    ),
                  ],
                ),
        ),
      ),
    );
  }

  void _pushScanOnlySample(BarnardDebugEvent e) {
    final Map<String, Object?>? data = e.data;
    if (data == null) return;
    final String? id = data["id"] as String?;
    final int? rssi = _asInt(data["rssi"]);
    if (id == null || rssi == null) return;
    final _PeerTrack track = _scanOnlyTracks.putIfAbsent(id, () => _PeerTrack());
    final String? name = data["name"] as String?;
    if (name != null && name.isNotEmpty) {
      track.localName = name;
    }
    track.samples.add(_TrackSample(
      at: e.timestamp,
      rssi: rssi,
      kind: _TrackKind.scanOnly,
    ));
    final DateTime cutoff = e.timestamp.subtract(const Duration(minutes: 5));
    while (track.samples.isNotEmpty && track.samples.first.at.isBefore(cutoff)) {
      track.samples.removeAt(0);
    }
    if (_scanOnlyTracks.length > 16) {
      final List<MapEntry<String, _PeerTrack>> entries =
          _scanOnlyTracks.entries.toList(growable: false)
            ..sort((a, b) {
              final DateTime aT = a.value.samples.isEmpty
                  ? DateTime.fromMillisecondsSinceEpoch(0)
                  : a.value.samples.last.at;
              final DateTime bT = b.value.samples.isEmpty
                  ? DateTime.fromMillisecondsSinceEpoch(0)
                  : b.value.samples.last.at;
              return aT.compareTo(bT);
            });
      _scanOnlyTracks.remove(entries.first.key);
    }
  }

  void _pushTrackSample(
    Uint8List rpid,
    DateTime at,
    int rssi,
    _TrackKind kind, {
    String? detectedDisplayId,
  }) {
    final String key = base64UrlEncode(rpid);
    final _PeerTrack track = _tracks.putIfAbsent(key, () => _PeerTrack());
    if (detectedDisplayId != null && detectedDisplayId.isNotEmpty) {
      track.detectedDisplayId = detectedDisplayId;
    }
    track.samples.add(_TrackSample(at: at, rssi: rssi, kind: kind));
    // Keep only last 5 minutes of samples per peer.
    final DateTime cutoff = at.subtract(const Duration(minutes: 5));
    while (track.samples.isNotEmpty && track.samples.first.at.isBefore(cutoff)) {
      track.samples.removeAt(0);
    }
    if (_tracks.length > 16) {
      // Evict the track with the oldest last sample.
      final List<MapEntry<String, _PeerTrack>> entries =
          _tracks.entries.toList(growable: false)
            ..sort((a, b) {
              final DateTime aT = a.value.samples.isEmpty
                  ? DateTime.fromMillisecondsSinceEpoch(0)
                  : a.value.samples.last.at;
              final DateTime bT = b.value.samples.isEmpty
                  ? DateTime.fromMillisecondsSinceEpoch(0)
                  : b.value.samples.last.at;
              return aT.compareTo(bT);
            });
      _tracks.remove(entries.first.key);
    }
  }

  void _updateSeen(DetectionEvent e) {
    final String key = base64UrlEncode(e.rpid);
    final _SeenEntry existing = _seenById[key] ?? _SeenEntry();
    existing.lastSeen = e.timestamp;
    existing.lastRssi = e.rssi;
    existing.lastEnin = e.enin;
    if (e.detectedDisplayId != null && e.detectedDisplayId!.isNotEmpty) {
      existing.detectedDisplayId = e.detectedDisplayId;
    }
    if (e.debugLocalName != null && e.debugLocalName!.isNotEmpty) {
      existing.debugLocalName = e.debugLocalName!;
    }
    existing.count += 1;
    _seenById[key] = existing;
    if (_seenById.length > 50) {
      final List<MapEntry<String, _SeenEntry>> entries =
          _seenById.entries.toList(growable: false)
            ..sort((a, b) => a.value.lastSeen.compareTo(b.value.lastSeen));
      final int removeCount = _seenById.length - 50;
      for (int i = 0; i < removeCount; i++) {
        _seenById.remove(entries[i].key);
      }
    }
  }

  void _updateSelfInfo(BarnardDebugEvent e) {
    final Map<String, Object?>? data = e.data;
    if (data == null) return;
    if (e.name == "advertise_start") {
      _selfInfo.formatVersion =
          _asInt(data["formatVersion"]) ?? _selfInfo.formatVersion;
      _selfInfo.serviceUuid =
          data["serviceUuid"] as String? ?? _selfInfo.serviceUuid;
      _selfInfo.localName =
          data["localName"] as String? ?? _selfInfo.localName;
    } else if (e.name == "gatt_respond_rpid") {
      _selfInfo.formatVersion =
          _asInt(data["formatVersion"]) ?? _selfInfo.formatVersion;
      _selfInfo.lastPayloadAt = e.timestamp;
    } else if (e.name == "advertise_stop") {
      _selfInfo.lastPayloadAt = null;
    }
  }

  int? _asInt(Object? v) {
    if (v is int) return v;
    if (v is num) return v.toInt();
    if (v is String) return int.tryParse(v);
    return null;
  }
}

class _IdentityCard extends StatelessWidget {
  const _IdentityCard({
    required this.state,
    required this.myDisplayId,
    required this.enin,
    required this.eventCode,
  });

  final BarnardState state;
  final String myDisplayId;
  final int enin;
  final String? eventCode;

  @override
  Widget build(BuildContext context) {
    final ColorScheme cs = Theme.of(context).colorScheme;
    return Container(
      padding: const EdgeInsets.fromLTRB(12, 8, 12, 8),
      decoration: BoxDecoration(
        color: cs.surfaceContainerLowest,
        border: Border(
          bottom: BorderSide(color: cs.outlineVariant),
        ),
      ),
      child: Row(
        children: <Widget>[
          _StateIcon(
            icon: Icons.radar,
            active: state.isScanning,
            tooltip: state.isScanning ? "Scanning" : "Not scanning",
          ),
          const SizedBox(width: 8),
          _StateIcon(
            icon: Icons.cell_tower,
            active: state.isAdvertising,
            tooltip: state.isAdvertising ? "Advertising" : "Not advertising",
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: <Widget>[
                Text(
                  myDisplayId,
                  style: const TextStyle(
                    fontFamily: "Menlo",
                    fontSize: 16,
                    fontWeight: FontWeight.w600,
                    letterSpacing: 0.5,
                  ),
                ),
                const SizedBox(height: 2),
                Text(
                  "enin $enin  ${eventCode == null ? "(no event)" : "event=$eventCode"}",
                  style: TextStyle(color: cs.onSurfaceVariant, fontSize: 12),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _StateIcon extends StatelessWidget {
  const _StateIcon({required this.icon, required this.active, required this.tooltip});

  final IconData icon;
  final bool active;
  final String tooltip;

  @override
  Widget build(BuildContext context) {
    final ColorScheme cs = Theme.of(context).colorScheme;
    return Tooltip(
      message: tooltip,
      child: Container(
        width: 34,
        height: 34,
        decoration: BoxDecoration(
          color: active ? cs.primary : cs.surfaceContainerHighest,
          borderRadius: BorderRadius.circular(10),
        ),
        child: Icon(
          icon,
          size: 18,
          color: active ? cs.onPrimary : cs.onSurfaceVariant,
        ),
      ),
    );
  }
}

class _ControlPanel extends StatelessWidget {
  const _ControlPanel({
    required this.eventCodeController,
    required this.state,
    required this.busy,
    required this.onToggleScan,
    required this.onToggleAdvertise,
    required this.onToggleAuto,
    required this.onExportTek,
  });

  final TextEditingController eventCodeController;
  final BarnardState state;
  final bool busy;
  final VoidCallback onToggleScan;
  final VoidCallback onToggleAdvertise;
  final VoidCallback onToggleAuto;
  final VoidCallback onExportTek;

  @override
  Widget build(BuildContext context) {
    final bool autoRunning = state.isScanning || state.isAdvertising;
    return Padding(
      padding: const EdgeInsets.fromLTRB(12, 8, 12, 8),
      child: Column(
        children: <Widget>[
          Row(
            children: <Widget>[
              Expanded(
                child: TextField(
                  controller: eventCodeController,
                  enabled: !autoRunning,
                  decoration: const InputDecoration(
                    labelText: "Event Code",
                    isDense: true,
                    border: OutlineInputBorder(),
                    helperText: "Auto-join on Start",
                    helperMaxLines: 1,
                  ),
                ),
              ),
              const SizedBox(width: 8),
              FilledButton.tonalIcon(
                onPressed: busy ? null : onExportTek,
                icon: const Icon(Icons.key, size: 18),
                label: const Text("Export TEK"),
              ),
            ],
          ),
          const SizedBox(height: 8),
          _PrimaryActionButton(
            state: state,
            busy: busy,
            onToggleAuto: onToggleAuto,
            onToggleScan: onToggleScan,
            onToggleAdvertise: onToggleAdvertise,
          ),
        ],
      ),
    );
  }
}

/// Split button: the large primary half toggles Start/Stop Auto (scan +
/// advertise), and the attached dropdown exposes the individual Scan-only
/// and Advertise-only toggles for granular control.
class _PrimaryActionButton extends StatelessWidget {
  const _PrimaryActionButton({
    required this.state,
    required this.busy,
    required this.onToggleAuto,
    required this.onToggleScan,
    required this.onToggleAdvertise,
  });

  final BarnardState state;
  final bool busy;
  final VoidCallback onToggleAuto;
  final VoidCallback onToggleScan;
  final VoidCallback onToggleAdvertise;

  @override
  Widget build(BuildContext context) {
    final ColorScheme cs = Theme.of(context).colorScheme;
    final bool autoRunning = state.isScanning || state.isAdvertising;
    final Color bg = autoRunning ? cs.error : cs.primary;
    final Color fg = autoRunning ? cs.onError : cs.onPrimary;
    final VoidCallback? primaryOnTap = busy ? null : onToggleAuto;
    return SizedBox(
      height: 44,
      child: Row(
        mainAxisSize: MainAxisSize.max,
        children: <Widget>[
          Expanded(
            child: Material(
              color: bg,
              borderRadius: const BorderRadius.only(
                topLeft: Radius.circular(22),
                bottomLeft: Radius.circular(22),
              ),
              child: InkWell(
                onTap: primaryOnTap,
                borderRadius: const BorderRadius.only(
                  topLeft: Radius.circular(22),
                  bottomLeft: Radius.circular(22),
                ),
                child: Center(
                  child: Row(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: <Widget>[
                      Icon(autoRunning ? Icons.stop_circle : Icons.sync,
                          size: 18, color: fg),
                      const SizedBox(width: 8),
                      Text(
                        autoRunning ? "Stop Auto" : "Start Auto",
                        style: TextStyle(
                            color: fg,
                            fontWeight: FontWeight.w600,
                            fontSize: 14),
                      ),
                      if (autoRunning) ...<Widget>[
                        const SizedBox(width: 8),
                        _StatusDot(
                          active: state.isScanning,
                          icon: Icons.radar,
                          tooltip: "Scan",
                          foreground: fg,
                        ),
                        const SizedBox(width: 4),
                        _StatusDot(
                          active: state.isAdvertising,
                          icon: Icons.cell_tower,
                          tooltip: "Advertise",
                          foreground: fg,
                        ),
                      ],
                    ],
                  ),
                ),
              ),
            ),
          ),
          Container(
            width: 1,
            height: 44,
            color: fg.withValues(alpha: 0.25),
          ),
          Material(
            color: bg,
            borderRadius: const BorderRadius.only(
              topRight: Radius.circular(22),
              bottomRight: Radius.circular(22),
            ),
            child: PopupMenuButton<_ControlMenuAction>(
              tooltip: "Scan / Advertise only",
              enabled: !busy,
              onSelected: (action) {
                switch (action) {
                  case _ControlMenuAction.toggleScan:
                    onToggleScan();
                    break;
                  case _ControlMenuAction.toggleAdvertise:
                    onToggleAdvertise();
                    break;
                }
              },
              itemBuilder: (context) => <PopupMenuEntry<_ControlMenuAction>>[
                PopupMenuItem<_ControlMenuAction>(
                  value: _ControlMenuAction.toggleScan,
                  child: _MenuRow(
                    icon: state.isScanning ? Icons.stop : Icons.radar,
                    text: state.isScanning ? "Stop Scan" : "Start Scan only",
                  ),
                ),
                PopupMenuItem<_ControlMenuAction>(
                  value: _ControlMenuAction.toggleAdvertise,
                  child: _MenuRow(
                    icon: state.isAdvertising ? Icons.stop : Icons.cell_tower,
                    text: state.isAdvertising
                        ? "Stop Advertise"
                        : "Start Advertise only",
                  ),
                ),
              ],
              child: Container(
                width: 44,
                height: 44,
                alignment: Alignment.center,
                decoration: BoxDecoration(
                  borderRadius: const BorderRadius.only(
                    topRight: Radius.circular(22),
                    bottomRight: Radius.circular(22),
                  ),
                ),
                child: Icon(Icons.arrow_drop_down, color: fg),
              ),
            ),
          ),
        ],
      ),
    );
  }
}

enum _ControlMenuAction { toggleScan, toggleAdvertise }

class _StatusDot extends StatelessWidget {
  const _StatusDot({
    required this.active,
    required this.icon,
    required this.tooltip,
    required this.foreground,
  });

  final bool active;
  final IconData icon;
  final String tooltip;
  final Color foreground;

  @override
  Widget build(BuildContext context) {
    return Tooltip(
      message: "$tooltip ${active ? "ON" : "OFF"}",
      child: Opacity(
        opacity: active ? 1.0 : 0.4,
        child: Icon(icon, size: 14, color: foreground),
      ),
    );
  }
}

class _MenuRow extends StatelessWidget {
  const _MenuRow({required this.icon, required this.text});

  final IconData icon;
  final String text;

  @override
  Widget build(BuildContext context) {
    return Row(
      children: <Widget>[
        Icon(icon, size: 18),
        const SizedBox(width: 10),
        Text(text),
      ],
    );
  }
}

class _EventsTab extends StatelessWidget {
  const _EventsTab({
    required this.events,
    required this.totalEvents,
    required this.totalDetections,
    required this.totalRssiUpdates,
    required this.totalIssues,
    required this.onlyDetections,
    required this.onlyIssues,
    required this.seenById,
    required this.onOnlyDetectionsChanged,
    required this.onOnlyIssuesChanged,
    required this.onClear,
  });

  final List<BarnardEvent> events;
  final int totalEvents;
  final int totalDetections;
  final int totalRssiUpdates;
  final int totalIssues;
  final bool onlyDetections;
  final bool onlyIssues;
  final Map<String, _SeenEntry> seenById;
  final ValueChanged<bool> onOnlyDetectionsChanged;
  final ValueChanged<bool> onOnlyIssuesChanged;
  final VoidCallback? onClear;

  @override
  Widget build(BuildContext context) {
    final DateTime now = DateTime.now();
    final List<BarnardEvent> filtered = events.where((e) {
      if (onlyDetections && e is! DetectionEvent) return false;
      if (onlyIssues && e is! ConstraintEvent && e is! ErrorEvent) return false;
      return true;
    }).toList(growable: false);
    return Column(
      children: <Widget>[
        _FilterBar(
          children: <Widget>[
            Text(
              "total $totalEvents · det $totalDetections · rssi $totalRssiUpdates · iss $totalIssues",
              style: Theme.of(context).textTheme.bodySmall,
            ),
            const Spacer(),
            FilterChip(
              label: const Text("Detections"),
              selected: onlyDetections,
              onSelected: onOnlyDetectionsChanged,
            ),
            const SizedBox(width: 4),
            FilterChip(
              label: const Text("Issues"),
              selected: onlyIssues,
              onSelected: onOnlyIssuesChanged,
            ),
            const SizedBox(width: 4),
            IconButton(
              onPressed: onClear,
              icon: const Icon(Icons.clear_all, size: 20),
              tooltip: "Clear events",
            ),
          ],
        ),
        Expanded(
          child: ListView.builder(
            itemCount: filtered.length,
            itemBuilder: (BuildContext context, int index) {
              final BarnardEvent e = filtered[filtered.length - 1 - index];
              return _EventTile(event: e, now: now, seenById: seenById);
            },
          ),
        ),
      ],
    );
  }
}

class _EventTile extends StatelessWidget {
  const _EventTile({
    required this.event,
    required this.now,
    required this.seenById,
  });

  final BarnardEvent event;
  final DateTime now;
  final Map<String, _SeenEntry> seenById;

  @override
  Widget build(BuildContext context) {
    final BarnardEvent e = event;
    final String ts = _hms(e.timestamp);
    final Duration age = now.difference(e.timestamp);
    final String ageText = " · ${age.inSeconds}s ago";
    if (e is DetectionEvent) {
      final String rpidKey = base64UrlEncode(e.rpid);
      final _SeenEntry? latest = seenById[rpidKey];
      final bool isActive = latest != null &&
          now.difference(latest.lastSeen) <= _MyAppState._staleAfter;
      final String displayLabel = e.detectedDisplayId ?? "(no B003)";
      return ListTile(
        dense: true,
        leading: Icon(Icons.wifi_tethering,
            size: 18, color: isActive ? Colors.green : null),
        title: Text("$ts  detection  $displayLabel · rssi ${e.rssi} · enin ${e.enin}"),
        subtitle: Text(
            "${e.transport.name} · rpid ${_shortHex(e.rpid)} · reporter ${_shortHex(e.reporterRpid)}$ageText"),
      );
    }
    if (e is RssiUpdateEvent) {
      return ListTile(
        dense: true,
        leading: const Icon(Icons.signal_cellular_alt, size: 18, color: Colors.blueGrey),
        title: Text(
            "$ts  rssi_update  ${e.detectedDisplayId ?? "(no B003)"} · ${e.rssi} dBm"),
        subtitle: Text("rpid ${_shortHex(e.rpid)}$ageText"),
      );
    }
    if (e is StateEvent) {
      return ListTile(
        dense: true,
        leading: const Icon(Icons.tune, size: 18),
        title: Text(
            "$ts  state  scan=${e.state.isScanning} adv=${e.state.isAdvertising}"),
        subtitle: Text("reason=${e.reasonCode ?? "-"}$ageText"),
      );
    }
    if (e is ConstraintEvent) {
      return ListTile(
        dense: true,
        leading: const Icon(Icons.warning_amber, size: 18, color: Colors.orange),
        title: Text("$ts  constraint  ${e.code}"),
        subtitle: Text("${e.message ?? "-"}$ageText"),
      );
    }
    if (e is ErrorEvent) {
      return ListTile(
        dense: true,
        leading: const Icon(Icons.error, size: 18, color: Colors.red),
        title: Text("$ts  error  ${e.code}"),
        subtitle: Text("${e.message}$ageText"),
      );
    }
    return ListTile(
      dense: true,
      title: Text("$ts  ${e.runtimeType}"),
    );
  }
}

String _hms(DateTime t) {
  final DateTime local = t.toLocal();
  String pad(int n, [int width = 2]) => n.toString().padLeft(width, "0");
  return "${pad(local.hour)}:${pad(local.minute)}:${pad(local.second)}.${pad(local.millisecond, 3)}";
}

class _DebugTab extends StatelessWidget {
  const _DebugTab({
    required this.events,
    required this.deviceLabel,
    required this.onlyIssues,
    required this.hideTrace,
    required this.query,
    required this.onOnlyIssuesChanged,
    required this.onHideTraceChanged,
    required this.onQueryChanged,
    required this.onClear,
    required this.showMessage,
  });

  final List<BarnardDebugEvent> events;
  final String deviceLabel;
  final bool onlyIssues;
  final bool hideTrace;
  final String query;
  final ValueChanged<bool> onOnlyIssuesChanged;
  final ValueChanged<bool> onHideTraceChanged;
  final ValueChanged<String> onQueryChanged;
  final VoidCallback? onClear;
  final ValueChanged<String> showMessage;

  Future<void> _copyFiltered(List<BarnardDebugEvent> filtered) async {
    final StringBuffer buf = StringBuffer();
    buf.writeln(
        "# barnard debug · $deviceLabel · ${filtered.length} events");
    for (final BarnardDebugEvent e in filtered) {
      buf.write(e.timestamp.toIso8601String());
      buf.write("\t");
      buf.write(e.level.name);
      buf.write("\t");
      buf.write(e.name);
      if (e.data != null) {
        buf.write("\t");
        buf.write(e.data);
      }
      buf.writeln();
    }
    await Clipboard.setData(ClipboardData(text: buf.toString()));
    showMessage("Copied ${filtered.length} debug events");
  }

  @override
  Widget build(BuildContext context) {
    final String needle = query.toLowerCase();
    final int issueCount = events
        .where((e) =>
            e.level == DebugLevel.warn || e.level == DebugLevel.error)
        .length;
    final List<BarnardDebugEvent> filtered = events.where((e) {
      if (hideTrace && e.level == DebugLevel.trace) return false;
      if (onlyIssues &&
          e.level != DebugLevel.warn &&
          e.level != DebugLevel.error) {
        return false;
      }
      if (needle.isEmpty) return true;
      return e.name.toLowerCase().contains(needle);
    }).toList(growable: false);
    return Column(
      children: <Widget>[
        _FilterBar(
          children: <Widget>[
            Text("${events.length} total • $issueCount issues",
                style: Theme.of(context).textTheme.bodySmall),
            const Spacer(),
            FilterChip(
              label: const Text("Issues"),
              selected: onlyIssues,
              onSelected: onOnlyIssuesChanged,
            ),
            const SizedBox(width: 4),
            FilterChip(
              label: const Text("Hide trace"),
              selected: hideTrace,
              onSelected: onHideTraceChanged,
            ),
            const SizedBox(width: 4),
            IconButton(
              onPressed: filtered.isEmpty
                  ? null
                  : () => _copyFiltered(filtered),
              icon: const Icon(Icons.copy_all, size: 20),
              tooltip: "Copy filtered events",
            ),
            IconButton(
              onPressed: onClear,
              icon: const Icon(Icons.clear_all, size: 20),
              tooltip: "Clear debug",
            ),
          ],
        ),
        Padding(
          padding: const EdgeInsets.fromLTRB(12, 0, 12, 4),
          child: TextField(
            decoration: const InputDecoration(
              hintText: "Filter by name",
              isDense: true,
              prefixIcon: Icon(Icons.search, size: 18),
              border: OutlineInputBorder(),
            ),
            onChanged: onQueryChanged,
          ),
        ),
        Expanded(
          child: ListView.builder(
            itemCount: filtered.length,
            itemBuilder: (BuildContext context, int index) {
              final BarnardDebugEvent e = filtered[filtered.length - 1 - index];
              final Color? color = switch (e.level) {
                DebugLevel.error => Colors.red,
                DebugLevel.warn => Colors.orange,
                _ => null,
              };
              final String data = e.data == null ? "" : " data=${e.data}";
              return ListTile(
                dense: true,
                leading: Icon(
                  e.level == DebugLevel.error
                      ? Icons.error
                      : e.level == DebugLevel.warn
                          ? Icons.warning_amber
                          : Icons.bug_report,
                  size: 18,
                  color: color,
                ),
                title: Text("${e.level.name} ${e.name}",
                    style: TextStyle(color: color)),
                subtitle: Text("${e.timestamp.toIso8601String()}$data"),
              );
            },
          ),
        ),
      ],
    );
  }
}

class _DiagnosticsTab extends StatelessWidget {
  const _DiagnosticsTab({
    required this.state,
    required this.selfInfo,
    required this.seen,
    required this.staleAfter,
    required this.serviceUuid,
    required this.defaultLocalName,
    required this.totalEvents,
    required this.totalDetections,
    required this.totalRssiUpdates,
    required this.totalDebug,
    required this.debugIssues,
  });

  final BarnardState state;
  final _SelfAdvertiseInfo selfInfo;
  final List<_SeenEntry> seen;
  final Duration staleAfter;
  final String serviceUuid;
  final String defaultLocalName;
  final int totalEvents;
  final int totalDetections;
  final int totalRssiUpdates;
  final int totalDebug;
  final int debugIssues;

  @override
  Widget build(BuildContext context) {
    final DateTime now = DateTime.now();
    final bool hasPayload = selfInfo.lastPayloadAt != null;
    final Duration? age =
        hasPayload ? now.difference(selfInfo.lastPayloadAt!) : null;
    final bool isStale = age != null && age > staleAfter;
    return ListView(
      padding: const EdgeInsets.all(12),
      children: <Widget>[
        Card(
          child: Padding(
            padding: const EdgeInsets.all(12),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: <Widget>[
                _sectionHeader(context, "Self advertise"),
                const SizedBox(height: 8),
                _kv("Advertising", state.isAdvertising ? "ON" : "OFF"),
                _kv("Local Name", selfInfo.localName ?? defaultLocalName),
                _kv("Service UUID", selfInfo.serviceUuid ?? serviceUuid,
                    monospace: true, softWrap: true),
                _kv("Format Version", "${selfInfo.formatVersion ?? 1}"),
                _kv(
                  "Last B002 read",
                  state.isAdvertising
                      ? (hasPayload
                          ? "${age!.inSeconds}s ago${isStale ? " (STALE)" : ""}"
                          : "never")
                      : "—",
                ),
              ],
            ),
          ),
        ),
        const SizedBox(height: 12),
        Card(
          child: Padding(
            padding: const EdgeInsets.all(12),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: <Widget>[
                _sectionHeader(context,
                    "Recently seen (stale > ${staleAfter.inSeconds}s)"),
                const SizedBox(height: 8),
                if (seen.isEmpty)
                  Text("No detections yet",
                      style: TextStyle(
                          color: Theme.of(context).colorScheme.onSurfaceVariant)),
                for (final _SeenEntry e in seen.take(10))
                  _SeenRow(entry: e, now: now, staleAfter: staleAfter),
              ],
            ),
          ),
        ),
        const SizedBox(height: 12),
        Card(
          child: Padding(
            padding: const EdgeInsets.all(12),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: <Widget>[
                _sectionHeader(context, "Counters (monotonic)"),
                const SizedBox(height: 8),
                _kv("total events", "$totalEvents"),
                _kv("detections", "$totalDetections"),
                _kv("rssi updates", "$totalRssiUpdates"),
                _kv("debug events", "$totalDebug"),
                _kv("debug issues", "$debugIssues"),
              ],
            ),
          ),
        ),
      ],
    );
  }

  static Widget _sectionHeader(BuildContext context, String text) {
    return Text(text,
        style: Theme.of(context)
            .textTheme
            .titleSmall
            ?.copyWith(fontWeight: FontWeight.w600));
  }

  static Widget _kv(String k, String v,
      {bool monospace = false, bool softWrap = false}) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 2),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: <Widget>[
          SizedBox(
            width: 110,
            child: Text(k,
                style: const TextStyle(color: Colors.black54, fontSize: 12)),
          ),
          Expanded(
            child: Text(
              v,
              softWrap: softWrap,
              overflow: softWrap ? null : TextOverflow.ellipsis,
              style: TextStyle(
                fontSize: 13,
                fontFamily: monospace ? "Menlo" : null,
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _SeenRow extends StatelessWidget {
  const _SeenRow({required this.entry, required this.now, required this.staleAfter});

  final _SeenEntry entry;
  final DateTime now;
  final Duration staleAfter;

  @override
  Widget build(BuildContext context) {
    final Duration age = now.difference(entry.lastSeen);
    final bool isStale = age > staleAfter;
    final Color color = isStale ? Colors.orange : Colors.green;
    final String displayLabel = entry.detectedDisplayId ?? "(no B003)";
    final String nameLabel =
        entry.debugLocalName == null ? "" : " · ${entry.debugLocalName}";
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        children: <Widget>[
          Container(
            width: 8,
            height: 8,
            decoration: BoxDecoration(
              color: color,
              shape: BoxShape.circle,
            ),
          ),
          const SizedBox(width: 8),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: <Widget>[
                Text(
                  "$displayLabel$nameLabel",
                  style: const TextStyle(
                      fontFamily: "Menlo", fontSize: 13, fontWeight: FontWeight.w600),
                ),
                Text(
                  "enin ${entry.lastEnin} · rssi ${entry.lastRssi} · ${age.inSeconds}s ago · ${entry.count} obs",
                  style: const TextStyle(fontSize: 11, color: Colors.black54),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _FilterBar extends StatelessWidget {
  const _FilterBar({required this.children});
  final List<Widget> children;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(12, 4, 12, 4),
      child: Row(children: children),
    );
  }
}

enum _TrackKind { detection, rssiUpdate, scanOnly }

class _TrackSample {
  _TrackSample({required this.at, required this.rssi, required this.kind});
  final DateTime at;
  final int rssi;
  final _TrackKind kind;
}

class _PeerTrack {
  String? detectedDisplayId;
  String? localName;
  final List<_TrackSample> samples = <_TrackSample>[];
}

class _TimelineTab extends StatelessWidget {
  const _TimelineTab({
    required this.tracks,
    required this.scanOnlyTracks,
    required this.totalDetections,
    required this.totalRssiUpdates,
    required this.onClear,
  });

  final Map<String, _PeerTrack> tracks;
  final Map<String, _PeerTrack> scanOnlyTracks;
  final int totalDetections;
  final int totalRssiUpdates;
  final VoidCallback? onClear;

  static const Duration _window = Duration(seconds: 60);
  // Window used for the per-peer moving-average RSSI that drives sort
  // stability. Larger window = less flicker, slower adjustment.
  static const Duration _avgWindow = Duration(seconds: 10);

  @override
  Widget build(BuildContext context) {
    final DateTime now = DateTime.now();
    final DateTime cutoff = now.subtract(_window);
    final List<_TimelineRow> active = <_TimelineRow>[];
    for (final MapEntry<String, _PeerTrack> e in tracks.entries) {
      final List<_TrackSample> recent =
          e.value.samples.where((s) => s.at.isAfter(cutoff)).toList();
      if (recent.isEmpty) continue;
      final double avg = _avgRssi(e.value.samples, now, _avgWindow);
      active.add(_TimelineRow(
        key: e.key,
        track: e.value,
        avgRssi: avg,
        resolved: true,
      ));
    }
    for (final MapEntry<String, _PeerTrack> e in scanOnlyTracks.entries) {
      final List<_TrackSample> recent =
          e.value.samples.where((s) => s.at.isAfter(cutoff)).toList();
      if (recent.isEmpty) continue;
      final double avg = _avgRssi(e.value.samples, now, _avgWindow);
      active.add(_TimelineRow(
        key: e.key,
        track: e.value,
        avgRssi: avg,
        resolved: false,
      ));
    }
    // Stable ordering: sort by avg RSSI descending (stronger/closer first).
    // Within the same RSSI, sort by key so the order does not flip between
    // frames on high-rate scan updates.
    active.sort((a, b) {
      final int cmp = b.avgRssi.compareTo(a.avgRssi);
      if (cmp != 0) return cmp;
      return a.key.compareTo(b.key);
    });

    final int resolvedCount = active.where((r) => r.resolved).length;
    final int scanOnlyCount = active.length - resolvedCount;

    return Column(
      children: <Widget>[
        _FilterBar(
          children: <Widget>[
            Text(
              "${_window.inSeconds}s · $resolvedCount peer${resolvedCount == 1 ? "" : "s"} · $scanOnlyCount scan · det $totalDetections · rssi $totalRssiUpdates",
              style: Theme.of(context).textTheme.bodySmall,
            ),
            const Spacer(),
            IconButton(
              onPressed: onClear,
              icon: const Icon(Icons.clear_all, size: 20),
              tooltip: "Clear timeline",
            ),
          ],
        ),
        Expanded(
          child: active.isEmpty
              ? Center(
                  child: Padding(
                    padding: const EdgeInsets.all(24),
                    child: Text(
                      "No BLE activity in the last ${_window.inSeconds}s.\nStart scan/advertise to populate.",
                      textAlign: TextAlign.center,
                      style: Theme.of(context).textTheme.bodyMedium,
                    ),
                  ),
                )
              : ListView.builder(
                  padding: const EdgeInsets.fromLTRB(12, 4, 12, 12),
                  itemCount: active.length,
                  itemBuilder: (BuildContext context, int index) {
                    final _TimelineRow row = active[index];
                    return _PeerTrackRow(
                      track: row.track,
                      avgRssi: row.avgRssi,
                      resolved: row.resolved,
                      peripheralId: row.key,
                      now: now,
                      window: _window,
                    );
                  },
                ),
        ),
      ],
    );
  }
}

double _avgRssi(List<_TrackSample> samples, DateTime now, Duration window) {
  final DateTime cutoff = now.subtract(window);
  int n = 0;
  int sum = 0;
  for (final _TrackSample s in samples) {
    if (s.at.isAfter(cutoff)) {
      sum += s.rssi;
      n += 1;
    }
  }
  if (n == 0) return -100.0;
  return sum / n;
}

class _TimelineRow {
  _TimelineRow({
    required this.key,
    required this.track,
    required this.avgRssi,
    required this.resolved,
  });

  final String key;
  final _PeerTrack track;
  final double avgRssi;
  final bool resolved;
}

class _PeerTrackRow extends StatelessWidget {
  const _PeerTrackRow({
    required this.track,
    required this.avgRssi,
    required this.resolved,
    required this.peripheralId,
    required this.now,
    required this.window,
  });

  final _PeerTrack track;
  final double avgRssi;
  final bool resolved;
  final String peripheralId;
  final DateTime now;
  final Duration window;

  @override
  Widget build(BuildContext context) {
    final DateTime cutoff = now.subtract(window);
    final List<_TrackSample> recent =
        track.samples.where((s) => s.at.isAfter(cutoff)).toList();
    final int detections =
        recent.where((s) => s.kind == _TrackKind.detection).length;
    final String primaryLabel = resolved
        ? (track.detectedDisplayId ?? "(no B003)")
        : (track.localName ?? peripheralId);
    final String secondaryLabel = resolved
        ? (track.localName ?? peripheralId)
        : "scan only · awaiting GATT";
    final Color tag = resolved ? Colors.deepPurple : Colors.grey;
    return Card(
      margin: const EdgeInsets.only(bottom: 8),
      child: Padding(
        padding: const EdgeInsets.fromLTRB(12, 8, 12, 10),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: <Widget>[
            Row(
              children: <Widget>[
                Container(
                  width: 10,
                  height: 10,
                  decoration: BoxDecoration(
                      color: tag, shape: BoxShape.circle),
                ),
                const SizedBox(width: 8),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: <Widget>[
                      Text(
                        primaryLabel,
                        overflow: TextOverflow.ellipsis,
                        style: const TextStyle(
                          fontFamily: "Menlo",
                          fontSize: 14,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                      Text(
                        secondaryLabel,
                        overflow: TextOverflow.ellipsis,
                        style: Theme.of(context).textTheme.bodySmall,
                      ),
                    ],
                  ),
                ),
                const SizedBox(width: 8),
                Column(
                  crossAxisAlignment: CrossAxisAlignment.end,
                  children: <Widget>[
                    Text(
                      "${avgRssi.toStringAsFixed(0)}dBm",
                      style: const TextStyle(
                          fontWeight: FontWeight.w600, fontSize: 13),
                    ),
                    Text(
                      "${recent.length} / $detections det",
                      style: Theme.of(context).textTheme.bodySmall,
                    ),
                  ],
                ),
              ],
            ),
            const SizedBox(height: 6),
            SizedBox(
              height: 36,
              child: CustomPaint(
                size: const Size.fromHeight(36),
                painter: _TrackPainter(
                  samples: recent,
                  now: now,
                  window: window,
                ),
                child: const SizedBox.expand(),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _TrackPainter extends CustomPainter {
  _TrackPainter({
    required this.samples,
    required this.now,
    required this.window,
  });

  final List<_TrackSample> samples;
  final DateTime now;
  final Duration window;

  @override
  void paint(Canvas canvas, Size size) {
    final Paint baselinePaint = Paint()
      ..color = const Color(0xFFE0E0E0)
      ..strokeWidth = 1;
    // Baseline at bottom
    canvas.drawLine(
      Offset(0, size.height - 1),
      Offset(size.width, size.height - 1),
      baselinePaint,
    );
    // Vertical gridlines every 10 seconds
    final double secWidth = size.width / window.inSeconds;
    final Paint grid = Paint()
      ..color = const Color(0xFFF0F0F0)
      ..strokeWidth = 1;
    for (int s = 10; s < window.inSeconds; s += 10) {
      final double x = size.width - s * secWidth;
      canvas.drawLine(Offset(x, 0), Offset(x, size.height), grid);
    }

    // Map RSSI (-95..-25) to y coordinate.
    // -25 (strongest) → near top, -95 (weakest) → near bottom.
    double rssiY(int rssi) {
      final double clamped = rssi.clamp(-95, -25).toDouble();
      final double t = (clamped + 95) / 70.0; // 0..1, strong=1
      return size.height - 4 - t * (size.height - 6);
    }

    for (final _TrackSample s in samples) {
      final double dtSeconds = now.difference(s.at).inMilliseconds / 1000.0;
      if (dtSeconds < 0 || dtSeconds > window.inSeconds) continue;
      final double x = size.width - dtSeconds * secWidth;
      final double y = rssiY(s.rssi);
      final Color c;
      final double r;
      switch (s.kind) {
        case _TrackKind.detection:
          c = const Color(0xFF6750A4); // purple
          r = 3.5;
          break;
        case _TrackKind.rssiUpdate:
          c = const Color(0xFF4CAF50); // green
          r = 2;
          break;
        case _TrackKind.scanOnly:
          c = const Color(0xFF9E9E9E); // grey
          r = 1.6;
          break;
      }
      canvas.drawCircle(Offset(x, y), r, Paint()..color = c);
    }
  }

  @override
  bool shouldRepaint(covariant _TrackPainter oldDelegate) =>
      oldDelegate.samples != samples || oldDelegate.now != now;
}

class _SeenEntry {
  _SeenEntry({DateTime? lastSeen})
      : lastSeen = lastSeen ?? DateTime.fromMillisecondsSinceEpoch(0);

  String? detectedDisplayId;
  String? debugLocalName;
  DateTime lastSeen;
  int count = 0;
  int lastRssi = 0;
  int lastEnin = 0;
}

class _SelfAdvertiseInfo {
  int? formatVersion;
  String? serviceUuid;
  String? localName;
  DateTime? lastPayloadAt;
}

String _shortHex(Uint8List bytes) {
  if (bytes.length <= 8) return bytesToHex(bytes);
  final String prefix = bytesToHex(bytes.sublist(0, 3));
  final String suffix = bytesToHex(bytes.sublist(bytes.length - 3));
  return "$prefix…$suffix";
}
