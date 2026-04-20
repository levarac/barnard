// Copyright 2024-2026 The Greeting Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license.

import "package:barnard/barnard.dart";
import "package:barnard/src/interface_adapter/ble/barnard_ble_client.dart";
import "package:flutter_test/flutter_test.dart";

void main() {
  group("parseBarnardEvent — detection v2", () {
    final Map<Object?, Object?> baseMap = <Object?, Object?>{
      "type": "detection",
      "timestamp": "2026-04-20T10:00:00.000Z",
      "transport": "ble",
      "formatVersion": 1,
      "rpid": "01${"a" * 32}", // 17 bytes
      "reporterRpid": "01${"b" * 32}",
      "detectedDisplayId": "9abcdef0",
      "rssi": -62,
      "enin": 2948599,
      "rssiSummary": <Object?, Object?>{
        "count": 3,
        "min": -70,
        "max": -55,
        "mean": -62.3,
      },
      "payloadRaw": "01${"a" * 32}",
      "debugLocalName": null,
    };

    test("decodes hex fields into Uint8List", () {
      final BarnardEvent event = parseBarnardEvent(baseMap);
      expect(event, isA<DetectionEvent>());
      final DetectionEvent d = event as DetectionEvent;

      expect(d.rpid.length, equals(17));
      expect(d.rpid[0], equals(0x01));
      expect(d.reporterRpid.length, equals(17));
      expect(d.reporterRpid[0], equals(0x01));
      expect(d.detectedDisplayId, equals("9abcdef0"));
      expect(d.enin, equals(2948599));
      expect(d.rssi, equals(-62));
      expect(d.formatVersion, equals(1));
      expect(d.transport, equals(TransportKind.ble));
    });

    test("detectedDisplayId may be null (B003 read failed)", () {
      final Map<Object?, Object?> m = Map<Object?, Object?>.from(baseMap);
      m["detectedDisplayId"] = null;
      final DetectionEvent d = parseBarnardEvent(m) as DetectionEvent;
      expect(d.detectedDisplayId, isNull);
    });

    test("detectedDisplayId absent key is treated as null", () {
      final Map<Object?, Object?> m = Map<Object?, Object?>.from(baseMap);
      m.remove("detectedDisplayId");
      final DetectionEvent d = parseBarnardEvent(m) as DetectionEvent;
      expect(d.detectedDisplayId, isNull);
    });

    test("malformed rpid hex throws FormatException", () {
      final Map<Object?, Object?> m = Map<Object?, Object?>.from(baseMap);
      m["rpid"] = "abc"; // odd length
      expect(() => parseBarnardEvent(m), throwsFormatException);
    });

    test("wrong-length rpid (even hex but not 17 bytes) throws", () {
      final Map<Object?, Object?> m = Map<Object?, Object?>.from(baseMap);
      m["rpid"] = "01" * 16; // 16 bytes, not 17
      expect(() => parseBarnardEvent(m), throwsFormatException);
    });

    test("empty rpid throws", () {
      final Map<Object?, Object?> m = Map<Object?, Object?>.from(baseMap);
      m["rpid"] = "";
      expect(() => parseBarnardEvent(m), throwsFormatException);
    });

    test("wrong-length reporterRpid throws", () {
      final Map<Object?, Object?> m = Map<Object?, Object?>.from(baseMap);
      m["reporterRpid"] = "01" * 10;
      expect(() => parseBarnardEvent(m), throwsFormatException);
    });

    test("malformed detectedDisplayId (not 8 hex chars) throws", () {
      final Map<Object?, Object?> m = Map<Object?, Object?>.from(baseMap);
      m["detectedDisplayId"] = "abc";
      expect(() => parseBarnardEvent(m), throwsFormatException);
    });

    test("uppercase detectedDisplayId rejected (lowercase contract)", () {
      final Map<Object?, Object?> m = Map<Object?, Object?>.from(baseMap);
      m["detectedDisplayId"] = "ABCDEF01";
      expect(() => parseBarnardEvent(m), throwsFormatException);
    });

    test("missing enin defaults to 0", () {
      final Map<Object?, Object?> m = Map<Object?, Object?>.from(baseMap);
      m.remove("enin");
      final DetectionEvent d = parseBarnardEvent(m) as DetectionEvent;
      expect(d.enin, equals(0));
    });

    test("payloadRaw is hex-decoded", () {
      final DetectionEvent d = parseBarnardEvent(baseMap) as DetectionEvent;
      expect(d.payloadRaw, isNotNull);
      expect(d.payloadRaw!.length, equals(17));
      expect(d.payloadRaw![0], equals(0x01));
    });

    test("rssiSummary is parsed when present", () {
      final DetectionEvent d = parseBarnardEvent(baseMap) as DetectionEvent;
      expect(d.rssiSummary, isNotNull);
      expect(d.rssiSummary!.count, equals(3));
      expect(d.rssiSummary!.min, equals(-70));
      expect(d.rssiSummary!.max, equals(-55));
      expect(d.rssiSummary!.mean, closeTo(-62.3, 1e-9));
    });
  });

  group("parseBarnardEvent — rssi_update v2", () {
    test("decodes rpid hex and nullable detectedDisplayId", () {
      final Map<Object?, Object?> map = <Object?, Object?>{
        "type": "rssi_update",
        "timestamp": "2026-04-20T10:00:00.000Z",
        "rpid": "01${"c" * 32}",
        "rssi": -55,
        "detectedDisplayId": "deadbeef",
      };
      final BarnardEvent event = parseBarnardEvent(map);
      expect(event, isA<RssiUpdateEvent>());
      final RssiUpdateEvent u = event as RssiUpdateEvent;
      expect(u.rpid.length, equals(17));
      expect(u.rssi, equals(-55));
      expect(u.detectedDisplayId, equals("deadbeef"));
    });

    test("null detectedDisplayId on scan-only update", () {
      final Map<Object?, Object?> map = <Object?, Object?>{
        "type": "rssi_update",
        "timestamp": "2026-04-20T10:00:00.000Z",
        "rpid": "01${"c" * 32}",
        "rssi": -55,
      };
      final RssiUpdateEvent u = parseBarnardEvent(map) as RssiUpdateEvent;
      expect(u.detectedDisplayId, isNull);
    });
  });

  group("parseBarnardEvent — other event types unchanged", () {
    test("state event parses", () {
      final BarnardEvent event = parseBarnardEvent(<Object?, Object?>{
        "type": "state",
        "timestamp": "2026-04-20T10:00:00.000Z",
        "state": <Object?, Object?>{
          "isScanning": true,
          "isAdvertising": false,
        },
        "reasonCode": "scan_start",
      });
      expect(event, isA<StateEvent>());
      final StateEvent s = event as StateEvent;
      expect(s.state.isScanning, isTrue);
      expect(s.reasonCode, equals("scan_start"));
    });

    test("error event parses", () {
      final BarnardEvent event = parseBarnardEvent(<Object?, Object?>{
        "type": "error",
        "timestamp": "2026-04-20T10:00:00.000Z",
        "code": "scan_failed",
        "message": "unknown",
        "recoverable": true,
      });
      expect(event, isA<ErrorEvent>());
    });
  });
}
