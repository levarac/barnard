import "dart:io";

import "package:test/test.dart";

void main() {
  group("iOS reporter RPID payload cache source invariants", () {
    for (final _SwiftSource source in <_SwiftSource>[
      const _SwiftSource(
        name: "Flutter iOS",
        path: "ios/barnard/Sources/barnard/BarnardRpidGenerator.swift",
        currentPayloadEndMarker: "// MARK: - DeviceSecret Management",
      ),
      const _SwiftSource(
        name: "React Native iOS",
        path: "../../react-native/barnard/ios/BarnardRpidGenerator.swift",
        currentPayloadEndMarker: "private func getOrCreateDeviceSecret()",
      ),
    ]) {
      test("${source.name} returns the cached Data on an ENIN and TEK hit", () {
        final String text = File(source.path).readAsStringSync();
        final String body = _sliceBetween(
          text,
          "func currentPayload(",
          source.currentPayloadEndMarker,
        );

        expect(
          text,
          contains(
            "private var cachedReporterPayload: (enin: UInt32, tekHash: Int, payload: Data)?",
          ),
        );
        expect(body, contains("let tek = currentTek"));
        expect(body, contains("let tekHash = tek.hashValue"));

        final int hitIndex = body.indexOf(
          "if let cached = cachedReporterPayload",
        );
        final int deriveIndex = body.indexOf(
          "BarnardCrypto.deriveRpik(from: tek)",
        );
        expect(hitIndex, isNonNegative);
        expect(deriveIndex, greaterThan(hitIndex));

        final String hitPath = body.substring(hitIndex, deriveIndex);
        expect(hitPath, contains("cached.enin == enin"));
        expect(hitPath, contains("cached.tekHash == tekHash"));
        expect(hitPath, contains("return cached.payload"));
      });

      test("${source.name} stores a newly computed Data after an ENIN miss", () {
        final String text = File(source.path).readAsStringSync();
        final String body = _sliceBetween(
          text,
          "func currentPayload(",
          source.currentPayloadEndMarker,
        );

        final int eninIndex = body.indexOf(
          "let enin = BarnardCrypto.calculateEnin(",
        );
        final int deriveIndex = body.indexOf(
          "BarnardCrypto.deriveRpik(from: tek)",
        );
        final int storeIndex = body.indexOf(
          "cachedReporterPayload = (enin: enin, tekHash: tekHash, payload: payload)",
        );
        final int returnIndex = body.indexOf("return payload");

        expect(eninIndex, isNonNegative);
        expect(deriveIndex, greaterThan(eninIndex));
        expect(storeIndex, greaterThan(deriveIndex));
        expect(returnIndex, greaterThan(storeIndex));
      });
    }
  });
}

String _sliceBetween(String text, String start, String end) {
  final int startIndex = text.indexOf(start);
  expect(startIndex, isNonNegative, reason: "missing start marker: $start");
  final int endIndex = text.indexOf(end, startIndex + start.length);
  expect(endIndex, isNonNegative, reason: "missing end marker: $end");
  return text.substring(startIndex, endIndex);
}

class _SwiftSource {
  const _SwiftSource({
    required this.name,
    required this.path,
    required this.currentPayloadEndMarker,
  });

  final String name;
  final String path;
  final String currentPayloadEndMarker;
}
