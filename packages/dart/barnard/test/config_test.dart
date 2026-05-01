import "dart:typed_data";

import "package:barnard/barnard.dart";
import "package:barnard/mock_barnard.dart";
import "package:test/test.dart";

void main() {
  group("ENIN config", () {
    test("BarnardConfig defaults to GAEN-compatible fixed-length ENIN", () {
      const config = BarnardConfig();

      expect(config.eninMode, equals(EninMode.fixedLength));
      expect(config.effectiveEninSeconds, equals(600));
      expect(config.beaconChain, equals(BeaconChainConfig.ethereumMainnet));
    });

    test("BarnardConfig clamps fixed-length ENIN seconds", () {
      const tooShort = BarnardConfig(eninSeconds: 1);
      const tooLong = BarnardConfig(eninSeconds: 7200);

      expect(tooShort.effectiveEninSeconds, equals(12));
      expect(tooLong.effectiveEninSeconds, equals(3600));
    });

    test("BeaconChainConfig validates effective timing parameters", () {
      const config = BeaconChainConfig(
        chainId: "local",
        genesisUnixSeconds: -1,
        slotSeconds: 0,
      );

      expect(config.effectiveGenesisUnixSeconds, equals(0));
      expect(config.effectiveSlotSeconds, equals(1));
    });

    test("MockBarnard surfaces ENIN mode in capabilities and state", () {
      final barnard = MockBarnard(
        config: const BarnardConfig(eninMode: EninMode.beaconSlot),
      );

      expect(barnard.capabilities.eninMode, equals(EninMode.beaconSlot));
      expect(barnard.state.eninMode, equals(EninMode.beaconSlot));
      expect(
        barnard.state.beaconChain,
        equals(BeaconChainConfig.ethereumMainnet),
      );
    });

    test("MockBarnard applies configured event code at creation", () async {
      final barnard = MockBarnard(
        config: const BarnardConfig(eventCode: "CONF-2026"),
        deviceSecret: Uint8List.fromList(List<int>.filled(32, 7)),
      );
      final expectedTek = deriveTek(
        Uint8List.fromList(List<int>.filled(32, 7)),
        "CONF-2026",
      );

      expect(barnard.currentEventCode, equals("CONF-2026"));
      expect(barnard.myDisplayId, equals(displayIdFromTek(expectedTek)));
    });
  });
}
