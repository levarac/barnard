import "config.dart";

class BarnardState {
  const BarnardState({
    required this.isScanning,
    required this.isAdvertising,
    this.eninMode = EninMode.fixedLength,
    this.eninSeconds = 300,
    this.beaconChain = BeaconChainConfig.ethereumMainnet,
  });

  static const idle = BarnardState(isScanning: false, isAdvertising: false);

  final bool isScanning;
  final bool isAdvertising;
  final EninMode eninMode;
  final int eninSeconds;
  final BeaconChainConfig beaconChain;

  @override
  String toString() =>
      "BarnardState(isScanning=$isScanning, isAdvertising=$isAdvertising, eninMode=$eninMode, eninSeconds=$eninSeconds, beaconChain=${beaconChain.chainId})";
}
