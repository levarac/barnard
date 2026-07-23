import Testing
@testable import BarnardAndroidLogicProbe

@Test func cExportPolicyShape() {
  #expect(barnardShouldEmitRssiUpdate(42, 42) == 1)
  #expect(barnardShouldEmitRssiUpdate(42, 43) == 0)
}

@Test func foundationDataAndDateShape() {
  #expect(FoundationProbe.enin(unixSeconds: 900) == 3)
  #expect(FoundationProbe.dataRoundTrip([0x00, 0xab, 0xff]) == "00abff")
}

@Test func secp256k1SourceIsLive() {
  let compressedGenerator = Secp256k1.compress(Secp256k1.G)
  #expect(compressedGenerator.count == 33)
  #expect(compressedGenerator.first == 0x02)
}
