import XCTest
@testable import BarnardCore

final class BarnardParticipantRelayTests: XCTestCase {
  func vectors(_ name: String) throws -> [String: String] {
    let here = URL(fileURLWithPath: #filePath)
    let root = here.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    let text = try String(contentsOf: root.appendingPathComponent("test-vectors/\(name).txt"), encoding: .utf8)
    return Dictionary(uniqueKeysWithValues: text.split(separator: "\n").filter { !$0.hasPrefix("#") && $0.contains("=") }.map { line in
      let pair = line.split(separator: "=", maxSplits: 1); return (String(pair[0]), String(pair[1]))
    })
  }
  final class Clock: BarnardRelayMonotonicClock { var now: Int64 = 0; func relayNowMilliseconds() -> Int64 { now } }
  final class Enin: BarnardRelayEninSource { var value: UInt32? = 10; func relayCurrentEnin() -> UInt32? { value } }
  final class Verifier: BarnardRelayVerifier {
    var result = BarnardRelayVerification.registryVerified(validFromEnin: 10, validThroughEnin: 22, relayExpiresAtEnin: 22)
    func verifyRelayEnvelope(_ bytes: [UInt8], currentEnin: UInt32) -> BarnardRelayVerification { result }
  }
  final class Sink: BarnardRelayOutputSink {
    var served: [[UInt8]] = []; var stops = 0
    func startServingRelayContainer(_ bytes: [UInt8]) { served.append(bytes) }
    func stopServingRelayContainer() { stops += 1 }
  }
  func container(_ hop: UInt8, _ envelope: [UInt8]) -> [UInt8] { [3, hop, UInt8(envelope.count >> 8), UInt8(envelope.count)] + envelope }
  func fixture() -> (BarnardParticipantRelay, Clock, Enin, Verifier, Sink) {
    let c = Clock(), e = Enin(), v = Verifier(), s = Sink()
    return (BarnardParticipantRelay(clock: c, eninSource: e, verifier: v, outputSink: s, randomnessSeedMaterial: [7,8,9]), c,e,v,s)
  }
  func finishContention(_ relay: BarnardParticipantRelay, _ clock: Clock) {
    relay.advance(); clock.now += 15_001; relay.advance()
    if !relay.isServing { clock.now = (clock.now / 30_000 + 1) * 30_000; relay.advance(); clock.now += 15_001; relay.advance() }
  }

  func testHopDedupCopiesEnvelopeAndRetainsLowestHop() {
    let (relay, clock, _, _, sink) = fixture(); let envelope: [UInt8] = [1,2,3,4]
    XCTAssertEqual(relay.observe(container: container(1, envelope), peerHandle: [1]), .accepted)
    XCTAssertEqual(relay.observe(container: container(0, envelope), peerHandle: [2]), .duplicate)
    finishContention(relay, clock)
    XCTAssertEqual(sink.served.last, container(1, envelope)); XCTAssertEqual(sink.served.last.map { Array($0[4...]) }, envelope)
  }
  func testHopTwoNeverServesAndRegistryConfirmationRequired() {
    let (relay, clock, _, verifier, sink) = fixture()
    XCTAssertEqual(relay.observe(container: container(2, [1]), peerHandle: [1]), .accepted); finishContention(relay, clock); XCTAssertTrue(sink.served.isEmpty)
    let other = container(0, [2]); verifier.result = .radioSelfVerified
    XCTAssertEqual(relay.observe(container: other, peerHandle: [2]), .rejected)
  }
  func testPinChoosesCompetingLowestHopAtFiveMinutes() {
    let (relay, clock, _, _, sink) = fixture()
    XCTAssertEqual(relay.observe(container: container(1, [1]), peerHandle: [1]), .accepted)
    XCTAssertEqual(relay.observe(container: container(0, [2]), peerHandle: [2]), .accepted)
    finishContention(relay, clock); XCTAssertEqual(sink.served.last?[1], 2)
    clock.now = 300_001; relay.advance(); clock.now += 15_001; relay.advance()
    XCTAssertEqual(sink.served.last?[1], 1)
  }
  func testEninHalfOpenBoundariesAndTwelveLifetime() {
    for (current, accepted) in [(UInt32(21), true), (22, false), (23, false)] {
      let (relay, _, enin, _, _) = fixture(); enin.value = current
      XCTAssertEqual(relay.observe(container: container(0, [UInt8(current)]), peerHandle: [1]) == .accepted, accepted)
    }
  }
  func testThirtyThreeHandlesSaturateAndCancelContention() {
    let (relay, clock, _, _, sink) = fixture(); let bytes = container(1, [4])
    XCTAssertEqual(relay.observe(container: bytes, peerHandle: [0]), .accepted)
    for i in 1...32 { XCTAssertEqual(relay.observe(container: bytes, peerHandle: [UInt8(i)]), .duplicate) }
    relay.advance(); clock.now += 15_001; relay.advance(); XCTAssertTrue(sink.served.isEmpty)
  }
  func testLeaseRenewalAndTeardownPaths() {
    let (relay, clock, enin, _, sink) = fixture(); XCTAssertEqual(relay.observe(container: container(0, [5]), peerHandle: [1]), .accepted)
    finishContention(relay, clock); XCTAssertTrue(relay.isServing)
    clock.now += 30_000; relay.advance(); clock.now += 15_001; relay.advance(); XCTAssertGreaterThanOrEqual(sink.served.count, 2)
    enin.value = 22; relay.advance(); XCTAssertFalse(relay.isServing); XCTAssertGreaterThan(sink.stops, 0)
  }
  func testContentionCancellationAndNoSensitivePublicOutput() {
    let (relay, clock, _, _, sink) = fixture(); let secret: [UInt8] = [7,8,9], handle: [UInt8] = [99]
    XCTAssertEqual(relay.observe(container: container(0, [6]), peerHandle: handle), .accepted); relay.advance()
    for i in 0..<3 { _ = relay.observe(container: container(1, [6]), peerHandle: [UInt8(i)]) }
    clock.now += 15_001; relay.advance(); XCTAssertTrue(sink.served.isEmpty)
    let publicBytes = sink.served.flatMap { $0 }; XCTAssertFalse(publicBytes == secret); XCTAssertFalse(publicBytes == handle)
  }
  func testSharedRelayHopAndDensityVectors() throws {
    let hop = try vectors("relay-hop-dedup"), density = try vectors("density-decisions")
    XCTAssertEqual(hop["served_from_zero"], "0301000401020304"); XCTAssertEqual(hop["handle_cap"], "32")
    for r in 0...4 { XCTAssertEqual(Int(density["r\(r)_enter_numerator"]!)!, max(0, 3-r)) }
    XCTAssertEqual(density["window_ms"], "30000"); XCTAssertEqual(density["contention_max_ms"], "15000")
  }
}
