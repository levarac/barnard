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
    var result = BarnardRelayVerification.registryVerified(eventId: [1], validFromEnin: 10, validThroughEnin: 22, relayExpiresAtEnin: 22)
    func verifyRelayEnvelope(_ bytes: [UInt8], currentEnin: UInt32) -> BarnardRelayVerification { result }
  }
  final class Sink: BarnardRelayOutputSink {
    var served: [[UInt8]] = []; var stops = 0
    func startServingRelayContainer(_ bytes: [UInt8]) { served.append(bytes) }
    func stopServingRelayContainer() { stops += 1 }
  }
  final class JoinedEvent: BarnardRelayJoinedEventProvider {
    var eventId: [UInt8]?
    func relayJoinedEventId() -> [UInt8]? { eventId }
  }
  func container(_ hop: UInt8, _ envelope: [UInt8]) -> [UInt8] { [3, hop, UInt8(envelope.count >> 8), UInt8(envelope.count)] + envelope }
  func fixture() -> (BarnardParticipantRelay, Clock, Enin, Verifier, Sink, JoinedEvent) {
    let c = Clock(), e = Enin(), v = Verifier(), s = Sink(), j = JoinedEvent()
    return (BarnardParticipantRelay(clock: c, eninSource: e, verifier: v, outputSink: s, joinedEventProvider: j, randomnessSeedMaterial: [7,8,9]), c,e,v,s,j)
  }
  func finishContention(_ relay: BarnardParticipantRelay, _ clock: Clock) {
    relay.advance(); clock.now += 15_001; relay.advance()
    if !relay.isServing { clock.now = (clock.now / 30_000 + 1) * 30_000; relay.advance(); clock.now += 15_001; relay.advance() }
  }

  func testHopDedupCopiesEnvelopeAndRetainsLowestHop() {
    let (relay, clock, _, _, sink, _) = fixture(); let envelope: [UInt8] = [1,2,3,4]
    XCTAssertEqual(relay.observe(container: container(1, envelope), peerHandle: [1]), .accepted)
    XCTAssertEqual(relay.observe(container: container(0, envelope), peerHandle: [2]), .duplicate)
    finishContention(relay, clock)
    XCTAssertEqual(sink.served.last, container(1, envelope)); XCTAssertEqual(sink.served.last.map { Array($0[4...]) }, envelope)
  }
  func testHopTwoNeverServesAndRegistryConfirmationRequired() {
    let (relay, clock, _, verifier, sink, _) = fixture()
    XCTAssertEqual(relay.observe(container: container(2, [1]), peerHandle: [1]), .accepted); finishContention(relay, clock); XCTAssertTrue(sink.served.isEmpty)
    let other = container(0, [2]); verifier.result = .radioSelfVerified
    XCTAssertEqual(relay.observe(container: other, peerHandle: [2]), .rejected)
  }
  func testPinChoosesCompetingLowestHopAtFiveMinutes() {
    let (relay, clock, _, _, sink, _) = fixture()
    XCTAssertEqual(relay.observe(container: container(1, [1]), peerHandle: [1]), .accepted)
    XCTAssertEqual(relay.observe(container: container(0, [2]), peerHandle: [2]), .accepted)
    finishContention(relay, clock); XCTAssertEqual(sink.served.last?[1], 2)
    clock.now = 300_001; relay.advance(); clock.now += 15_001; relay.advance()
    XCTAssertEqual(sink.served.last?[1], 1)
  }
  func testEninHalfOpenBoundariesAndTwelveLifetime() {
    for (current, accepted) in [(UInt32(21), true), (22, false), (23, false)] {
      let (relay, _, enin, _, _, _) = fixture(); enin.value = current
      XCTAssertEqual(relay.observe(container: container(0, [UInt8(current)]), peerHandle: [1]) == .accepted, accepted)
    }
  }
  func testThirtyThreeHandlesSaturateAndCancelContention() {
    let (relay, clock, _, _, sink, _) = fixture(); let bytes = container(1, [4])
    XCTAssertEqual(relay.observe(container: bytes, peerHandle: [0]), .accepted)
    for i in 1...32 { XCTAssertEqual(relay.observe(container: bytes, peerHandle: [UInt8(i)]), .duplicate) }
    relay.advance(); clock.now += 15_001; relay.advance(); XCTAssertTrue(sink.served.isEmpty)
  }
  /// P1: a saturated handle set (33rd handle) must expire after T=30s so an
  /// inactive candidate can be re-elected once local density is stale.
  func testSaturationExpiresAfterDensityWindow() {
    let (relay, clock, _, _, sink, _) = fixture(); let bytes = container(1, [4])
    XCTAssertEqual(relay.observe(container: bytes, peerHandle: [0]), .accepted)
    for i in 1...32 { XCTAssertEqual(relay.observe(container: bytes, peerHandle: [UInt8(i)]), .duplicate) }
    relay.advance(); clock.now += 15_001; relay.advance(); XCTAssertTrue(sink.served.isEmpty)
    clock.now += 30_000; relay.advance()
    finishContention(relay, clock)
    XCTAssertFalse(sink.served.isEmpty)
  }
  /// P1: selection rule 1 — the joined event's verified envelope wins over a
  /// lower-hop, earlier-verified competitor once a reselection actually runs
  /// (the five-minute pin holds the original choice until then, per spec).
  func testSelectionPrefersJoinedEventOverLowerHop() {
    let (relay, clock, _, verifier, sink, joined) = fixture()
    verifier.result = .registryVerified(eventId: [9], validFromEnin: 10, validThroughEnin: 600, relayExpiresAtEnin: 22)
    XCTAssertEqual(relay.observe(container: container(0, [1]), peerHandle: [1]), .accepted)
    joined.eventId = [42]
    verifier.result = .registryVerified(eventId: [42], validFromEnin: 10, validThroughEnin: 600, relayExpiresAtEnin: 22)
    XCTAssertEqual(relay.observe(container: container(1, [2]), peerHandle: [2]), .accepted)
    clock.now = 300_001
    relay.advance() // pin expired: reselection now compares both candidates
    finishContention(relay, clock)
    XCTAssertEqual(sink.served.last.map { Array($0[4...]) }, [2])
  }
  /// P1: lastDecisionEpoch must not survive a selection switch — a newly
  /// selected candidate must still get a decision within the same wall-clock
  /// epoch that its predecessor was decided in.
  func testDecisionEpochResetsOnSelectionSwitch() {
    let (relay, clock, enin, verifier, sink, _) = fixture()
    verifier.result = .registryVerified(eventId: [1], validFromEnin: 10, validThroughEnin: 22, relayExpiresAtEnin: 11)
    XCTAssertEqual(relay.observe(container: container(0, [1]), peerHandle: [1]), .accepted)
    relay.advance() // epoch 0 decision for candidate A (r=0, guaranteed contention entry)
    enin.value = 11 // candidate A falls out of [validFrom, expires)
    verifier.result = .registryVerified(eventId: [2], validFromEnin: 10, validThroughEnin: 22, relayExpiresAtEnin: 22)
    XCTAssertEqual(relay.observe(container: container(0, [2]), peerHandle: [2]), .accepted)
    relay.advance() // still epoch 0: must expire A, reset the epoch, and decide for B
    clock.now += 15_001
    relay.advance() // B's contention window (<=15s) must have completed by now
    XCTAssertTrue(relay.isServing)
    XCTAssertEqual(sink.served.last.map { Array($0[4...]) }, [2])
  }
  /// P1: a cached candidate must be re-checked against the full half-open
  /// window, both on duplicate short-circuit and in advance(), not just its
  /// upper bound — a clock regression below validFrom must deselect it.
  func testCachedCandidateRechecksFullWindowOnDuplicateAndAdvance() {
    let (relay, clock, enin, _, _, _) = fixture()
    enin.value = 15
    XCTAssertEqual(relay.observe(container: container(0, [1]), peerHandle: [1]), .accepted)
    finishContention(relay, clock); XCTAssertTrue(relay.isServing)
    // Advance() must deselect once ENIN regresses below validFrom, not just at/after expiry.
    enin.value = 5
    relay.advance()
    XCTAssertFalse(relay.isServing)
    // The duplicate short-circuit must also re-check the window: this observation is
    // now out of [validFrom, expires) and must be rejected, not treated as a duplicate.
    enin.value = 15
    XCTAssertEqual(relay.observe(container: container(0, [1]), peerHandle: [1]), .accepted)
    enin.value = 5
    XCTAssertEqual(relay.observe(container: container(0, [1]), peerHandle: [2]), .rejected)
  }
  func testLeaseRenewalAndTeardownPaths() {
    let (relay, clock, enin, _, sink, _) = fixture(); XCTAssertEqual(relay.observe(container: container(0, [5]), peerHandle: [1]), .accepted)
    finishContention(relay, clock); XCTAssertTrue(relay.isServing)
    clock.now += 30_000; relay.advance(); clock.now += 15_001; relay.advance(); XCTAssertGreaterThanOrEqual(sink.served.count, 2)
    enin.value = 22; relay.advance(); XCTAssertFalse(relay.isServing); XCTAssertGreaterThan(sink.stops, 0)
  }
  func testContentionCancellationAndNoSensitivePublicOutput() {
    let (relay, clock, _, _, sink, _) = fixture(); let secret: [UInt8] = [7,8,9], handle: [UInt8] = [99]
    XCTAssertEqual(relay.observe(container: container(0, [6]), peerHandle: handle), .accepted); relay.advance()
    for i in 0..<3 { _ = relay.observe(container: container(1, [6]), peerHandle: [UInt8(i)]) }
    clock.now += 15_001; relay.advance(); XCTAssertTrue(sink.served.isEmpty)
    let publicBytes = sink.served.flatMap { $0 }; XCTAssertFalse(publicBytes == secret); XCTAssertFalse(publicBytes == handle)
  }
  func testSharedRelayHopAndDensityVectors() throws {
    let hop = try vectors("relay-hop-dedup"), density = try vectors("density-decisions")
    XCTAssertEqual(hop["format_version"], "03"); XCTAssertEqual(hop["relay_lifetime_enins"], "12"); XCTAssertEqual(hop["handle_cap"], "32")
    XCTAssertEqual(density["k"], "3")
    func bytes(_ hex: String) -> [UInt8] {
      var out: [UInt8] = []; var it = hex.startIndex
      while it < hex.endIndex { let next = hex.index(it, offsetBy: 2); out.append(UInt8(hex[it..<next], radix: 16)!); it = next }
      return out
    }
    let envelope = bytes(hop["envelope"]!)
    let zeroContainer = bytes(hop["hop_zero_container"]!), oneContainer = bytes(hop["hop_one_container"]!), twoContainer = bytes(hop["hop_two_container"]!)
    XCTAssertEqual(zeroContainer, container(0, envelope)); XCTAssertEqual(oneContainer, container(1, envelope)); XCTAssertEqual(twoContainer, container(2, envelope))

    // hop 0 -> 1
    do {
      let (relay, clock, _, _, sink, _) = fixture()
      XCTAssertEqual(relay.observe(container: zeroContainer, peerHandle: [1]), .accepted)
      finishContention(relay, clock)
      XCTAssertEqual(sink.served.last, bytes(hop["served_from_zero"]!))
    }
    // hop 1 -> 2
    do {
      let (relay, clock, _, _, sink, _) = fixture()
      XCTAssertEqual(relay.observe(container: oneContainer, peerHandle: [1]), .accepted)
      finishContention(relay, clock)
      XCTAssertEqual(sink.served.last, bytes(hop["served_from_one"]!))
    }
    // hop 2 -> no output
    do {
      let (relay, clock, _, _, sink, _) = fixture()
      XCTAssertEqual(relay.observe(container: twoContainer, peerHandle: [1]), .accepted)
      finishContention(relay, clock)
      XCTAssertTrue(sink.served.isEmpty)
    }
    // enter/keep decisions for r = 0...4
    let window = Int64(density["window_ms"]!)!, contentionMax = Int64(density["contention_max_ms"]!)!, k = Int(density["k"]!)!
    for r in 0...4 {
      let enterNumerator = Int(density["r\(r)_enter_numerator"]!)!, keepNumerator = Int(density["r\(r)_keep_numerator"]!)!
      XCTAssertEqual(enterNumerator, max(0, k - r))
      XCTAssertEqual(keepNumerator, k)
      let (relay, clock, _, _, _, _) = fixture()
      // Establish the candidate at hop 0 (direct source) so accepting it does not
      // itself retain a handle -- only hop-positive relay sources count toward r.
      XCTAssertEqual(relay.observe(container: container(0, [UInt8(r)]), peerHandle: [1]), .accepted)
      for i in 0..<r { XCTAssertEqual(relay.observe(container: container(1, [UInt8(r)]), peerHandle: [UInt8(100 + i)]), .duplicate) }
      relay.advance()
      clock.now += contentionMax + 1
      relay.advance()
      let entered = relay.isServing
      let expectEnter = enterNumerator > 0
      XCTAssertEqual(entered, expectEnter, "r=\(r) enter decision mismatch")
      if entered {
        clock.now += window
        relay.advance()
        clock.now += contentionMax + 1
        relay.advance()
        XCTAssertEqual(relay.isServing, keepNumerator > 0, "r=\(r) keep decision mismatch")
      }
    }
  }
}
