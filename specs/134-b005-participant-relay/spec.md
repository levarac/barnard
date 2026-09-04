# B005 Participant Relay with Density Control

**Status:** Accepted (maintainer decision 2026-09-04, levarac/barnard#168). Implementation tracked in #128; signed-envelope bytes depend on #122.

## Problem statement

An organizer-designated Peripheral covers only its radio neighborhood. Event
information must reach venue edges through participant devices, but continuous
relay by every participant wastes Advertise, GATT, and battery capacity.

This specification adds signature-preserving participant relay and a bounded
local density controller. A verified receiver automatically enters election;
sparse neighborhoods elect more relays than dense ones.

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** in
this document are to be interpreted as described in RFC 2119 and RFC 8174 when,
and only when, they appear in all capitals.

## Goals

- Preserve the organizer-authorized signed event-info envelope byte-for-byte.
- Extend B005 reach without making every device a permanent beacon.
- Target about three relays per local radio neighborhood with observer-local,
  bounded state.
- Expire stale information and stop honest forwarding after at most two hops.
- Keep relay observations out of prevalence, majority, attendance, and census
  calculations.
- Relay at most one event from any device at a time.

## Non-goals

- Granting admission, joining an event, or carrying the raw event code.
- Proving that a relayer is a participant, organizer, unique person, or stable
  device.
- Estimating how popular, prevalent, or trustworthy an event is from relay
  volume.
- Defining the issue #82 census or allowing relay observations to feed it.
- Defining production APIs, implementing Swift or Android code, or changing the
  existing 31-byte advertisement payload.
- Guaranteeing background relay when the platform suspends Bluetooth work.

## Glossary

- **signed envelope**: canonical event-info bytes plus authority authentication,
  as minimally constrained below and completed by issue #122.
- **delivery header**: the unsigned B005 v2 prefix containing the observed hop
  count and the length of the signed envelope.
- **payload digest**: `SHA256(signedEnvelope)`, used only for local deduplication
  and density control.
- **direct source**: an organizer-authorized Peripheral serving hop count zero.
- **relay source**: a participant Peripheral serving hop count one or greater.
- **radio neighborhood**: relay sources discoverable by one Central during the
  trailing density window. It is a local radio observation, not a venue census.
- **ENIN**: the event's configured Exposure Notification Interval Number, as
  defined by B004.

## Scope and inherited B005 rules

The advertisement remains the B001 service UUID and local name described by
[`specification 113`](../113-event-info-discovery/spec.md). Event-info remains in
the read-only B005 GATT characteristic, capped at 512 bytes. B002-B004 and
existing Central peer resolution are unchanged.

The signed envelope carries the B005 event display name and the exact eight-byte
`eventCodeHash = SHA256(UTF8(EventCode))[0:8]`. It also carries the canonical
`eventId`. The receiver MUST verify that both fields match the authoritative
on-chain event definition for that `eventId`. The raw event code MUST NOT appear
in the signed envelope, delivery header, Advertise data, unknown extension,
debug substitute, or relay state.

A B005 value is only a discovery input. It MUST NOT grant admission, start a
join, create attendance evidence, or override direct B002-B004 observations.
Direct and relayed values receive identical trust and display checks.

## B005 v2 delivery container

Trust semantics differ from unsigned B005 v1, so this specification uses a new
format version rather than hiding authentication inside a v1 unknown TLV.
Integers are unsigned and big-endian.

| Offset | Size | Field | Rule |
|---:|---:|---|---|
| 0 | 1 | `formatVersion` | Exactly `0x03` |
| 1 | 1 | `relayHopCount` | `0` for direct; `1` or `2` for relay |
| 2 | 2 | `signedEnvelopeLength` | `1...508`; ends at value boundary |
| 4 | variable | `signedEnvelope` | Organizer-authorized bytes, unchanged by relays |

The complete value MUST be at most 512 bytes; the envelope is at most 508 bytes.
A relayer MUST copy its length and bytes exactly, changing only `relayHopCount`
to the smallest valid hop observed for this digest plus one.

The header is unsigned congestion control, not evidence. An attacker can reset
it, so hop count MUST NOT affect trust, prevalence, or admission. Signed expiry
is the adversary-resistant boundary; hop limit bounds conforming forwarders.

B005 v1 remains parseable with its legacy unverified-hint semantics under
specification 113, but it MUST NOT be participant-relayed or enter the verified
B005 v2 display path. An older Central that does not understand `0x03` treats
event-info as unavailable and continues the existing B004/B002/B003 flow.

## Minimal signed-envelope contract shared with issue #122

Issue #122 owns the final algorithm identifiers, canonical byte layout, key
encoding, delegation rules, and golden vectors. Until those are fixed, a B005
v2 implementation is blocked. Any adopted encoding MUST provide at least:

- `eventId`, `eventDisplayName`, and the eight-byte `eventCodeHash`;
- `validFromEnin` and `validThroughEnin` for the event definition;
- `relayExpiresAtEnin`, no later than `validThroughEnin`;
- `maxRelayHops`, which MUST be `2` for this version;
- an authority public key or an authority-signed delegation chain that binds the
  signing key to `eventId` and the on-chain definition; and
- a domain-separated signature covering every preceding field, including all
  validity and relay-policy fields.

The relay lifetime MUST be at most 12 ENINs: `relayExpiresAtEnin - validFromEnin`
MUST NOT exceed 12, and a receiver MUST reject an envelope whose lifetime exceeds
it. The relay window is the half-open interval `[validFromEnin,
relayExpiresAtEnin)`: an envelope is relayable while `currentEnin <
relayExpiresAtEnin` and stops the moment `currentEnin` reaches
`relayExpiresAtEnin`, so a lifetime of 12 covers exactly 12 ENIN values. Under
B004's 300-second default that is one hour. Longer events require
authority or delegate refresh (a new envelope with a later `validFromEnin`). A
receiver MUST NOT extend expiry.

A receiver MUST, in this order:

1. enforce the 512-byte container bound and canonical envelope structure;
2. verify the authority key or delegation chain and signature;
3. obtain the authoritative on-chain definition for `eventId`;
4. require exact `eventId`, `eventCodeHash`, display-name, validity-window, and
   signer-authority agreement with that definition;
5. require `validFromEnin <= currentEnin < relayExpiresAtEnin <=
   validThroughEnin`; and
6. only then expose the event to host display or relay APIs.

If clock or ENIN configuration cannot establish step 5, the device MUST NOT
relay or show the value as verified.

*Erratum (2026-09-05), display only:* step 6 is relaxed for **candidate display**
and unchanged for **relay**. A receiver that has completed steps 1, 2 and 5 but
not step 3 — because the registry is unreachable — MAY surface the event as a
discovery candidate in a distinct `RADIO_SELF_VERIFIED` state, meaning the
signature verifies and `eventId` is self-consistent with the key set the envelope
carries, while registration is **not** confirmed. That state MUST NOT be
presented to a user as verified or registered.

Relay, joining, per-event key generation and observation recording continue to
require step 3 against the pinned block. Testable scenario 2 is unaffected: an
unavailable definition still yields no *verified* display and no relay lease.

The rationale is that radio alone cannot prove registration — an attacker can
mint a self-consistent unregistered event freely — so offline verification earns
an earlier candidate display, not an earlier trust decision. What it does buy is
that impersonating an existing event, or pairing a genuine event-code hash with a
misleading display name, become infeasible for a third party at first sight. The
byte layout that makes this possible is fixed by
[`specification 122`](../122-b005-v2-signed-envelope/spec.md).

## Relay eligibility and the one-event cap

A device is eligible after all checks pass, Peripheral operation is available,
and observed hop is below signed `maxRelayHops`. Joining is not required: a
verified walk-up receiver may relay automatically before admission, subject to
host permission and operating-system policy.

A device MUST actively serve at most one payload digest at a time. The default
selection policy is:

1. prefer the verified, unexpired envelope for the device's joined event;
2. otherwise prefer the verified envelope observed at the lowest hop count;
3. break equal-hop ties by the earliest successful verification time, then by
   lexicographically smallest payload digest; and
4. pin the selection for five minutes, unless it expires or becomes invalid.

Switching MUST stop old B005 serving before enabling new serving. Other events
MAY remain in specification 113's display cache, never as simultaneous relays.

## Recommended density controller

The recommendation is probabilistic listen-before-relay suppression with
`k = 3` desired relays and `T = 30 seconds`. These defaults are not on-wire
claims. State is per digest and disappears on deselection or expiry.

For each matching digest, the Central retains the observer-local peer handle for
at most `T`; repeats count once. Only hop-positive sources count. Handles MUST
NOT be transmitted, persisted longer, or interpreted as people or stable devices.

At each 30-second decision boundary, let `r` be distinct matching relay sources
heard during the preceding `T`:

- An inactive candidate with `r >= k` remains silent.
- An inactive candidate with `r < k` enters with probability
  `pEnter = (k - r) / k`.
- An active relay remains active with probability
  `pKeep = min(1, k / (r + 1))`; `r + 1` includes itself.
- A positive decision waits a random zero-to-`T/2` contention delay,
  continues Scan, and starts or renews Advertise only if `r < k` at the end of
  the delay.
- An active lease lasts 30 seconds. Renewal requires a fresh decision. Random
  draws MUST come from a per-install secret plus payload digest and decision
  epoch, or an equivalent non-correlated source; the secret MUST NOT go on wire.

In a dense center, three relays suppress more transmitters. At an edge, `r`
falls and entry rises. Random delay reduces simultaneous starts. A single missed
packet SHOULD NOT stop and restart Advertise within one epoch.

The controller estimates coverage, not headcount. Rotation, radio asymmetry,
loss, and Sybils distort `r` and may suppress relay, but cannot upgrade trust or
inflate an event count because `r` never leaves the controller.

## Hop limit, deduplication, and bounded state

The direct source serves hop zero. A conforming receiver stores one copy per
payload digest and the smallest valid hop count observed. If that minimum is
less than two and the device wins election, it serves the same signed envelope
with `relayHopCount = minimum + 1`. A hop-two observation is displayable after
verification but is never forwarded.

Duplicates refresh only their density entry. They MUST NOT duplicate envelope
bytes, extend expiry, reset selection, or create hints. State is bounded to one
508-byte envelope and 32 handles; further handles saturate `r >= k` without
being retained.

When `currentEnin` reaches `relayExpiresAtEnin`, on definition invalidation, on signature failure, or
when the host stops Scan/Advertise, the implementation MUST stop new B005 reads,
clear the relay lease and density handles, and delete the cached relay envelope.
An immutable GATT snapshot already accepted at offset zero follows specification
113's bounded completion rules, but the receiving Central rejects it after
expiry.

## Battery and platform behavior

Relay MUST share specification 113's GATT queue, timeout, cooldown, retry, and
cancellation bounds; it MUST NOT create another unbounded Scan or queue. It
SHOULD reuse discovery Scan and stop when no consumer needs it.

Core Bluetooth Advertise is best effort. In iOS background, the local name is
omitted, service UUIDs use an overflow area visible only to an iOS device scanning
for them, and frequency may fall. A 30-second lease is not a packet-cadence
promise. Resume MUST recheck every guard instead of restoring an old lease.

## Alternatives considered

### Duty-cycled relay after joining

Every joined device could Advertise for 10 seconds per minute at a random phase.
It bounds average battery use, but transmitters still scale with crowd size, an
edge can wait nearly a minute, and verified unjoined devices cannot help.

### Role-gated relay by joined participants only

Joined-only relay makes event choice clear, but joined state is not radio proof
and coverage is weakest when discovery is most needed. It MAY be host privacy
policy, but is not the protocol default.

## Security and abuse considerations

- **Stale replay:** the authority-signed ENIN validity and relay expiry are
  checked by every receiver. Neither a relayer nor delivery-header mutation can
  extend them.
- **Amplification:** the two-hop limit, one-event cap, 30-second lease,
  probabilistic suppression, bounded retry policy, and bounded state limit
  conforming amplification. A malicious implementation can ignore congestion
  rules; receivers still apply signature, definition, and expiry checks.
- **Fake events and tampering:** a valid signature plus exact on-chain definition
  agreement is required before display as verified or relay. A copied signature
  cannot authorize changed display text, hash, validity, event ID, or hop limit.
- **Wrong-venue replay:** a genuine unexpired event can be replayed at another
  venue. Signatures do not prove physical location. Host UX and explicit event
  selection contain this risk; relay volume MUST NOT be treated as location
  consensus.
- **Count inflation:** peer handles and `r` exist only inside density control.
  Relay observations MUST NOT feed issue #82 census, prevalence, majority,
  attendance, admission, or proof unless a future issue #82 specification
  defines an independently authenticated mutual-detection input.
- **Tracking:** no relay identifier, participant identifier, peer handle,
  election secret, or device-unique persistent identifier is added on wire.

The presence of one relay or one thousand relays MUST NOT be interpreted as an
event's prevalence, majority support, authenticity, attendance, or legitimacy.

## Conformance requirements

A receiver MUST reject malformed, unauthenticated, mismatched, or expired input
before verified display or relay; treat direct and relayed envelopes identically;
deduplicate by digest; retain lowest hop; and bound every cache.

A relayer MUST serve one verified, selected, unexpired envelope; preserve its
bytes; increment lowest hop once; stop at hop two; elect; and stop on invalidation.
It MUST NOT re-sign, edit, extend, manufacture, or count the envelope.

## Testable scenarios

1. **Unit — byte preservation and hops:** feed the same signed envelope at hops
   zero, one, and two from duplicate and distinct handles. Assert one stored
   envelope, byte identity, minimum-hop retention, hop-one output from hop zero,
   hop-two output from hop one, and no output from hop two.
2. **Unit — trust failures:** mutate each signed field and the signature; return
   mismatching and unavailable on-chain definitions. Assert no verified display,
   no relay lease, no admission side effect, and unchanged direct B002-B004 flow.
3. **Unit — expiry:** exercise ENIN immediately before, at, and after each signed
   bound. Assert relay stops and state is deleted once `currentEnin` reaches
   `relayExpiresAtEnin` (the expiry ENIN itself is not relayable), and
   local time uncertainty fails closed for relay.
4. **Unit — density and bounds:** with deterministic random fixtures, exercise
   `r = 0, 1, 2, 3, 4`, contention cancellation, lease renewal, 33 peer handles,
   two competing valid events, and selection expiry. Assert the probabilities,
   saturation, one-event cap, and zero census/prevalence output.
5. **Real multi-device lab — center and edge:** use at least five physical BLE
   devices with one direct source. Capture exact builds, platforms, timestamps,
   signed-envelope digests, hops, and active relays. Verify propagation reaches
   a device outside direct-source range within two hops, a dense neighborhood
   settles near `k = 3`, and removing relays causes edge devices to enter.
6. **Real multi-device lab — platform lifecycle:** include Swift and Android in
   both Central and Peripheral roles where supported. Move iOS between foreground
   and background, rotate ENIN, expire the envelope, disconnect, and restart
   Bluetooth. Verify best-effort recovery never bypasses validity, hop, density,
   one-event, GATT queue, or bounded-state rules. Record unsupported combinations
   rather than replacing them with simulation.

Unit, simulator, and mock-Transport tests do not replace the two real multi-
device scenarios.

## Decisions (maintainer, 2026-09-04)

The questions raised in the draft were settled as follows (levarac/barnard#168).

1. **Delivery container**: B005 v2 uses the four-byte delivery container above, not an
   additive v1 TLV. Authenticated trust semantics are incompatible with v1, and nesting
   preserves the signed envelope exactly.
   *Erratum (2026-09-05):* the container's `formatVersion` is `0x03`, not `0x02` as
   originally written. `0x02` was already assigned by
   [`specification 123-128`](../123-128-adoption-credential-census/spec.md) to the
   adoption-credential census format, which is implemented and released in tag `v0.6.0`.
   Assigning `0x03` to the relay container leaves those released bytes untouched. Neither
   parser accepts the other's payload, so no deployed value changes meaning.
2. **Maximum relay lifetime**: 12 ENIN. Hourly refresh bounds replay while avoiding
   per-window signing. Issue #122 decides whether direct authority signing or delegated
   liveness signing performs the refresh.
3. **Unjoined relays**: an unjoined but fully verified receiver MAY relay. Early and edge
   coverage is the feature's purpose; joined-only remains an optional host privacy policy.
4. **One-event tie-break**: lowest hop plus a five-minute pin. It is deterministic and adds
   no UI dependency. Note for consumers: in beid v1.0 the join surface is always one
   explicit tap (a single candidate is preselected, several are listed), so relayed
   candidates simply appear in that list; the automatic choice takes effect together with
   the prevalence-based selection planned for v2.0 (levarac/dispatch#32).
5. **Defaults**: `k = 3`, `T = 30 seconds`, two hops, and a 32-handle density cap are the
   initial cross-platform defaults. They are bounded starting values that the required
   real-device tests validate before any constant is made permanent.

## Compatibility and implementation boundary

This specification changes no schema, package, example, or CI file. Before later
implementation, issue #122 must settle signed bytes and shared vectors. Exported
public shapes follow schema-first. Swift and Android MUST share fixtures,
defaults, errors, and bounded mock behavior.

## References

- [`specs/113-event-info-discovery`](../113-event-info-discovery/spec.md)
- [`specs/004-resolvable-id`](../004-resolvable-id/spec.md)
- Barnard issue #128: participant relay mechanics.
- Barnard issue #122: B005 authenticity and liveness signatures.
- Barnard issue #82: space census.
- Dispatch issue #11: participant-side event-info reach.
- Apple, [Core Bluetooth Background Processing for iOS Apps](https://developer.apple.com/library/archive/documentation/NetworkingInternetWeb/Conceptual/CoreBluetooth_concepts/CoreBluetoothBackgroundProcessingForIOSApps/PerformingTasksWhileYourAppIsInTheBackground.html).
- RFC 2119 and RFC 8174.
