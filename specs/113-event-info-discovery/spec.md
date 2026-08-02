# Event-Info GATT Discovery

## Problem statement

Barnard v2 lets a Central verify a Peripheral only when both already know the
same event code. The `B004 EventCodeHash` characteristic carries either zero
bytes or the first eight bytes of the SHA-256 digest of that code. This is
useful as a same-event gate, but it cannot tell a walk-up Central which event
is nearby.

This specification adds a read-only `B005 event-info` GATT characteristic. An
organizer-designated Peripheral can expose a bounded event display name and
the existing B004-compatible event-code hash. A Central can then show a nearby
event as an unauthenticated discovery hint before the user obtains the event
code through a separate channel and confirms joining.

Discovery and admission remain separate. The event-info payload never carries
the raw event code, never causes an automatic join, and never establishes that
the serving Peripheral is an organizer.

## Goals

- Define byte-exact, versioned, bounded TLV encoding for `B005 event-info`.
- Let a walk-up Central discover a human-readable event hint without already
  knowing the event code.
- Reuse the exact `B004 EventCodeHash` derivation for cross-checking a code
  obtained out of band.
- Bound disclosure by requiring explicit organizer designation before a
  Peripheral serves event-info.
- Keep the payload free of device-unique persistent identifiers and new
  device-linkable handles.
- Reserve an ignorable TLV type for the space-census extension in issue #82 so
  v1 readers can continue parsing the required event fields.
- Define Swift and Android parity and real-device validation before the GATT
  change ships.

## Non-goals

- Carrying the raw event code or granting admission over BLE.
- Authenticating the event name, the event-code hash, the organizer, or a
  space census.
- Automatically joining, selecting, or suppressing an event.
- Moving event metadata into the 31-byte advertisement payload.
- Defining the issue #82 census value, identifier, TTL, or reconciliation
  algorithm.
- Replacing `B004` or changing the existing `B002` RPID and `B003 displayId`
  resolution flow.
- Defining organizer provisioning, event-registry, signing, or user-interface
  APIs.
- Adding a validity window to the v1 payload.
- Changing production packages, schemas, examples, or CI in this spec-only
  change.

## Glossary

- **event-info**: the complete value read from GATT characteristic `B005`.
- **event display name**: organizer-supplied, human-readable event text. It is
  an untrusted hint, not an authenticated name.
- **EventCodeHash**: `SHA256(UTF8(EventCode))[0:8]`, exactly matching `B004`.
- **organizer-designated Peripheral**: a Peripheral whose host has explicitly
  enabled serving event-info for the active event. Designation is local host
  state and is not asserted on wire.
- **discovery hint**: unauthenticated data that may help a user find an event
  but cannot authorize, auto-join, or override direct BLE observation.
- **direct observation**: the Central's own observation of a `B001`
  advertisement and subsequent GATT exchange with that Peripheral.
- **unknown TLV**: a well-formed TLV whose type is not defined by the reader.
  v1 readers skip it after enforcing the payload-wide structural rules.

## Existing wire model

The Barnard discovery service remains:

| UUID | Name | Properties | Current value |
|---|---|---|---|
| `B001` | Barnard discovery service | — | Fixed service UUID |
| `B002` | RPID | Read | 17 bytes |
| `B003` | displayId | Read | 4 bytes when joined |
| `B004` | EventCodeHash | Read | 0 or 8 bytes |

The advertisement continues to contain the fixed `B001` service UUID and
local name only. Event-info is not advertisement data.

## Design decisions

### 1. Discovery-only, not discovery-plus-join

**Recommendation:** v1 is discovery-only. `B005` contains a display name and
the B004-compatible hash, but MUST NOT contain the raw event code in a known or
unknown TLV. A user obtains the raw code through a separate channel such as a
QR code, staff member, or venue sign and explicitly confirms joining.

**Rationale:** event visibility and event admission have different trust
postures. A readable GATT value is available to any nearby scanner. Keeping
the code out of it improves discovery without turning physical proximity into
admission. The hash also lets the app cross-check an out-of-band code before
joining without changing the existing B004 derivation.

**Rejected alternatives:**

- Raw event code in every payload: rejected because any passerby could join.
- Organizer-selectable raw-code field in v1: rejected because the same wire
  version would have two materially different privacy postures and a mistaken
  toggle would disclose admission data.
- Encrypted raw code: rejected because v1 has no authenticated key agreement;
  adding one would be a different protocol, not walk-up discovery.

A future discovery-plus-join protocol requires an explicit privacy review and
a new format version. It MUST NOT be introduced as an unknown TLV under v1.

### 2. Organizer-designated Peripherals serve event-info

**Recommendation:** serving is disabled by default. Only a locally
organizer-designated Peripheral serves event-info, and only while its host
considers the named event active. Ordinary joined participant devices do not
serve it.

**Rationale:** making every participant a venue beacon would disclose the
event's existence and name wherever attendees travel. Explicit designation
bounds disclosure to devices deliberately placed or enabled by an organizer.
Keeping designation local avoids adding a stable organizer or device role
identifier to the wire.

**Rejected alternatives:**

- Every joined device serves: rejected because disclosure follows every
  attendee and cannot be bounded to the venue.
- A designated-device identifier in the payload: rejected because it adds a
  device-linkable handle and still does not authenticate the role.
- Inferring organizer status from RPID or displayId: rejected because neither
  field proves organizer authority.

### 3. Event-info is an unauthenticated hint

**Recommendation:** a Central treats every parsed payload as an
unauthenticated discovery hint. It may show the candidate event and shorten a
discovery wait, but MUST require user confirmation before joining and MUST NOT
use event-info to suppress a directly observed event or peer.

**Rationale:** the read-only characteristic has neither a signature nor an
authenticated BLE session. An attacker can advertise `B001`, copy a valid
payload, invent a name and hash, omit an event, or replay stale bytes.
Restricting the payload to positive discovery assistance contains those
failures.

**Rejected alternatives:**

- Treating a successful GATT read as organizer authentication: rejected
  because BLE reachability proves only proximity to a radio.
- Auto-joining when exactly one event is visible: rejected because uniqueness
  does not establish authenticity or consent.
- Letting a missing event or future census entry veto direct observation:
  rejected because unauthenticated negative claims are trivial to forge.

### 4. No new stable or device-linkable identifier

**Recommendation:** v1 carries only event-scoped display text and the existing
event-scoped `EventCodeHash`. It carries no device identifier, organizer
identifier, displayId, RPID, public key, nonce, instance identifier, or new
event handle.

**Rationale:** the display name and hash deliberately make organizer beacons
for the same event linkable as one event, but they do not distinguish the
devices serving them. This preserves the existing rule that observer-local
correlation stays off wire and avoids worsening the `B003 displayId`
linkability tradeoff described in issue #64.

**Rejected alternatives:**

- Random payload instance ID: rejected because it is unnecessary for a GATT
  read and can become a tracking handle if retained or reused.
- Stable organizer or venue ID: rejected because it enables cross-event and
  cross-time tracking.
- Reusing `B003 displayId`: rejected because it identifies a participant
  within an event and is unrelated to event discovery.

### 5. Reserve an ignorable census extension

**Recommendation:** TLV type `0x10` is reserved for the issue #82 space census.
It is not emitted by this specification. All v1 readers skip well-formed
unknown TLVs, including `0x10`, while continuing to require and parse the event
display name and EventCodeHash.

**Rationale:** a length-delimited extension can ride the same bounded GATT
value without changing the advertisement or breaking v1 readers. Reserving
only the outer type leaves issue #82 free to define a bounded list, event-
scoped identifiers, freshness data, and reconciliation semantics after its
own privacy review.

**Rejected alternatives:**

- Fixed-position census fields: rejected because adding them would change all
  following offsets and break existing readers.
- A bare census count: rejected because it cannot identify which candidates a
  Central should seek or cross-check.
- Defining the census list in this spec: rejected because its identifier,
  lifetime, cap, and trust policy are separate decisions owned by issue #82.

## B005 characteristic

The event-info characteristic uses the Bluetooth base UUID:

```text
0000B005-0000-1000-8000-00805F9B34FB
```

It has the `Read` property only. It has no `Write`, `Write Without Response`,
`Notify`, or `Indicate` property. Its maximum complete value is 512 bytes.

A Peripheral implementation that supports this specification includes `B005`
in `B001` even when serving is currently disabled. Discovering the
characteristic therefore reveals implementation capability, not whether an
event is active. When the serve policy is false, a read returns GATT
`Read Not Permitted` and no value.

## Wire format

### Payload envelope

Integers are unsigned and big-endian. Offsets are measured from the first byte
of the complete characteristic value, before ATT MTU fragmentation.

| Offset | Size | Field | v1 value and rule |
|---:|---:|---|---|
| 0 | 1 | `formatVersion` | Exactly `0x01` |
| 1 | variable | `tlvs` | Zero or more TLV records, ending exactly at the value boundary |

Each TLV record is:

| Relative offset | Size | Field | Rule |
|---:|---:|---|---|
| 0 | 1 | `type` | `0x01` through `0xff`; `0x00` is invalid |
| 1 | 2 | `length` | Value length, unsigned big-endian |
| 3 | `length` | `value` | Exactly `length` bytes |

The complete payload MUST be between 16 and 512 bytes inclusive. TLVs MUST
appear in strictly increasing type order. A type therefore appears at most
once. A parser MUST reject the complete payload when:

- `formatVersion` is not `0x01`;
- the total length is outside the bound;
- a TLV header or value is truncated;
- a TLV has type `0x00`;
- types are duplicated or not strictly increasing;
- a required TLV is missing or malformed; or
- trailing bytes remain after parsing the last TLV.

A v1 parser MUST skip the value of every structurally valid unknown TLV and
continue parsing. Incompatible envelope or trust semantics require a new
`formatVersion`; they MUST NOT be smuggled into a v1 unknown TLV.

### v1 TLV registry

| Type | Name | Presence | Length | Value |
|---:|---|---|---:|---|
| `0x01` | `eventDisplayName` | Required | 1–64 bytes | Canonical UTF-8 event display name |
| `0x02` | `eventCodeHash` | Required | 8 bytes | `SHA256(UTF8(EventCode))[0:8]` |
| `0x10` | `spaceCensus` | Reserved | Not defined | Reserved for issue #82; v1 emitters omit it and v1 readers skip it |
| all other values | Unassigned | Optional to parse | 0–493 bytes within the total cap | v1 readers skip structurally valid values |

`eventDisplayName` is Unicode NFC encoded as UTF-8. It contains at least one
Unicode scalar value, contains no U+0000 through U+001F or U+007F control
characters, and occupies at most 64 bytes after NFC normalization. Emitters
MUST normalize before measuring and encoding. Parsers MUST reject invalid
UTF-8, non-NFC text, forbidden controls, or an out-of-range byte length. Hosts
render it as untrusted plain text, never markup.

`eventCodeHash` uses the exact event-code string supplied to the existing
Barnard B004 derivation. No trimming, case conversion, or Unicode
normalization is added:

```text
eventCodeBytes = UTF8(EventCode)
eventCodeHash  = first 8 bytes of SHA-256(eventCodeBytes)
```

The `0x02` bytes for a given event MUST equal that Peripheral's non-empty B004
value byte-for-byte. A mismatch is an invalid local serving configuration and
MUST prevent B005 from being served.

### Long-read snapshot behavior

The 512-byte bound allows a future census to exceed one ATT response. A
Peripheral MUST construct one immutable payload snapshot when it receives the
offset-zero read and use the same bytes for continuation reads belonging to
that Central's read transaction. For each valid offset from zero through the
payload length, it returns the suffix beginning at that offset, limited by the
platform's negotiated response size. An offset greater than the payload
length returns GATT `Invalid Offset`.

The Peripheral MUST NOT splice a changed display name, hash, or future census
into an in-progress long read. It may replace the snapshot after the read
completes, fails, disconnects, or times out under a bounded platform policy.

## Serve policy

`B005` serves bytes only when all of these conditions are true at the start of
an offset-zero read:

1. The host explicitly marks this Peripheral as organizer-designated.
2. The host marks the event active for discovery.
3. The Peripheral has a non-empty event code.
4. A valid NFC display name of 1–64 UTF-8 bytes is available.
5. The `0x02 eventCodeHash` equals the current non-empty B004 value.
6. The complete canonical payload is no more than 512 bytes.

Organizer designation and event-active state default to false and are not
derived from membership, RPID, displayId, or proximity. Disabling either state
MUST prevent new offset-zero reads immediately. Existing snapshots may finish
under the bounded long-read policy so a Central never receives mixed bytes.

The v1 payload has no start time, end time, or TTL. Those fields would still be
unauthenticated, would require clock and skew semantics, and are unnecessary
when deliberate organizer devices control serving. Hosts stop serving when an
event is no longer active. Readers nevertheless assume that any received
payload can be stale or replayed.

## Central behavior

The discovery and existing peer-resolution paths are independent:

1. A Central directly observes a `B001` advertisement and connects to its
   Peripheral.
2. If `B005` is present, the Central may read it whether or not it already has
   an event code.
3. A valid payload produces an unauthenticated event discovery hint containing
   the name and hash. A malformed value, unsupported format version,
   `Read Not Permitted`, or missing `B005` produces no event-info hint.
4. The host renders any hint as untrusted text and requires the user to
   confirm before joining.
5. When the host later obtains an event code out of band, it computes the B004
   hash and may compare it with the hint before presenting the join action.
6. Existing B004/B002/B003 same-event peer resolution continues under its
   current rules. B005 absence, failure, or mismatch MUST NOT suppress a
   directly observed advertisement or an otherwise valid existing
   same-event detection.

A Central may deduplicate simultaneous hints with the same 8-byte hash for a
bounded discovery session. This is observer-local state and MUST NOT be
transmitted. Hash equality is not authentication and hash inequality does not
prove that either event is legitimate.

## Compatibility

- `B005` is additive to the existing `B001` service. `B002`, `B003`, and
  `B004` UUIDs, values, properties, and behavior do not change.
- Older Centrals ignore the unknown `B005` characteristic and continue the
  existing same-event flow.
- New Centrals treat a Peripheral without `B005` as event-info unavailable and
  continue direct observation and existing peer resolution.
- The advertisement remains unchanged, preserving the current 31-byte budget.
- Unknown TLVs are length-delimited and skipped by v1 readers. The reserved
  `0x10` census TLV can therefore be added later without changing v1's required
  fields or their semantics.
- No public JSON shape or schema changes in this specification.

## Security and privacy

**No device-unique persistent identifiers are added on wire.** The payload has
no device, organizer, venue, account, wallet, or public-key identifier. Its
intended linkability is limited to recognizing organizer beacons that claim
the same event display name and EventCodeHash.

The following risks are inherent and normative host behavior contains rather
than eliminates them:

- **Public readability:** any nearby Central can read the event name and hash.
  Organizers enable serving only when public event visibility is appropriate.
- **Event-level linkability:** reusing an event code reuses its eight-byte hash.
  Hosts SHOULD use a fresh, high-entropy code for each event, including each
  recurrence, so observations cannot be linked across events by a reused hash.
- **Offline guessing:** a scanner can hash likely low-entropy codes and compare
  them with B005 or B004. Hosts SHOULD generate high-entropy event codes and
  MUST NOT treat hashing as encryption.
- **Spoofing and tampering:** there is no signature or authenticated channel.
  Hosts label the result as nearby/unverified, render the name as plain text,
  and require user confirmation plus normal admission checks.
- **Replay:** a scanner or malicious Peripheral can replay old event-info.
  Hosts do not infer freshness from a successful read and organizer devices
  stop serving promptly when the event ends.
- **Conflicting hints:** two Peripherals can serve the same hash with different
  names or the same name with different hashes. A Central preserves direct
  observations, may show the conflict, and MUST NOT silently choose one as
  authenticated.
- **Census abuse:** a future `0x10` value remains an unauthenticated hint. It
  may shorten discovery only when consistent with direct observation and must
  never suppress an observed event, matching issue #82.

The raw event code MUST NOT appear in the payload, debug-local-name substitute,
unknown v1 extension, or organizer designation. The payload MUST NOT carry a
new stable identifier to compensate for the absence of the code.

## Errors and retry behavior

- A Peripheral returns `Read Not Permitted` when the serve policy is false.
- A Peripheral returns `Invalid Offset` when a continuation offset exceeds
  the immutable snapshot length.
- A Central treats a missing characteristic, denied read, connection failure,
  timeout, malformed payload, unsupported version, or invalid UTF-8 as
  event-info unavailable, not as evidence that no event exists.
- Retrying a failed connection or read follows the existing bounded GATT retry
  and backoff policy. This specification adds no unbounded retry loop.
- Parsers allocate no more than the 512-byte payload cap. Future census and
  mock implementations must preserve an explicit count/size cap and bounded
  retention.
- A B005 failure does not change B004/B002/B003 retry or detection behavior.

## Golden vectors

Hex strings are lowercase and contiguous. Hashes are independently
recomputable as the first eight bytes of SHA-256 over the listed event-code
UTF-8 bytes.

### Vector 1: existing B004 behavior vector

This vector reuses the `CORE-SPLIT-80` input and expected EventCodeHash already
covered by Barnard's pre-split behavior tests.

| Item | Value |
|---|---|
| Event code | `CORE-SPLIT-80` |
| Event-code UTF-8 | `434f52452d53504c49542d3830` |
| EventCodeHash / B004 / TLV `0x02` | `0b9f14789f13968f` |
| Event display name | `Barnard Core Split` |
| Display-name UTF-8 | `4261726e61726420436f72652053706c6974` |
| Complete B005 payload | `010100124261726e61726420436f72652053706c69740200080b9f14789f13968f` |
| Payload length | 33 bytes |

Payload decomposition:

```text
01                                      formatVersion = 1
01 0012 4261726e61726420436f72652053706c6974
                                        eventDisplayName, 18 bytes
02 0008 0b9f14789f13968f                eventCodeHash, 8 bytes
```

### Vector 2: non-ASCII UTF-8

This vector catches accidental character-count lengths, locale conversion,
and platform-specific event-code normalization.

| Item | Value |
|---|---|
| Event code | `東京-2026` |
| Event-code UTF-8 | `e69db1e4baac2d32303236` |
| EventCodeHash / B004 / TLV `0x02` | `34dc60f26d21cb94` |
| Event display name | `東京 2026` |
| Display-name UTF-8 | `e69db1e4baac2032303236` |
| Complete B005 payload | `0101000be69db1e4baac203230323602000834dc60f26d21cb94` |
| Payload length | 26 bytes |

The display-name length is 11 UTF-8 bytes, not seven Unicode scalar values.
The event code is hashed exactly as supplied; replacing its ASCII hyphen,
normalizing a different string, trimming, or changing case produces a
different hash.

## Swift and Android parity plan

Implementation is a later change and proceeds schema-first if it introduces a
public exported shape. Swift and Android land as one protocol change with the
same fixtures and observable behavior:

1. Define shared conceptual types for canonical event-info input, parsed
   event-info, parse errors, and the explicit local serve-policy state. Do not
   expose organizer designation on wire.
2. Add the same `B005` UUID and Read-only properties to each Peripheral GATT
   service while leaving `B002`–`B004` unchanged.
3. Implement canonical serialization and strict bounded parsing in pure,
   hardware-free modules. Both platforms consume the two golden payloads above
   and a shared malformed-input corpus.
4. Compute TLV `0x02` through the existing platform EventCodeHash function,
   then assert byte equality with B004 rather than creating a second hash
   implementation.
5. Add B005 discovery and reading to each Central without placing it behind the
   existing known-event B004 match gate. Keep event-info errors independent
   from same-event RPID resolution.
6. Implement immutable, bounded long-read snapshots and valid-offset behavior
   on both Peripheral platforms.
7. Mirror public behavior, reason/error names, maximum lengths, Unicode NFC
   rules, unknown-TLV skipping, and retry outcomes across Swift and Android.
8. Regenerate or synchronize any repository-owned derived mirrors in the
   implementation PR; do not hand-edit generated copies.

Parity tests include byte-for-byte serialization, parsing, unknown `0x10`
skipping, ordering and duplicate rejection, all boundary lengths, malformed
UTF-8, non-NFC input, hash/B004 mismatch, disabled serving, and long-read
offsets.

## Two-device real-BLE verification plan

Because this changes GATT service discovery, characteristic reads, ATT offset
handling, and Central sequencing, unit tests are necessary but insufficient.
The implementation is not release-ready until it satisfies the real-device
duty tracked by issue #72.

Use two physical BLE-capable devices, A and B, and test both role directions
where the operating systems permit it. Capture platform, OS version, app/SDK
commit, timestamps, and raw B005 bytes for each run.

1. Configure A as organizer-designated with Vector 1 and B as a walk-up
   Central with no event code. Verify B directly observes A, reads B005, parses
   the exact 33 bytes, shows an unverified hint, and does not auto-join.
2. Give B `CORE-SPLIT-80` out of band. Verify B computes
   `0b9f14789f13968f`, matches both B005 and B004, and only joins after explicit
   user confirmation.
3. Disable organizer designation on A while it remains joined. Verify B can
   still observe A's advertisement, B005 returns unavailable, and no
   event-info hint is synthesized.
4. Serve a different B005 hash from A in an instrumented test build while B004
   remains Vector 1. Verify A's serving guard rejects the inconsistent local
   configuration; if malformed bytes are injected below that guard, B rejects
   the hint without suppressing direct observation.
5. Exercise a payload larger than the negotiated ATT response by adding a
   well-formed unknown TLV below the 512-byte cap. Verify continuation offsets
   reconstruct one immutable payload and B skips the unknown TLV.
6. Exercise truncation, invalid offset, disconnect, reconnect, and the current
   bounded retry/backoff behavior. Verify there is no unbounded connection,
   memory, or retry growth.
7. Repeat the applicable matrix with Swift Peripheral to Android Central and
   Android Peripheral to Swift Central. Record unsupported OS role
   combinations explicitly rather than substituting simulation for real BLE.
8. Run an older Central against the new Peripheral and a new Central against
   an older Peripheral. Verify existing B004/B002/B003 same-event detection
   remains functional in both compatibility directions.

Device-lab evidence must name the exact builds and devices. Emulator,
simulator, mock Transport, and unit-vector evidence supplement but do not
replace the two-device runs required by issue #72.

## Rejected alternatives

- Event-info in advertisement data: rejected because the existing fixed UUID
  and local name already consume the constrained 31-byte payload and issue #82
  needs a larger extensible value.
- JSON, CBOR, or protobuf: rejected because this small GATT contract needs a
  byte-exact, dependency-free parser and only two required fields.
- One-byte TLV lengths: rejected because the reserved census extension may
  need more than 255 bytes while the GATT value remains capped at 512 bytes.
- Fixed-width display name: rejected because padding wastes the value budget
  and complicates canonical Unicode handling.
- Required validity timestamps: rejected because unsigned time claims do not
  create freshness, clock skew complicates parsing, and the organizer serve
  policy already controls the active interval.
- Signed event-info in v1: rejected because Barnard has no standardized
  organizer trust root or delegation chain for a walk-up Central. Signatures
  without a trust decision would add bytes without authenticating the claim.
- Replacing B004 with B005: rejected because existing Centrals depend on B004
  and a walk-up hint must not alter same-event peer resolution.

## Future work

- Define the bounded `0x10 spaceCensus` value and reconciliation rules in
  issue #82.
- Add organizer/staff signatures only after a verifier trust model and
  delegation format exist.
- Consider a new format version for an explicitly authorized
  discovery-plus-join posture; it cannot be a silent v1 extension.
- Evaluate authenticated freshness only with a concrete event-registry and
  clock model.

## References

- Issue #113: event-info GATT discovery.
- Issue #82: space census carried by event-info.
- Issue #64: existing displayId linkability and collision tradeoffs.
- Issue #72: real-device coverage required for GATT-level changes.
- Bluetooth Core Specification, Vol 3, Part G: Attribute Protocol and Generic
  Attribute Profile.

## Validation

- Review each of the five issue #113 design questions against the numbered
  decisions above: one recommendation, rationale, and rejected alternatives
  are present for each.
- Verify the wire table, TLV registry, payload bounds, ordering, unknown-field
  behavior, and GATT error behavior are implementable without inference.
- Recompute every EventCodeHash and full payload golden vector independently
  in Swift and Android.
- Run shared pure serialization/parsing fixtures and malformed-input tests on
  both platforms.
- Verify B005 and B004 hashes are byte-identical for every shared vector.
- Run the two-device matrix above and attach exact-device evidence to the
  implementation PR before release.
- Confirm the implementation adds no device-unique persistent identifier to
  Advertise, GATT, or any other on-wire shape.
- Keep mocks, snapshots, queues, and future census retention bounded.
