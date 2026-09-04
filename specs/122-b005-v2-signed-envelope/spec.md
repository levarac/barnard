# B005 v2 Signed Event-Info Envelope

**Status:** Proposed (issue #122). Spec 134 depends on this document for the signed bytes that
relays copy verbatim; it states that "Until those are fixed, a B005 v2 implementation is blocked".
Implementation is tracked in #128.

## Problem statement

[`Specification 113`](../113-event-info-discovery/spec.md) deliberately scoped B005 as an
**unauthenticated** discovery hint: authenticating the event name, the event-code hash, or the
organizer is an explicit non-goal there. [`Specification 134`](../134-b005-participant-relay/spec.md)
now has participant devices re-broadcast event info, which makes that gap load-bearing — a relayed
value travels further than the radio of whoever created it, so a receiver cannot fall back on "I
heard this near the venue" as weak evidence.

This specification defines the signed envelope that spec 134 carries: its byte layout, its
verification path, and the conformance vectors both platforms share. It closes the two gaps issue
#122 names — fabricated events, and a genuine event-code hash paired with a misleading display name
— and it does so **without requiring network connectivity at verification time**, because venues are
where connectivity is worst and a walk-up device has not joined anything yet.

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** in this document are
to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all
capitals.

## Goals

- Define a byte-exact, versioned, bounded envelope that fits the existing 512-byte B005 value.
- Let a receiver with **no network access** establish that the event authority authored these exact
  display-name, event-code-hash and validity bytes.
- Carry a `DelegationCertV1` byte-identical to the copy published in the Parallax observation
  bundle, so the two can be compared without re-encoding either.
- Give Swift and Android one shared, independently recomputable vector set.
- Say plainly what the envelope does **not** establish, so hosts do not overclaim.

## Non-goals

- Granting admission, joining, or carrying the raw event code.
- Proving that a signer is physically present, is an organizer of anything in the real world, or
  that the event is registered on chain.
- Liveness. This version carries no per-window freshness proof (issue #122 Proposal B is deferred);
  a host MUST NOT present a verified envelope as "live" or "currently broadcasting".
- Relay mechanics, density control, hop limits and expiry behaviour, which are spec 134's.
- Changing the advertisement, `B002`, `B003`, or v1 `B005` behaviour.

## Glossary

- **authority key set**: the `EventKeySetV1` for an event — a non-empty, strictly sorted, unique
  array of compressed secp256k1 public keys with threshold 1. Immutable per event.
- **self-certifying `eventId`**: an `eventId` that commits to the authority key set, so recomputing
  it from its preimage binds that key set to that event identity with no registry read.
- **authority-direct mode**: the envelope is signed by an authority key; no certificate is carried.
- **delegate mode**: the envelope is signed by a delegate key designated by a `DelegationCertV1`
  that the envelope carries.
- **tbs**: the to-be-signed byte range — the envelope from offset 0 up to, but excluding, its
  trailing 65-byte signature.

## Delivery container

The container is spec 134's, restated here because this document fixes its version byte.

| Offset | Size | Field | Rule |
|---:|---:|---|---|
| 0 | 1 | `formatVersion` | Exactly `0x03` |
| 1 | 1 | `relayHopCount` | `0` direct; `1` or `2` relay |
| 2 | 2 | `signedEnvelopeLength` | Big-endian; the value MUST end exactly at the container boundary |
| 4 | variable | `signedEnvelope` | Copied byte-for-byte by relays |

The complete value MUST be at most 512 bytes.

**Why `0x03` and not `0x02`.** `0x02` is already taken. `specs/123-128-adoption-credential-census`
defines a different "B005 format version 2" (`0x02` followed by four strictly-increasing TLVs,
323–386 bytes) and that format is implemented and released — `BarnardAdoptionCensus.swift` declares
`formatVersion: UInt8 = 2`, and the same declaration is present at tag `v0.6.0`, which downstream
consumers pin. Assigning `0x03` to the relay container leaves the released bytes untouched. A
one-line erratum to spec 134 records the change.

## Signed envelope

Fixed offsets, no TLVs, and **no unknown-field skipping**: the signature covers every byte, so an
ignorable field would be a hole in what the signature means. A future shape takes a new
`envelopeVersion`. Integers are unsigned and big-endian.

Let `n` be `authorityKeyCount`, `L` be `displayNameLength`, `C` be `certLength`, and
`A = 74 + 33n`.

| Offset | Size | Field | Rule |
|---:|---:|---|---|
| 0 | 1 | `envelopeVersion` | Exactly `0x01` |
| 1 | 20 | `registrar` | EVM address; `eventId` preimage |
| 21 | 20 | `anchorOperator` | EVM address; `eventId` preimage |
| 41 | 32 | `nonce` | `eventId` preimage |
| 73 | 1 | `authorityKeyCount` | `1..8` |
| 74 | 33·n | `authorityKeys` | Compressed secp256k1, strictly ascending, unique |
| A | 1 | `joinMode` | `0x00` open, `0x01` gated; any other value MUST be rejected |
| A+1 | 2 | `eninSeconds` | Non-zero; the event's ENIN interval. Mode is pinned to `fixedLength` for envelope v1 |
| A+3 | 4 | `validFromEnin` | |
| A+7 | 4 | `validThroughEnin` | |
| A+11 | 4 | `relayExpiresAtEnin` | |
| A+15 | 1 | `maxRelayHops` | Exactly `0x02` |
| A+16 | 8 | `eventCodeHash` | `SHA256(UTF8(EventCode))[0:8]`; equals the B004 value |
| A+24 | 1 | `displayNameLength` | `1..64` |
| A+25 | L | `eventDisplayName` | NFC UTF-8; no U+0000–U+001F or U+007F |
| A+25+L | 1 | `certLength` | `0` = authority-direct; `> 0` = delegate mode |
| A+26+L | C | `delegationCert` | COSE_Sign1, byte-identical to the bundle copy; absent when `C = 0` |
| A+26+L+C | 65 | `signature` | `r‖s‖v`, low-S, `v` in `{0,1}` |

Total envelope length is `165 + 33n + L + C`, and it MUST equal `signedEnvelopeLength` exactly.

There is deliberately **no `threshold` field** — `EventKeySetV1` pins it to `1`, so a carried copy
could only ever hold one value and the receiver reconstructs `03 01` unconditionally when it rebuilds
the key-set bytes. There is likewise **no signer index**: public-key recovery does not take a
candidate key as input, so a verifier recovers at most twice and then tests set membership for free.
The certificate's signer is identified by its COSE `kid`, which must be checked anyway.

`certLength` is one byte because the CDDL bounds the certificate well under 256 (payload 78–94,
protected header 61, COSE framing); the published certificate is 222 bytes. A future certificate
that exceeds 255 bytes requires a new `envelopeVersion`.

### Two signing modes

| `certLength` | Mode | Envelope signed by | Accepted when |
|---|---|---|---|
| `0` | authority-direct | an authority key | the recovered key is a member of `authorityKeys` |
| `> 0` | delegate | the certificate's `delegatePublicKey` | the recovered key equals it exactly |

Authority-direct exists because an organizer-operated beacon needs no delegation to speak for its
own event. Delegate mode is for venue and staff devices; there the certificate MUST be carried
byte-identical to the copy published in the observation bundle. A relay copies the whole envelope
verbatim, so those bytes reach the bundle unchanged and a verifier can compare the two copies
directly. An implementation MUST treat the certificate as an opaque byte range — parse its fields,
never re-serialise it.

### There is no `eventId` field

The receiver **computes** `eventId` from `registrar`, `anchorOperator`, `nonce` and the key-set
digest; that computation is its definition, not a claim to be checked. In delegate mode the
certificate also carries `eventId` and the two MUST agree — that agreement is what ties the
certificate to this envelope body.

### Signature construction

```text
sigDigest = SHA256("barnard-b005-event-info:v1" || tbs)
signature = ECDSA-secp256k1 over sigDigest, 65 bytes r‖s‖v, low-S, v in {0,1}
```

The domain tag follows this repository's existing convention (`barnard-<name>:v1`, no NUL), matching
`barnard-self-proof:v1`, `barnard-adoption-sign:v1` and the rest. The 65-byte recoverable form also
matches house convention (`specs/092-owner-key`, `specs/123-128-adoption-credential-census`). `v` sits
in the signature field, outside `tbs`, because it is not knowable until after signing; a wrong `v`
can only cause rejection, never acceptance, since the recovered key is still checked against keys the
envelope commits to.

`v` values `2` and `3` (the `r + n < p` case, probability about 2⁻¹²⁸) MUST be rejected, consistent
with `specs/158-secp256k1-ecdsa-profile`. High-S signatures MUST likewise be **rejected**, not
normalised: normalising gives one logical signature two encodings, which splits the payload digest
spec 134 deduplicates on. The certificate's own COSE signature is 64-byte compact with no recovery
id, so a verifier there recovers with `0` then `1` and compares.

**Which check binds what** — worth stating because it is easy to attribute to the wrong step:

- The equality `cert.eventId == computed eventId` (verification step 6) is the **identity** binding.
  It is what rejects a certificate for event X pasted onto a body built from event Y's preimage, and
  it runs before any signature does.
- The envelope signature over `tbs`, which spans the certificate bytes, is the **integrity** binding.
  It stops a third party assembling an envelope at all, and stops the certificate being swapped
  underneath an existing signature.

Both are required; neither substitutes for the other.

## Verification

Steps 1–7 require no network and produce the `authenticated` tier. Step 8 is the online upgrade.

1. **Container.** `formatVersion == 0x03`; total ≤ 512; `signedEnvelopeLength` ends exactly at the
   container boundary; `relayHopCount <= 2`.
2. **Structure.** `envelopeVersion == 0x01`; `n` in `1..8`; each authority key a valid compressed
   point; keys strictly ascending and unique; `joinMode` in `{0,1}`; `eninSeconds != 0`;
   `maxRelayHops == 0x02`; `L` in `1..64`; and the length arithmetic MUST land exactly on the
   envelope boundary.
3. **Display name.** Valid UTF-8, NFC, no forbidden controls. Reject; do not sanitise.
4. **Key set.** `keySetBytes = A3 01 01 02 (0x80|n) (58 21 key)*n 03 01`;
   `keySetDigest = SHA256("levarac:event-key-set-digest:v1\0" || keySetBytes)`.
5. **Identity.**
   `eventId = keccak256(keccak256("levarac:event:v1") || zero12‖registrar || zero12‖anchorOperator
   || nonce || keySetDigest)`.
   This is the self-certification step: it binds the carried key set to the event identity with no
   registry read.
6. **Mode.**
   - `C == 0` (authority-direct): the signing key is whichever key the envelope signature recovers
     to, and it MUST be a member of `authorityKeys`.
   - `C > 0` (delegate): decode and check the certificate as below, then the signing key is
     `cert.delegatePublicKey`.

   **Certificate checks MUST match Parallax's verifier exactly**, or barnard's BLE verifier will
   accept certificates the bundle verifier rejects — a silent divergence that no barnard-only test
   would catch. Required, all of them:

   - COSE structure: tag `18` with exactly four items; the unprotected map exactly empty; the
     signature exactly 64 bytes.
   - Protected header: exactly the keys `{1, 3, 4}`; `alg == -47` (ES256K); content type exactly
     `application/vnd.levarac.delegation-cert+cbor`.
   - `kid == SHA-256("levarac:cose-kid:v1\0" || signerPublicKey)[0:8]`. The `kid` selects which
     authority key to check the certificate signature against; it MUST select exactly one.
   - Payload: exactly labels 1–6; `version == 1`; `delegatePublicKey` a valid compressed point;
     **`roles == 1` exactly** — the CDDL pins the field to the literal `1`, so a bitmask test such
     as `roles & anchor != 0` is wrong and would accept `roles == 3`, which Parallax rejects;
     `eninStart <= eninEnd`.
   - `cert.eventId == eventId` as computed in step 5.
   - `cert.eninStart <= currentEnin <= cert.eninEnd`, inclusive per Draft 0007. Certificate ENIN
     values are CBOR unsigned integers up to 2⁵³ and MUST be decoded as 64-bit.
   - Verify the COSE signature over `Sig_structure = ["Signature1", protected, h'', payload]`.

   **Ordering.** A receiver MUST deduplicate by `SHA256(signedEnvelope)` before doing any
   cryptography, and within a single envelope MUST run every cheap check — structure, display name,
   key-set digest, `eventId` recomputation and its equality with `cert.eventId`, `roles`, both ENIN
   windows, and the open-code binding — before either signature recovery. A distinct envelope then
   costs at most three recoveries once, and a repeat observation of the selected digest costs none.
   Spec 113's two-attempts-per-peer-per-session budget bounds an attacker feeding distinct invalid
   envelopes.
7. **Bindings and window.**
   - If `joinMode == open`, require
     `eventCodeHash == SHA256(UTF8(lowercaseHex(eventId)))[0:8]`, where `lowercaseHex` is 64
     lowercase hex characters, no `0x`, leading zeroes preserved. If `joinMode == gated`, this
     derivation does not apply and MUST NOT be attempted.
   - Verify `signature` over `sigDigest` against the mode's signing key; enforce low-S.
   - Require `validFromEnin <= currentEnin < relayExpiresAtEnin <= validThroughEnin` and
     `relayExpiresAtEnin - validFromEnin <= 12`.
   - If ENIN cannot be established, **fail closed**: no relay, no verified display.
8. *(Online, optional.)* Obtain and verify the anchored `EventDefinitionV1` for this `eventId` and
   require agreement. Success raises the tier to `registered`.

### Receiver policy — the display and relay gate

**Ratified by the maintainer, 2026-09-05.** This section is normative; it is no longer open.

A conforming implementation MUST expose the verification state explicitly, so a host cannot infer
one from another:

| State | Established | Needs network |
|---|---|---|
| `UNVERIFIED` | nothing, or checks still in progress | — |
| `RADIO_SELF_VERIFIED` | steps 1–7: the signature verifies and `eventId` is self-consistent with the carried key set. **Registration is not confirmed.** | no |
| `REGISTRY_VERIFIED` | additionally, an anchored `EventDefinitionV1` on the pinned block agrees | yes |

Radio alone reaches `RADIO_SELF_VERIFIED` and no further. That state MUST NOT be presented as
"verified" or "registered" to a user.

The gates:

- **Candidate display** MAY proceed at `RADIO_SELF_VERIFIED`, before any chain read. This is the
  one thing the offline path buys, and it is what makes discovery work where connectivity does not.
- **Relaying** MUST NOT proceed below `REGISTRY_VERIFIED`.
- **Joining, per-event key generation, and beginning to record observations** MUST NOT proceed below
  `REGISTRY_VERIFIED`. A host MUST NOT enter a join state asynchronously and fail it afterwards.

Registration confirmation means verification against the **pinned block**, not a bare
`EventRegistry` existence read: the anchored `EventDefinitionV1` supplies `validFrom`/`validUntil`
and `joinMode`, which an existence read does not. A definition whose `joinMode` disagrees with the
envelope's, or which carries none, is an invalidation and MUST tear down any relay state. An
*unreachable* registry is not an invalidation — it simply leaves the state at
`RADIO_SELF_VERIFIED`.

Consequently `specification 134` changes **for display only**: its step 6 permits candidate display
in the self-verified state before the chain read, while relay continues to require it. A separate
erratum records this.

The reasoning behind the split came from an external design review. Its central point is that radio
alone cannot prove registration — an attacker can mint a self-consistent unregistered event freely —
so the offline path earns an earlier *display*, not an earlier *trust decision*. What it does buy is
real: impersonating an existing event, or pairing a genuine event-code hash with a misleading
display name, both become infeasible for a third party at the moment a candidate first appears.

**On defining a reduced profile.** The same review proposed making the offline context optional
except for organizer-managed anchor devices, on the grounds that carrying it everywhere is too
expensive. That estimate assumed both a static authority signature and a per-window liveness
signature (issue #122 Proposal A *and* B together), which put the envelope over 512 bytes. This
version defers Proposal B, and the measured envelope is 256 bytes authority-direct and 438 bytes in
delegate mode, both inside the cap. Since a relay copies the envelope byte-for-byte and cannot add
context an origin omitted, a reduced profile would let an origin emit envelopes no walk-up device
can verify — reintroducing the gap this specification exists to close, to save bytes measurement
says are available. One shape is therefore specified, and it always carries the full context, which
also satisfies the ratified requirement that organizer and anchor devices MUST carry it.

## What this does not establish

A host MUST NOT present a verified envelope as proof of any of the following, and this section
exists because unbacked assurance has had to be withdrawn from a consumer product before.

- **Not registration.** `EventRegistry.register` takes `msg.sender` as the registrar with no access
  control: registration is permissionless. A fabricated but fully self-consistent event — attacker
  generates a key set, derives an `eventId` from it, signs an envelope — passes every offline check,
  and can be registered too. `registered` proves existence, not legitimacy.
- **Not "organizer".** Both tiers prove control of the event's authority key set and nothing more.
  A host wanting an organizer claim needs a registrar allowlist, which it MAY apply offline because
  `registrar` is carried in the envelope.
- **Not liveness.** No per-window freshness is carried. An envelope MAY be pre-signed for a whole
  event in advance, which is the intended operating mode for a cold authority key. The 12-ENIN bound
  limits replay of a captured envelope; it says nothing about whether the signer is currently active.
- **Not location.** A genuine unexpired envelope replayed at another venue passes every check.
- **Not "this device".** What is established is that an authorized signer produced these bytes — not
  that the GATT server currently being read is that signer. Under spec 134 any participant may
  re-serve the envelope byte-for-byte, so the serving peer is frequently *not* the delegate. A host
  MUST NOT present a verified envelope as evidence about the device it was read from.
- **Not integrity of the hop count.** `relayHopCount` sits outside the signed envelope and is
  unauthenticated by construction. The two-hop limit is delivery control for conforming
  implementations, not a security boundary; an attacker resets it freely.

One residual deserves naming because delegate mode introduces it. A **compromised or stolen delegate
device** can sign arbitrary display names under a genuine `eventId` until its certificate's
`eninEnd`. Draft 0007 provides no revocation and names short windows as the mitigation. Step 7's
open-code binding still pins `eventCodeHash` to the `eventId`, so a compromised delegate cannot
change *which* event it speaks for — only what name it displays for that event. Authorities SHOULD
therefore issue certificates with the shortest practical ENIN window.

## Long reads and ENIN rollover

A 256- to 486-byte value does not fit one ATT response at common MTUs, so it is read across several
PDUs. ATT provides no atomicity across those PDUs; keeping the value stable is this layer's
responsibility, and getting it wrong produces a signature failure rather than an obvious error —
fragments from two different generations concatenate into bytes that were never signed.

Specification 113 already defines the mechanism: one immutable snapshot per connected Central,
keyed by Central identity plus a connection epoch, replaced only by an accepted offset-zero request,
and released on completion, failure, disconnect, or a 30-second inactivity timeout. A v2 envelope
MUST use it unchanged. Concretely: an ENIN rollover, a re-issued envelope, a hop-count update, or a
selection change MUST NOT alter an in-flight snapshot, and a Peripheral MUST NOT splice new bytes
into one. The receiving Central still rejects a completed snapshot whose window has expired.

## Privacy

Specification 113 decision 4 promised no new on-wire public key, and spec 134's tracking bullet
repeats it. **Delegate mode changes that**, and the change is deliberate rather than overlooked.

The certificate carries the delegate device's per-event public key. Draft 0007 states that this key
is stable within one event and, given correct Barnard derivation, unlinkable across events, and that
publishing it is precisely the point of designation. So it identifies the designated device *within*
the event — the same linkability the organizer beacons already have through a shared display name
and event-code hash — and it is not a cross-event identifier.

What it is **not** is a relayer identifier. A relaying participant contributes no key, no handle and
no identifier of its own; it copies bytes. Nothing added here lets an observer distinguish or count
relaying devices, which is the boundary `specs/123-128` and spec 134 both draw. Authority-direct mode
adds no key at all beyond the authority key set that `eventId` already commits to.

## Byte budget

Caps: envelope ≤ 508, complete container ≤ 512.

Envelope length is `165 + 33n + L + C`.

| Mode | n | L | Envelope | Container | |
|---|---:|---:|---:|---:|---|
| authority-direct | 1 | 58 | **256** | 260 | vector 1, measured |
| authority-direct | 1 | 64 | 262 | 266 | |
| authority-direct | 8 | 64 | 493 | 497 | |
| delegate (C = 222) | 1 | 18 | **438** | 442 | vector 2, measured |
| delegate (C = 222) | 1 | 64 | 484 | 488 | |
| delegate (C = 222) | 2 | 64 | 517 | — | **over** |

The two bolded rows are the byte lengths of the committed conformance vectors, not arithmetic.

The certificate is 222 bytes as published in the Parallax positive vector. Consequences that
implementations MUST respect rather than discover:

- **Delegate mode supports exactly one authority key** at full display-name length; two keys
  overrun by 11 bytes. Authority-direct supports up to eight. `EventKeySetV1` permits multi-key sets
  in general, so this is a real limitation of carrying an event definition through a 512-byte GATT
  value, recorded here rather than hidden. The length arithmetic in step 2 enforces it; no separate
  rule is needed.
- The smallest possible envelope is 199 bytes (authority-direct, `n=1`, `L=1`) and the smallest
  delegate envelope is 421. Spec 134's stated `signedEnvelopeLength` range of `1..508` is far wider
  than this format can produce.

## Conformance vectors

`test-vectors/b005-envelope-v2.txt`, in the repository's existing `key=value` format. The event
identity is **shared with Parallax's own fixtures**: `event_id` is byte-identical to the `eventId`
in `protocol/vectors/positive/event-definition-v1.json`, and vector 2 carries the exact
`signedDelegationCertHex` bytes from `protocol/vectors/positive/delegation-cert-v1.json`. That
single shared value is what pins cross-repository interoperability; everything else is internal.

- **Vector 1** — authority-direct, hop 0, 58-byte display name: 256-byte envelope, 260-byte
  container.
- **Vector 2** — delegate mode, hop 1, carrying the Parallax certificate verbatim: 438-byte
  envelope, 442-byte container.

Both platforms MUST reproduce, from the fixture inputs alone: `event_key_set_digest`, `event_id`,
`open_code_v1`, `event_code_hash`, `cose_kid_authority`, both `signature_digest` values, and both
containers byte for byte; and MUST verify both vectors through the full path above.

They MUST additionally load Parallax's own certificate vectors verbatim and agree with them:
reproduce `sigStructureHex`, `signatureDigestHex` and the `kid` from
`protocol/vectors/positive/delegation-cert-v1.json`, and **reject every case** in
`protocol/vectors/negative/delegation-cert-v1.json` (inverted window, zero roles, unassigned role
bit, unknown version, unknown label, missing label, wrong event, foreign signer, corrupted
signature, substituted key set). This is the check that catches divergence from Parallax's verifier,
which no barnard-only test can see.

Signature fixtures are **verify-only**. They carry pre-signed bytes so that libsecp256k1's
RFC 6979 determinism and BouncyCastle's non-deterministic default never have to agree. Signing is
outside this specification's scope; if barnard later exposes it, that change mandates RFC 6979 plus
low-S on both platforms and vectors the output.

## Testable scenarios

1. **Positive.** Both vectors verify on Swift and Kotlin, byte-identically, in both modes.
2. **Structural rejection.** Every bound in steps 1–3: wrong `formatVersion`, length not ending at
   the container boundary, `n` out of range, non-ascending or duplicate keys, `threshold != 1`,
   `maxRelayHops != 2`, `joinMode` outside `{0,1}`, `eninSeconds == 0`, `signerIndex >= n`, `L`
   out of range, non-NFC name, forbidden control character, and arithmetic that does not land on the
   envelope boundary.
3. **Cryptographic rejection.** Single-byte mutation of each signed field and of each signature; a
   high-S counterpart of a valid signature; a certificate whose `eventId` does not match the
   recomputed one; a certificate with `roles == 0` or an unassigned role bit; a certificate outside
   its own ENIN window; an `eventId` that does not match its preimage; and, for an open event, an
   `eventCodeHash` that is not the derived one.
4. **Expiry edges.** `currentEnin` at `validFromEnin - 1` (reject), `relayExpiresAtEnin - 1`
   (accept), and `relayExpiresAtEnin` (reject — the window is half-open); and a lifetime exceeding
   12 ENIN (reject).
5. **Cross-format.** A census v2 payload (`specs/123-128`, leading byte `0x02`) MUST be rejected by
   this container parser, and a container of this format MUST be rejected by the census parser.
6. **Fail-closed.** With ENIN unestablished, no envelope verifies as `authenticated` and no relay
   lease is taken.

## Compatibility

B005 v1 (spec 113) continues to parse under its existing unauthenticated-hint semantics and MUST
NOT be relayed or enter the v2 verified path. The census format at `0x02` is untouched. A Central
that does not recognise `0x03` treats event-info as unavailable and continues the existing
B004/B002/B003 flow.

## Reconciliation of the external design review

An external design review raised ten points against issue #122's original text. Each is recorded
here as folded in or rejected, so none is silently dropped. Several were defects in the **issue
text** rather than in this specification; those are noted as such and corrected on the issue.

1. **`eventId` does not commit to a single authority key.** Correct, and #122's "possession of the
   ID is enough to verify signatures by that authority" is wrong. `eventId` commits to the
   registration fields and the *key-set digest*. Holding the ID alone verifies nothing. **Folded
   in:** this specification never derives a key from the ID; it carries the exact key set and
   recomputes the digest. Issue text corrected separately.
2. **A 33-byte key plus `keySetDigest` cannot prove key-set membership.** Correct: an attacker
   could sign with their own key and place any digest in the preimage. The minimum sufficient form
   is `registrar`, `anchorOperator`, `nonce`, and the *exact* `EventKeySetV1` bytes. **Folded in** —
   that is exactly the envelope's layout, which is why there is no `keySetDigest` field.
   Relatedly, #122's claim that this "closes fabricated (unregistered) events" is wrong; see
   *What this does not establish*.
3. **Certificate size.** #122 estimated ~105 bytes. The published `DelegationCertV1` is **222
   bytes** measured. **Folded in** throughout the byte budget.
4. **A liveness signature must bind more than the ENIN.** Correct: signing a bare window number
   lets a fresh signature be moved onto unrelated content. **Deferred with Proposal B**, which this
   version does not implement. Recorded as binding for when it lands: it MUST cover a domain tag,
   `eventId`, a digest of the signed core, a digest of the certificate, and `issuedEnin`. Note the
   present envelope signature already spans the entire `tbs`, including the certificate, so this
   version has no bare-window signature to weaken.
5. **"The serving device is organizer-designated" is not provable.** Correct, and sharpened by
   spec 134: any participant may re-serve the bytes, so the serving peer is frequently not the
   signer. **Folded in** as an explicit bullet in *What this does not establish*.
6. **Freshness and relay-eligibility are two different states.** **Folded in.** With pre-issuance
   permitted, `validFromEnin` is the issue point, and a receiver MUST distinguish:
   `currentEnin == validFromEnin` (freshly issued);
   `validFromEnin <= currentEnin < relayExpiresAtEnin` (authentic and relay-eligible);
   `currentEnin >= relayExpiresAtEnin` (expired). Neither of the first two is evidence of presence
   or of a live transmitter.
7. **The hop counter must sit outside the signed core.** **Folded in** and already structural: the
   hop byte lives in the delivery container, never in the envelope. What relays copy byte-for-byte
   is the `signedEnvelope` range; the container is rebuilt with the incremented hop. An explicit
   bullet records that the count is unauthenticated and is delivery control, not a boundary.
8. **Certificate validity and event validity must not be conflated.** **Folded in.** They are
   separate fields checked separately: `cert.eninStart`/`eninEnd` bound the delegate's authority,
   `validFromEnin`/`validThroughEnin` bound the event definition. A "happening now" judgement uses
   the event window; the certificate window alone MUST NOT be read as the event being live.
9. **Reusing the `anchor` delegation for the #82 census.** **Rejected as out of scope here.**
   Census authority lives in `specs/123-128-adoption-credential-census` and issue #82, and Draft
   0007 assigns `anchor` alone for v1. This specification neither grants nor implies census
   authority, and its relay observations are barred from feeding census by spec 134.
10. **Long reads must not straddle a value change.** Correct and applicable. **Folded in** as
    *Long reads and ENIN rollover*, binding this format to spec 113's existing immutable per-Central
    snapshot rules.

Two factual corrections to the review itself, recorded because the numbers propagate. It states
`eventId = SHA-256(registrar || operator || nonce || keySetDigest)`; the derivation is **keccak-256**
over a domain-prefixed, 12-byte-left-padded preimage, verified against Parallax's own fixture. And
its byte-budget table concludes that an exact one-key key set "exceeds 512 bytes"; that assumed
Proposal A and B together plus a separate `keySetDigest`. Measured against this specification, the
envelope is 256 bytes authority-direct and 438 bytes in delegate mode.

## Known divergences from Parallax

Recorded so implementers do not rediscover them. None is resolved here.

1. `EventDefinitionV1` carries no display name, so spec 134 step 4's display-name agreement check
   has no counterpart on chain. The authority's signature over this envelope is the only source.
2. Draft 0007 assigns one role bit, `anchor`, defined over the delegate's Observations rather than
   over event-info broadcast. This version reads `anchor` as also authorising event-info signing;
   that reading is being recorded in Draft 0007 rather than assumed here.
3. `specs/123-128-adoption-credential-census` defines its own `eventId` as `SHA-256(authorityKey)`,
   which is not the Parallax keccak derivation used here. Two notions of `eventId` therefore exist
   in this repository. Tracked separately; the relay path uses the Parallax derivation.

## References

- [`specs/113-event-info-discovery`](../113-event-info-discovery/spec.md)
- [`specs/134-b005-participant-relay`](../134-b005-participant-relay/spec.md)
- [`specs/123-128-adoption-credential-census`](../123-128-adoption-credential-census/spec.md)
- Barnard issue #122 (this specification), #128 (implementation), #82 (census).
- Levarac Parallax: `protocol/spec/v0.1/event-definition.md` (EventKeySetV1, EventDefinitionV1,
  `openCodeV1`), Draft 0007 (`DelegationCertV1`), `protocol/cddl/delegation-cert-v1.cddl`.
- RFC 2119, RFC 8174, RFC 6979, RFC 8949 (deterministic CBOR), RFC 9052 (COSE).
