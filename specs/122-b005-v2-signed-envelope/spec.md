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
  trailing 64-byte signature.

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
| A | 1 | `threshold` | Exactly `0x01` |
| A+1 | 1 | `joinMode` | `0x00` open, `0x01` gated; any other value MUST be rejected |
| A+2 | 2 | `eninSeconds` | Non-zero; the event's ENIN interval |
| A+4 | 4 | `validFromEnin` | |
| A+8 | 4 | `validThroughEnin` | |
| A+12 | 4 | `relayExpiresAtEnin` | |
| A+16 | 1 | `maxRelayHops` | Exactly `0x02` |
| A+17 | 8 | `eventCodeHash` | `SHA256(UTF8(EventCode))[0:8]`; equals the B004 value |
| A+25 | 1 | `displayNameLength` | `1..64` |
| A+26 | L | `eventDisplayName` | NFC UTF-8; no U+0000–U+001F or U+007F |
| A+26+L | 2 | `certLength` | `0` = authority-direct; `> 0` = delegate mode |
| A+28+L | C | `delegationCert` | COSE_Sign1, byte-identical to the bundle copy; absent when `C = 0` |
| A+28+L+C | 1 | `signerIndex` | Index into `authorityKeys` |
| A+29+L+C | 64 | `signature` | Compact `r‖s`, low-S |

Total envelope length is `167 + 33n + L + C`, and it MUST equal `signedEnvelopeLength` exactly.

### Two signing modes

| `certLength` | Mode | Envelope signed by | `signerIndex` selects |
|---|---|---|---|
| `0` | authority-direct | `authorityKeys[signerIndex]` | the envelope signer |
| `> 0` | delegate | the cert's `delegatePublicKey` | the authority key that signed the cert |

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
signature = ECDSA-secp256k1 over sigDigest, compact r‖s, low-S
```

The domain tag follows this repository's existing convention (`barnard-<name>:v1`, no NUL), matching
`barnard-self-proof:v1`, `barnard-adoption-sign:v1` and the rest. Because `tbs` spans the
certificate bytes, the envelope signature binds this certificate to this body: a valid certificate
for one event cannot be pasted onto another event's body.

Barnard exposes **no** `verify(publicKey, digest, signature)` primitive on either platform; both do
recover-and-compare. An implementation MUST recover with recovery id `0`, then `1`, and accept only
if one of them recovers the expected key byte-for-byte. High-S signatures MUST be **rejected**, not
normalised — normalising would give one logical signature two encodings and split the payload digest
that spec 134 deduplicates on.

## Verification

Steps 1–7 require no network and produce the `authenticated` tier. Step 8 is the online upgrade.

1. **Container.** `formatVersion == 0x03`; total ≤ 512; `signedEnvelopeLength` ends exactly at the
   container boundary; `relayHopCount <= 2`.
2. **Structure.** `envelopeVersion == 0x01`; `n` in `1..8`; each authority key a valid compressed
   point; keys strictly ascending; `threshold == 0x01`; `joinMode` in `{0,1}`; `eninSeconds != 0`;
   `maxRelayHops == 0x02`; `L` in `1..64`; `signerIndex < n`; and the length arithmetic MUST land
   exactly on the envelope boundary.
3. **Display name.** Valid UTF-8, NFC, no forbidden controls. Reject; do not sanitise.
4. **Key set.** `keySetBytes = A3 01 01 02 (0x80|n) (58 21 key)*n 03 01`;
   `keySetDigest = SHA256("levarac:event-key-set-digest:v1\0" || keySetBytes)`.
5. **Identity.**
   `eventId = keccak256(keccak256("levarac:event:v1") || zero12‖registrar || zero12‖anchorOperator
   || nonce || keySetDigest)`.
   This is the self-certification step: it binds the carried key set to the event identity with no
   registry read.
6. **Mode.**
   - `C == 0`: the signing key is `authorityKeys[signerIndex]`.
   - `C > 0`: decode the certificate per the Draft 0007 CDDL — exactly labels 1–6, `version == 1`,
     `delegatePublicKey` a valid compressed point, `roles` non-zero with no unassigned bit,
     `eninStart <= eninEnd`. Verify its COSE signature against `authorityKeys[signerIndex]` over
     `Sig_structure = ["Signature1", protected, h'', payload]`. Require `cert.eventId == eventId`,
     `roles & anchor != 0`, and `cert.eninStart <= currentEnin <= cert.eninEnd` (inclusive). The
     signing key is `cert.delegatePublicKey`.
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

> **This subsection is pending a maintainer ruling and is deliberately isolated.** The wire format
> above is identical under either outcome; only the gate below changes. If the ruling is that
> offline verification suffices, this subsection also becomes an erratum to spec 134 steps 3 and 6
> and testable scenario 2.

| Tier | Established | Needs network |
|---|---|---|
| `authenticated` | steps 1–7: the holder of this event's authority key set authored these exact bytes | no |
| `registered` | additionally, an anchored `EventDefinitionV1` agrees | yes |

Recommended policy: **relay and verified display gate on `authenticated`**, and `registered` is an
additive upgrade. Gating relay on `registered` disables the feature at exactly the venues spec 134
exists to serve. Recomputing `eventId` from its preimage obtains the same authority binding a
definition read would, and the authority key set is immutable per event, so there is no rotation a
read could reveal that the recomputation misses.

Spec 134 as ratified gates both display and relay on the on-chain definition (steps 3 and 6, and
scenario 2's "unavailable on-chain definitions ⇒ no verified display, no relay lease"). Adopting the
recommended policy therefore requires that erratum; it is not a matter of implementation latitude.

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

## Byte budget

Caps: envelope ≤ 508, complete container ≤ 512.

| Mode | n | L | Envelope | Container |
|---|---:|---:|---:|---:|
| authority-direct | 1 | 64 | 264 | 268 |
| authority-direct | 8 | 64 | 495 | 499 |
| delegate (C = 222) | 1 | 64 | 486 | 490 |
| delegate (C = 222) | 2 | 64 | 519 | **over** |

The certificate is 222 bytes as published in the Parallax positive vector. Consequences that
implementations MUST respect rather than discover:

- **Delegate mode supports exactly one authority key** at full display-name length; two keys
  overrun by 11 bytes. Authority-direct supports up to eight. `EventKeySetV1` permits multi-key sets
  in general, so this is a real limitation of carrying an event definition through a 512-byte GATT
  value, recorded here rather than hidden. The length arithmetic in step 2 enforces it; no separate
  rule is needed.
- The smallest possible envelope is 201 bytes (authority-direct, `n=1`, `L=1`) and the smallest
  delegate envelope is 423. Spec 134's stated `signedEnvelopeLength` range of `1..508` is far wider
  than this format can produce.

## Conformance vectors

`test-vectors/b005-envelope-v2.txt`, in the repository's existing `key=value` format. The event
identity is **shared with Parallax's own fixtures**: `event_id` is byte-identical to the `eventId`
in `protocol/vectors/positive/event-definition-v1.json`, and vector 2 carries the exact
`signedDelegationCertHex` bytes from `protocol/vectors/positive/delegation-cert-v1.json`. That
single shared value is what pins cross-repository interoperability; everything else is internal.

- **Vector 1** — authority-direct, hop 0, 58-byte display name: 258-byte envelope, 262-byte
  container.
- **Vector 2** — delegate mode, hop 1, carrying the Parallax certificate verbatim: 440-byte
  envelope, 444-byte container.

Both platforms MUST reproduce, from the fixture inputs alone: `event_key_set_digest`, `event_id`,
`open_code_v1`, `event_code_hash`, both `signature_digest` values, and both containers byte for
byte; and MUST verify both vectors through the full path above.

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
