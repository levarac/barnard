# AdoptionCredential and Signed Per-Window Census

## Problem statement

`B005 event-info` format version 1 is intentionally an unauthenticated
discovery hint. Its `B004 EventCodeHash` is useful after a person has an event
code, but it cannot authorize a code-less open-event admission and cannot make
a majority claim trustworthy. Counting radios, RPIs, `peripheralId` values,
relayers, or raw scan observations would let one participant inflate a local
majority.

Issues #123 and #128 add one coherent, versioned protocol slice:

- a signed, registry-bound **AdoptionCredential** for code-less admission to
  an open event; and
- a signed **SignedWindowCensus** whose count provenance is a deliberately
  explicit trusted Census Authority boundary.

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY**
are to be interpreted as described in RFC 2119 and RFC 8174 when, and only
when, they appear in all capitals.

## Goals

- Preserve B005 v1 and schema v1/v2 byte and public-contract compatibility.
- Define B005 format version 2 as a strict, bounded TLV payload with no raw
  event code or device-unique persistent identifier.
- Allow automatic code-less adoption only when a registry-verified **open**
  credential has a clear, fresh, signed cross-event local majority.
- Bind the credential identity to the canonical unsigned body so a different
  valid signature cannot create a separate TEK, relay cache key, or census
  identity.
- Define the trusted Census Authority's input pipeline precisely enough to
  rule out participant inflation across RPI/ENIN/peripheral rotation and
  relaying, while stating honestly that B005 carries no participant proofs.
- Preserve full original signed bytes during relaying, with bounded
  deduplication, expiry, and explicit conflict reporting.
- Provide byte-for-byte Swift/Android canonical vectors.

## Non-goals

- Implementing a connected Census Authority, gateway, registry backend, or
  venue sensor service in this SDK.
- Treating BLE proximity, RPI resolution, a B002 value, relayer count, or raw
  observation count as a voter or a cryptographic mutuality proof.
- Changing B005 v1, its EventCodeHash semantics, or the legacy EventCode key
  path.
- Putting raw EventCode, a device identifier, an account identifier, a
  peripheral identifier, an RPI, a stable relayer identifier, or participant
  proofs in B005.
- Claiming that an authority aggregate proves peer-to-peer RF mutuality.

## Glossary

- **AdoptionCredential**: a 159-byte signed artifact for one event and one
  credential validity interval.
- **credentialId**: `SHA-256` of the canonical 94-byte unsigned
  AdoptionCredential body. It excludes the recoverable signature.
- **Registry Event Definition**: an out-of-band, host-authenticated registry
  object that binds an eventId, credentialId, scope, name hash, time range,
  admission mode, and Census Authority policy. The SDK verifies its byte
  bindings but does not authenticate a registry service itself.
- **Census Authority**: the trusted authority that validates participant
  admission/presence inputs and signs aggregates. The reference deployment
  assumption is a connected backend. A designated venue device can play this
  role only if it has the same authenticated admission and observation inputs;
  a single local radio does not imply venue-wide visibility.
- **eligible voter**: one distinct registry-admitted device in the Census
  Authority's deduplicated nearby-domain set for the window.
- **qualified voter**: one eligible voter assigned to a specific verified
  event after the Census Authority accepted the required corroborated
  observation input for that event in that window.
- **cross-event local majority**: the winner's qualified count exceeds half
  of the shared local eligible denominator and exceeds every other verified
  event's qualified count in the same domain/window/policy epoch.
- **direct GATT self-check**: a post-adoption observation of one live GATT
  session with matching B004 scope, supported-shape B002, and a
  registry-verified same-credential B005. It is not a cross-device TEK
  resolution or ownership proof.

## Versioning and compatibility

`formatVersion=0x01` is the B005 event-info protocol in
[`specs/113-event-info-discovery/spec.md`](../113-event-info-discovery/spec.md).
Its bytes, B004 EventCodeHash semantics, parser, and user-confirmation flow
remain unchanged. A v1 observation MUST remain only an unauthenticated hint;
it MUST NOT enter v2 admission or majority evaluation.

`formatVersion=0x02` is the separate wire protocol defined here. It maps to
`schema/barnard/v3`, rather than schema v2, because the public host contract
gains typed credentials, registry bindings, decisions, and conflicts. Wire
version and JSON-schema version solve different compatibility problems:

| Surface | Existing behavior | v2/v3 behavior |
|---|---|---|
| B005 wire v1 | unchanged | parser continues to parse only v1 |
| B005 wire v2 | absent in v1 deployments | strict signed candidate transport |
| schema/barnard/v1 | unchanged | remains exact |
| schema/barnard/v2 | unchanged | remains exact |
| schema/barnard/v3 | new | versioned public projection for this slice |

Hosts MUST select the versioned v2 path explicitly after Registry Event
Definition verification. They MUST NOT reinterpret a v1 EventCodeHash as an
AdoptionCredential scope or silently replace an active legacy EventCode
session. Legacy deployments continue to derive keys from EventCode. A verified
v2 credential uses the new code-less derivations below.

## Canonical cryptographic primitives

All integers are unsigned big-endian. Hashes are SHA-256. Signatures are
recoverable secp256k1 ECDSA encoded as `r(32) || s(32) || recoveryId(1)`.

- `r` MUST be in `[1, n-1]`.
- `s` MUST be in `[1, floor(n/2)]` (canonical low-S).
- `recoveryId` MUST be `0` or `1`.
- Parsers MUST reject non-canonical signatures before using a recovered key.
- `eventId = SHA-256(compressedCredentialAuthorityPublicKey)`. This is
  self-certifying, not registry authorization.

### AdoptionCredential v1

The unsigned body is exactly 94 bytes:

| Offset | Size | Field | Rule |
|---:|---:|---|---|
| 0 | 1 | `credentialVersion` | exactly `0x01` |
| 1 | 1 | `admissionMode` | `0x01=open`, `0x02=gated` |
| 2 | 32 | `eventId` | SHA-256 of recovered credential authority compressed key |
| 34 | 8 | `b004AdoptionScopeHash` | opaque, registry-bound B004 value for v2 |
| 42 | 32 | `displayNameHash` | SHA-256 of canonical B005 display-name UTF-8 bytes |
| 74 | 8 | `validFromUnixSeconds` | inclusive |
| 82 | 8 | `validUntilUnixSeconds` | exclusive; strictly greater than start |
| 90 | 4 | `censusWindowSeconds` | 12 through 3600 |

```text
credentialId = SHA-256(unsignedCredentialBody)
credentialDigest = SHA-256("barnard-adoption-credential:v1" || unsignedCredentialBody)
credentialSignature = RecoverableECDSA(credentialAuthorityPrivateKey, credentialDigest)
AdoptionCredential = unsignedCredentialBody || credentialSignature
```

The complete artifact is exactly `94 + 65 = 159` bytes. `credentialId` MUST
be used for all of the following identities: v2 key derivation, Registry Event
Definition binding, SignedWindowCensus binding, relay-cache tuple, and
equivocation identity. The full 159-byte signed credential MUST nevertheless
be retained and verified before use.

Credential rotation is registry-authorized only. There MUST be one active
credentialId per event/domain/window. The authenticated replacement Registry
Event Definition carries `replacesCredentialId` and
`effectiveWindowIndex`; it MUST reference the old credentialId, take effect
at a future window boundary, and not overlap the old credential. These are
registry fields, not B005 or AdoptionCredential fields, so rotation does not
silently redefine the 94-byte credential layout. A re-signature with
unchanged unsigned bytes retains the same credentialId and is not a rotation.

### SignedWindowCensus v1

The unsigned body is exactly 77 bytes:

| Offset | Size | Field | Rule |
|---:|---:|---|---|
| 0 | 1 | `censusVersion` | exactly `0x01` |
| 1 | 32 | `credentialId` | exact AdoptionCredential stable ID |
| 33 | 8 | `windowIndex` | `floor(unixSeconds / censusWindowSeconds)` |
| 41 | 2 | `qualifiedVoterCount` | unsigned; no greater than eligible |
| 43 | 2 | `eligibleVoterCount` | unsigned cross-event local denominator |
| 45 | 32 | `countedSetMerkleRoot` | all zero bytes in census v1 |

```text
censusDigest = SHA-256("barnard-signed-window-census:v1" || unsignedCensusBody)
censusSignature = RecoverableECDSA(censusAuthorityPrivateKey, censusDigest)
SignedWindowCensus = unsignedCensusBody || censusSignature
```

The complete artifact is exactly `77 + 65 = 142` bytes. The 32-byte root is
reserved so a later proof-bearing census can allocate a new `censusVersion`
without changing this layout. v1 parsers MUST reject any non-zero root; they
MUST NOT treat it as a future proof or an optional hint.

### B005 format version 2

The value begins with `0x02`, followed by strictly increasing TLVs:

| Type | Name | Length | Rule |
|---:|---|---:|---|
| `0x01` | `eventDisplayName` | 1–64 | NFC UTF-8, no controls; length is a UTF-8 byte count, not a Unicode character count |
| `0x02` | `b004AdoptionScopeHash` | 8 | exactly the credential scope and B004 value |
| `0x20` | `adoptionCredential` | 159 | exact signed credential bytes |
| `0x21` | `signedWindowCensus` | 142 | exact signed census bytes |

Each TLV is `type(1) || length(2) || value`. v2 emitters and parsers MUST
accept exactly these four TLVs, exactly once, in this order. They MUST reject
unknown, duplicate, out-of-order, zero-type, truncated, or trailing data.
The parser MUST verify both signatures, the eventId anchor, the name/scope
cross-bindings, and the census credentialId binding before returning a
candidate.

The complete v2 B005 budget is:

```text
formatVersion                         1
eventDisplayName TLV          1 + 2 + 64 =  67
b004AdoptionScopeHash TLV      1 + 2 +  8 =  11
AdoptionCredential TLV         1 + 2 +159 = 162
SignedWindowCensus TLV         1 + 2 +142 = 145
                                                ---
maximum complete B005 value                    386 bytes
ATT 512-byte ceiling minus maximum             126 bytes
```

The minimum complete value is 323 bytes (one-byte display name). B005 v2 is
still a discovery **candidate transport**, not authenticated admission by
itself: it MUST NOT cause auto-adoption, form a voter, or override a direct
observation until all registry and decision gates below pass.

For v2, B004 carries the opaque `b004AdoptionScopeHash`, not an EventCodeHash.
It is tied byte-for-byte to the credential and contains no raw EventCode. The
legacy EventCodeHash role remains exclusive to v1.

## Registry binding and code-less derivation

The host obtains a Registry Event Definition through its authenticated
registry channel. Before setting `registryVerification=verified`, it MUST
verify the registry object's authenticity and bind all of these exact values:

- eventId, credentialId, admissionMode, validity interval;
- B004 adoption scope hash and display-name hash;
- census domain ID, window duration, policy epoch, minimum thresholds; and
- exactly one authorized Census Authority public-key hash for that
  domain/window/policy epoch; and
- for a replacement only, the prior `replacesCredentialId` and a non-null
  `effectiveWindowIndex`. Initial credentials carry both fields as null.

The SDK then checks the signed credential/census bytes against that definition.
A recovered event key with a matching self-certifying eventId but no verified
Registry Event Definition MUST produce `registry_unverified`, never automatic
adoption.

The registry validates a replacement against the currently active definition:
the referenced ID must match, the new ID must differ, the effective index must
be strictly later than the active window, and the old/new validity intervals
must not overlap. The SDK's local rotation validator checks this supplied
chain shape; it does not treat a re-signed credential as a new identity.

After successful verification, a device derives its local v2 material:

```text
adoptionTEK = HKDF-SHA256(
  IKM = DeviceSecret || credentialId,
  salt = 32 zero bytes,
  info = "barnard-adoption-tek:v1",
  L = 16
)

adoptionSignSeed = HKDF-SHA256(
  IKM = DeviceSecret || credentialId,
  salt = 32 zero bytes,
  info = "barnard-adoption-sign:v1",
  L = 32
)
adoptionSigningPrivateKey = reduction/admissible retry of adoptionSignSeed
```

These labels are separate from legacy `barnard-tek` and `barnard-sign` labels.
The raw EventCode is neither required nor used on the v2 path.

## Census Authority input pipeline and trust boundary

The following is normative for an authority that signs census v1. It describes
the evidence the authority validates; none of these internal identifiers are
put in B005.

1. The authority accepts an admission record only after the Registry Event
   Definition and the full AdoptionCredential verify. It binds that record to
   one `credentialId` and one registry-authenticated device/account admission
   record.
2. It derives one authority-local, per-event-stable contribution ID:

   ```text
   contributionId = HMAC-SHA256(
     CensusAuthoritySecret,
     "barnard-census-participant:v1" || credentialId || registryAdmittedDeviceHandle
   )
   ```

   This value never crosses the BLE wire. It survives ENIN, RPI, peripheral
   handle, and relayer rotation. A device observed across twelve 300-second
   windows retains the same contribution ID; each window is counted from that
   stable identity, not from twelve radio identifiers.
3. For a census window, the authority validates each submitted presence input
   against its authenticated admission record and a direct GATT session record
   containing a valid same-event v2 B005, matching B004 scope, and
   supported-shape B002. A raw advertisement or an unauthenticated B005 hint
   alone is not an input.
4. `eligibleVoterCount` is the cardinality of the deduplicated union of
   current, registry-admitted contribution IDs with accepted local-domain
   presence evidence across the verified candidate events for that one
   domain/window/policy epoch.
5. `qualifiedVoterCount` for one credentialId is the cardinality of the
   subset assigned to that credential after the authority has accepted its
   required corroborated observation record. The reference backend requires a
   device-authenticated session report plus an independently authenticated
   authority/venue observation for the same bounded session correlation. It
   deduplicates by `(contributionId, credentialId, domain, window)` before
   count, and rejects a second event assignment for the same contribution ID
   in the same window.
6. The authority signs only after enforcing `qualified <= eligible`, one
   contribution per device per window, and one authority key for the policy
   tuple. It signs the aggregate, not a participant list or proof.

This is a **trusted-authority aggregate**. It prevents local relayer/radio
count inflation at the SDK boundary, but it is not a cryptographic proof of
mutual RF observation and does not give a B005 reader independently verifiable
per-participant evidence. A venue device with narrower observation coverage
must report only the subset it can validate; it MUST NOT imply venue-wide
coverage.

## Decision, relay, and self-check behavior

### Cross-event automatic adoption

For one candidate domain, the SDK MUST:

1. verify signed B005 v2 bytes and Registry Event Definition binding;
2. require all candidates to share the configured domain, window seconds,
   policy epoch, current window, fresh observation (default at most 60
   seconds), and one authorized Census Authority key;
3. reject `qualified > eligible`, unequal eligible denominators, or a sum of
   qualified candidate counts greater than the denominator;
4. require the registry minimum eligible and qualified thresholds;
5. choose only a unique top qualified count `Q` such that `2*Q > E`, where
   `E` is the shared local eligible denominator; and
6. auto-adopt only when that winner is `open`.

Any registry-unverified, gated, stale, wrong-window, tie, no-majority,
insufficient-evidence, or inconsistent-denominator case MUST show the chooser
or confirmation fallback. A v2 `gated` credential MUST never auto-adopt.

Before any of the checks above run, the SDK MUST distinguish two non-answers
from an evaluated outcome. No verified candidate at all (`no_authoritative_census`)
and a structurally invalid domain policy (`invalid_domain_policy`) are
absence/configuration states — no authoritative census reached the SDK, or
the host misconfigured the policy — not an evaluated non-majority. Only a
completed evaluation that finds no unique qualified majority among present,
policy-valid candidates is `no_clear_majority`. A host UI MUST be able to
treat these differently: an evaluated `no_clear_majority` is a correct
chooser outcome, while `no_authoritative_census` or `invalid_domain_policy`
is a degraded fallback.

The domain/window/policy-epoch check MUST also distinguish a mixed set from
a wholesale mismatch. When every candidate fails to match the configured
domain, window, and policy epoch, the SDK MUST report
`no_candidate_in_domain`: this is a likely misconfiguration signal, since
nothing observed belongs to the host's own domain at all. When at least one
candidate matches and at least one does not, the SDK MUST report
`domain_mismatch`: this is normal steady state (e.g. a neighboring event's
candidates sharing the same radio range) and MUST NOT be conflated with the
wholesale case. Either case still requires the chooser or confirmation
fallback and MUST NOT auto-adopt; this is a reason split only, not a change
to which candidates suppress auto-adoption.

A valid different authority key in the same configured
domain/window/policy epoch is `domain_authority_inconsistency`; it MUST fail
closed and MUST NOT form a separate majority group. Future multi-authority
aggregation requires a new schema/protocol version.

### Relay conflict and TTL

Relay cache identity is:

```text
(credentialId, censusDomainId, authorityPolicyEpoch,
 censusAuthorityKeyHash, windowIndex)
```

The cache compares exact full B005 bytes. Same bytes are a duplicate even when
their peripheral handle, RPI, raw observation count, or relayer count differs.
Different valid signed bytes for the same tuple are
`census_equivocation`: retain up to two exact payloads for diagnosis, block
relay and automatic majority use, and report the conflict distinctly. It MUST
NOT first-seen-win. The cache is bounded; capacity exhaustion is fail-closed.
Artifacts expire when their census window has passed; expired tuples are not
relayed or counted.

### Post-join N-window self-check

After automatic adoption, the host completes one local window at a time. A
peer confirmation requires one direct live GATT session with all of:

- B004 exactly equal to the local credential scope;
- B002 exactly 17 bytes with supported format version `0x01` and opaque 16
  following bytes;
- B005 verified to the same credentialId and a verified Registry Event
  Definition.

The ephemeral GATT handle is immediately discarded and is not a voter. The
check does not resolve a remote B002 using a local TEK and does not prove
device ownership or RF mutuality. If no qualifying peer is confirmed after
the configured N complete windows (three in the reference vector), the host
MUST present a switch/chooser prompt rather than silently claiming mutuality.

## Privacy and security invariants

- B005 v2 MUST NOT carry raw EventCode or a device-unique persistent
  identifier.
- `credentialId`, eventId, display-name hash, and scope are event-scoped
  artifacts; they identify an event credential, not a participating device.
- `peripheralId`, RPI, B002 opaque bytes, raw observation counts,
  unauthenticated B005 hints, and relayer counts MUST NEVER become majority
  evidence.
- Original credential/census signature bytes MUST survive relaying unchanged.
- Registry verification and the external Census Authority are separate trust
  anchors; neither is inferred from BLE reachability.

## Canonical example

The fixed public test inputs in
[`test-vectors/adoption-census-v1.txt`](../../test-vectors/adoption-census-v1.txt)
use display name `Barnard Zero Tap`, a test-only credential authority key, a
test-only Census Authority key, a 300-second window, and a zero v1 Merkle
root. The fixture pins the 159-byte credential, 142-byte census, and complete
338-byte B005 v2 value. Both native implementations decode, verify, and
reconstruct those exact bytes.

The example's `qualified=4`, `eligible=7` wins only when the competing
verified events in the same domain/window leave it the unique top count. The
same numbers from a different authority key, stale window, missing registry
definition, or gated credential do not auto-adopt.
