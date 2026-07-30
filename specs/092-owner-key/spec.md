# Owner Key and Optional Wallet Endorsement

## Problem statement

Barnard has per-event signing keys and RPID-ownership proofs, but it has no
long-lived identity anchor. A holder therefore cannot selectively prove that
multiple pseudonymous event histories belong to the same persona. Requiring an
EVM wallet as that anchor would exclude wallet-less participants and would
couple the protocol to wallet software and RPC availability.

This specification adds an **owner key**: a deterministic, long-lived
secp256k1 key pair derived from an independently generated `AccountSecret`.
Every participant can use the owner key without a wallet (Tier 0). An EVM
wallet may optionally endorse the owner key through a human-readable
`personal_sign` ceremony (Tier 1).

Key generation entropy, secret custody, backup, migration, wallet transport,
and user-interface flows remain host responsibilities. Barnard provides only
pure, deterministic formats, builders, signing, and verification.

## Goals

- Define a long-lived owner key that is independent of `DeviceSecret`.
- Bind an event signing key to an owner key without disclosing TEK or RPIK.
- Define an optional, mutually authenticated EVM wallet endorsement.
- Define deterministic rotation and unbinding formats before host UX ships.
- Keep every operation in `BarnardCore` free of randomness, clock access,
  storage, wallet SDKs, and RPC configuration.
- Preserve full protocol capability for wallet-less Tier 0 holders.
- Keep all stable owner and wallet identifiers out of public and on-wire
  artifacts.

## Non-goals

- Generating, storing, backing up, or migrating `AccountSecret`.
- Wallet discovery, connection, SDK integration, or transaction signing.
- ERC-1271 or ERC-6492 RPC verification in v1.
- Presentation-time challenge-response or credential-transfer resistance.
- Changing Scan, Advertise, Central, Peripheral, GATT, Transport, RPID,
  event-signing, or existing RPID-ownership-proof behavior.
- Adding Kotlin or React Native implementations.

## Glossary

- **owner key**: a long-lived secp256k1 key pair anchoring one holder-chosen
  persona. Its compressed public key is 33-byte SEC1.
- **AccountSecret**: an independently generated 32-byte random seed and the
  sole input to owner-key derivation.
- **event signing key**: the per-event secp256k1 key pair derived from
  `DeviceSecret` and `EventCode`.
- **self-proof**: an owner-key signature binding one event signing public key
  and ENIN range to the owner key.
- **wallet endorsement / account binding**: an EIP-191 `personal_sign`
  signature by an EVM account over the canonical binding text, plus a
  mandatory owner-key acknowledgement.
- **EOA**: an externally owned EVM account whose signature can be verified by
  public-key recovery without RPC.
- **smart wallet**: an account requiring contract-aware verification such as
  ERC-1271 or ERC-6492.
- **Tier 0 / Tier 1**: owner-key identity without / with a wallet endorsement.
- **holder-held artifact**: a record retained by the holder and disclosed
  point-to-point, never placed in Advertise, GATT, anchors, or witness blobs.

## Key hierarchy

```text
DeviceSecret (device-scoped random seed)
├─ TEK = HKDF(DeviceSecret || EventCode)
│  └─ RPID = f(TEK, ENIN)
└─ event signing key = KDF(DeviceSecret, EventCode)

AccountSecret (independent 32-byte random seed)
└─ owner key = ownerKDF(AccountSecret)
   └─ signs self-proofs for event signing keys

wallet EOA -- personal_sign --> endorses the owner public key
owner key  -- SHA-256/ECDSA --> acknowledges the exact wallet endorsement
```

`AccountSecret` MUST NOT be derived from `DeviceSecret`. The owner key needs an
independent backup and migration lifetime; `DeviceSecret` remains
device-scoped.

### Owner-key derivation

`deriveOwnerKeyPair` accepts exactly 32 bytes and follows the existing
`deriveSigningKeyPair` scalar convention:

1. Compute HKDF-SHA256 with:
   - IKM = `AccountSecret`
   - salt = 32 zero bytes (the existing omitted-salt convention)
   - info = UTF-8 `barnard-owner`
   - output length = 32 bytes
2. Interpret the output as one unsigned big-endian integer.
3. Reduce once modulo the secp256k1 curve order `n`.
4. If the result is zero, set `seed = SHA256(seed)` and repeat steps 2–4.
5. Serialize the private scalar as 32-byte big-endian and the public key as
   33-byte compressed SEC1.

The same `AccountSecret` MUST produce the same key pair on every platform.
The `AccountSecret` itself is never used directly as a private key.

## Barnard-native signature rules

All four binary message families below use secp256k1 with deterministic
RFC 6979 signing over `SHA256(message)`. Signers emit low-S signatures.
This 65-byte format is named the **Barnard Recoverable secp256k1 Signature
Profile v1**. Signatures in this profile serialize as:

```text
r (32-byte unsigned big-endian)
|| s (32-byte unsigned big-endian)
|| recoveryId (1 byte, 0x00 or 0x01)
```

The Barnard profile is not ES256K. ES256K, as specified by RFC 8812, is a
64-octet `R || S` ECDSA signature over SHA-256 and has no recovery byte.
Implementations, schemas, and documentation MUST NOT label a Barnard
`r || s || recoveryId` signature as ES256K.

Every verifier MUST reject:

- a field whose byte length does not match its layout;
- `r` or `s` equal to zero or greater than or equal to curve order `n`;
- `s > n / 2`;
- a recovery ID other than `0` or `1`;
- a recovered key that does not match the required signer.

Domain tags are raw UTF-8 bytes. All following fields have fixed widths; a
variable input is converted to a fixed 32-byte digest before inclusion. No
delimiter or implicit host-language encoding is present.

## Message formats and behavior

### 1. Self-proof

Domain tag: `barnard-self-proof:v1`

```text
offset  size  value
0       21    UTF-8 "barnard-self-proof:v1"
21      32    eventIdHash
53      33    eventSigningPublicKey (compressed SEC1)
86       8    eninStart (unsigned big-endian)
94       8    eninEnd (unsigned big-endian)
102     33    ownerPublicKey (compressed SEC1)
total  135
```

`eninStart` MUST be less than or equal to `eninEnd`. The owner private key signs
the 135-byte message. Verification hashes the message with SHA-256, recovers
the signer, and requires it to equal `ownerPublicKey`.

The self-proof binds control of the owner key to the named event signing key
for the stated ENIN range. It does not contain TEK, RPIK, or an RPID.

The self-proof maps to the typed-envelope fields as follows: envelope `type`
is represented by the `barnard-self-proof` domain tag, `protocolVersion` by
its `:v1` suffix, `eventIdHash` by the same-named message field,
`signingPubkey` by `eventSigningPublicKey`, the ENIN window by `eninStart` and
`eninEnd`, and `ownerPubkey` by `ownerPublicKey`. Reporting-layer
`eventDefinitionDigest` and `reportDigest` fields are deliberately outside
the self-proof signature scope. The SCITT RFCs listed under References are
prior art for that separate reporting layer.

### 2. Wallet acknowledgement

Domain tag: `barnard-wallet-ack:v1`

```text
offset  size  value
0       21    UTF-8 "barnard-wallet-ack:v1"
21      20    walletAddress
41      32    SHA256(walletSignatureBytes)
total   73
```

The owner private key signs this message. Verification recovers the signer and
requires it to equal the owner public key from the canonical binding text.
Hashing the exact wallet signature makes the acknowledgement specific to one
endorsement, rather than merely to an address.

### 3. Owner-key rotation

Domain tag: `barnard-account-rotation:v1`

```text
offset  size  value
0       27    UTF-8 "barnard-account-rotation:v1"
27      33    previousOwnerPublicKey (compressed SEC1)
60      33    successorOwnerPublicKey (compressed SEC1)
total   93
```

The previous owner key signs this message. Verification recovers the signer
and requires it to equal `previousOwnerPublicKey`. Including both keys makes
the direction of succession explicit. The previous and successor keys MUST
be distinct; a same-key rotation is invalid. A Tier 1 holder MUST run a new
wallet binding ceremony for the successor; wallet endorsements do not
transfer implicitly.

### 4. Account unbinding

Domain tag: `barnard-account-unbinding:v1`

```text
offset  size  value
0       28    UTF-8 "barnard-account-unbinding:v1"
28      33    ownerPublicKey (compressed SEC1)
61      20    walletAddress
81      32    walletSignatureHash = SHA256(walletSignatureBytes)
total  113
```

The digest identifies one exact wallet-binding record. Either the owner key or
the EOA key controlling `walletAddress` may sign the SHA-256 digest of this
Barnard-native message. Verification therefore takes an explicit signer kind:

- `owner`: the recovered compressed key MUST equal `ownerPublicKey`;
- `wallet`: the recovered key is decompressed, its Ethereum address is
  derived, and that address MUST equal `walletAddress`.

The wallet-signing host UX for this reserved lifecycle format is not part of
v1. It is not the account-binding `personal_sign` ceremony and MUST NOT be
silently substituted for it.

## Canonical wallet-binding text

Open question 2 from the issue is resolved here. v1 includes the drafted
human-readable authorization statement but omits the unrelated URI, request,
resource, and expiration fields from full EIP-4361. This is the smallest field
set that identifies the protocol, account, owner key, chain context, global
scope, ceremony, and issuance time while stating that no transaction is
authorized.

The exact text is:

```text
{domain} wants to bind this wallet to a Levarac owner key.

This signature authorizes no transaction and moves no assets.

Domain-Tag: barnard-account-binding:v1
Wallet: 0x{walletAddress lowercase hex}
Owner-Key: 0x{compressed owner public key lowercase hex}
Chain-ID: eip155:{chainId unsigned decimal}
Scope: global
Nonce: 0x{16-byte nonce lowercase hex}
Issued-At: {issuedAt}
```

Canonical encoding rules are normative:

- Encode the complete text as UTF-8.
- Use LF (`0x0a`) only; CR is forbidden.
- Preserve the exact field names, punctuation, capitalization, blank lines,
  and order shown above.
- Do not append a trailing LF or any other trailing byte.
- `domain` is an already-normalized, lowercase ASCII authority (host or host
  plus a decimal port in the range 0 through 65535) with no whitespace, slash,
  CR, or LF. A port has no leading zero unless it is exactly `0`. Lowercase is
  pinned so two hosts cannot produce different signatures by varying DNS
  casing; Barnard emits the validated value exactly as supplied.
- `walletAddress` is exactly 20 bytes and is emitted as `0x` plus 40 lowercase
  hexadecimal digits.
- `ownerPublicKey` is exactly 33-byte compressed SEC1, begins with `0x02` or
  `0x03`, and is emitted as `0x` plus 66 lowercase hexadecimal digits.
- `chainId` is an unsigned 64-bit integer in the range 0 through
  18446744073709551615, emitted in base 10 with no leading zero, except that
  zero is emitted as `0`.
- `Scope` is the literal ASCII value `global` in v1. A scoped binding requires
  a future versioned domain tag and MUST NOT be represented by changing this
  line.
- `nonce` is exactly 16 bytes and is emitted as `0x` plus 32 lowercase
  hexadecimal digits.
- `issuedAt` is supplied by the host as a valid proleptic-Gregorian calendar
  date in RFC 3339 UTC, second precision: `YYYY-MM-DDTHH:MM:SSZ`. Barnard does
  not read a clock.
- No Unicode normalization, address checksum casing, JSON serialization, or
  locale-sensitive formatting is applied.

`nonce` and `issuedAt` make ceremonies unique and referenceable. They are not
a replay-prevention promise: a valid binding remains an idempotent long-lived
fact until an account-unbinding record revokes it. `Chain-ID` is context and
policy metadata; EIP-191 `personal_sign` itself is chain-agnostic.

### Example

For domain `beid.levarac.org`, the EOA derived from private scalar 1, the
compressed generator owner key, chain ID 1, nonce bytes `00` through `0f`, and
issuance at 2026-07-30 09:00 UTC, the byte-exact text is:

```text
beid.levarac.org wants to bind this wallet to a Levarac owner key.

This signature authorizes no transaction and moves no assets.

Domain-Tag: barnard-account-binding:v1
Wallet: 0x7e5f4552091a69125d5dfcb7b8c2659029395bdf
Owner-Key: 0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
Chain-ID: eip155:1
Scope: global
Nonce: 0x000102030405060708090a0b0c0d0e0f
Issued-At: 2026-07-30T09:00:00Z
```

## EIP-191 and Ethereum address derivation

`computeEip191Digest(text)` computes:

```text
keccak256(
  0x19
  || UTF-8 "Ethereum Signed Message:\n"
  || ASCII decimal(UTF8(text).count)
  || UTF8(text)
)
```

The length is the UTF-8 byte count, not a character count. `keccak256` is the
Ethereum Keccak-256 variant with rate 136 bytes and domain/padding bytes
`0x01 ... 0x80`. NIST SHA3-256 (`0x06 ... 0x80`) is incompatible and MUST NOT
be substituted.

To derive an EVM address from a recovered compressed public key:

1. Parse the 33-byte compressed SEC1 point and serialize it as uncompressed
   SEC1 `0x04 || x32 || y32`.
2. Hash `x32 || y32` with Ethereum Keccak-256; do not hash the `0x04` prefix.
3. Take the last 20 bytes.

## Wallet signature classification

Classification is a pure shape check and returns a typed result:

1. If the byte string ends with the 32-byte ERC-6492 magic suffix
   `0x6492` repeated 16 times, return `smartWalletUnsupported`. Suffix
   detection has priority over length.
2. Otherwise, if its length is exactly 65 bytes, return `validEoaShape`.
3. Otherwise return `invalid`.

`validEoaShape` does not mean cryptographically valid. Scalar, low-S,
recovery-ID, recovered-address, and acknowledgement checks occur during
verification.

## EOA wallet-binding verification

`verifyWalletBinding` verifies one record only. It takes the byte-exact
canonical text, wallet signature, expected 20-byte wallet address, expected
33-byte owner public key, and owner acknowledgement signature.

1. Parse the supplied text under the canonical grammar, reconstruct it
   byte-for-byte, and require its `Wallet:` and `Owner-Key:` fields to equal
   `expectedWalletAddress` and `expectedOwnerPublicKey`. Reject any
   noncanonical text, field mismatch, CR, or trailing LF before treating the
   signature as an endorsement.
2. Classify the wallet signature.
   - `smartWalletUnsupported` returns an unverified smart-wallet result.
   - `invalid` returns an invalid-shape result.
3. Parse `r || s || v` from the 65-byte signature.
4. Normalize `v = 27` to recovery ID 0 and `v = 28` to recovery ID 1. Raw
   `v = 0` and `v = 1` are also accepted. Reject every other value.
5. Require valid non-zero `r` and `s` scalars and low-S.
6. Compute the EIP-191 digest and recover the public key with the existing
   recovery primitive. Recovery IDs 2 and 3 remain unsupported deliberately.
7. Derive the recovered Ethereum address and compare it byte-for-byte with
   `expectedWalletAddress`. Human-readable hex comparisons at API boundaries
   are case-insensitive, then decoded to these 20 bytes.
8. Rebuild `barnard-wallet-ack:v1` from the expected address and exact wallet
   signature bytes. Verify its SHA-256 signature, including scalar and low-S
   rules, against `expectedOwnerPublicKey`.
9. Only if the canonical binding and both signatures pass, return `valid`.

The API does not aggregate endorsements and does not query RPC.

## Smart-wallet verifier port

Barnard defines a host-implemented port only:

```text
verify(address20, digest32, signatureBytes) -> verdict
```

The verdict is one of:

- `valid(verifiedAtUnixSeconds)`;
- `invalid(verifiedAtUnixSeconds)`;
- `unverified`.

No RPC client, endpoint, credential, retry, timeout, cache, or chain-selection
code belongs in Barnard. v2 hosts may implement the port with ERC-1271/6492
RPC. Contract state is time-dependent, so every valid or invalid RPC verdict
MUST record the observation time. A verifier without RPC returns `unverified`;
the endorsement then contributes no Tier 1 claim and the holder retains normal
Tier 0 semantics.

## Multi-wallet and persona rules

The model is **N wallets to one owner key**. Every wallet independently signs a
binding text for the same owner public key and receives its own owner
acknowledgement.

- Verifiers MUST NOT require disclosure of every endorsement.
- Verification APIs MUST remain per-record and MUST NOT offer aggregate
  all-wallet verification.
- Choosing another wallet endorsement changes only what the holder discloses;
  it MUST NOT create or rotate an owner key.
- Multiple owner keys (personas) are legal only through explicit user action.
- Hosts manage endorsement collections and disclosure choices outside
  BarnardCore.

## Tier 0 guarantee

| Capability | Tier 0 (no wallet) | Tier 1 (wallet-bound) |
|---|---|---|
| Within-event RPID ownership | Full | Same |
| Three-leg credential | Full, using the local owner key | Same |
| Cross-event selective disclosure | Full, same owner-key algorithm | Same plus optional wallet check |
| Device-loss continuity | Requires `AccountSecret` backup | Wallet may endorse a successor after rotation |
| External identity bridge | None by design | EVM address endorsement |

Loss of an unbacked-up `AccountSecret` orphans cross-event linkage. Existing
per-event artifacts remain independently verifiable; Barnard does not invent a
custodial recovery service.

## Compatibility

- All schemas and APIs in this specification are additive.
- No existing public schema or on-wire format changes.
- Existing Advertise, Scan, Central, Peripheral, GATT, Transport, RPID,
  event-signing, and RPID-proof behavior remains unchanged.
- New domain tags are disjoint from existing Barnard tags.
- EIP-191 prefixing and Ethereum Keccak keep wallet signatures in a different
  hash universe from Barnard-native SHA-256 signatures.

## Security and privacy

**No device-unique persistent identifiers are added on-wire.** Owner public
keys, wallet addresses, self-proofs, wallet bindings, rotations, and
unbindings are holder-held artifacts disclosed point-to-point. They MUST NOT
appear in Advertise data, GATT values, public anchors, or witness blobs.

The schema privacy invariant treats every schema as public/on-wire unless its
document root explicitly declares holder-held disclosure scope. Public/on-wire
schemas MUST NOT define a 33-byte compressed-public-key shape, a 20-byte
address shape, or references into holder-held schemas.

The wallet ceremony has three domain-separation layers:

1. EIP-191 prevents cross-use as a transaction or Barnard-native signature.
2. `Domain-Tag: barnard-account-binding:v1` prevents cross-protocol reuse.
3. The visible domain and no-assets statement reduce blind-signing risk.

Wallet linkage intentionally connects disclosed event history to a public
address. Hosts MUST request explicit consent and MUST NOT auto-prompt binding.
Using a fresh wallet address remains valid.

## Errors and retry behavior

- Pure builders are deterministic and perform no retries.
- Invalid fixed-length inputs are rejected before hashing or recovery.
- Cryptographically invalid signatures return typed invalid verdicts and do
  not throw or trap.
- ERC-6492 is classified before EOA validation and returns
  `smartWalletUnsupported` in v1.
- Owner-key zero-scalar derivation is the only retry loop and re-hashes the
  32-byte seed deterministically as specified above.
- RPC retry, timeout, and backoff are outside Barnard and belong to a future
  host implementation of the verifier port.

## Rejected alternatives

- Using `AccountSecret` directly as the private key: rejected to preserve
  domain separation and sibling-key derivation headroom.
- Deriving the owner key from `DeviceSecret`: rejected because device and
  identity migration lifetimes differ.
- P-256 Secure Enclave / StrongBox or passkeys: rejected because
  non-exportable keys conflict with the required backup and migration model,
  and passkeys cannot sign arbitrary protocol payloads.
- Ed25519: rejected to avoid a third signature stack with no protocol benefit.
- BLAKE3: rejected because SHA-256 matches the existing portable Barnard stack.
- Full EIP-4361 login fields: rejected because this is an endorsement, not an
  authentication session; unused URI/resource/expiration fields add canonical
  inputs without improving the binding.
- An `expiresAt` binding field: rejected because a binding is a long-lived,
  idempotent fact, revocation occurs through account unbinding, and v1 defines
  no expiry semantics.
- A binding text without the no-assets statement: rejected because the
  ceremony must remain human-readable and explicitly non-transactional.

## Future work

- ERC-1271/6492 verification through the verifier port.
- EIP-712 binding under `barnard-account-binding:v2`.
- A versioned COSE/CBOR interoperability profile in v2.
- Host UX for account rotation and wallet-authorized unbinding.
- Presentation-time challenge-response.
- Post-quantum migration through versioned domain tags and rotation records.

## References

- [RFC 8812: CBOR Object Signing and Encryption (COSE) and JSON Object
  Signing and Encryption (JOSE) Registrations for
  secp256k1](https://www.rfc-editor.org/rfc/rfc8812.html)
- [RFC 9942: An Information Model for Supply Chain Integrity,
  Transparency, and Trust](https://www.rfc-editor.org/rfc/rfc9942.html)
- [RFC 9943: An Architecture for Trustworthy and Transparent Digital Supply
  Chains](https://www.rfc-editor.org/rfc/rfc9943.html)

## Validation

- Cross-implementation HKDF owner-key vectors.
- Standard Ethereum Keccak-256 vectors, including empty input and `abc`.
- EIP-191 digest and `personal_sign` fixtures generated outside BarnardCore.
- Unit tests for every builder, signer, verifier, malformed scalar, high-S
  signature, recovery-ID normalization, address mismatch, acknowledgement
  mismatch, ERC-6492 suffix, and canonical text byte.
- C ABI tests for all exported owner-key functions and invalid arguments.
- Schema syntax and privacy-invariant CI.
- Existing Swift package and mirror checks remain green.
