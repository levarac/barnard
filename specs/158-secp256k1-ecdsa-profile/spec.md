# Barnard secp256k1 ECDSA Profile

## Problem statement

Barnard's Swift and Kotlin implementations contain their own secp256k1 code. The
signature contract was implicit, which made a cryptographic-backend replacement
capable of silently changing signature bytes. This profile records the existing
contract and adds shared, independently generated conformance vectors. This is
test-first work: it specifies and tests current behavior without changing
production code or public payload shapes.

## Goals and non-goals

- Define the byte-exact ECDSA behavior a replacement backend must preserve.
- Exercise positive, boundary, and negative cases in both implementations.
- Expose existing deviations as RED tests rather than repairing them here.
- Do not change production code, schemas, or on-wire formats.

## Glossary

- **Compact signature**: the 64-byte, big-endian `r || s` representation, with
  a separate recovery id `v`.
- **Low-S**: `s <= floor(N / 2)`, where `N` is the secp256k1 group order.
- **Recovery id**: the integer selecting the ephemeral point used to recover
  the compressed signing public key.

## Normative profile

1. The curve is secp256k1 and its private-key domain is the 32-byte big-endian
   scalar range `1 <= d < N`. Swift's owner-key boundary validates exactly that
   range (`BarnardCoreOwnerKey.swift:665-670`); Kotlin applies the same scalar
   bounds (`BarnardSigning.kt:413-414`). The order constant is pinned in Swift
   (`Secp256k1.swift:202-209`) and Kotlin (`BarnardSigning.kt:50-68`).
2. Public keys are serialized in 33-byte SEC1 compressed form: prefix `0x02`
   for even Y or `0x03` for odd Y, followed by the 32-byte big-endian X
   coordinate. Swift does so at `Secp256k1.swift:296-301`; Kotlin does so at
   `BarnardSigning.kt:118-124`. Inputs must have that length and prefix, X must
   be below the field prime, and decompression must produce an on-curve point
   (`BarnardCoreOwnerKey.swift:684-685`; `BarnardSigning.kt:260-267`).
3. The message input to this primitive is exactly 32 bytes. It is interpreted
   as a big-endian integer and reduced modulo `N` (`BarnardCoreSigning.swift:
   158-165`; `BarnardSigning.kt:505-509`).
4. Nonces use RFC 6979 with HMAC-SHA-256, `int2octets(d)` and
   `bits2octets(hash)`, and **no extra entropy**. The state starts as 32 `0x01`
   bytes for V and 32 `0x00` bytes for K, then follows the RFC's `0x00` and
   `0x01` update steps (`BarnardCoreSigning.swift:382-416`;
   `BarnardSigning.kt:474-495`). No random or auxiliary input enters either
   derivation.
5. Signing computes standard ECDSA `r = x(kG) mod N` and
   `s = k^-1(e + d*r) mod N`. If `r == 0` or `s == 0`, signing MUST advance the
   *existing* RFC 6979 generator state and request its next candidate, repeating
   until both are nonzero. The current signing loops identify those retry
   conditions (`BarnardCoreSigning.swift:170-212`; `BarnardSigning.kt:511-522`),
   but both currently restart nonce derivation on each iteration and therefore
   repeat the same candidate. This known deviation is intentionally not fixed
   by issue #158.
6. Signing normalizes high S to `N - s`, producing low-S output
   (`BarnardCoreSigning.swift:214-217`; `BarnardSigning.kt:524-527`). Strict
   Barnard verification rejects, rather than normalizes, an incoming high-S
   signature (`BarnardCoreOwnerKey.swift:634-643`).
7. `r` and `s` are each unsigned, big-endian, left-zero-padded 32-byte values;
   the compact encoding is `r || s` (64 bytes), with `v` carried separately.
   Both signers emit fixed 32-byte components (`BarnardCoreSigning.swift:
   233-237`; `BarnardSigning.kt:539`). Verification rejects any component whose
   encoded length is not exactly 32 bytes (`BarnardCoreOwnerKey.swift:625-631`).
8. After low-S normalization, the signer derives `v` by recovering candidates
   and selecting the one whose compressed key equals `dG`
   (`BarnardCoreSigning.swift:219-231`; `BarnardSigning.kt:529-537`). Barnard
   output and native verification accept only `v = 0` or `v = 1`
   (`BarnardCoreOwnerKey.swift:625-631`); Ethereum input adapters may normalize
   `27/28` to `0/1` (`BarnardCoreOwnerKey.swift:654-662`). All other values are
   invalid.

## Retry-vector feasibility

No `r == 0` or `s == 0` first-candidate vector is included. For a uniformly
distributed secp256k1 nonce, either event has probability approximately `1/N`,
so finding one by message/key search requires on the order of 2^256 trials.
The ecdsa 0.19.1 reference can model the required next-candidate transition,
but cannot feasibly construct such an input. The retry rule is nevertheless
normative, and the currently restarting loops are explicitly recorded above.

## Compatibility, security, and privacy

This profile freezes existing signature bytes and is intended to make backend
replacement compatible. It adds no runtime behavior and no public shape, so no
schema change is needed. The vectors use fixed test keys only. No Scan,
Advertise, Central, Peripheral, GATT, or Transport payload is changed, and no
device-unique persistent identifier is added on-wire.

## Example

For private scalar `1` and message hash `000102...1f`, RFC 6979 yields the
compact low-S signature and recovery id recorded in
`test-vectors/secp256k1-ecdsa-v1.txt`; recovery returns the compressed generator
public key. The same file shows that zero, `N`, and `N+1` private scalars,
non-32-byte components, high-S input, an off-curve key, and recovery id `2` are
invalid.
