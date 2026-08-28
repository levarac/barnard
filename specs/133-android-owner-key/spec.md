# Android Owner-Key Primitives and Cross-Language Conformance Vectors

## Problem statement

`specs/092-owner-key/spec.md` added a long-lived owner key, self-proofs, and
optional EVM wallet endorsement to `BarnardCore` (Swift). Its Non-goals
section explicitly excluded Kotlin and React Native implementations, which
was correct at the time: Android's `packages/android/barnard` is a full
parallel Kotlin implementation of the Barnard protocol (not a C-ABI bridge to
`BarnardCore`), and never received the owner-key/binding primitives #92
added on Swift.

Issue #133 asks for exactly that: bring the four owner-key primitive groups
to Kotlin, byte-exact with the Swift reference. Because Android is a
hand-written parallel implementation rather than a binding, there was no
existing mechanism to prove the two implementations agree on wire bytes.
Today Kotlin's owner-key-adjacent tests (once added) would only test
themselves against themselves — self-consistency, not conformance with
Swift. This spec introduces a shared, cross-language vector mechanism so a
future protocol drift in either implementation is caught on both sides.

This spec is a short follow-up increment. It does not repeat #92's byte
layouts, domain tags, or canonical-text rules — see
[`specs/092-owner-key/spec.md`](../092-owner-key/spec.md) for the normative
definitions of every primitive named below.

## Goals

- Add exactly these four primitive groups to
  `packages/android/barnard`, byte-exact with the `BarnardCore` Swift
  reference:
  - `deriveOwnerKeyPair` (HKDF info = `"barnard-owner"`, per #92 ยง
    "Owner-key derivation").
  - `buildAccountBindingText` (the canonical wallet-binding text producer
    only — Android produces this text for a wallet SDK to sign; it does not
    verify wallet signatures, see Non-goals).
  - `buildSelfProofMessage` / `signSelfProof`.
  - `buildWalletAcknowledgementMessage` / `signWalletAcknowledgement`.
- Introduce `test-vectors/`, a repo-level directory of golden values
  computed from the Swift `BarnardCore` reference implementation and
  consumed byte-for-byte by both the Swift and Kotlin test suites for these
  primitives. See `test-vectors/README.md` for the file format and
  convention, which is available for future specs beyond owner-key.
- Ensure a deliberate divergence between the Swift and Kotlin
  implementations of these primitives fails both test suites, not neither.

## Non-goals

- Keccak-256, EIP-191 digesting, or wallet-signature verification
  (`verifyWalletBinding`, `verifyAccountUnbinding`) on Android. Android only
  needs to *produce* the canonical `buildAccountBindingText` output for an
  external wallet SDK to sign with `personal_sign`; it does not need to
  verify EOA signatures itself in this increment.
- Owner-key rotation (`buildAccountRotationMessage` / `signAccountRotation`)
  or account unbinding (`buildAccountUnbindingMessage` /
  `signAccountUnbinding` / `buildAccountUnbindingText`) on Android.
- Any change to Swift `BarnardCore` behavior. The Swift implementation
  remains the reference; Kotlin conforms to it, not the other way around.
- Dart (`packages/dart/barnard`) or React Native
  (`packages/react-native/barnard`) wiring. Both packages carry their own
  Kotlin/Swift copies and may need the same four primitive groups, but
  whether and how is an open question, deliberately left unresolved by this
  spec (see "Open questions" below).

This spec supersedes #92's non-goal "Adding Kotlin or React Native
implementations" **only** for the four primitive groups listed under Goals,
and **only** for `packages/android/barnard`. Every other non-goal in #92
(rotation, unbinding, wallet-signature verification, RPC-based smart-wallet
verification, and so on) remains a non-goal on every platform, including
Android, until a future spec says otherwise.

## Cross-language conformance vectors

Prior to this spec, `packages/android/barnard`'s tests validated Kotlin's
protocol primitives (RPID, ENIN, event-signing) against fixed inputs and
Kotlin-computed expected outputs only. That catches Kotlin regressions but
cannot catch Kotlin diverging from the Swift reference it is meant to
mirror, because nothing outside Kotlin's own test file asserted what the
"correct" byte-exact output should be.

This spec introduces `test-vectors/`, a repository-level directory (sibling
to `packages/` and `specs/`) holding one plain-text golden-vector file per
primitive family. `test-vectors/owner-key-v1.txt` is the first such file,
covering `deriveOwnerKeyPair`, `buildAccountBindingText`,
`buildSelfProofMessage`/`signSelfProof`, and
`buildWalletAcknowledgementMessage`/`signWalletAcknowledgement`. Every
value in it is derived from running the Swift `BarnardCore` reference
implementation — never hand-computed or transcribed from Kotlin.

Both `packages/swift/barnard` and `packages/android/barnard` test suites
load this same file at test time, run their own implementation of each
primitive against the vector's inputs, and assert the outputs match the
vector's expected values byte-for-byte. A future change that alters either
implementation's output for these primitives, without also updating the
shared vector file, fails that implementation's test suite. A change that
alters only one implementation's behavior, leaving it disagreeing with the
vector (and therefore with the other implementation), is caught the same
way.

See `test-vectors/README.md` for the exact file format (a `key=value`
convention, chosen because the Kotlin test target has no JSON dependency
today) and for how to add further vector files as future specs add more
cross-language primitives.

## Compatibility

- No change to any public/on-wire schema, `BarnardCore` Swift behavior, or
  existing Android protocol behavior (RPID, ENIN, event-signing).
- Additive only: new Kotlin functions, a new test-vectors mechanism, new
  tests. No existing Kotlin API is renamed or removed.

## Security and privacy

- The four primitives added here are the same holder-held, point-to-point
  artifacts defined by #92: owner public keys, self-proofs, and wallet
  acknowledgements. Per #92's invariant, they MUST NOT appear in Advertise
  data, GATT values, public anchors, or witness blobs. This spec adds no
  new on-wire surface, so the invariant is inherited unchanged.
- `test-vectors/owner-key-v1.txt` contains only fixed, publicly-known test
  key material (e.g. private scalars `1` and `2`, all-zero and sequential
  seeds) used throughout the existing Swift test suite. It contains no real
  account secrets and carries no privacy risk.

## Open questions

- Do `packages/dart/barnard` and `packages/react-native/barnard` — which
  each carry their own copies of Kotlin and/or Swift code — need these same
  four owner-key primitive groups, and if so, do they consume
  `test-vectors/owner-key-v1.txt` directly or through their host packages'
  test suites? Not resolved here; left for a future spec once Android's
  primitives (and the vector mechanism itself) have shipped and proven out.

## References

- [`specs/092-owner-key/spec.md`](../092-owner-key/spec.md): normative byte
  layouts, domain tags, canonical-text rules, and security rationale for
  every primitive named in this spec.
