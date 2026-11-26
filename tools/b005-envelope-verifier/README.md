# `b005-envelope-verifier`

macOS SwiftPM CLI that verifies one B005 v2 signed envelope with Barnard's production verifier.
It accepts no keys, makes no network calls, and writes no raw envelope bytes to logs.

## Build and run

```bash
cd tools/b005-envelope-verifier
swift build
printf '%s' '{"signedEnvelopeHex":"<lowercase raw signed envelope hex>","currentEnin":6000000}' | .build/debug/B005EnvelopeVerifier
```

Invoke the legacy operation with no arguments or `--verify-signed-envelope-stdin`.
The input must be exactly one JSON object with exactly `signedEnvelopeHex` and `currentEnin`.
`signedEnvelopeHex` is the raw signed envelope before the four-byte B005 container; the tool wraps it
with relay hop `0` before calling `BarnardB005EnvelopeV2.verify` with the production name normalizer
and public-key recoverer. Input is capped at 2 KiB and signed envelopes at 508 bytes.
Because it builds its own container, it does not check the received container; receiving hosts
must apply specification 122's step 1 container checks before extracting `signedEnvelopeHex`.
It does not deduplicate repeated envelopes or enforce a per-peer attempt budget; receiving hosts
must do both before invoking it, as required by specification 122.
The [JSON Schema](../../schema/barnard/v2/b005-envelope-verifier.schema.json) defines the
versioned request and receipt shapes. `currentEnin` comes from the caller; this tool does not
establish the device's current time.

On success, stdout is one bounded JSON line:

```json
{"kind":"BARNARD_B005_VERIFIED_V1","eventIdHex":"...","joinMode":0,"validFromEnin":0,"validThroughEnin":0,"relayExpiresAtEnin":0}
```

This receipt reports only that the envelope's signature and lease window verified for the given current ENIN; it is not evidence that the event is registered, and registration is NOT confirmed by this result.
The CLI verifies stdin offline and does not observe radio reception. This result MUST NOT be
presented to a user as "verified" or "registered"; it does not prove physical presence or permit
relay or joining. Consumers must independently verify the anchored definition at a pinned block
before treating the event as `REGISTRY_VERIFIED`. The six-field V1 receipt is an exact-key
integration contract; changing its kind or fields requires a versioned consumer migration.

Malformed or unverified input exits nonzero and writes only `B005_ENVELOPE_VERIFICATION_FAILED` to
stderr.

## Tests

```bash
swift test
```

From the repository root, validate request and receipt fixtures (including invalid
boundaries) against the published root JSON Schema without third-party dependencies:

```bash
python3 scripts/check-b005-envelope-verifier-schema-contract.py
```

## Authority operation v1

`B005EnvelopeVerifier authority-v1` is a separately versioned, offline operation. Its stdin is the
strict request described by
[`b005-envelope-authority-verifier-v1.schema.json`](../../schema/barnard/v2/b005-envelope-authority-verifier-v1.schema.json).
It accepts the canonical signed-envelope bytes, `verificationEnin`, and an authorization context with unique JSON member names at every level.
It neither selects an RPC endpoint nor fetches, authenticates, or blesses a registry snapshot.

The caller obtains the registered definition and signer set through its own authenticated registry
path. It sets `definitionSha256Hex` to SHA-256 of the registry's canonical definition bytes and
`eventIdHex` to that definition's identity. Signers must be sorted strictly by public-key hex then
role, with no duplicates. The binding is:

```
contextDigest = SHA256(
  UTF8("barnard-b005-authorization-context:v1\\0") ||
  definitionSha256 || eventId || uint8(signerCount) ||
  each(compressedPublicKey || roleByte)
)
roleByte: authority-direct = 0, delegate = 1
```

The caller pins both `definitionSha256Hex` and `contextDigestHex` to the authenticated registry
result. Recomputing this digest only checks input integrity; the CLI does not assert registry
provenance. Input is capped at 8 KiB, canonical envelope bytes at 508 bytes, and stdout at 1 KiB.
The SDK verifier is the sole authority for signature, signer recovery, mode, and window. The
structure-only scheduling accessor can only distinguish an expired verified envelope after a
second SDK verification; it can never authorize a success.

Success emits one JSON line with `kind`, SHA-256 of the exact input envelope bytes,
authorization-context digest, registered event identity, authenticated signer compressed public
key and role, and `validFromEnin`, inclusive `validThroughEnin`, and exclusive
`relayExpiresAtEnin`. The offline request and receipt are holder-held records for
the caller and must stay outside Advertise, GATT, anchors, and witness blobs.

Stable stderr error codes are:

- `B005_AUTH_INVALID_CONTEXT`: missing, malformed, unsorted, or digest-mismatched context;
- `B005_AUTH_SIGNER_UNAUTHORIZED`: authenticated signer is absent, has the wrong allowed role, or
  the envelope identity differs from the registered definition identity;
- `B005_AUTH_SIGNATURE_VERIFICATION_FAILED`: malformed envelope or failed SDK verification;
- `B005_AUTH_SIGNED_WINDOW_EXPIRED`: an otherwise SDK-verified envelope is at or beyond its
  exclusive relay expiry.

### Reproducible release build and pinning

Build from a clean checkout at the consumer-selected tag and verify the tag's commit before use:

```bash
git checkout --detach refs/tags/<tag>
git rev-parse HEAD
cd tools/b005-envelope-verifier
swift build -c release
shasum -a 256 .build/release/B005EnvelopeVerifier
```

Publish the verified binary with its tag, commit ID, Swift toolchain version, target platform, and SHA-256.
A consumer checks the published identity and digest of the binary it will execute. Repeat the build with
the published toolchain and platform when checking reproducibility. The tests use synthetic fixtures.
The authority operation changes no B005 wire bytes and makes no network requests.
