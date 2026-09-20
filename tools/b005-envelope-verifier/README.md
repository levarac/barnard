# `b005-envelope-verifier`

macOS SwiftPM CLI that verifies one B005 v2 signed envelope with Barnard's production verifier.
It accepts no keys, makes no network calls, and writes no raw envelope bytes to logs.

## Build and run

```bash
cd tools/b005-envelope-verifier
swift build
printf '%s' '{"signedEnvelopeHex":"<lowercase raw signed envelope hex>","currentEnin":6000000}' | .build/debug/B005EnvelopeVerifier
```

The input must be exactly one JSON object with exactly `signedEnvelopeHex` and `currentEnin`.
`signedEnvelopeHex` is the raw signed envelope before the four-byte B005 container; the tool wraps it
with relay hop `0` before calling `BarnardB005EnvelopeV2.verify` with the production name normalizer
and public-key recoverer. Input is capped at 2 KiB and signed envelopes at 508 bytes.

On success, stdout is one bounded JSON line:

```json
{"kind":"BARNARD_B005_VERIFIED_V1","eventIdHex":"...","joinMode":0,"validFromEnin":0,"validThroughEnin":0,"relayExpiresAtEnin":0}
```

Malformed or unverified input exits nonzero and writes only `B005_ENVELOPE_VERIFICATION_FAILED` to
stderr.

## Tests

```bash
swift test
```
