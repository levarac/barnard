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
It does not deduplicate repeated envelopes or enforce a per-peer attempt budget; receiving hosts
must do both before invoking it, as required by specification 122.
The [JSON Schema](../../schema/barnard/v2/b005-envelope-verifier.schema.json) defines the
versioned request and receipt shapes. `currentEnin` comes from the caller; this tool does not
establish the device's current time.

On success, stdout is one bounded JSON line:

```json
{"kind":"BARNARD_B005_VERIFIED_V1","eventIdHex":"...","joinMode":0,"validFromEnin":0,"validThroughEnin":0,"relayExpiresAtEnin":0}
```

Despite the historical `VERIFIED` word in the kind, this receipt means only
[`RADIO_SELF_VERIFIED`](../../specs/122-b005-v2-signed-envelope/spec.md#receiver-policy--the-display-and-relay-gate)
at the supplied ENIN. It is not registry verification, proof of physical presence, or permission
to relay or join. Consumers must independently verify the anchored definition at a pinned block
before treating the event as `REGISTRY_VERIFIED`. The six-field V1 receipt is an exact-key
integration contract; changing its kind or fields requires a versioned consumer migration.

Malformed or unverified input exits nonzero and writes only `B005_ENVELOPE_VERIFICATION_FAILED` to
stderr.

## Tests

```bash
swift test
```
