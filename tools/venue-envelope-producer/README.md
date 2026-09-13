# `venue-envelope-producer`

macOS CLI that emits one real, signed B005 v2 envelope container -- the exact bytes a venue
device broadcasts. It runs the four-call chain spec 122 defines:
`BarnardB005EnvelopeV2.encodeUnsignedEnvelope` -> `BarnardCoreSigning.signRecoverable` ->
`BarnardB005EnvelopeV2.assembleSignedEnvelope` -> `BarnardB005EnvelopeV2.encodeContainer`.

It does **not** run a ceremony, generate or hold keys long-term, or write the outer
`VenueBundleV1` CBOR container. It takes fields and a private key you already have (from the
ceremony, once parallax#83 exists; from a test fixture today) and turns them into a container.

## Build and run

```bash
cd tools/venue-envelope-producer
swift build
.build/debug/VenueEnvelopeProducer input.json
```

`input.json`:

```json
{
  "registrarHex": "...20 bytes, hex...",
  "anchorOperatorHex": "...20 bytes, hex...",
  "nonceHex": "...32 bytes, hex...",
  "authorityKeysHex": ["...1-8 compressed secp256k1 points, hex, strictly ascending..."],
  "signingPrivateKeyHex": "...32 bytes, hex -- must correspond to one of authorityKeysHex...",
  "joinMode": 0,
  "eninSeconds": 300,
  "validFromEnin": 6000000,
  "validThroughEnin": 6000010,
  "relayExpiresAtEnin": 6000004,
  "eventCodeHashHex": null,
  "eventDisplayName": "My Event",
  "relayHopCount": 0
}
```

`eventCodeHashHex` is only read when `joinMode == 1` (gated); in open mode (`joinMode == 0`)
the code hash is derived from `eventId` per spec 122 and any supplied value is ignored.
`delegationCert` is not exposed here: this tool only produces authority-direct envelopes (empty
cert), per beid#432's design -- the venue device holds no key, so there is nothing to delegate to.

The container hex goes to stdout; `eventId`, the derived signer public key, and the container's
byte length go to stderr as a sanity check.

## Ceremony driver mode

`VenueEnvelopeProducer --signed-envelope-stdin` is the native signing boundary for a ceremony
driver. It reads exactly one frame from stdin: a four-byte big-endian descriptor length, that many
UTF-8 JSON descriptor bytes (the input shape above without `signingPrivateKeyHex`), then exactly 32
raw private-key bytes, followed by EOF. It writes exactly one JSON line to stdout:

```json
{"kind":"SIGNED_ENVELOPE_V1","eventIdHex":"...","signedEnvelopeHex":"..."}
```

`signedEnvelopeHex` is the assembled B005 envelope before BLE wrapping. The key is never accepted
from argv, JSON, or stderr. The descriptor is capped at 16 KiB and malformed, truncated, trailing,
or key-mismatched input is refused. The caller owns the input buffer and should clear it after the
process returns; the Swift boundary also clears its temporary mutable key buffer on exit, without
claiming secure-memory erasure of copies made by the runtime.

If you have a private key but not yet its compressed public key for `authorityKeysHex`, derive it
first with `VenueEnvelopeProducer.derivePublicKeyHex(fromPrivateKeyHex:)` (see
`Sources/VenueEnvelopeProducerKit/VenueEnvelopeProducer.swift`) -- there is no separate CLI flag
for it today.

## Tests

```bash
swift test
```

`Tests/VenueEnvelopeProducerKitTests` exercises the same `VenueEnvelopeProducer.produce` code
path the CLI calls, against a real signing key (not a precomputed vector): the real Swift
verifier accepting the output, three negative controls, and the `r ‖ s ‖ v` assembly pin. It also
writes `test-vectors/venue-envelope-producer-fixture.txt`, which
`BarnardVenueEnvelopeProducerFixtureTest.kt` in `packages/android/barnard` reads to confirm the
real Kotlin verifier accepts the exact same bytes.
