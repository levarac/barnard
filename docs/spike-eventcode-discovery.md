# Spike: BLE Event Auto-Discovery (eliminate manual EventCode entry)

Status: EXPERIMENT / prototype-and-learn. Branch `spike/eventcode-discovery`. Not for merge.

## Problem

`joinEvent(code)` (`BarnardEngine.kt:404`) requires the participant to already
possess the EventCode string, which today means typing it at check-in. The
EventCode is the sole input (besides the per-device `DeviceSecret`) to the
whole crypto chain:

```
TEK    = HKDF(DeviceSecret || EventCode, "barnard-tek", 16)      BarnardCrypto.kt:55
RPIK   = HKDF(TEK, "EN-RPIK", 16)                                  BarnardCrypto.kt:77
RPI    = AES128-ECB(RPIK, "EN-RPI" || 000000 || ENIN_be32)         BarnardCrypto.kt:91
EventCodeHash = SHA256(EventCode)[0:8]                             BarnardCrypto.kt:178
```

`EventCodeHash` is already broadcast today, but only as a GATT characteristic
(`B004`, read after a full connect) used to gate detection matching
(`gatt_b004_mismatch`, `BarnardEngine.kt:1383`) — it is not present in the
BLE advertisement payload itself, and it is a one-way hash, not the code.

There is no organizer/participant role distinction anywhere in the codebase
today (`joinEvent` is symmetric), and the EventCode itself has no defined
length/charset/entropy contract — it's an opaque UTF-8 string
(`schema/barnard/v2/events.schema.json:118`).

## Goal

Organizer device advertises an announcement; participant device scans,
derives the same event scope, and calls the existing `joinEvent(code)` with
**zero manual entry**, then reaches normal RPID mutual detection.

## Payload format

**Hardware constraint drove the design.** The two emi lab devices (Galaxy S7
edge, Nexus 5X) predate reliable Android BLE 5 extended-advertising support,
so the classic 31-byte legacy advertisement budget applies. After a flags AD
structure (3 bytes) and a 16-bit service UUID (4 bytes) there are only
~24 bytes left — not enough for `eventId + EventCode + TTL` with any safety
margin, and definitely not enough for a signature.

So the announcement is **not** carried in the advertisement payload itself.
It reuses the pattern the codebase already has for `B002`/`B003`/`B004`: the
advertisement is just a low-information beacon that says "an announcement is
readable here," and the actual payload rides over GATT after connect, where
the ATT MTU budget (~185–512 bytes typical) comfortably fits everything:

- **Advertisement** (new, organizer-only, separate from the existing `B001`
  detection service so normal detection scanning is unaffected): a fixed
  16-bit discovery service UUID (fixed, not per-event, for the same
  background-scan reason `B001` is fixed — see `specs/004-resolvable-id/spec.md:20`)
  + optional debug local name. No event-specific bytes at all — nothing
  device-unique, nothing event-unique, in the over-the-air advertisement.
- **New GATT characteristic** (`EventAnnouncement`, read-only), populated
  only when the app is in organizer mode, containing:

  | field | bytes | notes |
  |---|---|---|
  | version | 1 | payload format versioning |
  | eventId | 16 | organizer-chosen opaque event label (not the code) |
  | eventCode | variable, length-prefixed | the actual join secret |
  | expiresAtEpochSec | 4 | TTL — participant refuses to auto-join a stale announcement |

  Total easily under 200 bytes for realistic EventCode lengths.

- **Participant flow**: scan for the discovery service UUID → connect → read
  `EventAnnouncement` → validate `expiresAtEpochSec` is in the future →
  call `joinEvent(eventCode)` → proceed exactly as today (existing
  `startAuto()`/detection path, `gatt_b004_mismatch` still fires as the
  existing safety net if something is wrong).

This is deliberately the cheapest change that reuses 100% of the existing
connect/GATT-read machinery (`handleScanResult`, `enqueueConnect`,
`gattCallback.onCharacteristicRead`, `BarnardEngine.kt:972-1447`) instead of
inventing a second radio protocol.

No device-unique persistent identifier appears anywhere in the announcement:
`eventId` is organizer-chosen and event-scoped, `eventCode` is the existing
event-scoped secret, `expiresAtEpochSec` is a timestamp. The organizer's BLE
MAC is already randomized by the OS per the existing advertising code path.

## Security trade-offs

**Broadcasting the EventCode over BLE (even via GATT-read rather than raw
advertisement) defeats EventCode secrecy as an admission-control
mechanism.** Any device within BLE range (~10–30m, more with a directional
antenna) that speaks the discovery protocol can read the announcement and
auto-join without the organizer's intent to admit them.

This sounds worse than it is, given what EventCode secrecy actually
protects today: **the real Sybil/admission gate in barnard is
check-in/eventAuth (physical presence + ticket verification), not EventCode
secrecy.** EventCode's job in the current design is to scope the crypto
namespace — to give TEK/RPID derivation a distinct input per event so
unrelated events don't collide or let devices correlate across events — not
to act as a capability token that grants participation rights by itself.
Making it openly discoverable converts it from "shared secret" to "shared
namespace label," which is a much smaller trade-off than it first appears,
**as long as check-in remains the actual admission gate** and nothing
downstream treats "has derived the correct TEK" as proof of authorization.
This assumption should be verified against the actual check-in/eventAuth
implementation before this design is taken past spike stage — it was not in
scope for this spike's exploration.

Residual risks, none of which are identity/privacy risks (the privacy
invariant — no device-unique data in the payload — holds under this design):

- **Event squatting / DoS via spoofed announcement.** An attacker (or a
  second organizer device in range) could advertise a bogus announcement
  with a plausible `eventId` and a garbage or malicious `eventCode` before
  the real organizer starts. Victims would derive a TEK that never matches
  the real event. This fails *loud*, not silent: `gatt_b004_mismatch`
  already fires today when detection RPIDs don't align, so it manifests as
  "nobody detects anybody," not as silent misbinding — but it's still a
  usable griefing vector with zero cost to the attacker.
- **No organizer authentication is possible today.** `BarnardSigning.kt`
  derives a per-device signing key from `HKDF(DeviceSecret || EventCode,
  "barnard-sign", 32)` — but that requires already knowing the EventCode,
  so it cannot be used to sign the announcement that delivers the
  EventCode in the first place (chicken-and-egg). Any signature scheme for
  the announcement itself would need a *separate*, pre-provisioned
  organizer keypair not tied to the EventCode chain — out of scope for this
  spike.
- **Replay of a stale-but-still-cached announcement** after the organizer
  rotates/ends the event. Mitigated by the `expiresAtEpochSec` TTL field,
  but only as well as participant clocks and the chosen TTL length allow.

## Alternative designs considered

1. **Raw EventCode in the legacy advertisement payload itself (chosen
   design's rejected sibling).** Pro: zero-connect, lowest latency, works
   even where GATT connect is flaky. Con: the 31-byte legacy AD budget
   forces very short EventCodes with no room for TTL or event ID, and
   there's no natural place to add a spoofing check later. Rejected because
   it locks the EventCode format to something far shorter than what's
   possible today, for a latency win that doesn't matter at check-in time.

2. **GATT-characteristic announcement (chosen).** See above. Reuses
   existing connect/read plumbing, has payload room for TTL and eventId, and
   the existing `gatt_b004_mismatch` mismatch path is a free safety net.
   Main cost: an extra BLE connect round-trip before `joinEvent`, on top of
   the connect(s) detection already performs — acceptable since it happens
   once at join time, not per-detection-cycle.

3. **One-tap confirmation instead of fully silent auto-join.** Same wire
   format as (2), but the participant UI shows "Join <eventId>, organizer
   nearby?" before calling `joinEvent`, instead of joining the instant the
   announcement is read. Pro: gives a human a chance to notice an
   implausible/duplicate announcement (mitigates the squatting risk above
   without needing organizer signatures). Con: not literally
   zero-manual-entry — trades "type a code" for "tap to confirm," which is
   a much smaller UX cost but isn't what the MTG framed the goal as.
   **Recommended as the production-track evolution of design 2** even
   though this spike prototypes fully-silent auto-join per the stated
   objective, because it closes the one open spoofing gap without
   requiring new crypto infrastructure.

4. **Server-mediated discovery (organizer registers event with a backend,
   participant queries by proximity/QR/BLE-ID-only, backend returns the
   real EventCode over an authenticated channel).** Pro: real spoofing
   resistance via account-bound organizer identity. Con: requires network
   connectivity at check-in (today's BLE-only detection path deliberately
   doesn't need it) and a facilitator-side API that doesn't exist yet
   (`facilitator-check` is a separate, unrelated repo/spike). Out of scope
   for a BLE-native spike; worth a separate spike if design 3's UX
   compromise turns out to be insufficient.

## Recommendation

Ship design 2 (GATT-announcement) as the spike, matching the literal "zero
manual code entry" ask from the MTG. Flag design 3 (one-tap confirm) as the
recommended production path in the write-up to the team, since it removes
the only unmitigated spoofing/squatting risk at negligible UX cost — this is
a judgment call for the team, not something this spike settles.
