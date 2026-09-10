// Use of this source code is governed by a BSD-style license.

package org.levarac.barnard

import java.nio.charset.CharacterCodingException
import java.security.MessageDigest
import org.bouncycastle.crypto.digests.KeccakDigest

enum class BarnardB005ReceiverState { UNVERIFIED, RADIO_SELF_VERIFIED, REGISTRY_VERIFIED }

interface BarnardB005PublicKeyRecovering {
    fun recover(recoveryId: Int, r: ByteArray, s: ByteArray, digest: ByteArray): ByteArray?
    fun isValidCompressedKey(key: ByteArray): Boolean
}

object BarnardB005NativeRecoverer : BarnardB005PublicKeyRecovering {
    override fun recover(recoveryId: Int, r: ByteArray, s: ByteArray, digest: ByteArray) =
        BarnardSigning.recoverPublicKey(recoveryId, r, s, digest)
    override fun isValidCompressedKey(key: ByteArray) = BouncyCastleSecp256k1Backend.isValidCompressedPublicKey(key)
}

/**
 * A plain (non-`data`) class with a private constructor: `data class` would generate a public
 * `copy()` (and, from Java, a callable constructor) that lets a caller fabricate
 * `receiverState = REGISTRY_VERIFIED` directly. There is no public or `internal` constructor at
 * all -- the only way to obtain one is [BarnardB005EnvelopeV2.verify], which always produces
 * `UNVERIFIED` or `RADIO_SELF_VERIFIED`. This SDK never assigns `REGISTRY_VERIFIED`: doing so is
 * the responsibility of the component that performed the authenticated registry read (the host
 * app), per spec 122's receiver policy; tracked as beid#367 / dispatch#11 (P4). It reaches the
 * private constructor through the `internal` factory function in [Companion], which is a member
 * of this class and so has access to it.
 *
 * Kotlin's codegen for "private constructor + companion factory" unconditionally emits a second,
 * JVM-`public` constructor overload carrying a trailing `kotlin.jvm.internal.DefaultConstructorMarker`
 * parameter -- a synthetic bridge letting the companion, a distinct JVM class, reach the private
 * constructor (confirmed empirically via javap; no combination of Kotlin visibility keywords
 * avoids it once a companion touches the private constructor). This bridge is `ACC_SYNTHETIC` and
 * reachable only via raw JVM reflection from within this same process; it is accepted as outside
 * this SDK's threat model, which is a hostile *peer* over the radio, not a hostile co-resident
 * process reflecting into this class's own bytecode.
 */
class BarnardB005VerifiedEnvelope private constructor(
    val receiverState: BarnardB005ReceiverState,
    val relayHopCount: Int,
    private val eventIdBacking: ByteArray,
    private val keySetDigestBacking: ByteArray,
    val joinMode: Int,
    private val eventCodeHashBacking: ByteArray,
    val eventDisplayName: String,
    val validFromEnin: Long,
    val validThroughEnin: Long,
    /**
     * The signed relay expiry, and the **exclusive** end of the half-open relay window
     * `[validFromEnin, relayExpiresAtEnin)` (spec 134: an envelope is relayable while
     * `currentEnin < relayExpiresAtEnin` and stops the moment `currentEnin` reaches it).
     * [BarnardB005EnvelopeV2.verify] has already enforced `relayExpiresAtEnin <=
     * validThroughEnin` and the 12-ENIN lifetime cap, so a host may use this directly as a relay
     * lease bound instead of falling back to a pessimistic `currentEnin + 1`.
     *
     * Both conventions a host needs to read this window are settled. `relayExpiresAtEnin` is the
     * **exclusive** end of the relay window, fixed by spec 134. `validThroughEnin` is the
     * **inclusive** last ENIN lying wholly inside the definition's validity window, per the
     * maintainer decision of 2026-09-10 on barnard#180, which also fixes the issuer derivation:
     * `validThroughEnin = floorDiv(validUntil + 1, eninSeconds) - 1` and
     * `validFromEnin = ceilDiv(validFrom, eninSeconds)`, the formulas `registryAgreement`
     * computes as `registryEndEnin` and `registryStartEnin`. Any other issuer derivation fails
     * spec 134 step 4. A host reading these values therefore applies the same rule the SDK does.
     *
     * One consequence of the two conventions together, recorded rather than hidden: because step
     * 5 requires `currentEnin < relayExpiresAtEnin <= validThroughEnin`, no envelope is servable
     * at `currentEnin == validThroughEnin`. Whether that final ENIN should become servable is the
     * part of barnard#180 still open, and it does not affect the meaning of this field.
     */
    val relayExpiresAtEnin: Long,
    val eninSeconds: Int,
    private val signedEnvelopeBacking: ByteArray,
) {
    // Every ByteArray getter returns a defensive copy: the backing arrays are the only mutable
    // state on this otherwise-immutable type, and returning them directly would let a caller
    // mutate a supposedly-verified envelope's fields in place after the fact.
    val eventId: ByteArray get() = eventIdBacking.copyOf()
    val keySetDigest: ByteArray get() = keySetDigestBacking.copyOf()
    val eventCodeHash: ByteArray get() = eventCodeHashBacking.copyOf()
    val signedEnvelope: ByteArray get() = signedEnvelopeBacking.copyOf()

    internal companion object {
        internal fun radioSelfVerified(
            relayHopCount: Int,
            eventId: ByteArray,
            keySetDigest: ByteArray,
            joinMode: Int,
            eventCodeHash: ByteArray,
            eventDisplayName: String,
            validFromEnin: Long,
            validThroughEnin: Long,
            relayExpiresAtEnin: Long,
            eninSeconds: Int,
            signedEnvelope: ByteArray,
        ) = BarnardB005VerifiedEnvelope(
            BarnardB005ReceiverState.RADIO_SELF_VERIFIED, relayHopCount, eventId, keySetDigest, joinMode,
            eventCodeHash, eventDisplayName, validFromEnin, validThroughEnin, relayExpiresAtEnin, eninSeconds,
            signedEnvelope,
        )
    }
}

/**
 * The subset of parallax's anchored `EventDefinitionV1` (protocol/spec/v0.1/event-definition.md)
 * that spec 134 step 4 requires a receiver to agree against: `eventId`, the authority key-set
 * digest (signer-authority agreement), `joinMode`, `eventCodeHash`, and the registered Unix-time
 * validity window.
 */
data class BarnardEventDefinitionV1(
    val eventId: ByteArray,
    val keySetDigest: ByteArray,
    val joinMode: Int,
    val eventCodeHash: ByteArray,
    val validFromUnixSeconds: Long,
    val validUntilUnixSeconds: Long,
)

/** A single field on which [registryAgreement] can find a mismatch between an envelope and a registered `EventDefinitionV1`. */
enum class BarnardRegistryMismatchField { EVENT_ID, EVENT_CODE_HASH, KEY_SET_DIGEST, JOIN_MODE, VALIDITY_WINDOW }

/**
 * The result of comparing a `RADIO_SELF_VERIFIED` envelope against a registered `EventDefinitionV1`:
 * either the two agree, or [mismatchedFields] names every field that disagreed. Either way this is
 * a pure comparison -- it never changes the envelope's [BarnardB005ReceiverState]. Assigning
 * `REGISTRY_VERIFIED` is the responsibility of the component that performed the authenticated
 * registry read (the host app), per spec 122's receiver policy; tracked as beid#367 / dispatch#11 (P4).
 */
sealed class BarnardRegistryAgreement {
    object Agrees : BarnardRegistryAgreement()
    data class Mismatched(val mismatchedFields: Set<BarnardRegistryMismatchField>) : BarnardRegistryAgreement()
}

/**
 * Why a set of envelope fields cannot be encoded. Each entry names the rule from
 * `specification 122`'s signed-envelope table that the input breaks.
 *
 * Every case here is a shape the shipped verifier would reject, so the encoder refuses to produce
 * it: a producer that can emit bytes [BarnardB005EnvelopeV2.verify] rejects is a defect in the
 * producer.
 */
enum class BarnardB005EncodeError {
    REGISTRAR_LENGTH, ANCHOR_OPERATOR_LENGTH, NONCE_LENGTH,
    KEY_COUNT, KEY_LENGTH, KEY_ORDER,

    /**
     * An authority key is not a valid compressed secp256k1 point. [BarnardB005EnvelopeV2.verify]
     * checks every key with `isValidCompressedKey`, so this closes the same gap on the producing
     * side.
     */
    KEY_NOT_ON_CURVE,
    JOIN_MODE, ENIN_SECONDS,
    EVENT_CODE_HASH_LENGTH,

    /** `joinMode == open` requires `eventCodeHash == SHA256(UTF8(lowercaseHex(eventId)))[0:8]`. */
    OPEN_EVENT_CODE_HASH_MISMATCH,
    DISPLAY_NAME_LENGTH, DISPLAY_NAME_CHARACTERS,

    /**
     * The display name is not NFC. `verify` enforces this, so an encoder that could not check it
     * was able to emit a name the verifier rejects.
     */
    DISPLAY_NAME_NOT_NORMALIZED,

    /**
     * A field is outside the range its wire encoding can represent, so serialising it would
     * silently truncate: `eninSeconds` is two bytes and the three ENIN fields are four each.
     * Swift cannot reach this case — its fields are typed `UInt16` and `UInt32` — which is why it
     * exists only here.
     */
    FIELD_WIRE_RANGE,
    CERT_LENGTH,

    /**
     * The window relations `verify` enforces: `validFromEnin < relayExpiresAtEnin <=
     * validThroughEnin`. An inverted or empty window is unsatisfiable there, so it is refused here.
     */
    VALIDITY_WINDOW,

    /** `relayExpiresAtEnin - validFromEnin` exceeds the 12-ENIN relay lifetime cap. */
    RELAY_LIFETIME,

    /** The assembled envelope would not fit the 508-byte `signedEnvelope` bound. */
    ENVELOPE_LENGTH,
    SIGNATURE_LENGTH,
}

/**
 * The typed fields of a B005 v2 signed envelope, in the order `specification 122` lays them out.
 * This is the encoder's input; [BarnardB005VerifiedEnvelope] is the decoder's output, and the two
 * are deliberately separate types — one carries what an issuer chose, the other what a receiver
 * established.
 */
class BarnardB005EnvelopeFields(
    val registrar: ByteArray,
    val anchorOperator: ByteArray,
    val nonce: ByteArray,
    /** Compressed secp256k1 points, `1..8`, strictly ascending and unique. */
    val authorityKeys: List<ByteArray>,
    val joinMode: Int,
    val eninSeconds: Int,
    val validFromEnin: Long,
    val validThroughEnin: Long,
    val relayExpiresAtEnin: Long,
    val eventCodeHash: ByteArray,
    val eventDisplayName: String,
    /** COSE_Sign1 delegation certificate, byte-identical to the bundle copy. Empty is authority-direct mode. */
    val delegationCert: ByteArray = ByteArray(0),
)

/** What an issuer signs, and what it signs it over. */
class BarnardB005UnsignedEnvelope internal constructor(
    private val toBeSignedBacking: ByteArray,
    private val signatureDigestBacking: ByteArray,
) {
    // Defensive copies, as BarnardB005VerifiedEnvelope already does in this file. Returning the
    // backing arrays would let a caller mutate `toBeSigned` after encoding while `signatureDigest`
    // kept its computed value -- and then sign a digest that no longer represents the bytes.
    // Swift needs no equivalent: its arrays are value types.

    /** The envelope from offset 0 up to but excluding the 65-byte signature — spec 122's `tbs`. */
    val toBeSigned: ByteArray get() = toBeSignedBacking.copyOf()

    /** `SHA256("barnard-b005-event-info:v1" || tbs)`, the value an issuer signs (spec 122). */
    val signatureDigest: ByteArray get() = signatureDigestBacking.copyOf()
}

/** The outcome of an encode attempt: the bytes, or the rule that refused them. */
sealed class BarnardB005EncodeResult {
    class Encoded(val envelope: BarnardB005UnsignedEnvelope) : BarnardB005EncodeResult()
    class Refused(val error: BarnardB005EncodeError) : BarnardB005EncodeResult()
}

/** The outcome of assembling a signed envelope. */
sealed class BarnardB005AssembleResult {
    class Assembled(val signedEnvelope: ByteArray) : BarnardB005AssembleResult()
    class Refused(val error: BarnardB005EncodeError) : BarnardB005AssembleResult()
}

/**
 * The four scheduling fields a B005 v2 container carries, read after **structure validation
 * only**: no signature check, no key recovery, no registry read, and no current ENIN.
 *
 * **Trust boundary, in one sentence: a window a host acts on comes only from a verified
 * envelope, and these values may be used solely to choose the ENIN it asks
 * [BarnardB005EnvelopeV2.verify] to run at.** An attacker controls every byte here, so treating
 * any of them as a fact about the event is a defect; using them to decide *what to ask* is not,
 * because the answer still comes from `verify`.
 *
 * This exists because decode and time-parameterised verification are fused: `verify` takes a
 * container and a `currentEnin`, so a host holding several pre-signed envelopes for one event must
 * already know an envelope's window in order to verify it, and that window lives in bytes it has
 * not decoded. Two alternatives were rejected and should not be reintroduced. A host-side parser
 * copies spec 122's offsets into the host and creates removal debt. An unsigned schedule hint
 * carried beside the envelopes is unverifiable by construction: `verify` sees only the container
 * and `currentEnin` and never sees the hint, so a hint claiming `[100, 112)` over a signed
 * `[100, 105)` verifies at the hinted start and the extra ENINs are checked by nothing.
 */
class BarnardB005SchedulingFields internal constructor(
    val validFromEnin: Long,
    val validThroughEnin: Long,
    /** Exclusive end of the half-open relay window, as on [BarnardB005VerifiedEnvelope]. */
    val relayExpiresAtEnin: Long,
    val eninSeconds: Int,
)

/**
 * Why a B005 v2 container failed the clock-independent structural checks.
 *
 * These are exactly the guards that depend on nothing but the bytes: no
 * current ENIN, no signature or key recovery, no display-name normalisation.
 * [BarnardB005EnvelopeV2.verify] runs them first, and a host serving its own
 * container runs them on their own, so both paths accept and reject the same
 * shapes.
 */
enum class BarnardB005StructureError {
    /** Container outside `4..512` bytes. */
    CONTAINER_LENGTH,

    /** Byte 0 is not [BarnardB005EnvelopeV2.FORMAT_VERSION]. */
    FORMAT_VERSION,

    /** Byte 1 exceeds the spec 134 hop limit of 2. */
    HOP_COUNT,

    /** The big-endian length at bytes 2-3 exceeds 508 or disagrees with the byte count. */
    ENVELOPE_LENGTH,

    /** Envelope byte 0 is not [BarnardB005EnvelopeV2.ENVELOPE_VERSION]. */
    ENVELOPE_VERSION,

    /** The envelope is shorter than the 199-byte floor its fixed fields need. */
    ENVELOPE_TOO_SMALL,

    /** The authority key count is outside `1..8`. */
    KEY_COUNT,

    /**
     * A declared length runs past the envelope, or the total size disagrees
     * with the sum of its parts.
     */
    FIELD_LAYOUT,

    /** `joinMode` is neither 0 nor 1. */
    JOIN_MODE,

    /** `eninSeconds` is zero, which no ENIN arithmetic can use. */
    ENIN_SECONDS,

    /** The event-code-hash TLV type byte is not 2. */
    EVENT_CODE_HASH_TLV_TYPE,

    /** The display-name length is outside `1..64`. */
    DISPLAY_NAME_LENGTH,
}

object BarnardB005EnvelopeV2 {
    const val FORMAT_VERSION = 3
    const val ENVELOPE_VERSION = 1

    /**
     * Clock-independent structural validation of a container, shared by
     * [verify] and by any caller that must judge a container's shape without a
     * current ENIN, a signature check, or key recovery.
     *
     * Returns null when the container is well formed at this layer. Passing
     * says nothing about authenticity: the signature, the validity window, the
     * key set and the display-name normalisation are all still unchecked,
     * because each of those needs an input this function deliberately does not
     * take.
     */
    fun validateStructure(container: ByteArray): BarnardB005StructureError? {
        if (container.size !in 4..512) return BarnardB005StructureError.CONTAINER_LENGTH
        if (container[0].u != FORMAT_VERSION) return BarnardB005StructureError.FORMAT_VERSION
        if (container[1].u > 2) return BarnardB005StructureError.HOP_COUNT
        val length = container[2].u shl 8 or container[3].u
        if (length > 508 || length != container.size - 4) return BarnardB005StructureError.ENVELOPE_LENGTH
        val e = container.copyOfRange(4, container.size)
        if (e.size < 199) return BarnardB005StructureError.ENVELOPE_TOO_SMALL
        if (e[0].u != ENVELOPE_VERSION) return BarnardB005StructureError.ENVELOPE_VERSION
        val n = e[73].u
        if (n !in 1..8) return BarnardB005StructureError.KEY_COUNT
        val a = 74 + 33 * n
        if (a + 91 > e.size) return BarnardB005StructureError.FIELD_LAYOUT
        if (e[a].u !in 0..1) return BarnardB005StructureError.JOIN_MODE
        if (read16(e, a + 1) == 0) return BarnardB005StructureError.ENIN_SECONDS
        if (e[a + 15].u != 2) return BarnardB005StructureError.EVENT_CODE_HASH_TLV_TYPE
        val nameLength = e[a + 24].u
        if (nameLength !in 1..64) return BarnardB005StructureError.DISPLAY_NAME_LENGTH
        val certLengthOffset = a + 25 + nameLength
        if (certLengthOffset >= e.size) return BarnardB005StructureError.FIELD_LAYOUT
        if (e.size != 165 + 33 * n + nameLength + e[certLengthOffset].u) {
            return BarnardB005StructureError.FIELD_LAYOUT
        }
        return null
    }
    /**
     * Reads the four scheduling fields at the offsets spec 122 fixes, from an envelope body that
     * has already passed [validateStructure]. [a] is the post-key-set base offset, `74 + 33 * n`.
     *
     * This is the single offset table for those four fields: [verify] and [schedulingFields] both
     * read through it, so the trusted and untrusted paths cannot come to disagree about where a
     * window lives in the bytes.
     */
    private fun readSchedulingFields(e: ByteArray, a: Int) = BarnardB005SchedulingFields(
        validFromEnin = read32(e, a + 3),
        validThroughEnin = read32(e, a + 7),
        relayExpiresAtEnin = read32(e, a + 11),
        eninSeconds = read16(e, a + 1),
    )

    /**
     * Structure-only scheduling accessor: the window a container claims, before any signature, key
     * recovery, registry read or clock. Returns null when [validateStructure] rejects the
     * container, so a caller receives four fields or none -- never a partial read of a malformed
     * container.
     *
     * **The values are untrusted.** See [BarnardB005SchedulingFields] for the trust boundary: use
     * them only to choose the `currentEnin` to pass to [verify], and take every value a host acts
     * on from `verify`'s result.
     */
    fun schedulingFields(container: ByteArray): BarnardB005SchedulingFields? {
        if (validateStructure(container) != null) return null
        val e = container.copyOfRange(4, container.size)
        return readSchedulingFields(e, 74 + 33 * e[73].u)
    }

    /**
     * The value at spec 122's offset `A+15`, which that table names `maxRelayHops` and pins to
     * `0x02` for `envelopeVersion 0x01`. Spec 134 requires the same value and describes a relayer
     * respecting it.
     *
     * Note for a future version: both cores validate this byte but neither reads it as a hop limit
     * — the two-hop bound is enforced by a separate constant — so a version permitting another
     * value would need the relay path changed too. Tracked as barnard#209.
     */
    const val MAX_RELAY_HOPS = 2

    /**
     * Encodes the canonical unsigned envelope for [fields], together with the digest an issuer
     * signs, per `specification 122`'s signed-envelope table. Refusal names the rule broken rather
     * than returning null, so a caller learns which field to fix.
     *
     * **The encoder refuses anything [verify] would reject.** An issuer that can produce
     * unverifiable bytes has only moved the failure later, to a venue with no connectivity.
     *
     * The layout is taken from the spec text rather than from [verify]'s reverse: an encoder
     * written as the decoder's inverse agrees with the decoder by construction and inherits
     * whatever the decoder assumes, which a round-trip test cannot detect because both sides share
     * the assumption. Byte-reproduction against the committed vectors is the check that can fail.
     */
    fun encodeUnsignedEnvelope(fields: BarnardB005EnvelopeFields, recoverer: BarnardB005PublicKeyRecovering = BarnardB005NativeRecoverer): BarnardB005EncodeResult {
        fun refuse(e: BarnardB005EncodeError) = BarnardB005EncodeResult.Refused(e)
        if (fields.registrar.size != 20) return refuse(BarnardB005EncodeError.REGISTRAR_LENGTH)
        if (fields.anchorOperator.size != 20) return refuse(BarnardB005EncodeError.ANCHOR_OPERATOR_LENGTH)
        if (fields.nonce.size != 32) return refuse(BarnardB005EncodeError.NONCE_LENGTH)
        if (fields.authorityKeys.size !in 1..8) return refuse(BarnardB005EncodeError.KEY_COUNT)
        if (fields.authorityKeys.any { it.size != 33 }) return refuse(BarnardB005EncodeError.KEY_LENGTH)
        if (fields.authorityKeys.any { !recoverer.isValidCompressedKey(it) }) return refuse(BarnardB005EncodeError.KEY_NOT_ON_CURVE)
        for (i in 1 until fields.authorityKeys.size) {
            if (compare(fields.authorityKeys[i - 1], fields.authorityKeys[i]) >= 0) return refuse(BarnardB005EncodeError.KEY_ORDER)
        }
        if (fields.joinMode !in 0..1) return refuse(BarnardB005EncodeError.JOIN_MODE)
        if (fields.eninSeconds == 0) return refuse(BarnardB005EncodeError.ENIN_SECONDS)
        // Checked BEFORE the window arithmetic below, so a value that cannot be represented can
        // never reach a subtraction or be truncated by be32.
        if (fields.eninSeconds !in 1..0xffff) return refuse(BarnardB005EncodeError.FIELD_WIRE_RANGE)
        if (listOf(fields.validFromEnin, fields.validThroughEnin, fields.relayExpiresAtEnin).any { it !in 0..0xffff_ffffL }) {
            return refuse(BarnardB005EncodeError.FIELD_WIRE_RANGE)
        }
        if (fields.eventCodeHash.size != 8) return refuse(BarnardB005EncodeError.EVENT_CODE_HASH_LENGTH)

        // verify requires validFromEnin <= currentEnin < relayExpiresAtEnin <= validThroughEnin, so
        // a window that is inverted, or whose relay expiry sits at or before its start, is
        // unsatisfiable there for every currentEnin. Refuse it rather than emit unverifiable bytes.
        if (fields.validFromEnin >= fields.relayExpiresAtEnin || fields.relayExpiresAtEnin > fields.validThroughEnin) {
            return refuse(BarnardB005EncodeError.VALIDITY_WINDOW)
        }
        if (fields.relayExpiresAtEnin - fields.validFromEnin > 12) return refuse(BarnardB005EncodeError.RELAY_LIFETIME)

        val nameBytes = fields.eventDisplayName.encodeToByteArray()
        if (nameBytes.size !in 1..64) return refuse(BarnardB005EncodeError.DISPLAY_NAME_LENGTH)
        if (fields.eventDisplayName.any { it.code <= 0x1f || it.code == 0x7f }) return refuse(BarnardB005EncodeError.DISPLAY_NAME_CHARACTERS)
        // Round-trips the encoded bytes through the same check verify applies, rather than
        // reimplementing it: whatever verify would refuse to decode, this refuses to encode.
        if (strictDisplayName(nameBytes) != fields.eventDisplayName) return refuse(BarnardB005EncodeError.DISPLAY_NAME_NOT_NORMALIZED)
        if (fields.delegationCert.size > 255) return refuse(BarnardB005EncodeError.CERT_LENGTH)

        val ks = keySetDigest(fields.authorityKeys) ?: return refuse(BarnardB005EncodeError.KEY_LENGTH)
        val eventId = computeEventId(fields.registrar, fields.anchorOperator, fields.nonce, ks)
            ?: return refuse(BarnardB005EncodeError.KEY_LENGTH)
        if (fields.joinMode == 0) {
            val expected = openEventCodeHash(eventId) ?: return refuse(BarnardB005EncodeError.EVENT_CODE_HASH_LENGTH)
            if (!expected.contentEquals(fields.eventCodeHash)) return refuse(BarnardB005EncodeError.OPEN_EVENT_CODE_HASH_MISMATCH)
        }

        var envelope = byteArrayOf(ENVELOPE_VERSION.toByte())
        envelope += fields.registrar
        envelope += fields.anchorOperator
        envelope += fields.nonce
        envelope += byteArrayOf(fields.authorityKeys.size.toByte())
        for (key in fields.authorityKeys) envelope += key
        envelope += byteArrayOf(fields.joinMode.toByte())
        envelope += byteArrayOf((fields.eninSeconds shr 8).toByte(), fields.eninSeconds.toByte())
        envelope += be32(fields.validFromEnin)
        envelope += be32(fields.validThroughEnin)
        envelope += be32(fields.relayExpiresAtEnin)
        envelope += byteArrayOf(MAX_RELAY_HOPS.toByte())
        envelope += fields.eventCodeHash
        envelope += byteArrayOf(nameBytes.size.toByte())
        envelope += nameBytes
        envelope += byteArrayOf(fields.delegationCert.size.toByte())
        envelope += fields.delegationCert

        // Spec 122: the total is 165 + 33n + L + C, and the signature is the trailing 65 bytes.
        val total = envelope.size + 65
        if (total != 165 + 33 * fields.authorityKeys.size + nameBytes.size + fields.delegationCert.size || total > 508) {
            return refuse(BarnardB005EncodeError.ENVELOPE_LENGTH)
        }
        return BarnardB005EncodeResult.Encoded(BarnardB005UnsignedEnvelope(envelope, sha256(signatureDomain + envelope)))
    }

    /**
     * Appends the 65-byte `r‖s‖v` signature to a [toBeSigned] range, producing the signed envelope
     * that [encodeContainer] wraps. Split from [encodeUnsignedEnvelope] because the signature is
     * not knowable until after signing, and because an issuer's signing key may live elsewhere.
     */
    fun assembleSignedEnvelope(toBeSigned: ByteArray, signature: ByteArray): BarnardB005AssembleResult {
        if (signature.size != 65) return BarnardB005AssembleResult.Refused(BarnardB005EncodeError.SIGNATURE_LENGTH)
        if (toBeSigned.size + 65 > 508) return BarnardB005AssembleResult.Refused(BarnardB005EncodeError.ENVELOPE_LENGTH)
        return BarnardB005AssembleResult.Assembled(toBeSigned + signature)
    }

    private fun be32(v: Long) = byteArrayOf((v shr 24).toByte(), (v shr 16).toByte(), (v shr 8).toByte(), v.toByte())

    private val signatureDomain = "barnard-b005-event-info:v1".encodeToByteArray()

    fun keccak256(input: ByteArray): ByteArray {
        val digest = KeccakDigest(256); digest.update(input, 0, input.size)
        return ByteArray(32).also { digest.doFinal(it, 0) }
    }
    private fun sha256(input: ByteArray) = MessageDigest.getInstance("SHA-256").digest(input)

    fun eventKeySetBytes(keys: List<ByteArray>): ByteArray? {
        if (keys.size !in 1..8 || keys.any { it.size != 33 }) return null
        return byteArrayOf(0xa3.toByte(), 1, 1, 2, (0x80 or keys.size).toByte()) +
            keys.fold(ByteArray(0)) { a, k -> a + byteArrayOf(0x58, 0x21) + k } + byteArrayOf(3, 1)
    }
    fun keySetDigest(keys: List<ByteArray>): ByteArray? = eventKeySetBytes(keys)?.let {
        sha256("levarac:event-key-set-digest:v1\u0000".encodeToByteArray() + it)
    }
    fun computeEventId(registrar: ByteArray, anchorOperator: ByteArray, nonce: ByteArray, keySetDigest: ByteArray): ByteArray? {
        if (registrar.size != 20 || anchorOperator.size != 20 || nonce.size != 32 || keySetDigest.size != 32) return null
        return keccak256(keccak256("levarac:event:v1".encodeToByteArray()) + ByteArray(12) + registrar + ByteArray(12) + anchorOperator + nonce + keySetDigest)
    }
    fun openEventCodeHash(eventId: ByteArray): ByteArray? {
        if (eventId.size != 32) return null
        val code = eventId.joinToString("") { "%02x".format(it.u) }.encodeToByteArray()
        return sha256(code).copyOf(8)
    }
    fun encodeContainer(relayHopCount: Int, signedEnvelope: ByteArray): ByteArray? {
        if (relayHopCount !in 0..2 || signedEnvelope.size > 508) return null
        return byteArrayOf(3, relayHopCount.toByte(), (signedEnvelope.size shr 8).toByte(), signedEnvelope.size.toByte()) + signedEnvelope
    }

    fun verify(container: ByteArray, currentEnin: Long?, recoverer: BarnardB005PublicKeyRecovering = BarnardB005NativeRecoverer): BarnardB005VerifiedEnvelope? {
        // Every clock-independent shape check lives in one place, so a host
        // serving its own container rejects exactly what a receiver would.
        if (validateStructure(container) != null) return null
        if (currentEnin == null || currentEnin < 0) return null
        val e = container.copyOfRange(4, container.size)
        val registrar = e.copyOfRange(1, 21); val anchor = e.copyOfRange(21, 41); val nonce = e.copyOfRange(41, 73)
        val n = e[73].u
        val a = 74 + 33 * n
        val keys = mutableListOf<ByteArray>()
        repeat(n) { i ->
            val key = e.copyOfRange(74 + i * 33, 107 + i * 33)
            if (!recoverer.isValidCompressedKey(key) || (keys.lastOrNull()?.let { compare(it, key) >= 0 } == true)) return null
            keys += key
        }
        val joinMode = e[a].u
        val scheduling = readSchedulingFields(e, a)
        val validFrom = scheduling.validFromEnin; val validThrough = scheduling.validThroughEnin
        val expires = scheduling.relayExpiresAtEnin
        val codeHash = e.copyOfRange(a + 16, a + 24); val nameLength = e[a + 24].u
        val nameStart = a + 25; val certLengthOffset = nameStart + nameLength
        val certLength = e[certLengthOffset].u
        val nameBytes = e.copyOfRange(nameStart, certLengthOffset); val name = strictDisplayName(nameBytes) ?: return null
        val ks = keySetDigest(keys) ?: return null
        val eventId = computeEventId(registrar, anchor, nonce, ks) ?: return null
        if (validFrom > currentEnin || currentEnin >= expires || expires > validThrough || expires < validFrom || expires - validFrom > 12) return null
        if (joinMode == 0) {
            if (!codeHash.contentEquals(openEventCodeHash(eventId))) return null
        }
        val certStart = certLengthOffset + 1; val signatureStart = certStart + certLength
        val signer: ByteArray? = if (certLength == 0) null else {
            val c = parseCertificate(e.copyOfRange(certStart, signatureStart)) ?: return null
            if (!c.eventId.contentEquals(eventId) || c.roles != 1UL || currentEnin.toULong() !in c.eninStart..c.eninEnd || !recoverer.isValidCompressedKey(c.delegateKey)) return null
            val candidates = keys.filter { sha256("levarac:cose-kid:v1\u0000".encodeToByteArray() + it).copyOf(8).contentEquals(c.kid) }
            if (candidates.size != 1) return null
            val sigStructure = buildSigStructure(c.protectedBytes, c.payload) ?: return null
            if (!signatureMatches(c.signature, sha256(sigStructure), candidates[0], recoverer, false)) return null
            c.delegateKey
        }
        val signature = e.copyOfRange(signatureStart, e.size)
        val digest = sha256(signatureDomain + e.copyOfRange(0, signatureStart))
        // Recover once: the recovered pubkey depends only on (r, s, v, digest), not on which
        // authority key it is compared against, so recovering per candidate key would recover the
        // identical point up to n times. Recover once and test set membership on the result.
        val accepted = if (signer != null) signatureMatches(signature, digest, signer, recoverer, true)
            else recoverMember(signature, digest, keys, recoverer) != null
        if (!accepted) return null
        return BarnardB005VerifiedEnvelope.radioSelfVerified(
            container[1].u, eventId, ks, joinMode, codeHash, name, validFrom, validThrough, expires,
            scheduling.eninSeconds, e,
        )
    }

    /**
     * Pure comparison of a `RADIO_SELF_VERIFIED` envelope against a registered `EventDefinitionV1`
     * for this `eventId` (spec 122 receiver policy, step 8; spec 134 step 4 as amended by errata
     * #173, which drops the unsatisfiable display-name agreement). This never changes the
     * envelope's [BarnardB005ReceiverState.receiverState] -- assigning `REGISTRY_VERIFIED` is the
     * responsibility of the component that performed the authenticated registry read (the host
     * app), per spec 122's receiver policy; tracked as beid#367 / dispatch#11 (P4).
     *
     * Spec 134 step 4 requires validity-window CONTAINMENT, not equality: the envelope's window
     * must lie inside the definition's, `definitionStart <= validFromEnin` and `validThroughEnin
     * <= definitionEnd` (spec 134 erratum of 2026-09-10; see barnard#200). Equality made the rule
     * unsatisfiable for any definition longer than the 12-ENIN relay cap: spec 134:122-123 directs
     * an issuer to refresh with a LATER `validFromEnin`, and equality rejected every such refresh
     * as a `VALIDITY_WINDOW` mismatch, so nothing was servable after the first 12 ENINs. The cap
     * itself (`relayExpiresAtEnin - validFromEnin <= 12`) and step 5 are unchanged and stay in
     * [verify]. Spec 122:477-482 calls `validFromEnin` the issue point, which likewise presumes it
     * can move.
     * `validThroughEnin` is treated as the INCLUSIVE last valid ENIN (window `[validFromEnin,
     * validThroughEnin]`): spec 122 never states its own convention for this field, but parallax's
     * `event-definition.md` (`validFrom`/`validUntil`, lines 52-53) is explicitly inclusive on both
     * ends, and spec 122's only other ENIN range (the delegation cert's `eninStart`/`eninEnd`,
     * spec 122:211) is likewise inclusive -- this is an issuer derivation erratum, tracked in the
     * spec 122 errata. `eninSeconds`-denominated ENINs each cover `eninSeconds` consecutive Unix
     * seconds, so the registry's inclusive Unix-second window is converted to the same inclusive
     * ENIN shape conservatively (start rounded up, end rounded down) before the envelope's window
     * is tested for containment in it. A registry window that does not fall on ENIN boundaries
     * converts to an empty range and still agrees with nothing: containment also requires the
     * envelope's own window to be well formed (`validFromEnin <= validThroughEnin`), so the chain
     * `registryStart <= validFromEnin <= validThroughEnin <= registryEnd` is unsatisfiable whenever
     * `registryEnd < registryStart`. Under equality that emptiness argument needed nothing from the
     * envelope; under containment it does, so well-formedness is re-checked here rather than
     * inherited from [verify]'s `validFromEnin <= currentEnin < relayExpiresAtEnin <=
     * validThroughEnin` -- the same defense-in-depth footing as the `eninSeconds <= 0` rejection
     * below.
     *
     * The conversion is `expectedFrom = ceilDiv(validFromUnixSeconds, eninSeconds)` and
     * `expectedThrough = floorDiv(validUntilUnixSeconds + 1, eninSeconds) - 1` (spec 122 erratum
     * for the issuer-side derivation; see barnard#180). `expectedThrough` is computed without ever
     * forming `validUntilUnixSeconds + 1`, so it stays overflow-safe for an adversarial registry
     * read. A registry definition with `validFromUnixSeconds < 0`, `validUntilUnixSeconds < 0`,
     * `validFromUnixSeconds > validUntilUnixSeconds`, or `eninSeconds <= 0` is rejected as a
     * `VALIDITY_WINDOW` mismatch before any of this arithmetic runs, so every input to it stays
     * non-negative and the conversion never negates `Long.MIN_VALUE`.
     */
    fun registryAgreement(verified: BarnardB005VerifiedEnvelope, definition: BarnardEventDefinitionV1): BarnardRegistryAgreement {
        val eninPerSecond = verified.eninSeconds.toLong()
        val validFrom = definition.validFromUnixSeconds
        val validUntil = definition.validUntilUnixSeconds
        val windowIsWellFormed = eninPerSecond > 0 && validFrom >= 0 && validUntil >= 0 && validFrom <= validUntil
        val registryStartEnin = if (!windowIsWellFormed) null else -Math.floorDiv(-validFrom, eninPerSecond)
        val registryEndEnin = if (!windowIsWellFormed) null else {
            // expectedThrough = floorDiv(validUntil + 1, eninPerSecond) - 1. Rather than forming
            // validUntil + 1 (which would overflow when validUntil == Long.MAX_VALUE), use the
            // floorMod identity: floorDiv(validUntil + 1, m) is floorDiv(validUntil, m) + 1 when
            // validUntil sits on the last second of its ENIN (floorMod(validUntil, m) == m - 1),
            // and floorDiv(validUntil, m) otherwise. Subtracting the trailing "- 1" immediately
            // collapses both branches to q or q - 1, so "+ 1" is never actually computed.
            val q = Math.floorDiv(validUntil, eninPerSecond)
            val r = Math.floorMod(validUntil, eninPerSecond)
            if (r == eninPerSecond - 1L) q else q - 1
        }
        val windowIsContained = registryStartEnin != null && registryEndEnin != null &&
            verified.validFromEnin <= verified.validThroughEnin &&
            registryStartEnin <= verified.validFromEnin &&
            verified.validThroughEnin <= registryEndEnin
        val mismatches = buildSet {
            if (!verified.eventId.contentEquals(definition.eventId)) add(BarnardRegistryMismatchField.EVENT_ID)
            if (!verified.eventCodeHash.contentEquals(definition.eventCodeHash)) add(BarnardRegistryMismatchField.EVENT_CODE_HASH)
            if (!verified.keySetDigest.contentEquals(definition.keySetDigest)) add(BarnardRegistryMismatchField.KEY_SET_DIGEST)
            if (verified.joinMode != definition.joinMode) add(BarnardRegistryMismatchField.JOIN_MODE)
            if (!windowIsContained) add(BarnardRegistryMismatchField.VALIDITY_WINDOW)
        }
        return if (mismatches.isEmpty()) BarnardRegistryAgreement.Agrees else BarnardRegistryAgreement.Mismatched(mismatches)
    }

    fun buildSigStructure(protectedBytes: ByteArray, payload: ByteArray): ByteArray? {
        val p = cborBytes(protectedBytes) ?: return null
        val pl = cborBytes(payload) ?: return null
        return byteArrayOf(0x84.toByte(), 0x6a) + "Signature1".encodeToByteArray() + p + byteArrayOf(0x40) + pl
    }

    private data class Cert(val protectedBytes: ByteArray, val payload: ByteArray, val signature: ByteArray, val kid: ByteArray, val eventId: ByteArray, val delegateKey: ByteArray, val roles: ULong, val eninStart: ULong, val eninEnd: ULong)
    private fun parseCertificate(bytes: ByteArray): Cert? {
        if (bytes.size > 255) return null
        val r = CborReader(bytes)
        if (r.tag() != 18UL || r.array() != 4UL) return null
        val protected = r.bytes() ?: return null
        if (r.map() != 0UL) return null
        val payload = r.bytes() ?: return null; val signature = r.bytes() ?: return null
        if (signature.size != 64 || !r.finished) return null
        val h = CborReader(protected)
        if (h.map() != 3UL || h.uint() != 1UL || h.negative() != -47L || h.uint() != 3UL || h.text() != "application/vnd.levarac.delegation-cert+cbor" || h.uint() != 4UL) return null
        val kid = h.bytes() ?: return null; if (kid.size != 8 || !h.finished) return null
        val p = CborReader(payload)
        if (p.map() != 6UL || p.uint() != 1UL || p.uint() != 1UL || p.uint() != 2UL) return null
        val eventId = p.bytes() ?: return null; if (eventId.size != 32 || p.uint() != 3UL) return null
        val delegate = p.bytes() ?: return null; if (delegate.size != 33 || p.uint() != 4UL) return null
        val roles = p.uint() ?: return null; if (p.uint() != 5UL) return null
        val start = p.uint() ?: return null; if (p.uint() != 6UL) return null
        val end = p.uint() ?: return null
        if (start > end || end > 9_007_199_254_740_991UL || !p.finished) return null
        return Cert(protected, payload, signature, kid, eventId, delegate, roles, start, end)
    }
    // secp256k1 group order n, and n/2 (BIP-62/146 low-S bound), both big-endian.
    private val curveOrder = byteArrayOf(
        0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(),
        0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xfe.toByte(),
        0xba.toByte(), 0xae.toByte(), 0xdc.toByte(), 0xe6.toByte(), 0xaf.toByte(), 0x48, 0xa0.toByte(), 0x3b,
        0xbf.toByte(), 0xd2.toByte(), 0x5e, 0x8c.toByte(), 0xd0.toByte(), 0x36, 0x41, 0x41,
    )
    private val curveOrderHalf = byteArrayOf(
        0x7f, 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(),
        0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(),
        0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4.toByte(), 0x50, 0x1d,
        0xdf.toByte(), 0xe9.toByte(), 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0.toByte(),
    )
    private fun isZero(b: ByteArray) = b.all { it == 0.toByte() }
    // Big-endian comparison for equal-length byte arrays: negative if a < b, 0 if equal, positive if a > b.
    private fun compareUnsigned(a: ByteArray, b: ByteArray): Int { for (i in a.indices) { val d = a[i].u - b[i].u; if (d != 0) return d }; return 0 }

    /**
     * Enforces `0 < r < N` and `0 < s <= N/2` independent of the injected recoverer: the
     * [BarnardB005PublicKeyRecovering] interface carries no contract that a conforming backend
     * rejects a high-S or out-of-range signature on its own, so this MUST be checked here.
     */
    private fun isLowSInRange(r: ByteArray, s: ByteArray) =
        !isZero(r) && compareUnsigned(r, curveOrder) < 0 && !isZero(s) && compareUnsigned(s, curveOrderHalf) <= 0

    private fun signatureMatches(signature: ByteArray, digest: ByteArray, key: ByteArray, recoverer: BarnardB005PublicKeyRecovering, recoveryByte: Boolean): Boolean {
        if (signature.size != if (recoveryByte) 65 else 64) return false
        val r = signature.copyOfRange(0, 32); val s = signature.copyOfRange(32, 64)
        if (!isLowSInRange(r, s)) return false
        if (recoveryByte) { val v = signature[64].u; return v <= 1 && recoverer.recover(v, r, s, digest)?.contentEquals(key) == true }
        return (0..1).any { recoverer.recover(it, r, s, digest)?.contentEquals(key) == true }
    }

    /**
     * Recovers the signer exactly once (the recovery id is carried in the signature, so there is
     * no ambiguity to resolve by trying candidates), then tests set membership on the result.
     */
    private fun recoverMember(signature: ByteArray, digest: ByteArray, keys: List<ByteArray>, recoverer: BarnardB005PublicKeyRecovering): ByteArray? {
        if (signature.size != 65) return null
        val r = signature.copyOfRange(0, 32); val s = signature.copyOfRange(32, 64)
        if (!isLowSInRange(r, s)) return null
        val v = signature[64].u; if (v > 1) return null
        val recovered = recoverer.recover(v, r, s, digest) ?: return null
        return keys.firstOrNull { it.contentEquals(recovered) }
    }
    private fun strictDisplayName(bytes: ByteArray): String? {
        val value = try {
            bytes.decodeToString(throwOnInvalidSequence = true)
        } catch (e: CharacterCodingException) {
            return null
        }
        if (value.any { it.code in 0..31 || it.code == 127 }) return null
        if (java.text.Normalizer.normalize(value, java.text.Normalizer.Form.NFC) != value) return null
        return value
    }
    private fun cborBytes(bytes: ByteArray): ByteArray? = when {
        bytes.size < 24 -> byteArrayOf((0x40 or bytes.size).toByte()) + bytes
        bytes.size < 256 -> byteArrayOf(0x58, bytes.size.toByte()) + bytes
        bytes.size < 65536 -> byteArrayOf(0x59, (bytes.size shr 8).toByte(), bytes.size.toByte()) + bytes
        else -> null
    }
    private fun read16(b: ByteArray, i: Int) = b[i].u shl 8 or b[i + 1].u
    private fun read32(b: ByteArray, i: Int): Long = (b[i].u.toLong() shl 24) or (b[i + 1].u.toLong() shl 16) or (b[i + 2].u.toLong() shl 8) or b[i + 3].u.toLong()
    private fun compare(a: ByteArray, b: ByteArray): Int { for (i in a.indices) if (a[i] != b[i]) return a[i].u - b[i].u; return 0 }
    private val Byte.u get() = toInt() and 255
}

private class CborReader(private val input: ByteArray) {
    private var offset = 0
    val finished get() = offset == input.size
    private fun head(major: Int): ULong? {
        if (offset >= input.size) return null
        val initial = input[offset++].toInt() and 255; if (initial ushr 5 != major) return null
        val ai = initial and 31; if (ai < 24) return ai.toULong()
        val count = when (ai) { 24 -> 1; 25 -> 2; 26 -> 4; 27 -> 8; else -> return null }
        if (offset + count > input.size) return null
        var value = 0UL; repeat(count) { value = (value shl 8) or (input[offset++].toInt() and 255).toULong() }
        val minimum = when (count) { 1 -> 24UL; 2 -> 256UL; 4 -> 65_536UL; else -> 4_294_967_296UL }
        return value.takeIf { it >= minimum }
    }
    fun uint() = head(0)
    fun negative(): Long? { val v = head(1) ?: return null; if (v > Long.MAX_VALUE.toULong()) return null; return -1L - v.toLong() }
    fun bytes(): ByteArray? = take(head(2))
    fun text(): String? = take(head(3))?.let {
        try {
            it.decodeToString(throwOnInvalidSequence = true)
        } catch (e: CharacterCodingException) {
            null
        }
    }
    private fun take(size: ULong?): ByteArray? { size ?: return null; if (size > (input.size - offset).toULong()) return null; val end = offset + size.toInt(); return input.copyOfRange(offset, end).also { offset = end } }
    fun array() = head(4); fun map() = head(5); fun tag() = head(6)
}
