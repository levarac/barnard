// Use of this source code is governed by a BSD-style license.

package org.levarac.barnard

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.text.Normalizer

/** Canonical wire/verification failures for AdoptionCredential and census v1. */
public enum class BarnardAdoptionProtocolError {
    INVALID_LENGTH,
    UNSUPPORTED_CREDENTIAL_VERSION,
    UNSUPPORTED_CENSUS_VERSION,
    INVALID_ADMISSION_MODE,
    INVALID_FIELD,
    INVALID_VALIDITY_WINDOW,
    INVALID_CENSUS_WINDOW,
    NON_CANONICAL_SIGNATURE,
    INVALID_CREDENTIAL_SIGNATURE,
    INVALID_CENSUS_SIGNATURE,
    EVENT_ID_NOT_ANCHORED,
    NON_CANONICAL_MERKLE_ROOT,
    INVALID_CENSUS_COUNTS,
    INVALID_B005_V2,
    MISSING_REQUIRED_TLV,
    INVALID_DISPLAY_NAME,
    CREDENTIAL_SCOPE_MISMATCH,
    CREDENTIAL_DISPLAY_NAME_MISMATCH,
    CENSUS_CREDENTIAL_MISMATCH,
}

public class BarnardAdoptionProtocolException(
    public val reason: BarnardAdoptionProtocolError,
) : IllegalArgumentException(reason.name)

private fun adoptionFailure(reason: BarnardAdoptionProtocolError): Nothing =
    throw BarnardAdoptionProtocolException(reason)

/** Explicit credential posture; only [OPEN] can use zero-tap admission. */
public enum class BarnardAdoptionAdmissionMode(public val wireValue: Int) {
    OPEN(1),
    GATED(2),
    ;

    internal companion object {
        fun fromWire(value: Int): BarnardAdoptionAdmissionMode? = entries.firstOrNull { it.wireValue == value }
    }
}

/** The Registry Event Definition was authenticated by the host's registry trust root. */
public enum class BarnardRegistryVerification { VERIFIED, UNVERIFIED }

private object BarnardAdoptionWire {
    const val credentialVersion = 1
    const val censusVersion = 1
    const val credentialUnsignedLength = 94
    const val censusUnsignedLength = 77
    const val recoverableSignatureLength = 65
    const val credentialFullLength = credentialUnsignedLength + recoverableSignatureLength
    const val censusFullLength = censusUnsignedLength + recoverableSignatureLength
    const val credentialDomainTag = "barnard-adoption-credential:v1"
    const val censusDomainTag = "barnard-signed-window-census:v1"

    private val curveOrder = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
    private val halfOrder = curveOrder.shiftRight(1)

    fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

    fun messageHash(domainTag: String, body: ByteArray): ByteArray =
        sha256(domainTag.toByteArray(StandardCharsets.UTF_8) + body)

    fun canonicalSignature(signature: ByteArray): Triple<BigInteger, BigInteger, Int> {
        if (signature.size != recoverableSignatureLength) adoptionFailure(BarnardAdoptionProtocolError.INVALID_LENGTH)
        val r = BigInteger(1, signature.copyOfRange(0, 32))
        val s = BigInteger(1, signature.copyOfRange(32, 64))
        val recoveryId = signature[64].toInt() and 0xff
        if (r <= BigInteger.ZERO || r >= curveOrder || s <= BigInteger.ZERO || s > halfOrder || recoveryId !in 0..1) {
            adoptionFailure(BarnardAdoptionProtocolError.NON_CANONICAL_SIGNATURE)
        }
        return Triple(r, s, recoveryId)
    }

    fun recoveredPublicKey(signature: ByteArray, messageHash: ByteArray): ByteArray {
        val (r, s, recoveryId) = canonicalSignature(signature)
        return BarnardSigning.recoverPublicKey(recoveryId, r, s, messageHash)
            ?: adoptionFailure(BarnardAdoptionProtocolError.NON_CANONICAL_SIGNATURE)
    }

    fun encodeSignature(signature: BarnardSigning.RecoverableSignature): ByteArray =
        signature.r + signature.s + byteArrayOf(signature.v.toByte())

    fun appendUInt16(output: ByteArrayOutputStream, value: UShort) {
        output.write((value.toInt() ushr 8) and 0xff)
        output.write(value.toInt() and 0xff)
    }

    fun appendUInt32(output: ByteArrayOutputStream, value: UInt) {
        output.write(((value.toLong() ushr 24) and 0xff).toInt())
        output.write(((value.toLong() ushr 16) and 0xff).toInt())
        output.write(((value.toLong() ushr 8) and 0xff).toInt())
        output.write((value.toLong() and 0xff).toInt())
    }

    fun appendUInt64(output: ByteArrayOutputStream, value: ULong) {
        for (shift in 56 downTo 0 step 8) output.write(((value shr shift) and 0xffu).toInt())
    }
}

private class BarnardAdoptionReader(private val bytes: ByteArray) {
    private var offset = 0

    fun readByte(): Int {
        if (offset >= bytes.size) adoptionFailure(BarnardAdoptionProtocolError.INVALID_LENGTH)
        return bytes[offset++].toInt() and 0xff
    }

    fun readBytes(count: Int): ByteArray {
        if (count < 0 || offset + count > bytes.size) adoptionFailure(BarnardAdoptionProtocolError.INVALID_LENGTH)
        val end = offset + count
        val value = bytes.copyOfRange(offset, end)
        offset = end
        return value
    }

    fun readUInt16(): UShort {
        val value = (readByte() shl 8) or readByte()
        return value.toUShort()
    }

    fun readUInt32(): UInt {
        var value = 0u
        repeat(4) { value = (value shl 8) or readByte().toUInt() }
        return value
    }

    fun readUInt64(): ULong {
        var value = 0uL
        repeat(8) { value = (value shl 8) or readByte().toULong() }
        return value
    }
}

/**
 * The signed 94-byte event artifact. [credentialId] hashes only the unsigned
 * canonical body, so re-signing cannot divide a single event into distinct
 * TEK, census, relay, or equivocation identities.
 */
public class BarnardAdoptionCredential private constructor(
    public val unsignedBody: UnsignedBody,
    signature: ByteArray,
    authorityPublicKey: ByteArray,
) {
    private val signatureBytes = signature.copyOf()
    private val authorityPublicKeyBytes = authorityPublicKey.copyOf()

    public val signature: ByteArray get() = signatureBytes.copyOf()
    public val authorityPublicKey: ByteArray get() = authorityPublicKeyBytes.copyOf()
    public val credentialId: ByteArray get() = unsignedBody.credentialId

    public fun canonicalBytes(): ByteArray = unsignedBody.canonicalBytes() + signatureBytes

    public class UnsignedBody(
        public val admissionMode: BarnardAdoptionAdmissionMode,
        eventId: ByteArray,
        b004AdoptionScopeHash: ByteArray,
        displayNameHash: ByteArray,
        public val validFromUnixSeconds: ULong,
        public val validUntilUnixSeconds: ULong,
        public val censusWindowSeconds: UInt,
    ) {
        private val eventIdBytes = eventId.copyOf()
        private val b004AdoptionScopeHashBytes = b004AdoptionScopeHash.copyOf()
        private val displayNameHashBytes = displayNameHash.copyOf()

        public val eventId: ByteArray get() = eventIdBytes.copyOf()
        public val b004AdoptionScopeHash: ByteArray get() = b004AdoptionScopeHashBytes.copyOf()
        public val displayNameHash: ByteArray get() = displayNameHashBytes.copyOf()

        init {
            if (eventId.size != 32 || b004AdoptionScopeHash.size != 8 || displayNameHash.size != 32) {
                adoptionFailure(BarnardAdoptionProtocolError.INVALID_FIELD)
            }
            if (validFromUnixSeconds >= validUntilUnixSeconds) adoptionFailure(BarnardAdoptionProtocolError.INVALID_VALIDITY_WINDOW)
            if (censusWindowSeconds !in 12u..3600u) adoptionFailure(BarnardAdoptionProtocolError.INVALID_CENSUS_WINDOW)
        }

        public fun canonicalBytes(): ByteArray = ByteArrayOutputStream().use { output ->
            output.write(BarnardAdoptionWire.credentialVersion)
            output.write(admissionMode.wireValue)
            output.write(eventIdBytes)
            output.write(b004AdoptionScopeHashBytes)
            output.write(displayNameHashBytes)
            BarnardAdoptionWire.appendUInt64(output, validFromUnixSeconds)
            BarnardAdoptionWire.appendUInt64(output, validUntilUnixSeconds)
            BarnardAdoptionWire.appendUInt32(output, censusWindowSeconds)
            output.toByteArray()
        }

        public val credentialId: ByteArray get() = BarnardAdoptionWire.sha256(canonicalBytes())

        public companion object {
            public fun decode(bytes: ByteArray): UnsignedBody {
                if (bytes.size != BarnardAdoptionWire.credentialUnsignedLength) {
                    adoptionFailure(BarnardAdoptionProtocolError.INVALID_LENGTH)
                }
                val reader = BarnardAdoptionReader(bytes)
                if (reader.readByte() != BarnardAdoptionWire.credentialVersion) {
                    adoptionFailure(BarnardAdoptionProtocolError.UNSUPPORTED_CREDENTIAL_VERSION)
                }
                val admissionMode = BarnardAdoptionAdmissionMode.fromWire(reader.readByte())
                    ?: adoptionFailure(BarnardAdoptionProtocolError.INVALID_ADMISSION_MODE)
                return UnsignedBody(
                    admissionMode = admissionMode,
                    eventId = reader.readBytes(32),
                    b004AdoptionScopeHash = reader.readBytes(8),
                    displayNameHash = reader.readBytes(32),
                    validFromUnixSeconds = reader.readUInt64(),
                    validUntilUnixSeconds = reader.readUInt64(),
                    censusWindowSeconds = reader.readUInt32(),
                )
            }
        }
    }

    public companion object {
        public fun decode(bytes: ByteArray): BarnardAdoptionCredential {
            if (bytes.size != BarnardAdoptionWire.credentialFullLength) {
                adoptionFailure(BarnardAdoptionProtocolError.INVALID_LENGTH)
            }
            val bodyBytes = bytes.copyOfRange(0, BarnardAdoptionWire.credentialUnsignedLength)
            val unsignedBody = UnsignedBody.decode(bodyBytes)
            val signature = bytes.copyOfRange(BarnardAdoptionWire.credentialUnsignedLength, bytes.size)
            val recovered = try {
                BarnardAdoptionWire.recoveredPublicKey(
                    signature,
                    BarnardAdoptionWire.messageHash(BarnardAdoptionWire.credentialDomainTag, bodyBytes),
                )
            } catch (error: BarnardAdoptionProtocolException) {
                if (error.reason == BarnardAdoptionProtocolError.NON_CANONICAL_SIGNATURE) throw error
                adoptionFailure(BarnardAdoptionProtocolError.INVALID_CREDENTIAL_SIGNATURE)
            }
            if (!BarnardAdoptionWire.sha256(recovered).contentEquals(unsignedBody.eventId)) {
                adoptionFailure(BarnardAdoptionProtocolError.EVENT_ID_NOT_ANCHORED)
            }
            return BarnardAdoptionCredential(unsignedBody, signature, recovered)
        }

        internal fun encodeSigned(unsignedBody: UnsignedBody, authorityPrivateKey: ByteArray): ByteArray {
            if (authorityPrivateKey.size != 32) adoptionFailure(BarnardAdoptionProtocolError.INVALID_FIELD)
            val signature = BarnardSigning.signRecoverable(
                BigInteger(1, authorityPrivateKey),
                BarnardAdoptionWire.messageHash(BarnardAdoptionWire.credentialDomainTag, unsignedBody.canonicalBytes()),
            )
            return unsignedBody.canonicalBytes() + BarnardAdoptionWire.encodeSignature(signature)
        }
    }
}

/** v1 signed trusted-authority per-window aggregate, with a reserved zero root. */
public class BarnardSignedWindowCensus private constructor(
    public val unsignedBody: UnsignedBody,
    signature: ByteArray,
    authorityPublicKey: ByteArray,
) {
    private val signatureBytes = signature.copyOf()
    private val authorityPublicKeyBytes = authorityPublicKey.copyOf()

    public val signature: ByteArray get() = signatureBytes.copyOf()
    public val authorityPublicKey: ByteArray get() = authorityPublicKeyBytes.copyOf()
    public fun canonicalBytes(): ByteArray = unsignedBody.canonicalBytes() + signatureBytes

    public class UnsignedBody(
        credentialId: ByteArray,
        public val windowIndex: ULong,
        public val qualifiedVoterCount: UShort,
        public val eligibleVoterCount: UShort,
        countedSetMerkleRoot: ByteArray,
    ) {
        private val credentialIdBytes = credentialId.copyOf()
        private val countedSetMerkleRootBytes = countedSetMerkleRoot.copyOf()
        public val credentialId: ByteArray get() = credentialIdBytes.copyOf()
        public val countedSetMerkleRoot: ByteArray get() = countedSetMerkleRootBytes.copyOf()

        init {
            if (credentialId.size != 32 || countedSetMerkleRoot.size != 32) adoptionFailure(BarnardAdoptionProtocolError.INVALID_FIELD)
            if (countedSetMerkleRoot.any { it.toInt() != 0 }) adoptionFailure(BarnardAdoptionProtocolError.NON_CANONICAL_MERKLE_ROOT)
            if (qualifiedVoterCount > eligibleVoterCount) adoptionFailure(BarnardAdoptionProtocolError.INVALID_CENSUS_COUNTS)
        }

        public fun canonicalBytes(): ByteArray = ByteArrayOutputStream().use { output ->
            output.write(BarnardAdoptionWire.censusVersion)
            output.write(credentialIdBytes)
            BarnardAdoptionWire.appendUInt64(output, windowIndex)
            BarnardAdoptionWire.appendUInt16(output, qualifiedVoterCount)
            BarnardAdoptionWire.appendUInt16(output, eligibleVoterCount)
            output.write(countedSetMerkleRootBytes)
            output.toByteArray()
        }

        public companion object {
            public fun decode(bytes: ByteArray): UnsignedBody {
                if (bytes.size != BarnardAdoptionWire.censusUnsignedLength) adoptionFailure(BarnardAdoptionProtocolError.INVALID_LENGTH)
                val reader = BarnardAdoptionReader(bytes)
                if (reader.readByte() != BarnardAdoptionWire.censusVersion) {
                    adoptionFailure(BarnardAdoptionProtocolError.UNSUPPORTED_CENSUS_VERSION)
                }
                return UnsignedBody(
                    credentialId = reader.readBytes(32),
                    windowIndex = reader.readUInt64(),
                    qualifiedVoterCount = reader.readUInt16(),
                    eligibleVoterCount = reader.readUInt16(),
                    countedSetMerkleRoot = reader.readBytes(32),
                )
            }
        }
    }

    public companion object {
        public fun decode(bytes: ByteArray): BarnardSignedWindowCensus {
            if (bytes.size != BarnardAdoptionWire.censusFullLength) adoptionFailure(BarnardAdoptionProtocolError.INVALID_LENGTH)
            val bodyBytes = bytes.copyOfRange(0, BarnardAdoptionWire.censusUnsignedLength)
            val unsignedBody = UnsignedBody.decode(bodyBytes)
            val signature = bytes.copyOfRange(BarnardAdoptionWire.censusUnsignedLength, bytes.size)
            val recovered = try {
                BarnardAdoptionWire.recoveredPublicKey(
                    signature,
                    BarnardAdoptionWire.messageHash(BarnardAdoptionWire.censusDomainTag, bodyBytes),
                )
            } catch (error: BarnardAdoptionProtocolException) {
                if (error.reason == BarnardAdoptionProtocolError.NON_CANONICAL_SIGNATURE) throw error
                adoptionFailure(BarnardAdoptionProtocolError.INVALID_CENSUS_SIGNATURE)
            }
            return BarnardSignedWindowCensus(unsignedBody, signature, recovered)
        }

        internal fun encodeSigned(unsignedBody: UnsignedBody, authorityPrivateKey: ByteArray): ByteArray {
            if (authorityPrivateKey.size != 32) adoptionFailure(BarnardAdoptionProtocolError.INVALID_FIELD)
            val signature = BarnardSigning.signRecoverable(
                BigInteger(1, authorityPrivateKey),
                BarnardAdoptionWire.messageHash(BarnardAdoptionWire.censusDomainTag, unsignedBody.canonicalBytes()),
            )
            return unsignedBody.canonicalBytes() + BarnardAdoptionWire.encodeSignature(signature)
        }
    }
}

/** Strict B005 formatVersion=2 payload. It contains no raw EventCode or device identity. */
public class BarnardB005V2Payload(
    public val eventDisplayName: String,
    b004AdoptionScopeHash: ByteArray,
    public val credential: BarnardAdoptionCredential,
    public val census: BarnardSignedWindowCensus,
) {
    private val b004AdoptionScopeHashBytes = b004AdoptionScopeHash.copyOf()
    public val b004AdoptionScopeHash: ByteArray get() = b004AdoptionScopeHashBytes.copyOf()
}

public object BarnardB005V2Codec {
    public const val formatVersion = 2
    public const val maximumPayloadBytes = 386
    public const val maximumDisplayNameBytes = 64

    public fun serialize(payload: BarnardB005V2Payload): ByteArray {
        val nameBytes = canonicalDisplayNameBytes(payload.eventDisplayName)
        if (payload.b004AdoptionScopeHash.size != 8 ||
            !payload.credential.unsignedBody.b004AdoptionScopeHash.contentEquals(payload.b004AdoptionScopeHash)
        ) adoptionFailure(BarnardAdoptionProtocolError.CREDENTIAL_SCOPE_MISMATCH)
        if (!BarnardAdoptionWire.sha256(nameBytes).contentEquals(payload.credential.unsignedBody.displayNameHash)) {
            adoptionFailure(BarnardAdoptionProtocolError.CREDENTIAL_DISPLAY_NAME_MISMATCH)
        }
        if (!payload.census.unsignedBody.credentialId.contentEquals(payload.credential.credentialId)) {
            adoptionFailure(BarnardAdoptionProtocolError.CENSUS_CREDENTIAL_MISMATCH)
        }
        return ByteArrayOutputStream().use { output ->
            output.write(formatVersion)
            appendTlv(output, 0x01, nameBytes)
            appendTlv(output, 0x02, payload.b004AdoptionScopeHash)
            appendTlv(output, 0x20, payload.credential.canonicalBytes())
            appendTlv(output, 0x21, payload.census.canonicalBytes())
            val result = output.toByteArray()
            if (result.size > maximumPayloadBytes) adoptionFailure(BarnardAdoptionProtocolError.INVALID_B005_V2)
            result
        }
    }

    public fun decode(bytes: ByteArray): BarnardB005V2Payload {
        if (bytes.size > maximumPayloadBytes || bytes.firstOrNull()?.toInt()?.and(0xff) != formatVersion) {
            adoptionFailure(BarnardAdoptionProtocolError.INVALID_B005_V2)
        }
        var offset = 1
        var previousType = 0
        var displayNameBytes: ByteArray? = null
        var scopeHash: ByteArray? = null
        var credentialBytes: ByteArray? = null
        var censusBytes: ByteArray? = null
        while (offset < bytes.size) {
            if (offset + 3 > bytes.size) adoptionFailure(BarnardAdoptionProtocolError.INVALID_B005_V2)
            val type = bytes[offset++].toInt() and 0xff
            val length = ((bytes[offset++].toInt() and 0xff) shl 8) or (bytes[offset++].toInt() and 0xff)
            if (type == 0 || type <= previousType || offset + length > bytes.size) {
                adoptionFailure(BarnardAdoptionProtocolError.INVALID_B005_V2)
            }
            previousType = type
            val value = bytes.copyOfRange(offset, offset + length)
            offset += length
            when (type) {
                0x01 -> displayNameBytes = value
                0x02 -> scopeHash = value
                0x20 -> credentialBytes = value
                0x21 -> censusBytes = value
                else -> adoptionFailure(BarnardAdoptionProtocolError.INVALID_B005_V2)
            }
        }
        val name = displayNameBytes ?: adoptionFailure(BarnardAdoptionProtocolError.MISSING_REQUIRED_TLV)
        val scope = scopeHash ?: adoptionFailure(BarnardAdoptionProtocolError.MISSING_REQUIRED_TLV)
        val credentialWire = credentialBytes ?: adoptionFailure(BarnardAdoptionProtocolError.MISSING_REQUIRED_TLV)
        val censusWire = censusBytes ?: adoptionFailure(BarnardAdoptionProtocolError.MISSING_REQUIRED_TLV)
        // Validate the display name (0x01 TLV) before the scope hash (0x02 TLV),
        // matching Swift and the TLV order in the spec, so a payload invalid in
        // both ways reports the same reason on both platforms.
        val displayName = validatedDisplayName(name)
        if (scope.size != 8) adoptionFailure(BarnardAdoptionProtocolError.INVALID_B005_V2)
        val credential = try {
            BarnardAdoptionCredential.decode(credentialWire)
        } catch (_: BarnardAdoptionProtocolException) {
            adoptionFailure(BarnardAdoptionProtocolError.INVALID_CREDENTIAL_SIGNATURE)
        }
        val census = try {
            BarnardSignedWindowCensus.decode(censusWire)
        } catch (_: BarnardAdoptionProtocolException) {
            adoptionFailure(BarnardAdoptionProtocolError.INVALID_CENSUS_SIGNATURE)
        }
        val payload = BarnardB005V2Payload(displayName, scope, credential, census)
        serialize(payload)
        return payload
    }

    private fun appendTlv(output: ByteArrayOutputStream, type: Int, value: ByteArray) {
        output.write(type)
        output.write((value.size ushr 8) and 0xff)
        output.write(value.size and 0xff)
        output.write(value)
    }

    private fun canonicalDisplayNameBytes(value: String): ByteArray {
        val bytes = value.toByteArray(StandardCharsets.UTF_8)
        if (Normalizer.normalize(value, Normalizer.Form.NFC) != value || bytes.size !in 1..maximumDisplayNameBytes ||
            value.any { it.code in 0x00..0x1f || it.code in 0x7f..0x9f }
        ) adoptionFailure(BarnardAdoptionProtocolError.INVALID_DISPLAY_NAME)
        return bytes
    }

    private fun validatedDisplayName(bytes: ByteArray): String {
        val decoder = StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
        val value = try {
            decoder.decode(ByteBuffer.wrap(bytes)).toString()
        } catch (_: Exception) {
            adoptionFailure(BarnardAdoptionProtocolError.INVALID_DISPLAY_NAME)
        }
        canonicalDisplayNameBytes(value)
        return value
    }
}

/** Host-authenticated Registry Event Definition binding; not a backend implementation. */
public class BarnardRegistryEventDefinition(
    eventId: ByteArray,
    credentialId: ByteArray,
    b004AdoptionScopeHash: ByteArray,
    displayNameHash: ByteArray,
    public val validFromUnixSeconds: ULong,
    public val validUntilUnixSeconds: ULong,
    public val admissionMode: BarnardAdoptionAdmissionMode,
    public val censusDomainPolicy: BarnardCensusDomainPolicy,
    replacesCredentialId: ByteArray? = null,
    /** Registry-only future census window for a replacement credential. */
    public val effectiveWindowIndex: ULong? = null,
) {
    private val eventIdBytes = eventId.copyOf()
    private val credentialIdBytes = credentialId.copyOf()
    private val b004AdoptionScopeHashBytes = b004AdoptionScopeHash.copyOf()
    private val displayNameHashBytes = displayNameHash.copyOf()
    private val replacesCredentialIdBytes = replacesCredentialId?.copyOf()
    public val eventId: ByteArray get() = eventIdBytes.copyOf()
    public val credentialId: ByteArray get() = credentialIdBytes.copyOf()
    public val b004AdoptionScopeHash: ByteArray get() = b004AdoptionScopeHashBytes.copyOf()
    public val displayNameHash: ByteArray get() = displayNameHashBytes.copyOf()
    /** Registry-only rotation reference. It is never serialized into B005. */
    public val replacesCredentialId: ByteArray? get() = replacesCredentialIdBytes?.copyOf()

    public fun verify(
        credential: BarnardAdoptionCredential,
        census: BarnardSignedWindowCensus,
        nowUnixSeconds: ULong,
    ): BarnardRegistryVerification {
        val body = credential.unsignedBody
        return if (eventIdBytes.size == 32 && credentialIdBytes.size == 32 && b004AdoptionScopeHashBytes.size == 8 &&
            displayNameHashBytes.size == 32 && body.eventId.contentEquals(eventIdBytes) &&
            credential.credentialId.contentEquals(credentialIdBytes) &&
            body.b004AdoptionScopeHash.contentEquals(b004AdoptionScopeHashBytes) &&
            body.displayNameHash.contentEquals(displayNameHashBytes) &&
            body.admissionMode == admissionMode && body.validFromUnixSeconds == validFromUnixSeconds &&
            body.validUntilUnixSeconds == validUntilUnixSeconds && nowUnixSeconds >= validFromUnixSeconds &&
            nowUnixSeconds < validUntilUnixSeconds && body.censusWindowSeconds == censusDomainPolicy.censusWindowSeconds &&
            census.unsignedBody.credentialId.contentEquals(credentialIdBytes) &&
            BarnardAdoptionWire.sha256(census.authorityPublicKey).contentEquals(censusDomainPolicy.authorizedAuthorityKeyHash) &&
            censusDomainPolicy.structurallyValid && rotationFieldsAreStructurallyValid
        ) BarnardRegistryVerification.VERIFIED else BarnardRegistryVerification.UNVERIFIED
    }

    private val rotationFieldsAreStructurallyValid: Boolean
        get() = when {
            replacesCredentialIdBytes == null && effectiveWindowIndex == null -> true
            replacesCredentialIdBytes != null && effectiveWindowIndex != null ->
                replacesCredentialIdBytes.size == 32 && !replacesCredentialIdBytes.contentEquals(credentialIdBytes)
            else -> false
        }
}

/** One authorized Census Authority key per v1 domain/window/policy epoch. */
public class BarnardCensusDomainPolicy(
    censusDomainId: ByteArray,
    public val censusWindowSeconds: UInt,
    public val authorityPolicyEpoch: UInt,
    authorizedAuthorityKeyHash: ByteArray,
    public val minimumEligibleVoterCount: UShort,
    public val minimumQualifiedVoterCount: UShort,
    public val maximumCandidateAgeSeconds: ULong = 60uL,
) {
    private val censusDomainIdBytes = censusDomainId.copyOf()
    private val authorizedAuthorityKeyHashBytes = authorizedAuthorityKeyHash.copyOf()
    public val censusDomainId: ByteArray get() = censusDomainIdBytes.copyOf()
    public val authorizedAuthorityKeyHash: ByteArray get() = authorizedAuthorityKeyHashBytes.copyOf()
    internal val structurallyValid: Boolean
        get() = censusDomainIdBytes.size == 32 && authorizedAuthorityKeyHashBytes.size == 32 &&
            censusWindowSeconds in 12u..3600u && minimumQualifiedVoterCount <= minimumEligibleVoterCount
}

public class BarnardCensusTuple(
    credentialId: ByteArray,
    censusDomainId: ByteArray,
    public val authorityPolicyEpoch: UInt,
    censusAuthorityKeyHash: ByteArray,
    public val windowIndex: ULong,
) {
    private val credentialIdBytes = credentialId.copyOf()
    private val censusDomainIdBytes = censusDomainId.copyOf()
    private val censusAuthorityKeyHashBytes = censusAuthorityKeyHash.copyOf()
    public val credentialId: ByteArray get() = credentialIdBytes.copyOf()
    public val censusDomainId: ByteArray get() = censusDomainIdBytes.copyOf()
    public val censusAuthorityKeyHash: ByteArray get() = censusAuthorityKeyHashBytes.copyOf()

    override fun equals(other: Any?): Boolean = other is BarnardCensusTuple &&
        credentialIdBytes.contentEquals(other.credentialIdBytes) && censusDomainIdBytes.contentEquals(other.censusDomainIdBytes) &&
        authorityPolicyEpoch == other.authorityPolicyEpoch && censusAuthorityKeyHashBytes.contentEquals(other.censusAuthorityKeyHashBytes) &&
        windowIndex == other.windowIndex

    override fun hashCode(): Int = listOf(
        credentialIdBytes.contentHashCode(), censusDomainIdBytes.contentHashCode(), authorityPolicyEpoch.hashCode(),
        censusAuthorityKeyHashBytes.contentHashCode(), windowIndex.hashCode(),
    ).fold(1) { acc, value -> 31 * acc + value }
}

/**
 * Verified candidate whose public fields can only come from exact B005 bytes
 * after signature verification and Registry Event Definition binding.
 */
public class BarnardVerifiedCensusCandidate private constructor(
    exactB005Bytes: ByteArray,
    credentialId: ByteArray,
    eventId: ByteArray,
    public val admissionMode: BarnardAdoptionAdmissionMode,
    censusDomainId: ByteArray,
    public val censusWindowSeconds: UInt,
    public val authorityPolicyEpoch: UInt,
    censusAuthorityKeyHash: ByteArray,
    public val windowIndex: ULong,
    public val qualifiedVoterCount: UShort,
    public val eligibleVoterCount: UShort,
    public val observedAtUnixSeconds: ULong,
    public val registryVerification: BarnardRegistryVerification,
) {
    private val exactB005BytesValue = exactB005Bytes.copyOf()
    private val credentialIdBytes = credentialId.copyOf()
    private val eventIdBytes = eventId.copyOf()
    private val censusDomainIdBytes = censusDomainId.copyOf()
    private val censusAuthorityKeyHashBytes = censusAuthorityKeyHash.copyOf()
    /** Exact bound B005 artifact; relay code must never accept a separate byte string. */
    public val exactB005Bytes: ByteArray get() = exactB005BytesValue.copyOf()
    public val credentialId: ByteArray get() = credentialIdBytes.copyOf()
    public val eventId: ByteArray get() = eventIdBytes.copyOf()
    public val censusDomainId: ByteArray get() = censusDomainIdBytes.copyOf()
    public val censusAuthorityKeyHash: ByteArray get() = censusAuthorityKeyHashBytes.copyOf()
    public val censusTuple: BarnardCensusTuple
        get() = BarnardCensusTuple(credentialIdBytes, censusDomainIdBytes, authorityPolicyEpoch, censusAuthorityKeyHashBytes, windowIndex)

    public companion object {
        /**
         * The sole verified-candidate factory. All exposed credential, event,
         * domain, authority, window, and count fields are derived from the
         * signature-verified B005 artifact plus its exact registry binding.
         */
        public fun decodeAndBind(
            b005Bytes: ByteArray,
            registryDefinition: BarnardRegistryEventDefinition,
            observedAtUnixSeconds: ULong,
        ): BarnardVerifiedCensusCandidate {
            val payload = BarnardB005V2Codec.decode(b005Bytes)
            if (registryDefinition.verify(payload.credential, payload.census, observedAtUnixSeconds) !=
                BarnardRegistryVerification.VERIFIED
            ) adoptionFailure(BarnardAdoptionProtocolError.INVALID_FIELD)
            val credential = payload.credential
            val census = payload.census
            val policy = registryDefinition.censusDomainPolicy
            return BarnardVerifiedCensusCandidate(
                exactB005Bytes = b005Bytes,
                credentialId = credential.credentialId,
                eventId = credential.unsignedBody.eventId,
                admissionMode = credential.unsignedBody.admissionMode,
                censusDomainId = policy.censusDomainId,
                censusWindowSeconds = policy.censusWindowSeconds,
                authorityPolicyEpoch = policy.authorityPolicyEpoch,
                censusAuthorityKeyHash = BarnardAdoptionWire.sha256(census.authorityPublicKey),
                windowIndex = census.unsignedBody.windowIndex,
                qualifiedVoterCount = census.unsignedBody.qualifiedVoterCount,
                eligibleVoterCount = census.unsignedBody.eligibleVoterCount,
                observedAtUnixSeconds = observedAtUnixSeconds,
                registryVerification = BarnardRegistryVerification.VERIFIED,
            )
        }
    }
}

public enum class BarnardAdoptionFallbackReason {
    REGISTRY_UNVERIFIED,
    GATED,
    NO_CLEAR_MAJORITY,
    INSUFFICIENT_EVIDENCE,
    STALE_CANDIDATE,
    WRONG_CENSUS_WINDOW,
    INCONSISTENT_ELIGIBILITY,
    DOMAIN_MISMATCH,
    NO_AUTHORITATIVE_CENSUS,
    INVALID_DOMAIN_POLICY,
}

public sealed class BarnardAdoptionDecisionResult {
    public class AutoAdopt(credentialId: ByteArray) : BarnardAdoptionDecisionResult() {
        private val credentialIdBytes = credentialId.copyOf()
        public val credentialId: ByteArray get() = credentialIdBytes.copyOf()
        override fun equals(other: Any?): Boolean = other is AutoAdopt && credentialIdBytes.contentEquals(other.credentialIdBytes)
        override fun hashCode(): Int = credentialIdBytes.contentHashCode()
    }

    public class RequiresChooser(public val reason: BarnardAdoptionFallbackReason) : BarnardAdoptionDecisionResult() {
        override fun equals(other: Any?): Boolean = other is RequiresChooser && reason == other.reason
        override fun hashCode(): Int = reason.hashCode()
    }

    public object DomainAuthorityInconsistency : BarnardAdoptionDecisionResult()

    public companion object {
        public val DOMAIN_AUTHORITY_INCONSISTENCY: BarnardAdoptionDecisionResult = DomainAuthorityInconsistency
    }
}

/** Evaluates the trusted-authority cross-event local majority, not raw radio observations. */
public object BarnardAdoptionDecision {
    public fun evaluate(
        candidates: List<BarnardVerifiedCensusCandidate>,
        domainPolicy: BarnardCensusDomainPolicy,
        nowUnixSeconds: ULong,
    ): BarnardAdoptionDecisionResult {
        if (candidates.isEmpty()) {
            return BarnardAdoptionDecisionResult.RequiresChooser(BarnardAdoptionFallbackReason.NO_AUTHORITATIVE_CENSUS)
        }
        if (!domainPolicy.structurallyValid) {
            return BarnardAdoptionDecisionResult.RequiresChooser(BarnardAdoptionFallbackReason.INVALID_DOMAIN_POLICY)
        }
        if (candidates.any { it.registryVerification != BarnardRegistryVerification.VERIFIED }) {
            return BarnardAdoptionDecisionResult.RequiresChooser(BarnardAdoptionFallbackReason.REGISTRY_UNVERIFIED)
        }
        if (candidates.any {
                !it.censusDomainId.contentEquals(domainPolicy.censusDomainId) ||
                    it.censusWindowSeconds != domainPolicy.censusWindowSeconds ||
                    it.authorityPolicyEpoch != domainPolicy.authorityPolicyEpoch
            }
        ) return BarnardAdoptionDecisionResult.RequiresChooser(BarnardAdoptionFallbackReason.DOMAIN_MISMATCH)
        if (candidates.any { !it.censusAuthorityKeyHash.contentEquals(domainPolicy.authorizedAuthorityKeyHash) }) {
            return BarnardAdoptionDecisionResult.DOMAIN_AUTHORITY_INCONSISTENCY
        }
        if (candidates.any { it.admissionMode != BarnardAdoptionAdmissionMode.OPEN }) {
            return BarnardAdoptionDecisionResult.RequiresChooser(BarnardAdoptionFallbackReason.GATED)
        }
        val expectedWindow = nowUnixSeconds / domainPolicy.censusWindowSeconds.toULong()
        if (candidates.any { it.windowIndex != expectedWindow }) {
            return BarnardAdoptionDecisionResult.RequiresChooser(BarnardAdoptionFallbackReason.WRONG_CENSUS_WINDOW)
        }
        if (candidates.any { nowUnixSeconds < it.observedAtUnixSeconds || nowUnixSeconds - it.observedAtUnixSeconds > domainPolicy.maximumCandidateAgeSeconds }) {
            return BarnardAdoptionDecisionResult.RequiresChooser(BarnardAdoptionFallbackReason.STALE_CANDIDATE)
        }
        if (candidates.any { it.qualifiedVoterCount > it.eligibleVoterCount }) {
            return BarnardAdoptionDecisionResult.RequiresChooser(BarnardAdoptionFallbackReason.INCONSISTENT_ELIGIBILITY)
        }
        val eligibleCounts = candidates.map { it.eligibleVoterCount }.toSet()
        if (eligibleCounts.size != 1) {
            return BarnardAdoptionDecisionResult.RequiresChooser(BarnardAdoptionFallbackReason.INCONSISTENT_ELIGIBILITY)
        }
        val eligible = eligibleCounts.single()
        val aggregateQualified = candidates.fold(0uL) { total, candidate -> total + candidate.qualifiedVoterCount.toULong() }
        if (aggregateQualified > eligible.toULong()) {
            return BarnardAdoptionDecisionResult.RequiresChooser(BarnardAdoptionFallbackReason.INCONSISTENT_ELIGIBILITY)
        }
        if (eligible < domainPolicy.minimumEligibleVoterCount) {
            return BarnardAdoptionDecisionResult.RequiresChooser(BarnardAdoptionFallbackReason.INSUFFICIENT_EVIDENCE)
        }
        val winner = candidates.maxByOrNull { it.qualifiedVoterCount.toInt() }
            ?: return BarnardAdoptionDecisionResult.RequiresChooser(BarnardAdoptionFallbackReason.NO_CLEAR_MAJORITY)
        if (candidates.count { it.qualifiedVoterCount == winner.qualifiedVoterCount } != 1 ||
            winner.qualifiedVoterCount < domainPolicy.minimumQualifiedVoterCount ||
            winner.qualifiedVoterCount.toULong() * 2uL <= eligible.toULong()
        ) return BarnardAdoptionDecisionResult.RequiresChooser(BarnardAdoptionFallbackReason.NO_CLEAR_MAJORITY)
        return BarnardAdoptionDecisionResult.AutoAdopt(winner.credentialId)
    }
}

public enum class BarnardCredentialRotationResult {
    VALID_BOUNDARY_REPLACEMENT,
    CREDENTIAL_ROTATION_INCONSISTENCY,
}

/** Local chain-shape check; registry authorization and non-overlap stay external. */
public object BarnardCredentialRotation {
    public fun validate(
        activeCredentialId: ByteArray,
        replacementCredentialId: ByteArray,
        replacesCredentialId: ByteArray?,
        activeWindowIndex: ULong,
        effectiveWindowIndex: ULong,
    ): BarnardCredentialRotationResult =
        if (activeCredentialId.size == 32 && replacementCredentialId.size == 32 &&
            !activeCredentialId.contentEquals(replacementCredentialId) && replacesCredentialId?.contentEquals(activeCredentialId) == true &&
            effectiveWindowIndex > activeWindowIndex
        ) BarnardCredentialRotationResult.VALID_BOUNDARY_REPLACEMENT
        else BarnardCredentialRotationResult.CREDENTIAL_ROTATION_INCONSISTENCY
}

public enum class BarnardRelayCacheResult {
    ACCEPTED_FOR_RELAY,
    DUPLICATE,
    CENSUS_EQUIVOCATION,
    CAPACITY_EXCEEDED,
    EXPIRED,
}

public enum class BarnardRelayDisposition { NOT_OBSERVED, RELAYABLE, BLOCKED_BY_EQUIVOCATION, EXPIRED }

/**
 * Bounded exact-byte cache which reports, rather than first-seen-wins,
 * conflicts. Transport metadata, RPI, raw observations, and relayer count
 * are excluded: only a bound verified candidate can enter this cache.
 */
public class BarnardCensusRelayCache(
    maximumActiveTuples: Int,
    maximumPayloadsPerConflict: Int,
) {
    private data class Entry(var payloads: MutableList<ByteArray>, var equivocated: Boolean)
    private val maximumActiveTuples = maximumActiveTuples.coerceAtLeast(1)
    private val maximumPayloadsPerConflict = maximumPayloadsPerConflict.coerceIn(2, 2)
    private val entries = linkedMapOf<BarnardCensusTuple, Entry>()
    private val expired = linkedSetOf<BarnardCensusTuple>()
    /** Exclusive monotonic floor that survives bounded tombstone eviction. */
    private var expiredWindowFloor: ULong = 0uL

    @Synchronized
    public fun record(candidate: BarnardVerifiedCensusCandidate): BarnardRelayCacheResult {
        val tuple = candidate.censusTuple
        if (tuple.windowIndex < expiredWindowFloor || tuple in expired) return BarnardRelayCacheResult.EXPIRED
        val existing = entries[tuple]
        if (existing != null) {
            if (existing.payloads.any { it.contentEquals(candidate.exactB005Bytes) }) return BarnardRelayCacheResult.DUPLICATE
            if (existing.payloads.size < maximumPayloadsPerConflict) existing.payloads += candidate.exactB005Bytes
            existing.equivocated = true
            return BarnardRelayCacheResult.CENSUS_EQUIVOCATION
        }
        if (entries.size >= maximumActiveTuples) return BarnardRelayCacheResult.CAPACITY_EXCEEDED
        entries[tuple] = Entry(mutableListOf(candidate.exactB005Bytes), false)
        return BarnardRelayCacheResult.ACCEPTED_FOR_RELAY
    }

    @Synchronized
    public fun relayDisposition(tuple: BarnardCensusTuple): BarnardRelayDisposition = when {
        tuple.windowIndex < expiredWindowFloor || tuple in expired -> BarnardRelayDisposition.EXPIRED
        entries[tuple]?.equivocated == true -> BarnardRelayDisposition.BLOCKED_BY_EQUIVOCATION
        tuple in entries -> BarnardRelayDisposition.RELAYABLE
        else -> BarnardRelayDisposition.NOT_OBSERVED
    }

    @Synchronized
    public fun retainedPayloadCount(tuple: BarnardCensusTuple): Int = entries[tuple]?.payloads?.size ?: 0

    @Synchronized
    public fun prune(expiredThroughWindow: ULong) {
        if (expiredThroughWindow > expiredWindowFloor) expiredWindowFloor = expiredThroughWindow
        val expiredTuples = entries.keys.filter { it.windowIndex < expiredWindowFloor }
        expiredTuples.forEach {
            entries.remove(it)
            expired += it
        }
        while (expired.size > maximumActiveTuples) expired.remove(expired.first())
    }
}

public class BarnardDirectGattPeerObservation(
    public val ephemeralPeerHandle: String,
    b004Value: ByteArray,
    b002Value: ByteArray,
    verifiedB005CredentialId: ByteArray,
    public val registryVerification: BarnardRegistryVerification,
) {
    private val b004ValueBytes = b004Value.copyOf()
    private val b002ValueBytes = b002Value.copyOf()
    private val verifiedB005CredentialIdBytes = verifiedB005CredentialId.copyOf()
    public val b004Value: ByteArray get() = b004ValueBytes.copyOf()
    public val b002Value: ByteArray get() = b002ValueBytes.copyOf()
    public val verifiedB005CredentialId: ByteArray get() = verifiedB005CredentialIdBytes.copyOf()
}

public enum class BarnardSelfCheckObservationResult { PEER_CONFIRMED, IGNORED }
public enum class BarnardSelfCheckWindowResult { CONTINUE_CHECKING, PRESENT_SWITCH_PROMPT }

/** Same-GATT-session shape check; it never tries to resolve another device's TEK. */
public class BarnardAutoAdoptionSelfCheck(
    credentialId: ByteArray,
    b004AdoptionScopeHash: ByteArray,
    requiredCompleteWindows: Int,
) {
    private val credentialIdBytes = credentialId.copyOf()
    private val b004AdoptionScopeHashBytes = b004AdoptionScopeHash.copyOf()
    private val requiredCompleteWindows = requiredCompleteWindows.coerceAtLeast(1)
    private var peerConfirmed = false
    private val completedWindows = mutableSetOf<ULong>()

    public fun observe(observation: BarnardDirectGattPeerObservation, inWindow: ULong): BarnardSelfCheckObservationResult {
        val supportedB002 = observation.b002Value.size == 17 &&
            ((observation.b002Value.first().toInt() and 0xff) == 0x01)
        if (observation.registryVerification != BarnardRegistryVerification.VERIFIED ||
            !observation.b004Value.contentEquals(b004AdoptionScopeHashBytes) ||
            !observation.verifiedB005CredentialId.contentEquals(credentialIdBytes) || !supportedB002
        ) return BarnardSelfCheckObservationResult.IGNORED
        // The ephemeral handle is intentionally not retained or used as identity.
        peerConfirmed = true
        return BarnardSelfCheckObservationResult.PEER_CONFIRMED
    }

    public fun completeWindow(windowIndex: ULong): BarnardSelfCheckWindowResult {
        if (completedWindows.size < requiredCompleteWindows) completedWindows += windowIndex
        return if (!peerConfirmed && completedWindows.size >= requiredCompleteWindows) {
            BarnardSelfCheckWindowResult.PRESENT_SWITCH_PROMPT
        } else BarnardSelfCheckWindowResult.CONTINUE_CHECKING
    }
}

/** Code-less per-device derivations; legacy EventCode APIs remain v1-only. */
public object BarnardAdoptionKeyDerivation {
    public fun deriveTek(deviceSecret: ByteArray, credentialId: ByteArray): ByteArray =
        try {
            BarnardCrypto.deriveTekForAdoptionCredential(deviceSecret, credentialId)
        } catch (_: BarnardCryptoInputException) {
            adoptionFailure(BarnardAdoptionProtocolError.INVALID_LENGTH)
        }

    public fun deriveSigningPublicKey(deviceSecret: ByteArray, credentialId: ByteArray): ByteArray =
        BarnardSigning.deriveSigningKeyPairForAdoptionCredential(deviceSecret, credentialId).publicKeyCompressed
}
