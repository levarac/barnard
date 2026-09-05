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

data class BarnardB005VerifiedEnvelope internal constructor(
    val receiverState: BarnardB005ReceiverState,
    val relayHopCount: Int,
    val eventId: ByteArray,
    val keySetDigest: ByteArray,
    val joinMode: Int,
    val eventCodeHash: ByteArray,
    val eventDisplayName: String,
    val validFromEnin: Long,
    val validThroughEnin: Long,
    val eninSeconds: Int,
    val signedEnvelope: ByteArray,
)

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

object BarnardB005EnvelopeV2 {
    const val FORMAT_VERSION = 3
    const val ENVELOPE_VERSION = 1
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
        if (container.size !in 4..512 || container[0].u != 3 || container[1].u > 2 || currentEnin == null || currentEnin < 0) return null
        val length = container[2].u shl 8 or container[3].u
        if (length > 508 || length != container.size - 4) return null
        val e = container.copyOfRange(4, container.size); if (e.size < 199 || e[0].u != 1) return null
        val registrar = e.copyOfRange(1, 21); val anchor = e.copyOfRange(21, 41); val nonce = e.copyOfRange(41, 73)
        val n = e[73].u; if (n !in 1..8) return null
        val a = 74 + 33 * n; if (a + 91 > e.size) return null
        val keys = mutableListOf<ByteArray>()
        repeat(n) { i ->
            val key = e.copyOfRange(74 + i * 33, 107 + i * 33)
            if (!recoverer.isValidCompressedKey(key) || (keys.lastOrNull()?.let { compare(it, key) >= 0 } == true)) return null
            keys += key
        }
        val joinMode = e[a].u; if (joinMode !in 0..1 || read16(e, a + 1) == 0 || e[a + 15].u != 2) return null
        val validFrom = read32(e, a + 3); val validThrough = read32(e, a + 7); val expires = read32(e, a + 11)
        val codeHash = e.copyOfRange(a + 16, a + 24); val nameLength = e[a + 24].u
        if (nameLength !in 1..64) return null
        val nameStart = a + 25; val certLengthOffset = nameStart + nameLength
        if (certLengthOffset >= e.size) return null
        val certLength = e[certLengthOffset].u
        if (e.size != 165 + 33 * n + nameLength + certLength) return null
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
        return BarnardB005VerifiedEnvelope(
            BarnardB005ReceiverState.RADIO_SELF_VERIFIED, container[1].u, eventId, ks, joinMode, codeHash, name,
            validFrom, validThrough, read16(e, a + 1), e,
        )
    }

    /**
     * Confirms a `RADIO_SELF_VERIFIED` envelope against the authenticated, pinned-block
     * `EventDefinitionV1` for this `eventId` (spec 122 receiver policy, step 8; spec 134 step 4 as
     * amended by errata #173, which drops the unsatisfiable display-name agreement). This is the
     * only path to `REGISTRY_VERIFIED`: it is not derivable from a caller-supplied boolean, only
     * from checking every field of an actual definition the caller obtained on-chain.
     */
    fun confirmAgainstRegistry(verified: BarnardB005VerifiedEnvelope, definition: BarnardEventDefinitionV1): BarnardB005VerifiedEnvelope {
        if (verified.eninSeconds <= 0) return verified.copy(receiverState = BarnardB005ReceiverState.RADIO_SELF_VERIFIED)
        val eninPerSecond = verified.eninSeconds.toLong()
        val agrees = verified.eventId.contentEquals(definition.eventId) &&
            verified.keySetDigest.contentEquals(definition.keySetDigest) &&
            verified.joinMode == definition.joinMode &&
            verified.eventCodeHash.contentEquals(definition.eventCodeHash) &&
            definition.validFromUnixSeconds / eninPerSecond <= verified.validFromEnin &&
            verified.validThroughEnin <= definition.validUntilUnixSeconds / eninPerSecond
        return verified.copy(receiverState = if (agrees) BarnardB005ReceiverState.REGISTRY_VERIFIED else BarnardB005ReceiverState.RADIO_SELF_VERIFIED)
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
        if (start > end || end > 9_007_199_254_740_992UL || !p.finished) return null
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
