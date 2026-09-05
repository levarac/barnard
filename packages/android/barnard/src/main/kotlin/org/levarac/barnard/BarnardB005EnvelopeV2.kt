// Use of this source code is governed by a BSD-style license.

package org.levarac.barnard

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

data class BarnardB005VerifiedEnvelope(
    val receiverState: BarnardB005ReceiverState,
    val relayHopCount: Int,
    val eventId: ByteArray,
    val keySetDigest: ByteArray,
    val eventCodeHash: ByteArray,
    val eventDisplayName: String,
    val signedEnvelope: ByteArray,
) {
    fun confirmingRegistry(agrees: Boolean) = if (agrees) BarnardB005ReceiverState.REGISTRY_VERIFIED else BarnardB005ReceiverState.RADIO_SELF_VERIFIED
}

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

    fun verify(container: ByteArray, currentEnin: Long?, registryConfirmed: Boolean = false, recoverer: BarnardB005PublicKeyRecovering = BarnardB005NativeRecoverer): BarnardB005VerifiedEnvelope? {
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
            if (!signatureMatches(c.signature, sha256(buildSigStructure(c.protectedBytes, c.payload)), candidates[0], recoverer, false)) return null
            c.delegateKey
        }
        val signature = e.copyOfRange(signatureStart, e.size)
        val digest = sha256(signatureDomain + e.copyOfRange(0, signatureStart))
        val accepted = if (signer != null) signatureMatches(signature, digest, signer, recoverer, true)
            else keys.any { signatureMatches(signature, digest, it, recoverer, true) }
        if (!accepted) return null
        return BarnardB005VerifiedEnvelope(if (registryConfirmed) BarnardB005ReceiverState.REGISTRY_VERIFIED else BarnardB005ReceiverState.RADIO_SELF_VERIFIED, container[1].u, eventId, ks, codeHash, name, e)
    }

    fun buildSigStructure(protectedBytes: ByteArray, payload: ByteArray): ByteArray =
        byteArrayOf(0x84.toByte(), 0x6a) + "Signature1".encodeToByteArray() + cborBytes(protectedBytes) + byteArrayOf(0x40) + cborBytes(payload)

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
    private fun signatureMatches(signature: ByteArray, digest: ByteArray, key: ByteArray, recoverer: BarnardB005PublicKeyRecovering, recoveryByte: Boolean): Boolean {
        if (signature.size != if (recoveryByte) 65 else 64) return false
        val r = signature.copyOfRange(0, 32); val s = signature.copyOfRange(32, 64)
        if (recoveryByte) { val v = signature[64].u; return v <= 1 && recoverer.recover(v, r, s, digest)?.contentEquals(key) == true }
        return (0..1).any { recoverer.recover(it, r, s, digest)?.contentEquals(key) == true }
    }
    private fun strictDisplayName(bytes: ByteArray): String? {
        val value = bytes.decodeToString(throwOnInvalidSequence = true)
        if (value.any { it.code in 0..31 || it.code == 127 || it.code in 0x300..0x36f }) return null
        return value
    }
    private fun cborBytes(bytes: ByteArray) = if (bytes.size < 24) byteArrayOf((0x40 or bytes.size).toByte()) + bytes else byteArrayOf(0x58, bytes.size.toByte()) + bytes
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
    fun text(): String? = take(head(3))?.decodeToString(throwOnInvalidSequence = true)
    private fun take(size: ULong?): ByteArray? { size ?: return null; if (size > (input.size - offset).toULong()) return null; val end = offset + size.toInt(); return input.copyOfRange(offset, end).also { offset = end } }
    fun array() = head(4); fun map() = head(5); fun tag() = head(6)
}
