package org.levarac.barnard

import java.math.BigInteger
import java.nio.charset.StandardCharsets
import org.bouncycastle.crypto.digests.KeccakDigest
import org.junit.Assert.assertEquals
import org.junit.Test

class BarnardWalletBindingVerificationTest {
    private val owner = BigInteger.ONE
    private val wallet = BigInteger("2")
    private val ownerPublic = BouncyCastleSecp256k1Backend.compressedPublicKey(owner)!!
    private val walletPublic = BouncyCastleSecp256k1Backend.compressedPublicKey(wallet)!!
    private val walletAddress = ethereumAddress(walletPublic)
    private val text = BarnardSigning.buildAccountBindingText(
        "beid.levarac.org", walletAddress, ownerPublic, 1u,
        ByteArray(16) { it.toByte() }, "2026-07-30T09:00:00Z",
    )!!

    @Test fun validBindingAndAcknowledgementPass() {
        val walletSig = BarnardSigning.signRecoverable(wallet, eip191(text))
        val walletBytes = walletSig.r + walletSig.s + byteArrayOf(walletSig.v.toByte())
        val ack = BarnardSigning.signWalletAcknowledgement(owner, walletAddress, walletBytes)!!
        assertEquals(WalletBindingVerification.VALID, BarnardSigning.verifyWalletBinding(text, walletBytes, walletAddress, ownerPublic, ack))
    }

    @Test fun wrongMessageAndAddressFail() {
        val walletSig = BarnardSigning.signRecoverable(wallet, eip191(text))
        val walletBytes = walletSig.r + walletSig.s + byteArrayOf(walletSig.v.toByte())
        val ack = BarnardSigning.signWalletAcknowledgement(owner, walletAddress, walletBytes)!!
        assertEquals(WalletBindingVerification.INVALID, BarnardSigning.verifyWalletBinding(text.replace("Scope: global", "Scope: local"), walletBytes, walletAddress, ownerPublic, ack))
        assertEquals(WalletBindingVerification.INVALID, BarnardSigning.verifyWalletBinding(text, walletBytes, ByteArray(20), ownerPublic, ack))
    }

    @Test fun malformedAndSmartWalletSignaturesAreRejected() {
        val ack = BarnardSigning.signWalletAcknowledgement(owner, walletAddress, ByteArray(65))!!
        assertEquals(WalletSignatureClassification.INVALID, BarnardSigning.classifyWalletSignature(ByteArray(64)))
        assertEquals(WalletSignatureClassification.SMART_WALLET_UNSUPPORTED, BarnardSigning.classifyWalletSignature(ERC6492_MAGIC))
        assertEquals(WalletBindingVerification.INVALID, BarnardSigning.verifyWalletBinding(text, ByteArray(64), walletAddress, ownerPublic, ack))
        assertEquals(WalletBindingVerification.SMART_WALLET_UNSUPPORTED, BarnardSigning.verifyWalletBinding(text, ERC6492_MAGIC, walletAddress, ownerPublic, ack))
    }

    @Test fun walletAndAcknowledgementRejectZeroAndHighS() {
        val walletSig = BarnardSigning.signRecoverable(wallet, eip191(text))
        val walletBytes = walletSig.r + walletSig.s + byteArrayOf(walletSig.v.toByte())
        val ack = BarnardSigning.signWalletAcknowledgement(owner, walletAddress, walletBytes)!!
        val highWalletS = fixed32(SECP256K1_N.subtract(BigInteger(1, walletSig.s)))
        val highWallet = walletSig.r + highWalletS + byteArrayOf(walletSig.v.toByte())
        val highWalletAck = BarnardSigning.signWalletAcknowledgement(owner, walletAddress, highWallet)!!
        assertEquals(WalletBindingVerification.INVALID, BarnardSigning.verifyWalletBinding(text, highWallet, walletAddress, ownerPublic, highWalletAck))
        val highAckS = fixed32(SECP256K1_N.subtract(BigInteger(1, ack.s)))
        assertEquals(WalletBindingVerification.INVALID, BarnardSigning.verifyWalletBinding(text, walletBytes, walletAddress, ownerPublic, BarnardSigning.RecoverableSignature(ack.r, highAckS, ack.v)))
        assertEquals(WalletBindingVerification.INVALID, BarnardSigning.verifyWalletBinding(text, ByteArray(32) + walletSig.s + byteArrayOf(walletSig.v.toByte()), walletAddress, ownerPublic, ack))
    }

    private fun eip191(value: String): ByteArray {
        val bytes = value.toByteArray(StandardCharsets.UTF_8)
        return keccak("\u0019Ethereum Signed Message:\n${bytes.size}".toByteArray(StandardCharsets.US_ASCII) + bytes)
    }
    private fun ethereumAddress(compressed: ByteArray): ByteArray = keccak(BouncyCastleSecp256k1Backend.uncompressedPublicKey(compressed)!!.copyOfRange(1, 65)).copyOfRange(12, 32)
    private fun keccak(bytes: ByteArray): ByteArray = KeccakDigest(256).let { it.update(bytes, 0, bytes.size); ByteArray(32).also { out -> it.doFinal(out, 0) } }
    private fun fixed32(value: BigInteger): ByteArray {
        val raw = value.toByteArray()
        val trimmed = if (raw.size == 33 && raw[0] == 0.toByte()) raw.copyOfRange(1, 33) else raw
        return ByteArray(32 - trimmed.size) + trimmed
    }
    private val SECP256K1_N = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
    private val ERC6492_MAGIC = "6492649264926492649264926492649264926492649264926492649264926492".chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
