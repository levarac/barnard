package org.levarac.barnard

import java.io.File
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class BarnardB005EnvelopeV2Test {
    private val vectors by lazy { parseVectors(File(findRepoRoot(), "test-vectors/b005-envelope-v2.txt")) }
    private val parallaxNegVectors by lazy { parseVectors(File(findRepoRoot(), "test-vectors/parallax-delegation-cert-v1.txt")) }
    private fun v(name: String) = vectors[name] ?: error("missing $name")
    @Test fun sharedVectorsAndBoundaries() {
        val key = hex(v("authority_public_key"))
        assertContentEquals(hex(v("event_key_set_bytes")), BarnardB005EnvelopeV2.eventKeySetBytes(listOf(key)))
        assertContentEquals(hex(v("event_key_set_digest")), BarnardB005EnvelopeV2.keySetDigest(listOf(key)))
        assertContentEquals(hex(v("event_id")), BarnardB005EnvelopeV2.computeEventId(hex(v("registrar")), hex(v("anchor_operator")), hex(v("nonce")), hex(v("event_key_set_digest"))))
        assertContentEquals(hex("6c86c6aac5fb24bc"), BarnardB005EnvelopeV2.openEventCodeHash(ByteArray(32) { it.toByte() }))
        val first = hex(v("v1_container")); val second = hex(v("v2_container"))
        assertEquals(BarnardB005ReceiverState.RADIO_SELF_VERIFIED, BarnardB005EnvelopeV2.verify(first, 6_000_000)?.receiverState)
        assertEquals(BarnardB005ReceiverState.RADIO_SELF_VERIFIED, BarnardB005EnvelopeV2.verify(second, 6_000_000)?.receiverState)
        assertNull(BarnardB005EnvelopeV2.verify(first, 5_999_989)); assertNotNull(BarnardB005EnvelopeV2.verify(first, 6_000_001)); assertNull(BarnardB005EnvelopeV2.verify(first, 6_000_002)); assertNull(BarnardB005EnvelopeV2.verify(first, null))
        for (i in 4 until first.size) { val m = first.copyOf(); m[i] = (m[i].toInt() xor 1).toByte(); assertNull(BarnardB005EnvelopeV2.verify(m, 6_000_000), "mutation $i") }
        for (i in 4 until second.size) { val m = second.copyOf(); m[i] = (m[i].toInt() xor 1).toByte(); assertNull(BarnardB005EnvelopeV2.verify(m, 6_000_000), "v2 mutation $i") }
    }

    @Test fun negativeCensusV2PayloadIsRejected() {
        val length = v("neg_census_v2_payload_length").toInt()
        val payload = hex(v("neg_census_v2_prefix")) + ByteArray(length - hex(v("neg_census_v2_prefix")).size)
        assertNull(BarnardB005EnvelopeV2.verify(payload, 6_000_000))
    }

    @Test fun displayNameRejectsInvalidUtf8WithoutThrowing() {
        val container = hex(v("v1_container"))
        // Name starts at container offset 4 (container header) + 1 (envelopeVersion) + 20 + 20 + 32 + 1 (n)
        // + 33*n (keys) + 25 (a offset into fixed window fields) = 136 for vector 1 (n = 1).
        val nameStart = 136
        container[nameStart] = 0xff.toByte() // invalid UTF-8 lead byte, same length as the original name
        assertNull(BarnardB005EnvelopeV2.verify(container, 6_000_000))
    }

    @Test fun displayNameRejectsNonNfcFormWithoutFalsePositive() {
        val container = hex(v("v1_container"))
        val nameStart = 136; val nameLength = 58
        // Decomposed Hangul jamo U+1100 U+1161 (6 bytes) normalizes under NFC to the single
        // precomposed syllable U+AC00 (3 bytes) -- neither codepoint falls in the U+0300-U+036F
        // combining-diacritic range the old ad-hoc check used, so this is a case the old check
        // would have wrongly accepted. The correct NFC check MUST reject it.
        val decomposedJamo = byteArrayOf(0xe1.toByte(), 0x84.toByte(), 0x80.toByte(), 0xe1.toByte(), 0x85.toByte(), 0xa1.toByte())
        val name = decomposedJamo + ByteArray(nameLength - decomposedJamo.size) { 'x'.code.toByte() }
        name.copyInto(container, nameStart)
        assertNull(BarnardB005EnvelopeV2.verify(container, 6_000_000))
    }

    @Test fun parallaxDelegationCertPositiveAndNegativeVectors() {
        val second = v("v2_container")
        val envelopeHex = v("v2_envelope")
        val oldCert = v("v2_delegation_cert")

        fun containerWithCert(certHex: String): ByteArray? {
            val idx = envelopeHex.indexOf(oldCert)
            if (idx < 0) return null
            val replacedHex = envelopeHex.substring(0, idx) + certHex + envelopeHex.substring(idx + oldCert.length)
            val envelope = hex(replacedHex)
            val certByteOffset = idx / 2
            envelope[certByteOffset - 1] = (certHex.length / 2).toByte()
            return BarnardB005EnvelopeV2.encodeContainer(1, envelope)
        }

        // Positive: the parallax bundle's positive fixture is byte-identical to vector 2's own cert.
        assertEquals(oldCert, parallaxNegVectors["pos_signed_delegation_cert"])
        assertNotNull(BarnardB005EnvelopeV2.verify(hex(second), 6_000_000))

        for (key in listOf("neg_inverted_window", "neg_zero_roles", "neg_unassigned_role", "neg_unknown_version",
            "neg_unknown_field", "neg_missing_window", "neg_wrong_event", "neg_foreign_signer", "neg_corrupt_signature")) {
            val certHex = parallaxNegVectors[key] ?: error("missing $key")
            val container = containerWithCert(certHex) ?: error("$key: could not build substitute container")
            assertNull(BarnardB005EnvelopeV2.verify(container, 6_000_000), key)
        }
    }

    @Test fun certContentTypeRejectsInvalidUtf8WithoutThrowing() {
        // Regression for the CborReader.text() call parsing the delegation cert's COSE
        // content-type header: an invalid UTF-8 lead byte there must fail closed (verify()
        // returns null), not escape as an unguarded CharacterCodingException.
        val envelopeHex = v("v2_envelope")
        val oldCert = v("v2_delegation_cert")
        val contentTypeHex = "6170706c69636174696f6e2f766e642e6c6576617261632e64656c65676174696f6e2d636572742b63626f72"
        val idxInCert = oldCert.indexOf(contentTypeHex)
        check(idxInCert >= 0)
        val corruptedCert = oldCert.substring(0, idxInCert) + "ff" + oldCert.substring(idxInCert + 2, oldCert.length)
        val idx = envelopeHex.indexOf(oldCert)
        val replacedHex = envelopeHex.substring(0, idx) + corruptedCert + envelopeHex.substring(idx + oldCert.length)
        val envelope = hex(replacedHex)
        val container = BarnardB005EnvelopeV2.encodeContainer(1, envelope) ?: error("could not build container")
        assertNull(BarnardB005EnvelopeV2.verify(container, 6_000_000))
    }

    @Test fun parallaxSubstitutedKeySetIsRejected() {
        // Spec 122's parallax negative list also names "substituted key set": swap the single
        // authority key embedded in vector 2's own envelope for Parallax's substitutedEventKeySetHex
        // key (same 33-byte compressed layout, same cert kept verbatim) so the cert's own eventId
        // no longer matches the eventId recomputed from the (now different) embedded key set.
        val originalKeyHex = v("authority_public_key")
        val substitutedKeyHex = parallaxNegVectors["neg_substituted_event_key"] ?: error("missing neg_substituted_event_key")
        val container = v("v2_container")
        assertEquals(1, container.split(originalKeyHex).size - 1, "expected exactly one occurrence of the authority key")
        val mutated = hex(container.replace(originalKeyHex, substitutedKeyHex))
        assertNull(BarnardB005EnvelopeV2.verify(mutated, 6_000_000))
    }

    // --- Registry agreement (pure comparison; this SDK never assigns REGISTRY_VERIFIED) ---

    // --- Signed relay expiry and the structural scheduling accessor (barnard#197, #203) ---

    /**
     * [BarnardB005EnvelopeV2.verify] parses `relayExpiresAtEnin`, enforces `currentEnin <
     * relayExpiresAtEnin <= validThroughEnin` and the 12-ENIN cap against it, and now carries it
     * on the receipt instead of discarding it. Asserted against the committed conformance vector,
     * so a value that disagrees with the vector fails.
     */
    @Test fun verifiedEnvelopeExposesSignedWindowFromVector() {
        val container = hex(v("v1_container"))
        val verified = assertNotNull(BarnardB005EnvelopeV2.verify(container, 6_000_000L), "expected the v1 vector container to verify")
        assertEquals(v("v1_relay_expires_at_enin").toLong(), verified.relayExpiresAtEnin, "relayExpiresAtEnin must match the vector")
        assertEquals(v("v1_valid_from_enin").toLong(), verified.validFromEnin, "validFromEnin must match the vector")
        assertEquals(v("v1_valid_through_enin").toLong(), verified.validThroughEnin, "validThroughEnin must match the vector")
        assertEquals(v("v1_enin_seconds").toInt(), verified.eninSeconds, "eninSeconds must match the vector")

        // The relay window is half-open, so the expiry ENIN itself is outside it while the one
        // before it is inside -- the property a host leases against.
        assertNotNull(BarnardB005EnvelopeV2.verify(container, verified.relayExpiresAtEnin - 1), "the ENIN before expiry is still relayable")
        assertNull(BarnardB005EnvelopeV2.verify(container, verified.relayExpiresAtEnin), "the expiry ENIN itself is not relayable")
    }

    /**
     * The structural accessor reads the same four fields without a signature, a key recovery, a
     * registry read or a clock. Both vector containers are checked, and each is cross-checked
     * against `verify`'s own result: the untrusted read and the trusted read go through one offset
     * table, so they must agree on every field.
     */
    @Test fun schedulingFieldsMatchVectorAndAgreeWithVerify() {
        val v1 = assertNotNull(BarnardB005EnvelopeV2.schedulingFields(hex(v("v1_container"))), "expected scheduling fields for the v1 vector container")
        assertEquals(v("v1_valid_from_enin").toLong(), v1.validFromEnin)
        assertEquals(v("v1_valid_through_enin").toLong(), v1.validThroughEnin)
        assertEquals(v("v1_relay_expires_at_enin").toLong(), v1.relayExpiresAtEnin)
        assertEquals(v("v1_enin_seconds").toInt(), v1.eninSeconds)

        for (key in listOf("v1_container", "v2_container")) {
            val container = hex(v(key))
            val structural = assertNotNull(BarnardB005EnvelopeV2.schedulingFields(container), "expected scheduling fields for $key")
            val verified = assertNotNull(BarnardB005EnvelopeV2.verify(container, structural.validFromEnin), "expected $key to verify at its own validFromEnin")
            assertEquals(structural.validFromEnin, verified.validFromEnin, "$key: validFromEnin")
            assertEquals(structural.validThroughEnin, verified.validThroughEnin, "$key: validThroughEnin")
            assertEquals(structural.relayExpiresAtEnin, verified.relayExpiresAtEnin, "$key: relayExpiresAtEnin")
            assertEquals(structural.eninSeconds, verified.eninSeconds, "$key: eninSeconds")
        }
    }

    /**
     * A malformed container yields no accessor result rather than partial fields. Both a
     * first-guard rejection (truncation) and a LAST-guard rejection (the length arithmetic, which
     * is the final check [BarnardB005EnvelopeV2.validateStructure] runs) are exercised, so "no
     * partial fields" is not tested only at the point where nothing has been read yet.
     */
    @Test fun schedulingFieldsRejectsMalformedContainerWithoutPartialFields() {
        val container = hex(v("v1_container"))

        assertNull(BarnardB005EnvelopeV2.schedulingFields(ByteArray(0)), "empty container")
        assertNull(BarnardB005EnvelopeV2.schedulingFields(container.copyOfRange(0, 120)), "truncated container")

        // Last guard: 165 + 33n + nameLength + certLength must equal the envelope length. The
        // vector is n=1, nameLength=58, certLength=0 summing to 256; raising the certLength byte
        // breaks only that final equality, so every earlier structural check still passes.
        val n = container[4 + 73].toInt() and 0xff
        val nameLength = container[4 + 74 + 33 * n + 24].toInt() and 0xff
        val certLengthContainerOffset = 4 + 74 + 33 * n + 25 + nameLength
        assertNull(BarnardB005EnvelopeV2.validateStructure(container), "the unmodified vector container is structurally valid")
        val badCertLength = container.copyOf().also { it[certLengthContainerOffset] = 1 }
        assertEquals(BarnardB005StructureError.FIELD_LAYOUT, BarnardB005EnvelopeV2.validateStructure(badCertLength), "expected the final length-arithmetic guard to reject")
        assertNull(BarnardB005EnvelopeV2.schedulingFields(badCertLength), "a container failing the last structural guard yields no fields")
    }

    // --- Envelope encoder (barnard#207) ---

    /** Every field of vector 1, from the decimal values the vector file states. */
    private fun vectorOneFields(displayName: String = v("v1_display_name"), cert: ByteArray = ByteArray(0)) =
        BarnardB005EnvelopeFields(
            registrar = hex(v("registrar")), anchorOperator = hex(v("anchor_operator")), nonce = hex(v("nonce")),
            authorityKeys = listOf(hex(v("authority_public_key"))),
            joinMode = v("v1_join_mode").toInt(), eninSeconds = v("v1_enin_seconds").toInt(),
            validFromEnin = v("v1_valid_from_enin").toLong(), validThroughEnin = v("v1_valid_through_enin").toLong(),
            relayExpiresAtEnin = v("v1_relay_expires_at_enin").toLong(),
            eventCodeHash = hex(v("event_code_hash")), eventDisplayName = displayName, delegationCert = cert,
        )

    private fun encoded(f: BarnardB005EnvelopeFields) =
        (BarnardB005EnvelopeV2.encodeUnsignedEnvelope(f) as? BarnardB005EncodeResult.Encoded)?.envelope

    private fun refusal(f: BarnardB005EnvelopeFields) =
        (BarnardB005EnvelopeV2.encodeUnsignedEnvelope(f) as? BarnardB005EncodeResult.Refused)?.error

    /**
     * **The load-bearing acceptance.** Re-encoding each committed vector's fields must reproduce
     * its bytes exactly. The vectors were produced by an independent reference implementation (see
     * the vector file's provenance header), not by this encoder and not by this repository's
     * decoder, so agreement here is agreement with the spec rather than with ourselves.
     *
     * Vector 2's window fields are not stated in the vector file, so they are the literals vector 1
     * states and vector 2 shares -- reading them out of the bytes and writing them back would be a
     * fixed-point test that a symmetric offset error would satisfy.
     */
    @Test fun encoderReproducesCommittedVectorsByteForByte() {
        for (spec in listOf(
            Triple("vector 1 (authority-direct)", "v1", ByteArray(0)),
            Triple("vector 2 (delegate)", "v2", hex(v("v2_delegation_cert"))),
        )) {
            val (label, prefix, cert) = spec
            val expected = hex(v("${prefix}_envelope"))
            val unsigned = assertNotNull(encoded(vectorOneFields(v("${prefix}_display_name"), cert)), "$label: encoder refused the vector's own fields")
            assertContentEquals(expected.copyOfRange(0, expected.size - 65), unsigned.toBeSigned, "$label: unsigned bytes")
            assertContentEquals(hex(v("${prefix}_signature_digest")), unsigned.signatureDigest, "$label: signature digest")
            val assembled = BarnardB005EnvelopeV2.assembleSignedEnvelope(unsigned.toBeSigned, hex(v("${prefix}_signature_r_s_v")))
            val signed = assertNotNull((assembled as? BarnardB005AssembleResult.Assembled)?.signedEnvelope, "$label: assembly refused a 65-byte signature")
            assertContentEquals(expected, signed, "$label: assembled envelope must be byte-identical to the committed vector")
        }
    }

    /**
     * The byte at spec 122's `A+15` must be **literally 2** on the wire. Asserting it equals
     * [BarnardB005EnvelopeV2.MAX_RELAY_HOPS] would pass whatever that constant happened to be: it
     * would witness that the encoder uses the constant, not that the constant is right.
     */
    @Test fun encoderEmitsLiteralMaxRelayHopsByteOnTheWire() {
        val unsigned = assertNotNull(encoded(vectorOneFields()), "encoder refused vector 1's fields")
        val n = unsigned.toBeSigned[73].toInt() and 0xff
        val a = 74 + 33 * n
        assertEquals(2, unsigned.toBeSigned[a + 15].toInt() and 0xff, "spec 122 pins maxRelayHops at A+15 to 0x02")
        assertEquals(2, BarnardB005EnvelopeV2.MAX_RELAY_HOPS, "and the constant must agree with the spec, not the other way round")
    }

    /**
     * A re-encoded vector still verifies -- corroboration, not proof: a round-trip shows the
     * encoder and the decoder agree, which they would even if both were wrong.
     */
    @Test fun encodedVectorRoundTripsThroughVerify() {
        val unsigned = assertNotNull(encoded(vectorOneFields()), "encoder refused vector 1's fields")
        val assembled = BarnardB005EnvelopeV2.assembleSignedEnvelope(unsigned.toBeSigned, hex(v("v1_signature_r_s_v")))
        val signed = assertNotNull((assembled as? BarnardB005AssembleResult.Assembled)?.signedEnvelope)
        val container = assertNotNull(BarnardB005EnvelopeV2.encodeContainer(0, signed))
        assertContentEquals(hex(v("v1_container")), container, "container must match the committed vector")
        val verified = assertNotNull(BarnardB005EnvelopeV2.verify(container, 6_000_000L), "a re-encoded committed vector must verify")
        assertEquals(6_000_002L, verified.relayExpiresAtEnin)
    }

    /**
     * Negative cases, each paired with the input that must stay **accepted** -- a guard with no
     * such pair cannot be shown to fire only where it should.
     */
    @Test fun encoderRefusalsEachHaveAnAcceptedCounterpart() {
        val base = vectorOneFields()
        fun window(from: Long, through: Long, expires: Long) = BarnardB005EnvelopeFields(
            base.registrar, base.anchorOperator, base.nonce, base.authorityKeys, base.joinMode,
            base.eninSeconds, from, through, expires, base.eventCodeHash, base.eventDisplayName)
        fun gated(keys: List<ByteArray>) = BarnardB005EnvelopeFields(
            base.registrar, base.anchorOperator, base.nonce, keys, 1, base.eninSeconds,
            base.validFromEnin, base.validThroughEnin, base.relayExpiresAtEnin, base.eventCodeHash, base.eventDisplayName)

        // Display name: 65 bytes refused, 64 accepted.
        assertEquals(BarnardB005EncodeError.DISPLAY_NAME_LENGTH, refusal(vectorOneFields("a".repeat(65))), "65-byte name")
        assertNull(refusal(vectorOneFields("a".repeat(64))), "a 64-byte name is the maximum and must be accepted")
        assertEquals(BarnardB005EncodeError.DISPLAY_NAME_CHARACTERS, refusal(vectorOneFields("bad\u007fname")), "DEL is forbidden")
        assertNull(refusal(vectorOneFields("ok name")), "an ordinary name must be accepted")

        // Keys: gated mode, because two keys change the eventId and the open-mode binding would
        // otherwise refuse for an unrelated reason.
        val lo = ByteArray(33) { 2 }; val hi = ByteArray(33) { 3 }
        assertEquals(BarnardB005EncodeError.KEY_ORDER, refusal(gated(listOf(hi, lo))), "descending keys")
        assertEquals(BarnardB005EncodeError.KEY_ORDER, refusal(gated(listOf(lo, lo))), "duplicate keys are not strictly ascending")
        assertNull(refusal(gated(listOf(lo, hi))), "ascending keys must be accepted")

        // Windows. A window whose bounds are EQUAL is not the accepted counterpart -- it is itself
        // unsatisfiable, since verify needs validFrom <= currentEnin < relayExpires <= validThrough.
        // The correct counterpart is the minimal satisfiable window.
        assertEquals(BarnardB005EncodeError.VALIDITY_WINDOW, refusal(window(100, 50, 60)), "inverted window")
        assertEquals(BarnardB005EncodeError.VALIDITY_WINDOW, refusal(window(100, 100, 100)), "equal bounds leave no servable ENIN")
        assertEquals(BarnardB005EncodeError.VALIDITY_WINDOW, refusal(window(100, 200, 100)), "relay expiry at the window start")
        assertNull(refusal(window(100, 101, 101)), "the minimal satisfiable window must be accepted")
        assertEquals(BarnardB005EncodeError.RELAY_LIFETIME, refusal(window(100, 200, 113)), "a 13-ENIN lifetime")
        assertNull(refusal(window(100, 200, 112)), "a 12-ENIN lifetime is the cap and must be accepted")
    }

    @Test fun registryAgreementRequiresFullAgreement() {
        val container = hex(v("v1_container"))
        val verified = BarnardB005EnvelopeV2.verify(container, 6_000_000) ?: error("expected RADIO_SELF_VERIFIED baseline")
        assertEquals(BarnardB005ReceiverState.RADIO_SELF_VERIFIED, verified.receiverState)
        // The exact ENIN window is the INCLUSIVE [validFromEnin, validThroughEnin] (see
        // registryAgreement's doc comment); an aligned registry seconds window covers exactly
        // that ENIN range, i.e. seconds [validFromEnin * eninSeconds, (validThroughEnin + 1) *
        // eninSeconds - 1].
        fun agreeing() = BarnardEventDefinitionV1(
            verified.eventId, verified.keySetDigest, verified.joinMode, verified.eventCodeHash,
            verified.validFromEnin * verified.eninSeconds, (verified.validThroughEnin + 1) * verified.eninSeconds - 1,
        )
        assertEquals(BarnardRegistryAgreement.Agrees, BarnardB005EnvelopeV2.registryAgreement(verified, agreeing()))

        val wrongEventId = agreeing().eventId.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertEquals(BarnardRegistryAgreement.Mismatched(setOf(BarnardRegistryMismatchField.EVENT_ID)), BarnardB005EnvelopeV2.registryAgreement(verified, agreeing().copy(eventId = wrongEventId)), "eventId mismatch")

        assertEquals(BarnardRegistryAgreement.Mismatched(setOf(BarnardRegistryMismatchField.JOIN_MODE)), BarnardB005EnvelopeV2.registryAgreement(verified, agreeing().copy(joinMode = if (verified.joinMode == 0) 1 else 0)), "joinMode mismatch")

        assertEquals(BarnardRegistryAgreement.Mismatched(setOf(BarnardRegistryMismatchField.VALIDITY_WINDOW)), BarnardB005EnvelopeV2.registryAgreement(verified, agreeing().copy(validFromUnixSeconds = verified.validThroughEnin * verified.eninSeconds)), "window mismatch")

        val wrongKeySetDigest = verified.keySetDigest.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertEquals(BarnardRegistryAgreement.Mismatched(setOf(BarnardRegistryMismatchField.KEY_SET_DIGEST)), BarnardB005EnvelopeV2.registryAgreement(verified, agreeing().copy(keySetDigest = wrongKeySetDigest)), "signer-authority (keySetDigest) mismatch")
    }

    @Test fun registryAgreementRejectsMisalignedValidityWindowExample() {
        // eninSeconds=300, envelope declares the inclusive ENIN window [10, 11] (validFromEnin=10,
        // validThroughEnin=11 -- see registryAgreement's doc comment on the inclusive convention).
        // synthesizeWindow requires validThroughEnin > validFromEnin (see its doc comment), so this
        // is the narrowest window it can build; a single-ENIN example is covered separately below.
        val misaligned = synthesizeWindow(eninSeconds = 300, validFromEnin = 10, validThroughEnin = 11)
        val registryDefinition = BarnardEventDefinitionV1(
            misaligned.eventId, misaligned.keySetDigest, misaligned.joinMode, misaligned.eventCodeHash,
            validFromUnixSeconds = 3001, validUntilUnixSeconds = 3299,
        )
        assertEquals(BarnardRegistryAgreement.Mismatched(setOf(BarnardRegistryMismatchField.VALIDITY_WINDOW)), BarnardB005EnvelopeV2.registryAgreement(misaligned, registryDefinition), "misaligned window must not agree")

        // Aligned: registry inclusive seconds [3000, 3599] covers exactly ENIN 10 ([3000, 3299])
        // and ENIN 11 ([3300, 3599]), i.e. the inclusive ENIN range [10, 11] -- accepted.
        // expectedFrom = ceilDiv(3000, 300) = 10. expectedThrough = floorDiv(3599 + 1, 300) - 1 =
        // floorDiv(3600, 300) - 1 = 12 - 1 = 11.
        val aligned = BarnardEventDefinitionV1(
            misaligned.eventId, misaligned.keySetDigest, misaligned.joinMode, misaligned.eventCodeHash,
            validFromUnixSeconds = 3000, validUntilUnixSeconds = 3599,
        )
        assertEquals(BarnardRegistryAgreement.Agrees, BarnardB005EnvelopeV2.registryAgreement(misaligned, aligned), "aligned window must agree")

        // Reviewer's exact single-ENIN counter-example: registry inclusive seconds [3000, 3299] is
        // exactly ENIN 10 alone, so expectedThrough = floorDiv(3299 + 1, 300) - 1 = 11 - 1 = 10, not
        // 11. An envelope declaring validThroughEnin=11 (this same `misaligned` envelope) must be
        // rejected against it.
        val singleEnin = aligned.copy(validUntilUnixSeconds = 3299)
        assertEquals(BarnardRegistryAgreement.Mismatched(setOf(BarnardRegistryMismatchField.VALIDITY_WINDOW)), BarnardB005EnvelopeV2.registryAgreement(misaligned, singleEnin), "validThroughEnin=11 must not agree with [3000, 3299]")

        // Widening the registry window at the START is exactly the refresh case spec 134's
        // validity-window containment erratum (2026-09-10) admits: "definitionStart <=
        // validFromEnin". Registry seconds [2700, 3599] is ENIN [9, 11]; the envelope's [10, 11]
        // sits inside it, so it agrees. This assertion states the erratum, not a relaxation of the
        // old one -- under exact agreement a definition that merely started earlier was rejected,
        // which is what made every refresh envelope unservable past the 12-ENIN cap.
        val startWidened = aligned.copy(validFromUnixSeconds = 2700)
        assertEquals(BarnardRegistryAgreement.Agrees, BarnardB005EnvelopeV2.registryAgreement(misaligned, startWidened), "a definition starting before validFromEnin contains the envelope window")

        // Narrowing at the END is still rejected: containment requires validThroughEnin <= definitionEnd.
        val endOffByOne = aligned.copy(validUntilUnixSeconds = 3299)
        assertEquals(BarnardRegistryAgreement.Mismatched(setOf(BarnardRegistryMismatchField.VALIDITY_WINDOW)), BarnardB005EnvelopeV2.registryAgreement(misaligned, endOffByOne), "end off-by-one must not agree")
    }

    // --- Validity-window containment (spec 134 erratum 2026-09-10; barnard#200) ---

    /**
     * The refresh case the erratum exists for. One definition covers ENIN [10, 40] -- 31 ENINs,
     * well past the 12-ENIN relay lifetime cap -- and an envelope re-issued for the slice [22, 33]
     * sits inside it. Under the old exact-agreement rule this envelope was rejected as a
     * `VALIDITY_WINDOW` mismatch, which is precisely why nothing was servable after the first 12
     * ENINs of any longer event.
     *
     * Registry seconds are the inclusive ENIN window scaled by `eninSeconds`: ENIN [10, 40] is
     * seconds [10 * 300, (40 + 1) * 300 - 1] = [3000, 12299].
     */
    @Test fun registryAgreementAcceptsRefreshedEnvelopeInsideDefinitionWindow() {
        val refreshed = synthesizeWindow(eninSeconds = 300, validFromEnin = 22, validThroughEnin = 33)
        val definition = BarnardEventDefinitionV1(
            refreshed.eventId, refreshed.keySetDigest, refreshed.joinMode, refreshed.eventCodeHash,
            validFromUnixSeconds = 3000, validUntilUnixSeconds = 12299,
        )
        assertEquals(BarnardRegistryAgreement.Agrees, BarnardB005EnvelopeV2.registryAgreement(refreshed, definition), "a later validFromEnin inside the definition window must agree")
    }

    /**
     * The two containment failures, each isolating one side of `definitionStart <= validFromEnin`
     * and `validThroughEnin <= definitionEnd`.
     */
    @Test fun registryAgreementRejectsEnvelopeOutsideDefinitionWindow() {
        val refreshed = synthesizeWindow(eninSeconds = 300, validFromEnin = 22, validThroughEnin = 33)
        fun definition(validFrom: Long, validUntil: Long) = BarnardEventDefinitionV1(
            refreshed.eventId, refreshed.keySetDigest, refreshed.joinMode, refreshed.eventCodeHash,
            validFromUnixSeconds = validFrom, validUntilUnixSeconds = validUntil,
        )

        // validFromEnin < definitionStart: definition ENIN [25, 40] is seconds [7500, 12299]; the
        // envelope starts at 22, three ENINs before the definition does.
        assertEquals(BarnardRegistryAgreement.Mismatched(setOf(BarnardRegistryMismatchField.VALIDITY_WINDOW)), BarnardB005EnvelopeV2.registryAgreement(refreshed, definition(7500, 12299)), "validFromEnin before definitionStart must not agree")

        // validThroughEnin > definitionEnd: definition ENIN [10, 30] is seconds [3000, 9299]; the
        // envelope runs through 33, three ENINs past the definition's end.
        assertEquals(BarnardRegistryAgreement.Mismatched(setOf(BarnardRegistryMismatchField.VALIDITY_WINDOW)), BarnardB005EnvelopeV2.registryAgreement(refreshed, definition(3000, 9299)), "validThroughEnin past definitionEnd must not agree")
    }

    /**
     * The 12-ENIN relay lifetime cap is unchanged by the erratum, and it is enforced in
     * [BarnardB005EnvelopeV2.verify], not in `registryAgreement` -- so containment does not let a
     * long-lived envelope through some other door. [synthesizeWindowContainer] sets
     * `relayExpiresAtEnin = validThroughEnin`, so a window of [0, 13] is a lifetime of 13 and must
     * be refused at the wire.
     */
    @Test fun verifyRejectsRelayLifetimeOverTwelveEnins() {
        val recoverer = AlwaysAcceptingRecoverer(ByteArray(33) { 1 })
        val atCap = synthesizeWindowContainer(eninSeconds = 300, validFromEnin = 0, validThroughEnin = 12)
        assertNotNull(BarnardB005EnvelopeV2.verify(atCap, 0L, recoverer), "a lifetime of exactly 12 is still accepted")
        val overCap = synthesizeWindowContainer(eninSeconds = 300, validFromEnin = 0, validThroughEnin = 13)
        assertNull(BarnardB005EnvelopeV2.verify(overCap, 0L, recoverer), "a lifetime of 13 must still be rejected")
    }

    /**
     * Containment makes an inverted ENVELOPE window reachable in a way exact agreement did not.
     * Under equality, a registry window that does not fall on ENIN boundaries converts to an empty
     * range and could never equal anything, whatever the envelope carried. Under containment,
     * `registryStart <= validFromEnin && validThroughEnin <= registryEnd` is satisfiable by an
     * empty range exactly when `validThroughEnin < validFromEnin` -- so the emptiness argument now
     * depends on the envelope's own window being ordered. [BarnardB005EnvelopeV2.verify] guarantees
     * that ordering, but `registryAgreement` is a separate function, so it re-checks rather than
     * inherits, on the same footing as its `eninSeconds <= 0` branch. Built through the internal
     * factory because `verify` will not produce an inverted window.
     */
    @Test fun registryAgreementRejectsInvertedEnvelopeWindow() {
        val envelope = synthesizeWindow(eninSeconds = 300, validFromEnin = 22, validThroughEnin = 33)
        // validFromEnin=22, validThroughEnin=10; relayExpiresAtEnin is not read by
        // registryAgreement and carries no meaning for this case. Both bounds below are chosen so that each side of
        // the containment test passes on its own and only the ordering check refuses them, which is
        // what makes this a witness for the guard rather than for the arithmetic.
        val inverted = BarnardB005VerifiedEnvelope.radioSelfVerified(
            0, envelope.eventId, envelope.keySetDigest, envelope.joinMode, envelope.eventCodeHash,
            envelope.eventDisplayName, 22L, 10L, 22L, 300, envelope.signedEnvelope,
        )
        fun definition(validFrom: Long, validUntil: Long) = BarnardEventDefinitionV1(
            envelope.eventId, envelope.keySetDigest, envelope.joinMode, envelope.eventCodeHash,
            validFromUnixSeconds = validFrom, validUntilUnixSeconds = validUntil,
        )

        // A well-formed definition, ENIN [10, 40] as seconds [3000, 12299]: 10 <= 22 and 10 <= 40
        // both hold, so without the ordering check this inverted envelope would agree.
        assertEquals(BarnardRegistryAgreement.Mismatched(setOf(BarnardRegistryMismatchField.VALIDITY_WINDOW)), BarnardB005EnvelopeV2.registryAgreement(inverted, definition(3000, 12299)), "an inverted envelope window must not agree with a window that spans it")

        // And the empty range an off-boundary registry window converts to: seconds [3001, 3299] is
        // ENIN start ceil(3001/300) = 11, end floorDiv(3300, 300) - 1 = 10, i.e. the empty [11, 10].
        // 11 <= 22 and 10 <= 10 both hold, so this is the exact shape that would let an EMPTY
        // registry range agree with something -- the claim the rationale comment makes -- if the
        // envelope's own window were not required to be ordered.
        assertEquals(BarnardRegistryAgreement.Mismatched(setOf(BarnardRegistryMismatchField.VALIDITY_WINDOW)), BarnardB005EnvelopeV2.registryAgreement(inverted, definition(3001, 3299)), "an empty registry range must still agree with nothing")
    }

    @Test fun registryAgreementFailsClosedOnInvalidRegistryWindow() {
        val envelope = synthesizeWindow(eninSeconds = 300, validFromEnin = 0, validThroughEnin = 1)
        fun definition(validFrom: Long, validUntil: Long) = BarnardEventDefinitionV1(
            envelope.eventId, envelope.keySetDigest, envelope.joinMode, envelope.eventCodeHash,
            validFromUnixSeconds = validFrom, validUntilUnixSeconds = validUntil,
        )

        // A negative validFromUnixSeconds must not agree, even with an envelope claiming ENIN [0, 1] inclusive
        // as unix seconds would suggest.
        assertEquals(BarnardRegistryAgreement.Mismatched(setOf(BarnardRegistryMismatchField.VALIDITY_WINDOW)), BarnardB005EnvelopeV2.registryAgreement(envelope, definition(validFrom = -1, validUntil = 299)), "negative validFromUnixSeconds must not agree")

        // Long.MIN_VALUE must not crash the negation in the ceil-division of the start bound.
        assertEquals(BarnardRegistryAgreement.Mismatched(setOf(BarnardRegistryMismatchField.VALIDITY_WINDOW)), BarnardB005EnvelopeV2.registryAgreement(envelope, definition(validFrom = Long.MIN_VALUE, validUntil = 299)), "Long.MIN_VALUE validFrom must not crash and must not agree")

        // validFrom > validUntil is an invalid definition.
        assertEquals(BarnardRegistryAgreement.Mismatched(setOf(BarnardRegistryMismatchField.VALIDITY_WINDOW)), BarnardB005EnvelopeV2.registryAgreement(envelope, definition(validFrom = 300, validUntil = 0)), "validFrom > validUntil must not agree")

        // eninSeconds=0 is an invalid definition (division by zero). verify() itself already
        // rejects a wire envelope with eninSeconds=0, so build the verified envelope directly via
        // the internal factory to exercise registryAgreement's own defense in depth.
        val zeroEninEnvelope = BarnardB005VerifiedEnvelope.radioSelfVerified(
            0, envelope.eventId, envelope.keySetDigest, envelope.joinMode, envelope.eventCodeHash,
            envelope.eventDisplayName, 0L, 0L, 0L, 0, envelope.signedEnvelope,
        )
        assertEquals(BarnardRegistryAgreement.Mismatched(setOf(BarnardRegistryMismatchField.VALIDITY_WINDOW)), BarnardB005EnvelopeV2.registryAgreement(zeroEninEnvelope, definition(validFrom = 0, validUntil = 299)), "eninSeconds=0 must not agree")
    }

    @Test fun registryAgreementEndConversionIsOverflowSafeAtLongMaxValue() {
        // eninPerSecond=1 makes floorMod(Long.MAX_VALUE, 1)==0==eninPerSecond-1, which is exactly
        // the branch that would try to compute Long.MAX_VALUE + 1 (overflowing to Long.MIN_VALUE)
        // without the floorMod-identity guard in registryAgreement.
        //
        // Under spec 134's containment erratum (2026-09-10) the expected verdict here is Agrees,
        // and that is the STRONGER assertion, not a weakened one. Registry seconds
        // [10, Long.MAX_VALUE] at eninSeconds=1 is ENIN [10, Long.MAX_VALUE], which genuinely
        // contains the envelope's [10, 11], so containment holds -- but only if the end conversion
        // did not wrap. Had it overflowed to a negative registryEndEnin, validThroughEnin <=
        // registryEndEnin would fail and this would report a mismatch. So Agrees is precisely the
        // statement that no wrap occurred; under the old exact rule the same probe could only say
        // "did not wrap INTO an equality".
        val envelope = synthesizeWindow(eninSeconds = 1, validFromEnin = 10, validThroughEnin = 11)
        val definition = BarnardEventDefinitionV1(
            envelope.eventId, envelope.keySetDigest, envelope.joinMode, envelope.eventCodeHash,
            validFromUnixSeconds = 10, validUntilUnixSeconds = Long.MAX_VALUE,
        )
        assertEquals(BarnardRegistryAgreement.Agrees, BarnardB005EnvelopeV2.registryAgreement(envelope, definition), "an unwrapped Long.MAX_VALUE end contains ENIN [10, 11]")
    }

    @Test fun verifiedEnvelopeHasNoPublicConstructorOrCopy() {
        // P1: a `data class` would generate a public `copy()` (and, from Java, a directly
        // callable constructor) letting a caller fabricate `receiverState = REGISTRY_VERIFIED`.
        // Assert via reflection that neither escape hatch exists on the compiled class.
        //
        // Kotlin's codegen for "private constructor + companion factory" unconditionally emits a
        // second, JVM-`public` constructor overload carrying a trailing
        // `kotlin.jvm.internal.DefaultConstructorMarker` parameter (a synthetic bridge letting the
        // companion, a distinct JVM class, reach the private constructor -- confirmed empirically
        // via javap; no combination of Kotlin visibility keywords avoids it once a companion
        // touches the private constructor). That bridge is `ACC_SYNTHETIC`: real (non-synthetic)
        // constructors must all be private.
        val constructors = BarnardB005VerifiedEnvelope::class.java.declaredConstructors
        val realConstructors = constructors.filter { !it.isSynthetic }
        assertEquals(1, realConstructors.size, "expected exactly one non-synthetic constructor")
        assertTrue(!java.lang.reflect.Modifier.isPublic(realConstructors[0].modifiers), "the real constructor must not be public")
        for (ctor in constructors) {
            if (java.lang.reflect.Modifier.isPublic(ctor.modifiers)) {
                assertTrue(ctor.isSynthetic, "a public constructor must be the synthetic companion-access bridge, not a real one")
            }
        }
        val hasCopy = BarnardB005VerifiedEnvelope::class.java.methods.any { it.name == "copy" }
        assertTrue(!hasCopy, "must not expose a public copy() method")
    }

    /**
     * Builds a structurally-valid `RADIO_SELF_VERIFIED` envelope with a caller-chosen
     * `eninSeconds`/window, using an `AlwaysAcceptingRecoverer` to stand in for real ECDSA math
     * (same technique as [buildSyntheticContainer] below), so `registryAgreement`'s window
     * logic can be exercised against known, exact ENIN values. Requires `validThroughEnin >
     * validFromEnin`: a verified envelope's `expires` field must satisfy `validFromEnin <=
     * currentEnin < expires <= validThroughEnin`, which is unsatisfiable when the two are equal.
     */
    private fun synthesizeWindow(eninSeconds: Int, validFromEnin: Int, validThroughEnin: Int): BarnardB005VerifiedEnvelope {
        val container = synthesizeWindowContainer(eninSeconds, validFromEnin, validThroughEnin)
        val recoverer = AlwaysAcceptingRecoverer(ByteArray(33) { 1 })
        return BarnardB005EnvelopeV2.verify(container, validFromEnin.toLong(), recoverer) ?: error("expected synthetic window container to verify")
    }

    /**
     * The container half of [synthesizeWindow], without the verification step, so a test can
     * assert that [BarnardB005EnvelopeV2.verify] REJECTS a window (the 12-ENIN relay lifetime cap)
     * rather than only exercising windows it accepts.
     */
    private fun synthesizeWindowContainer(eninSeconds: Int, validFromEnin: Int, validThroughEnin: Int): ByteArray {
        var envelope = byteArrayOf(1) + ByteArray(20) + ByteArray(20) + ByteArray(32) + byteArrayOf(1)
        envelope += ByteArray(33) { 1 }
        envelope += byteArrayOf(1) // joinMode = gated
        envelope += byteArrayOf((eninSeconds shr 8).toByte(), eninSeconds.toByte())
        envelope += byteArrayOf((validFromEnin shr 24).toByte(), (validFromEnin shr 16).toByte(), (validFromEnin shr 8).toByte(), validFromEnin.toByte())
        envelope += byteArrayOf((validThroughEnin shr 24).toByte(), (validThroughEnin shr 16).toByte(), (validThroughEnin shr 8).toByte(), validThroughEnin.toByte())
        envelope += byteArrayOf((validThroughEnin shr 24).toByte(), (validThroughEnin shr 16).toByte(), (validThroughEnin shr 8).toByte(), validThroughEnin.toByte()) // expires = validThroughEnin
        envelope += byteArrayOf(2) // fixed marker byte
        envelope += ByteArray(8) // eventCodeHash (unchecked under gated mode)
        envelope += byteArrayOf(1) // nameLength
        envelope += "X".encodeToByteArray()
        envelope += byteArrayOf(0) // certLength = 0
        envelope += ByteArray(31) + byteArrayOf(1) + ByteArray(31) + byteArrayOf(1) + byteArrayOf(0) // r=1, s=1, v=0
        return BarnardB005EnvelopeV2.encodeContainer(0, envelope) ?: error("container build failed")
    }

    // --- Recover-once and low-S (P1) ---

    private class CountingNonMemberRecoverer : BarnardB005PublicKeyRecovering {
        var count = 0
        override fun recover(recoveryId: Int, r: ByteArray, s: ByteArray, digest: ByteArray): ByteArray? {
            count++
            return ByteArray(33) { 0xff.toByte() } // never a member of the synthetic key set below.
        }
        override fun isValidCompressedKey(key: ByteArray) = true
    }

    private class AlwaysAcceptingRecoverer(private val key: ByteArray) : BarnardB005PublicKeyRecovering {
        override fun recover(recoveryId: Int, r: ByteArray, s: ByteArray, digest: ByteArray) = key
        override fun isValidCompressedKey(key: ByteArray) = true
    }

    // --- Delegation certificate ENIN upper bound (parallax parity: 2^53-1, not 2^53) ---

    private fun cborUintMajor(major: Int, value: Long): ByteArray {
        val v = value.toULong()
        return when {
            v < 24UL -> byteArrayOf(((major shl 5) or v.toInt()).toByte())
            v < 256UL -> byteArrayOf(((major shl 5) or 24).toByte(), v.toByte())
            v < 65_536UL -> byteArrayOf(((major shl 5) or 25).toByte(), (v shr 8).toByte(), v.toByte())
            v < 4_294_967_296UL -> byteArrayOf(((major shl 5) or 26).toByte()) + ByteArray(4) { (v shr (8 * (3 - it))).toByte() }
            else -> byteArrayOf(((major shl 5) or 27).toByte()) + ByteArray(8) { (v shr (8 * (7 - it))).toByte() }
        }
    }
    private fun cborUint(value: Long) = cborUintMajor(0, value)
    private fun cborBytesField(b: ByteArray) = cborUintMajor(2, b.size.toLong()) + b
    private fun cborTextField(s: String): ByteArray { val b = s.encodeToByteArray(); return cborUintMajor(3, b.size.toLong()) + b }
    private fun cborNegative47() = byteArrayOf(0x38, 46) // major 1, ai=24, value 46 -> -(46+1) = -47

    /**
     * Hand-encodes a delegation certificate with a caller-chosen `eninEnd`, using an
     * [AlwaysAcceptingRecoverer] for both the cert's COSE signature and the envelope signature so
     * the boundary on `eninEnd` (parallax parity: at most `2^53-1`) can be exercised without real
     * ECDSA math. `kid` is computed the same way production code derives it so the single
     * authority key is found as the unique candidate signer; `eventId` is the real
     * `computeEventId` output for the envelope's own registrar/anchor/nonce/key-set, so the
     * cert's own `eventId` tie-in check passes independent of the field under test.
     */
    private fun buildCertContainer(eninEnd: Long): ByteArray {
        val authorityKey = ByteArray(33) { 1 }
        val delegateKey = authorityKey
        val registrar = ByteArray(20) { 4 }
        val anchor = ByteArray(20) { 5 }
        val nonce = ByteArray(32) { 6 }
        val ksDigest = BarnardB005EnvelopeV2.keySetDigest(listOf(authorityKey)) ?: error("keySetDigest failed")
        val eventId = BarnardB005EnvelopeV2.computeEventId(registrar, anchor, nonce, ksDigest) ?: error("computeEventId failed")
        val kid = MessageDigest.getInstance("SHA-256").digest("levarac:cose-kid:v1 ".encodeToByteArray() + authorityKey).copyOf(8)

        val protectedHeader = byteArrayOf(0xa3.toByte()) + byteArrayOf(0x01) + cborNegative47() +
            byteArrayOf(0x03) + cborTextField("application/vnd.levarac.delegation-cert+cbor") +
            byteArrayOf(0x04) + cborBytesField(kid)
        val payload = byteArrayOf(0xa6.toByte()) +
            byteArrayOf(0x01) + cborUint(1) +
            byteArrayOf(0x02) + cborBytesField(eventId) +
            byteArrayOf(0x03) + cborBytesField(delegateKey) +
            byteArrayOf(0x04) + cborUint(1) +
            byteArrayOf(0x05) + cborUint(1000) +
            byteArrayOf(0x06) + cborUint(eninEnd)
        // r=1, s=1: isLowSInRange rejects an all-zero r/s regardless of the injected recoverer.
        val certSignature = ByteArray(31) + byteArrayOf(1) + ByteArray(31) + byteArrayOf(1)
        val cert = byteArrayOf(0xd2.toByte()) + byteArrayOf(0x84.toByte()) +
            cborBytesField(protectedHeader) + byteArrayOf(0xa0.toByte()) +
            cborBytesField(payload) + cborBytesField(certSignature)
        check(cert.size <= 255) { "synthetic cert too large: ${cert.size}" }

        var envelope = byteArrayOf(1) + registrar + anchor + nonce + byteArrayOf(1)
        envelope += authorityKey
        envelope += byteArrayOf(1) // joinMode = gated
        envelope += byteArrayOf(0x01, 0x2c) // eninSeconds = 300
        envelope += byteArrayOf(0x00, 0x5b.toByte(), 0x8d.toByte(), 0x7b.toByte()) // validFrom = 5_999_995
        envelope += byteArrayOf(0x00, 0x5b.toByte(), 0x8d.toByte(), 0x85.toByte()) // validThrough = 6_000_005
        envelope += byteArrayOf(0x00, 0x5b.toByte(), 0x8d.toByte(), 0x81.toByte()) // relayExpiresAtEnin = 6_000_001 (lifetime 6 <= 12)
        envelope += byteArrayOf(2) // fixed marker byte
        envelope += ByteArray(8) // eventCodeHash (unchecked under gated mode)
        envelope += byteArrayOf(1) // nameLength
        envelope += "X".encodeToByteArray()
        envelope += byteArrayOf(cert.size.toByte())
        envelope += cert
        envelope += ByteArray(31) + byteArrayOf(1) + ByteArray(31) + byteArrayOf(1) + byteArrayOf(0) // envelope signature r=1, s=1, v=0
        return BarnardB005EnvelopeV2.encodeContainer(0, envelope) ?: error("container build failed")
    }

    @Test fun delegationCertEninEndAcceptsMaxAndRejectsOneAboveMax() {
        // Parallax's verifier allows at most 2^53-1; both must match exactly.
        val recoverer = AlwaysAcceptingRecoverer(ByteArray(33) { 1 })
        val atMax = buildCertContainer(9_007_199_254_740_991L)
        assertNotNull(BarnardB005EnvelopeV2.verify(atMax, 6_000_000, recoverer), "2^53-1 must be accepted")
        val overMax = buildCertContainer(9_007_199_254_740_992L)
        assertNull(BarnardB005EnvelopeV2.verify(overMax, 6_000_000, recoverer), "2^53 must be rejected")
    }

    // Builds a structurally-valid authority-direct-mode container with `keyCount` synthetic
    // authority keys, no delegation certificate, and a caller-supplied raw signature, so tests
    // can drive signatureMatches/recoverMember with arbitrary r/s/v without real ECDSA math.
    private fun buildSyntheticContainer(keyCount: Int, signature: ByteArray): ByteArray {
        var envelope = byteArrayOf(1) + ByteArray(20) + ByteArray(20) + ByteArray(32) + byteArrayOf(keyCount.toByte())
        for (i in 0 until keyCount) envelope += ByteArray(33) { (i + 1).toByte() }
        envelope += byteArrayOf(1) // joinMode = gated
        envelope += byteArrayOf(0x01, 0x2c) // eninSeconds = 300
        envelope += byteArrayOf(0, 0, 0x03, 0xe8.toByte()) // validFrom = 1000
        envelope += byteArrayOf(0, 0, 0x03, 0xe9.toByte()) // validThrough = 1001
        envelope += byteArrayOf(0, 0, 0x03, 0xe9.toByte()) // relayExpiresAtEnin = 1001
        envelope += byteArrayOf(2) // fixed marker byte
        envelope += ByteArray(8) // eventCodeHash (unchecked under gated mode)
        envelope += byteArrayOf(1) // nameLength
        envelope += "X".encodeToByteArray()
        envelope += byteArrayOf(0) // certLength = 0
        envelope += signature
        return BarnardB005EnvelopeV2.encodeContainer(0, envelope) ?: error("container build failed")
    }

    @Test fun authorityDirectVerificationRecoversExactlyOnce() {
        val recoverer = CountingNonMemberRecoverer()
        val signature = ByteArray(31) + byteArrayOf(1) + ByteArray(31) + byteArrayOf(1) + byteArrayOf(0) // r=1, s=1, v=0
        val container = buildSyntheticContainer(8, signature)
        assertNull(BarnardB005EnvelopeV2.verify(container, 1000, recoverer), "recovered key is never a set member")
        assertEquals(1, recoverer.count, "authority-direct mode must recover exactly once regardless of key-set size")
    }

    @Test fun highSSignatureRejectedEvenWithAnAcceptingRecoverer() {
        // s = N - 1 (maximal, definitely > N/2): a fake recoverer that never checks S itself
        // would happily "match" this, so the rejection MUST come from signatureMatches's own
        // low-S gate.
        val highS = byteArrayOf(
            0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(),
            0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xfe.toByte(),
            0xba.toByte(), 0xae.toByte(), 0xdc.toByte(), 0xe6.toByte(), 0xaf.toByte(), 0x48, 0xa0.toByte(), 0x3b,
            0xbf.toByte(), 0xd2.toByte(), 0x5e, 0x8c.toByte(), 0xd0.toByte(), 0x36, 0x41, 0x40,
        )
        val r = ByteArray(31) + byteArrayOf(1)
        val acceptingKey = ByteArray(33) { 7 }
        val signature = r + highS + byteArrayOf(0)
        val container = buildSyntheticContainer(1, signature)
        assertNull(BarnardB005EnvelopeV2.verify(container, 1000, AlwaysAcceptingRecoverer(acceptingKey)))
    }

    @Test fun highSCertificateSignatureRejectedEvenWithAnAcceptingRecoverer() {
        // Same claim as above but for the certificate's own COSE signature path
        // (recoveryByte = false, the two-attempt branch), a separate code path from the
        // envelope signature.
        val envelopeHex = v("v2_envelope")
        val oldCert = v("v2_delegation_cert")
        val idx = envelopeHex.indexOf(oldCert)
        check(idx >= 0)
        val envelope = hex(envelopeHex)
        val certByteOffset = idx / 2
        val certEnd = certByteOffset + oldCert.length / 2
        val highS = byteArrayOf(
            0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(),
            0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xfe.toByte(),
            0xba.toByte(), 0xae.toByte(), 0xdc.toByte(), 0xe6.toByte(), 0xaf.toByte(), 0x48, 0xa0.toByte(), 0x3b,
            0xbf.toByte(), 0xd2.toByte(), 0x5e, 0x8c.toByte(), 0xd0.toByte(), 0x36, 0x41, 0x40,
        )
        // Certificate signature is the last 64 bytes of the cert byte range (COSE_Sign1 bstr .size 64).
        val sigStart = certEnd - 64
        val r = ByteArray(31) + byteArrayOf(1)
        r.copyInto(envelope, sigStart)
        highS.copyInto(envelope, sigStart + 32)
        val container = BarnardB005EnvelopeV2.encodeContainer(1, envelope) ?: error("container build failed")
        assertNull(BarnardB005EnvelopeV2.verify(container, 6_000_000, AlwaysAcceptingRecoverer(ByteArray(33) { 7 })))
    }

    // --- CBOR builder overflow (P2) ---

    @Test fun buildSigStructureHandlesFieldsAtAndBeyond256Bytes() {
        val protected300 = ByteArray(300) { 0x11 }
        val payload10 = ByteArray(10) { 0x22 }
        val structure = BarnardB005EnvelopeV2.buildSigStructure(protected300, payload10) ?: error("300-byte field must not truncate or fail")
        val headerEnd = 2 + 10
        assertContentEquals(byteArrayOf(0x59, 0x01, 0x2c), structure.copyOfRange(headerEnd, headerEnd + 3), "canonical 2-byte length for 300")
        assertEquals(2 + 10 + 3 + 300 + 1 + 1 + 10, structure.size)
        assertContentEquals(protected300, structure.copyOfRange(headerEnd + 3, headerEnd + 3 + 300))
    }

    @Test fun buildSigStructureRejectsOversizedField() {
        val tooLarge = ByteArray(65536)
        assertNull(BarnardB005EnvelopeV2.buildSigStructure(tooLarge, ByteArray(0)))
    }

    private fun hex(s: String) = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    private fun findRepoRoot(): File { var f = File(System.getProperty("user.dir")); repeat(20) { if (File(f, "test-vectors/b005-envelope-v2.txt").isFile) return f; f = f.parentFile }; error("repo root") }
    private fun parseVectors(file: File) = file.readLines().map { it.trim() }.filter { it.isNotEmpty() && !it.startsWith("#") }.associate { val i = it.indexOf('='); it.substring(0, i) to it.substring(i + 1) }
}
