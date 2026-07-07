import { BarnardIdentityModule } from './NativeBarnardIdentity';
import type { BarnardSignature, RpidOwnershipProof } from './types';

/**
 * Barnard's per-event device signing identity (barnard#65).
 *
 * This is a **sibling module to `BarnardManager`**, not part of it — the
 * sensing SDK is transport-only by charter
 * (`specs/001-barnard-core-sdk/spec.md`). `BarnardIdentity` owns the
 * device's signing capability instead: a per-event, `DeviceSecret`-rooted
 * secp256k1 keypair whose private key never leaves the SDK (the opposite
 * of `BarnardManager.exportCurrentTek`).
 *
 * The signing public key is **not** a cross-event-stable identifier: it
 * is stable only within one `eventCode` and differs across `eventCode`s,
 * so it cannot be used to correlate a participant's activity across
 * events (see barnard#65 for the threat this avoids).
 *
 * @example
 * ```typescript
 * const identity = new BarnardIdentity();
 * const pubKey = await identity.signingPublicKey('my-event');
 * const sig = await identity.sign('my-event', observationTupleHex);
 * ```
 */
export class BarnardIdentity {
  /**
   * The per-event signing public key, SEC1-compressed, as 66 lowercase
   * hex chars (33 bytes).
   *
   * Same value for every call with the same `eventCode`; a different
   * value for every other `eventCode`. Re-derivable offline at any time
   * from `DeviceSecret` — it never "expires".
   */
  async signingPublicKey(eventCode: string): Promise<string> {
    return BarnardIdentityModule.signingPublicKey(eventCode);
  }

  /**
   * Sign `bytesHex` (lowercase hex) with the per-event signing key for
   * `eventCode`. The private key never leaves the SDK; only the resulting
   * signature is returned. The bytes are hashed (SHA-256) natively before
   * ECDSA signing.
   */
  async sign(eventCode: string, bytesHex: string): Promise<BarnardSignature> {
    return BarnardIdentityModule.sign(eventCode, bytesHex);
  }

  /**
   * Prove ownership of the RPID generated for `enin` within `eventCode`,
   * bound to `eventIdHashHex` and (optionally) a verifier-supplied
   * `challengeHex` for replay resistance, without disclosing the
   * TEK/RPIK or any other ENIN's RPI (barnard#63).
   *
   * `eventIdHashHex` must be 64 hex chars (32 bytes); `challengeHex`, if
   * given, is arbitrary hex.
   */
  async proveRpidOwnership(
    eventCode: string,
    enin: number,
    eventIdHashHex: string,
    challengeHex?: string
  ): Promise<RpidOwnershipProof> {
    const native = await BarnardIdentityModule.proveRpidOwnership(
      eventCode,
      enin,
      eventIdHashHex,
      challengeHex ?? null
    );
    return {
      rpi: native.rpi,
      enin,
      eventIdHash: eventIdHashHex,
      signingPublicKey: native.signingPublicKey,
      sig: { r: native.r, s: native.s, v: native.v },
    };
  }

  /**
   * Bind `signingPublicKey` to `displayIdHex` for `eventCode`: a
   * self-signed statement a verifier can check to establish
   * "signingPublicKey ↔ device" at join time, before any
   * `proveRpidOwnership` call (barnard#63 acceptance criterion 3).
   *
   * `displayIdHex` must be 8 hex chars (4 bytes), matching `getMyDisplayId()`.
   */
  async proveKeyBinding(eventCode: string, displayIdHex: string): Promise<BarnardSignature> {
    return BarnardIdentityModule.proveKeyBinding(eventCode, displayIdHex);
  }
}
