import { BarnardIdentityModule } from './NativeBarnardIdentity';
import type { BarnardSignature } from './types';

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
}
