import { NativeModules } from 'react-native';
import type { BarnardSignature } from './types';

/**
 * Raw native return shape for `proveRpidOwnership`: the native side does
 * not echo back the caller-supplied `enin`/`eventIdHash` (it only computes
 * `rpi`/`signingPublicKey`/the signature); `BarnardIdentity.proveRpidOwnership`
 * reassembles the full `RpidOwnershipProof` from the call arguments.
 */
export interface NativeRpidOwnershipProof {
  rpi: string;
  signingPublicKey: string;
  r: string;
  s: string;
  v: number;
}

const LINKING_ERROR =
  "The package 'barnard' doesn't seem to be linked. Make sure: \n\n" +
  '- You rebuilt the app after installing the package\n' +
  '- You are not using Expo Go\n' +
  '- If you are using Expo, install it in a custom dev client or bare workflow\n';

/**
 * Native module interface for the per-event device signing identity
 * (barnard#65). A separate native module from `Barnard` (the sensing
 * client) — its own bridge surface, own method channel/native module.
 */
interface BarnardIdentityNativeModule {
  /** SEC1-compressed signing public key (33 bytes) as 66 hex chars. */
  signingPublicKey(eventCode: string): Promise<string>;
  /** `bytesHex` is signed after being SHA-256 hashed natively. */
  sign(eventCode: string, bytesHex: string): Promise<BarnardSignature>;
  /** `eventIdHashHex` is 64 hex chars (32 bytes); `challengeHex` is optional. */
  proveRpidOwnership(
    eventCode: string,
    enin: number,
    eventIdHashHex: string,
    challengeHex?: string | null
  ): Promise<NativeRpidOwnershipProof>;
  /** `displayIdHex` is 8 hex chars (4 bytes), matching `getMyDisplayId()`. */
  proveKeyBinding(eventCode: string, displayIdHex: string): Promise<BarnardSignature>;
}

const BarnardIdentityModule = NativeModules.BarnardIdentity
  ? (NativeModules.BarnardIdentity as BarnardIdentityNativeModule)
  : (new Proxy(
      {},
      {
        get() {
          throw new Error(LINKING_ERROR);
        },
      }
    ) as BarnardIdentityNativeModule);

export { BarnardIdentityModule };
