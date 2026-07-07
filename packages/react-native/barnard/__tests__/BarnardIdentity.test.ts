export {};

jest.mock('react-native', () => {
  const BarnardIdentity = {
    signingPublicKey: jest.fn().mockImplementation((eventCode: string) => {
      // Deterministic per-eventCode stub good enough to test module wiring
      // (real per-event uniqueness/domain-separation is proven in
      // packages/dart/barnard/test/signing_test.dart and the Kotlin/Swift
      // native unit tests, which exercise the real secp256k1 derivation).
      const hash = Array.from(eventCode).reduce((acc, c) => (acc * 31 + c.charCodeAt(0)) >>> 0, 7);
      return Promise.resolve('02' + hash.toString(16).padStart(64, '0'));
    }),
    sign: jest.fn().mockResolvedValue({
      r: 'aa'.repeat(32),
      s: 'bb'.repeat(32),
      v: 1,
    }),
    proveRpidOwnership: jest.fn().mockResolvedValue({
      rpi: 'cc'.repeat(16),
      signingPublicKey: '02' + 'dd'.repeat(32),
      r: 'ee'.repeat(32),
      s: 'ff'.repeat(32),
      v: 0,
    }),
    proveKeyBinding: jest.fn().mockResolvedValue({
      r: '11'.repeat(32),
      s: '22'.repeat(32),
      v: 1,
    }),
  };

  return {
    NativeModules: { BarnardIdentity },
  };
});

const setup = () => {
  jest.resetModules();
  const reactNative = require('react-native') as {
    NativeModules: { BarnardIdentity: Record<string, jest.Mock> };
  };
  const { BarnardIdentity } = require('../src/BarnardIdentity') as {
    BarnardIdentity: new () => {
      signingPublicKey: (eventCode: string) => Promise<string>;
      sign: (eventCode: string, bytesHex: string) => Promise<{ r: string; s: string; v: number }>;
      proveRpidOwnership: (
        eventCode: string,
        enin: number,
        eventIdHashHex: string,
        challengeHex?: string
      ) => Promise<{
        rpi: string;
        enin: number;
        eventIdHash: string;
        signingPublicKey: string;
        sig: { r: string; s: string; v: number };
      }>;
      proveKeyBinding: (eventCode: string, displayIdHex: string) => Promise<{ r: string; s: string; v: number }>;
    };
  };

  return {
    BarnardIdentity,
    nativeModule: reactNative.NativeModules.BarnardIdentity,
  };
};

describe('BarnardIdentity (sibling module to BarnardManager)', () => {
  it('delegates signingPublicKey to the native module, keyed by eventCode', async () => {
    const { BarnardIdentity, nativeModule } = setup();
    const identity = new BarnardIdentity();

    await identity.signingPublicKey('event-A');

    expect(nativeModule.signingPublicKey).toHaveBeenCalledWith('event-A');
    expect(nativeModule.signingPublicKey).toHaveBeenCalledTimes(1);
  });

  it('returns a different signing public key for a different eventCode', async () => {
    const { BarnardIdentity } = setup();
    const identity = new BarnardIdentity();

    const a = await identity.signingPublicKey('event-A');
    const b = await identity.signingPublicKey('event-B');

    expect(a).not.toBe(b);
  });

  it('returns the same signing public key for the same eventCode', async () => {
    const { BarnardIdentity } = setup();
    const identity = new BarnardIdentity();

    const first = await identity.signingPublicKey('event-A');
    const second = await identity.signingPublicKey('event-A');

    expect(first).toBe(second);
  });

  it('delegates sign to the native module and returns a (r, s, v) signature', async () => {
    const { BarnardIdentity, nativeModule } = setup();
    const identity = new BarnardIdentity();

    const sig = await identity.sign('event-A', 'deadbeef');

    expect(nativeModule.sign).toHaveBeenCalledWith('event-A', 'deadbeef');
    expect(sig.r).toMatch(/^[0-9a-f]{64}$/);
    expect(sig.s).toMatch(/^[0-9a-f]{64}$/);
    expect([0, 1]).toContain(sig.v);
  });

  it('exposes no private-key-shaped accessor (opposite of exportCurrentTek)', () => {
    const { BarnardIdentity } = setup();
    const identity = new BarnardIdentity();

    expect((identity as unknown as Record<string, unknown>).exportPrivateKey).toBeUndefined();
    expect((identity as unknown as Record<string, unknown>).privateKey).toBeUndefined();
  });
});

describe('BarnardIdentity.proveRpidOwnership (barnard#63)', () => {
  it('delegates to the native module and reassembles enin/eventIdHash into the proof', async () => {
    const { BarnardIdentity, nativeModule } = setup();
    const identity = new BarnardIdentity();
    const eventIdHash = 'ab'.repeat(32);

    const proof = await identity.proveRpidOwnership('event-A', 2948599, eventIdHash);

    expect(nativeModule.proveRpidOwnership).toHaveBeenCalledWith('event-A', 2948599, eventIdHash, null);
    expect(proof.enin).toBe(2948599);
    expect(proof.eventIdHash).toBe(eventIdHash);
    expect(proof.rpi).toMatch(/^[0-9a-f]{32}$/);
    expect(proof.signingPublicKey).toMatch(/^0[23][0-9a-f]{64}$/);
    expect(proof.sig.r).toMatch(/^[0-9a-f]{64}$/);
  });

  it('forwards an optional challenge to the native module', async () => {
    const { BarnardIdentity, nativeModule } = setup();
    const identity = new BarnardIdentity();

    await identity.proveRpidOwnership('event-A', 1, 'ab'.repeat(32), 'deadbeef');

    expect(nativeModule.proveRpidOwnership).toHaveBeenCalledWith('event-A', 1, 'ab'.repeat(32), 'deadbeef');
  });

  it('does not disclose TEK/RPIK: the proof shape carries only rpi, not a 16-byte TEK/RPIK field', async () => {
    const { BarnardIdentity } = setup();
    const identity = new BarnardIdentity();

    const proof = await identity.proveRpidOwnership('event-A', 1, 'ab'.repeat(32));

    expect(Object.keys(proof).sort()).toEqual(['enin', 'eventIdHash', 'rpi', 'signingPublicKey', 'sig'].sort());
  });
});

describe('BarnardIdentity.proveKeyBinding (barnard#63 acceptance criterion 3)', () => {
  it('delegates to the native module with eventCode and displayId', async () => {
    const { BarnardIdentity, nativeModule } = setup();
    const identity = new BarnardIdentity();

    const sig = await identity.proveKeyBinding('event-A', '374708ff');

    expect(nativeModule.proveKeyBinding).toHaveBeenCalledWith('event-A', '374708ff');
    expect(sig.r).toMatch(/^[0-9a-f]{64}$/);
  });
});
