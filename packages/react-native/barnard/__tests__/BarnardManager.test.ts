jest.mock('react-native', () => {
  const listeners = new Map<string, Set<(event: unknown) => void>>();

  const Barnard = {
    getCapabilities: jest.fn().mockResolvedValue({ supportedTransports: ['ble'] }),
    getState: jest.fn().mockResolvedValue({ isScanning: false, isAdvertising: false }),
    getPermissionStatus: jest.fn().mockResolvedValue({
      platform: 'mock',
      permissions: { 'mock.bluetooth': 'granted' },
      requiredPermissions: ['mock.bluetooth'],
      missingPermissions: [],
      canScan: true,
      canAdvertise: true,
    }),
    requestPermissions: jest.fn().mockResolvedValue({
      platform: 'mock',
      permissions: { 'mock.bluetooth': 'granted' },
      requiredPermissions: ['mock.bluetooth'],
      missingPermissions: [],
      canScan: true,
      canAdvertise: true,
    }),
    getCurrentEventCode: jest.fn().mockResolvedValue(null),
    getMyDisplayId: jest.fn().mockResolvedValue('374708ff'),
    getCurrentRpi: jest.fn().mockResolvedValue('00'.repeat(16)),
    getCurrentEnin: jest.fn().mockResolvedValue(2948599),
    exportCurrentTek: jest.fn().mockResolvedValue('00'.repeat(16)),
    startScan: jest.fn().mockResolvedValue(undefined),
    stopScan: jest.fn().mockResolvedValue(undefined),
    startAdvertise: jest.fn().mockResolvedValue(undefined),
    stopAdvertise: jest.fn().mockResolvedValue(undefined),
    startAuto: jest.fn().mockResolvedValue({
      scanningStarted: true,
      advertisingStarted: true,
      issues: [],
    }),
    stopAuto: jest.fn().mockResolvedValue(undefined),
    joinEvent: jest.fn().mockResolvedValue(undefined),
    leaveEvent: jest.fn().mockResolvedValue(undefined),
    dispose: jest.fn().mockResolvedValue(undefined),
  };

  class NativeEventEmitter {
    constructor(_module: unknown) {}

    addListener(eventName: string, callback: (event: unknown) => void) {
      if (!listeners.has(eventName)) {
        listeners.set(eventName, new Set());
      }
      listeners.get(eventName)?.add(callback);

      return {
        remove: () => {
          listeners.get(eventName)?.delete(callback);
        },
      };
    }
  }

  return {
    NativeModules: { Barnard },
    NativeEventEmitter,
    __listeners: listeners,
  };
});

type ListenerMap = Map<string, Set<(event: unknown) => void>>;

const emit = (listeners: ListenerMap, eventName: string, payload: unknown) => {
  for (const callback of listeners.get(eventName) ?? []) {
    callback(payload);
  }
};

const setup = () => {
  jest.resetModules();
  const reactNative = require('react-native') as {
    NativeModules: { Barnard: Record<string, jest.Mock> };
    __listeners: ListenerMap;
  };
  const { BarnardManager } = require('../src/BarnardManager') as {
    BarnardManager: new () => {
      getCurrentEventCode: () => Promise<string | null>;
      getMyDisplayId: () => Promise<string>;
      getCurrentRpi: () => Promise<string>;
      getCurrentEnin: () => Promise<number>;
      exportCurrentTek: () => Promise<string>;
      getPermissionStatus: () => Promise<unknown>;
      requestPermissions: () => Promise<unknown>;
      joinEvent: (eventCode: string) => Promise<void>;
      onDetection: (callback: (event: unknown) => void) => () => void;
      onRssiUpdate: (callback: (event: unknown) => void) => () => void;
      onEvent: (callback: (event: unknown) => void) => () => void;
      dispose: () => Promise<void>;
    };
  };

  return {
    BarnardManager,
    nativeModule: reactNative.NativeModules.Barnard,
    listeners: reactNative.__listeners,
  };
};

describe('BarnardManager v2 API', () => {
  it('delegates getCurrentEventCode to native module', async () => {
    const { BarnardManager, nativeModule } = setup();
    nativeModule.getCurrentEventCode.mockResolvedValueOnce('ETHGLOBAL');

    const manager = new BarnardManager();
    await expect(manager.getCurrentEventCode()).resolves.toBe('ETHGLOBAL');
    expect(nativeModule.getCurrentEventCode).toHaveBeenCalledTimes(1);
  });

  it('returns 8-char lowercase hex from getMyDisplayId', async () => {
    const { BarnardManager } = setup();
    const manager = new BarnardManager();
    const displayId = await manager.getMyDisplayId();
    expect(displayId).toMatch(/^[0-9a-f]{8}$/);
  });

  it('returns 32-char lowercase hex from getCurrentRpi', async () => {
    const { BarnardManager } = setup();
    const manager = new BarnardManager();
    const rpi = await manager.getCurrentRpi();
    expect(rpi).toMatch(/^[0-9a-f]{32}$/);
  });

  it('returns a positive int from getCurrentEnin', async () => {
    const { BarnardManager } = setup();
    const manager = new BarnardManager();
    const enin = await manager.getCurrentEnin();
    expect(enin).toBeGreaterThan(0);
  });

  it('returns 32-char lowercase hex from exportCurrentTek', async () => {
    const { BarnardManager } = setup();
    const manager = new BarnardManager();
    const tek = await manager.exportCurrentTek();
    expect(tek).toMatch(/^[0-9a-f]{32}$/);
  });

  it('delegates permission status APIs to native module', async () => {
    const { BarnardManager, nativeModule } = setup();
    const manager = new BarnardManager();

    await expect(manager.getPermissionStatus()).resolves.toMatchObject({
      platform: 'mock',
      canScan: true,
      canAdvertise: true,
    });
    await expect(manager.requestPermissions()).resolves.toMatchObject({
      platform: 'mock',
      canScan: true,
      canAdvertise: true,
    });

    expect(nativeModule.getPermissionStatus).toHaveBeenCalledTimes(1);
    expect(nativeModule.requestPermissions).toHaveBeenCalledTimes(1);
  });

  it('forwards joinEvent argument to native module', async () => {
    const { BarnardManager, nativeModule } = setup();
    const manager = new BarnardManager();

    await manager.joinEvent('ETHGLOBAL');

    expect(nativeModule.joinEvent).toHaveBeenCalledWith('ETHGLOBAL');
    expect(nativeModule.joinEvent).toHaveBeenCalledTimes(1);
  });
});

describe('BarnardManager event streams', () => {
  it('stops receiving detection events after unsubscribe', () => {
    const { BarnardManager, listeners } = setup();
    const manager = new BarnardManager();
    const callback = jest.fn();

    const unsubscribe = manager.onDetection(callback);

    emit(listeners, 'BarnardDetection', {
      type: 'detection',
      detectedDisplayId: '374708ff',
      enin: 2948599,
    });
    expect(callback).toHaveBeenCalledTimes(1);

    unsubscribe();
    emit(listeners, 'BarnardDetection', { type: 'detection', detectedDisplayId: null });

    expect(callback).toHaveBeenCalledTimes(1);
  });

  it('delivers null detectedDisplayId when B003 read failed', () => {
    const { BarnardManager, listeners } = setup();
    const manager = new BarnardManager();
    const captured: Array<Record<string, unknown>> = [];
    manager.onDetection((ev) => captured.push(ev as Record<string, unknown>));

    emit(listeners, 'BarnardDetection', {
      type: 'detection',
      detectedDisplayId: null,
      enin: 2948599,
    });

    expect(captured).toHaveLength(1);
    expect(captured[0].detectedDisplayId).toBeNull();
  });

  it('subscribes and unsubscribes all channels via onEvent', () => {
    const { BarnardManager, listeners } = setup();
    const manager = new BarnardManager();
    const callback = jest.fn();

    const unsubscribe = manager.onEvent(callback);

    emit(listeners, 'BarnardDetection', { type: 'detection' });
    emit(listeners, 'BarnardRssiUpdate', { type: 'rssi_update' });
    emit(listeners, 'BarnardState', { type: 'state' });
    emit(listeners, 'BarnardConstraint', { type: 'constraint' });

    expect(callback).toHaveBeenCalledTimes(4);

    unsubscribe();
    emit(listeners, 'BarnardError', { type: 'error' });
    emit(listeners, 'BarnardDebug', { type: 'debug' });

    expect(callback).toHaveBeenCalledTimes(4);
  });

  it('calls native dispose and removes active subscriptions', async () => {
    const { BarnardManager, nativeModule, listeners } = setup();
    const manager = new BarnardManager();
    const callback = jest.fn();

    manager.onDetection(callback);
    await manager.dispose();

    emit(listeners, 'BarnardDetection', { type: 'detection' });

    expect(nativeModule.dispose).toHaveBeenCalledTimes(1);
    expect(callback).not.toHaveBeenCalled();
  });

  it('dispose() awaits native completion before resolving', async () => {
    const { BarnardManager, nativeModule } = setup();
    const manager = new BarnardManager();

    let resolveNative: (() => void) | undefined;
    const nativePending = new Promise<void>((resolve) => {
      resolveNative = resolve;
    });
    nativeModule.dispose.mockReturnValueOnce(nativePending);

    const disposeResult = manager.dispose();

    let settled = false;
    void disposeResult.then(() => {
      settled = true;
    });

    await Promise.resolve();
    await Promise.resolve();
    expect(settled).toBe(false);

    resolveNative?.();
    await disposeResult;
    expect(settled).toBe(true);
  });

  it('dispose() propagates native rejection to the caller', async () => {
    const { BarnardManager, nativeModule } = setup();
    const manager = new BarnardManager();

    const nativeError = new Error('native dispose failed');
    nativeModule.dispose.mockRejectedValueOnce(nativeError);

    await expect(manager.dispose()).rejects.toThrow('native dispose failed');
  });
});
