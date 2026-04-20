jest.mock('react-native', () => {
  const listeners = new Map<string, Set<(event: unknown) => void>>();

  const Barnard = {
    getCapabilities: jest.fn().mockResolvedValue({ supportedTransports: ['ble'] }),
    getState: jest.fn().mockResolvedValue({ isScanning: false, isAdvertising: false }),
    getEventMode: jest.fn().mockResolvedValue({ mode: 'anonymous', eventCode: null }),
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
    getExchangedTeks: jest.fn().mockResolvedValue([]),
    clearTeksForEvent: jest.fn().mockResolvedValue(0),
    clearAllTeks: jest.fn().mockResolvedValue(0),
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
      getEventMode: () => Promise<unknown>;
      joinEvent: (eventCode: string) => Promise<void>;
      onDetection: (callback: (event: unknown) => void) => () => void;
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

describe('BarnardManager', () => {
  it('delegates getEventMode to native module', async () => {
    const { BarnardManager, nativeModule } = setup();
    nativeModule.getEventMode.mockResolvedValueOnce({ mode: 'event', eventCode: 'ETHGLOBAL' });

    const manager = new BarnardManager();

    await expect(manager.getEventMode()).resolves.toEqual({
      mode: 'event',
      eventCode: 'ETHGLOBAL',
    });
    expect(nativeModule.getEventMode).toHaveBeenCalledTimes(1);
  });

  it('forwards joinEvent argument to native module', async () => {
    const { BarnardManager, nativeModule } = setup();
    const manager = new BarnardManager();

    await manager.joinEvent('ETHGLOBAL');

    expect(nativeModule.joinEvent).toHaveBeenCalledWith('ETHGLOBAL');
    expect(nativeModule.joinEvent).toHaveBeenCalledTimes(1);
  });

  it('stops receiving detection events after unsubscribe', () => {
    const { BarnardManager, listeners } = setup();
    const manager = new BarnardManager();
    const callback = jest.fn();

    const unsubscribe = manager.onDetection(callback);

    emit(listeners, 'BarnardDetection', { type: 'detection', displayId: 'abc123' });
    expect(callback).toHaveBeenCalledTimes(1);

    unsubscribe();
    emit(listeners, 'BarnardDetection', { type: 'detection', displayId: 'def456' });

    expect(callback).toHaveBeenCalledTimes(1);
  });

  it('subscribes and unsubscribes all channels via onEvent', () => {
    const { BarnardManager, listeners } = setup();
    const manager = new BarnardManager();
    const callback = jest.fn();

    const unsubscribe = manager.onEvent(callback);

    emit(listeners, 'BarnardDetection', { type: 'detection' });
    emit(listeners, 'BarnardState', { type: 'state' });
    emit(listeners, 'BarnardConstraint', { type: 'constraint' });

    expect(callback).toHaveBeenCalledTimes(3);

    unsubscribe();
    emit(listeners, 'BarnardError', { type: 'error' });
    emit(listeners, 'BarnardDebug', { type: 'debug' });

    expect(callback).toHaveBeenCalledTimes(3);
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

    // Let any microtasks run; native is still pending, so dispose must not have resolved.
    await Promise.resolve();
    await Promise.resolve();
    expect(settled).toBe(false);

    // Resolving the native side lets dispose() complete.
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
