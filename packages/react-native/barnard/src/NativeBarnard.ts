import { NativeModules, NativeEventEmitter } from 'react-native';
import type {
  BarnardCapabilities,
  BarnardState,
  EventModeState,
  ScanConfig,
  AdvertiseConfig,
  AutoConfig,
  AutoStartResult,
  TekEntry,
} from './types';

const LINKING_ERROR =
  "The package 'barnard' doesn't seem to be linked. Make sure: \n\n" +
  '- You rebuilt the app after installing the package\n' +
  '- You are not using Expo Go\n' +
  '- If you are using Expo, install it in a custom dev client or bare workflow\n';

/**
 * Native module interface.
 */
interface BarnardNativeModule {
  getCapabilities(): Promise<BarnardCapabilities>;
  getState(): Promise<BarnardState>;
  getEventMode(): Promise<EventModeState>;
  startScan(config?: ScanConfig): Promise<void>;
  stopScan(): Promise<void>;
  startAdvertise(config?: AdvertiseConfig): Promise<void>;
  stopAdvertise(): Promise<void>;
  startAuto(config?: AutoConfig): Promise<AutoStartResult>;
  stopAuto(): Promise<void>;
  joinEvent(eventCode: string): Promise<void>;
  leaveEvent(): Promise<void>;
  getExchangedTeks(eventCode: string): Promise<TekEntry[]>;
  clearTeksForEvent(eventCode: string): Promise<number>;
  clearAllTeks(): Promise<number>;
  dispose(): Promise<void>;
}

/**
 * Native module instance.
 */
const BarnardModule = NativeModules.Barnard
  ? (NativeModules.Barnard as BarnardNativeModule)
  : new Proxy(
      {},
      {
        get() {
          throw new Error(LINKING_ERROR);
        },
      }
    ) as BarnardNativeModule;

/**
 * Native event emitter for Barnard events.
 */
const BarnardEventEmitter: NativeEventEmitter = NativeModules.Barnard
  ? new NativeEventEmitter(NativeModules.Barnard)
  : ({
      addListener() {
        throw new Error(LINKING_ERROR);
      },
      removeAllListeners() {},
      listenerCount() {
        return 0;
      },
    } as unknown as NativeEventEmitter);

export { BarnardModule, BarnardEventEmitter };
