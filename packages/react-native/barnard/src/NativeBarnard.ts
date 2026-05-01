import { NativeModules, NativeEventEmitter } from 'react-native';
import type {
  BarnardCapabilities,
  BarnardState,
  ScanConfig,
  AdvertiseConfig,
  AutoConfig,
  AutoStartResult,
} from './types';

const LINKING_ERROR =
  "The package 'barnard' doesn't seem to be linked. Make sure: \n\n" +
  '- You rebuilt the app after installing the package\n' +
  '- You are not using Expo Go\n' +
  '- If you are using Expo, install it in a custom dev client or bare workflow\n';

/**
 * Native module interface (v2).
 *
 * Byte-valued return types are lowercase hex strings. `exportCurrentTek()`
 * returns 32 hex chars (16-byte TEK); `getMyDisplayId()` returns 8 hex chars;
 * `getCurrentRpi()` returns 32 hex chars (16-byte inner RPI).
 */
interface BarnardNativeModule {
  getCapabilities(): Promise<BarnardCapabilities>;
  getState(): Promise<BarnardState>;

  // v2 API
  getCurrentEventCode(): Promise<string | null>;
  getMyDisplayId(): Promise<string>;
  getCurrentRpi(): Promise<string>;
  getCurrentEnin(): Promise<number>;
  exportCurrentTek(): Promise<string>;

  startScan(config?: ScanConfig): Promise<void>;
  stopScan(): Promise<void>;
  startAdvertise(config?: AdvertiseConfig): Promise<void>;
  stopAdvertise(): Promise<void>;
  startAuto(config?: AutoConfig): Promise<AutoStartResult>;
  stopAuto(): Promise<void>;
  joinEvent(eventCode: string): Promise<void>;
  leaveEvent(): Promise<void>;
  dispose(): Promise<void>;
}

const BarnardModule = NativeModules.Barnard
  ? (NativeModules.Barnard as BarnardNativeModule)
  : (new Proxy(
      {},
      {
        get() {
          throw new Error(LINKING_ERROR);
        },
      }
    ) as BarnardNativeModule);

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
