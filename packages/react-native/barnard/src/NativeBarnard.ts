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
  "The package 'react-native-barnard' doesn't seem to be linked. Make sure: \n\n" +
  '- You rebuilt the app after installing the package\n' +
  '- You are not using Expo Go\n' +
  '- If you are using Expo, install it in a custom dev client or bare workflow\n';

/**
 * Native module interface.
 */
interface BarnardNativeModule {
  getCapabilities(): Promise<BarnardCapabilities>;
  getState(): Promise<BarnardState>;
  startScan(config?: ScanConfig): Promise<void>;
  stopScan(): Promise<void>;
  startAdvertise(config?: AdvertiseConfig): Promise<void>;
  stopAdvertise(): Promise<void>;
  startAuto(config?: AutoConfig): Promise<AutoStartResult>;
  stopAuto(): Promise<void>;
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
const BarnardEventEmitter = new NativeEventEmitter(NativeModules.Barnard);

export { BarnardModule, BarnardEventEmitter };
