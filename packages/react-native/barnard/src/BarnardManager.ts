import { EmitterSubscription } from 'react-native';
import { BarnardModule, BarnardEventEmitter } from './NativeBarnard';
import type {
  BarnardCapabilities,
  BarnardPermissionStatus,
  BarnardState,
  ScanConfig,
  AdvertiseConfig,
  AutoConfig,
  AutoStartResult,
  DetectionEvent,
  RssiUpdateEvent,
  StateEvent,
  ConstraintEvent,
  ErrorEvent,
  DebugEvent,
  BarnardEvent,
} from './types';

/**
 * High-level API for Barnard SDK (v2).
 *
 * - `myDisplayId` is `SHA256(TEK)[0:4]` as 8 lowercase hex chars.
 * - `exportCurrentTek` is the only explicit TEK egress; the SDK never
 *   transmits TEK over BLE.
 * - Byte-valued return types (`getCurrentRpi`, `exportCurrentTek`) are
 *   lowercase hex strings.
 *
 * @example
 * ```typescript
 * const barnard = new BarnardManager();
 * const myId = await barnard.getMyDisplayId();
 * console.log('My displayId:', myId);
 *
 * const unsub = barnard.onDetection((e) => {
 *   console.log('peer', e.detectedDisplayId, 'rssi', e.rssi);
 * });
 *
 * await barnard.startAuto();
 * // ...
 * unsub();
 * await barnard.dispose();
 * ```
 */
export class BarnardManager {
  private subscriptions: EmitterSubscription[] = [];

  async getCapabilities(): Promise<BarnardCapabilities> {
    return BarnardModule.getCapabilities();
  }

  async getState(): Promise<BarnardState> {
    return BarnardModule.getState();
  }

  async getPermissionStatus(): Promise<BarnardPermissionStatus> {
    return BarnardModule.getPermissionStatus();
  }

  async requestPermissions(): Promise<BarnardPermissionStatus> {
    return BarnardModule.requestPermissions();
  }

  async openAppSettings(): Promise<void> {
    return BarnardModule.openAppSettings();
  }

  /** v2: currently joined event code, or null. */
  async getCurrentEventCode(): Promise<string | null> {
    return BarnardModule.getCurrentEventCode();
  }

  /** v2: this device's displayId (8 lowercase hex chars). */
  async getMyDisplayId(): Promise<string> {
    return BarnardModule.getMyDisplayId();
  }

  /** v2: inner 16-byte RPI for the current ENIN as 32-char hex. */
  async getCurrentRpi(): Promise<string> {
    return BarnardModule.getCurrentRpi();
  }

  /** v2: current ENIN (floor(unix_seconds / 600)). */
  async getCurrentEnin(): Promise<number> {
    return BarnardModule.getCurrentEnin();
  }

  /**
   * v2: raw 16-byte TEK as 32-char lowercase hex. Explicit privacy egress;
   * the SDK never transmits TEK over BLE.
   */
  async exportCurrentTek(): Promise<string> {
    return BarnardModule.exportCurrentTek();
  }

  async startScan(config?: ScanConfig): Promise<void> {
    return BarnardModule.startScan(config);
  }

  async stopScan(): Promise<void> {
    return BarnardModule.stopScan();
  }

  async startAdvertise(config?: AdvertiseConfig): Promise<void> {
    return BarnardModule.startAdvertise(config);
  }

  async stopAdvertise(): Promise<void> {
    return BarnardModule.stopAdvertise();
  }

  async startAuto(config?: AutoConfig): Promise<AutoStartResult> {
    return BarnardModule.startAuto(config);
  }

  async stopAuto(): Promise<void> {
    return BarnardModule.stopAuto();
  }

  async joinEvent(eventCode: string): Promise<void> {
    return BarnardModule.joinEvent(eventCode);
  }

  async leaveEvent(): Promise<void> {
    return BarnardModule.leaveEvent();
  }

  async dispose(): Promise<void> {
    this.subscriptions.forEach((sub) => sub.remove());
    this.subscriptions = [];
    await BarnardModule.dispose();
  }

  onDetection(callback: (event: DetectionEvent) => void): () => void {
    return this.addEventListener('BarnardDetection', callback);
  }

  onRssiUpdate(callback: (event: RssiUpdateEvent) => void): () => void {
    return this.addEventListener('BarnardRssiUpdate', callback);
  }

  onStateChange(callback: (event: StateEvent) => void): () => void {
    return this.addEventListener('BarnardState', callback);
  }

  onConstraint(callback: (event: ConstraintEvent) => void): () => void {
    return this.addEventListener('BarnardConstraint', callback);
  }

  onError(callback: (event: ErrorEvent) => void): () => void {
    return this.addEventListener('BarnardError', callback);
  }

  onDebug(callback: (event: DebugEvent) => void): () => void {
    return this.addEventListener('BarnardDebug', callback);
  }

  onEvent(callback: (event: BarnardEvent) => void): () => void {
    const detection = this.onDetection(callback);
    const rssi = this.onRssiUpdate(callback);
    const state = this.onStateChange(callback);
    const constraint = this.onConstraint(callback);
    const error = this.onError(callback);
    const debug = this.onDebug(callback);

    return () => {
      detection();
      rssi();
      state();
      constraint();
      error();
      debug();
    };
  }

  private addEventListener<T>(
    eventName: string,
    callback: (event: T) => void
  ): () => void {
    const subscription = BarnardEventEmitter.addListener(eventName, callback);
    this.subscriptions.push(subscription);

    return () => {
      const index = this.subscriptions.indexOf(subscription);
      if (index !== -1) {
        this.subscriptions.splice(index, 1);
      }
      subscription.remove();
    };
  }
}
