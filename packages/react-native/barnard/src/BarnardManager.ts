import { EmitterSubscription } from 'react-native';
import { BarnardModule, BarnardEventEmitter } from './NativeBarnard';
import type {
  BarnardCapabilities,
  BarnardState,
  EventModeState,
  ScanConfig,
  AdvertiseConfig,
  AutoConfig,
  AutoStartResult,
  TekEntry,
  DetectionEvent,
  StateEvent,
  ConstraintEvent,
  ErrorEvent,
  DebugEvent,
  BarnardEvent,
} from './types';

/**
 * High-level API for Barnard SDK.
 *
 * Provides BLE Scan/Advertise functionality with GATT-based RPID detection.
 *
 * @example
 * ```typescript
 * const barnard = new BarnardManager();
 *
 * // Listen for detections
 * const unsubscribe = barnard.onDetection((event) => {
 *   console.log('Detected:', event.displayId, event.rssi);
 * });
 *
 * // Start scanning and advertising
 * await barnard.startAuto();
 *
 * // Later: cleanup
 * unsubscribe();
 * barnard.dispose();
 * ```
 */
export class BarnardManager {
  private subscriptions: EmitterSubscription[] = [];

  /**
   * Get platform capabilities.
   */
  async getCapabilities(): Promise<BarnardCapabilities> {
    return BarnardModule.getCapabilities();
  }

  /**
   * Get current state (scanning/advertising status).
   */
  async getState(): Promise<BarnardState> {
    return BarnardModule.getState();
  }

  /**
   * Get current event mode state.
   */
  async getEventMode(): Promise<EventModeState> {
    return BarnardModule.getEventMode();
  }

  /**
   * Start BLE scanning for nearby devices.
   *
   * @param config - Optional scan configuration
   */
  async startScan(config?: ScanConfig): Promise<void> {
    return BarnardModule.startScan(config);
  }

  /**
   * Stop BLE scanning.
   */
  async stopScan(): Promise<void> {
    return BarnardModule.stopScan();
  }

  /**
   * Start BLE advertising as a peripheral.
   *
   * @param config - Optional advertise configuration
   */
  async startAdvertise(config?: AdvertiseConfig): Promise<void> {
    return BarnardModule.startAdvertise(config);
  }

  /**
   * Stop BLE advertising.
   */
  async stopAdvertise(): Promise<void> {
    return BarnardModule.stopAdvertise();
  }

  /**
   * Start both scanning and advertising simultaneously.
   *
   * @param config - Optional auto configuration
   * @returns Result indicating which operations started successfully
   */
  async startAuto(config?: AutoConfig): Promise<AutoStartResult> {
    return BarnardModule.startAuto(config);
  }

  /**
   * Stop both scanning and advertising.
   */
  async stopAuto(): Promise<void> {
    return BarnardModule.stopAuto();
  }

  /**
   * Join an event and enable TEK exchange/resolution.
   */
  async joinEvent(eventCode: string): Promise<void> {
    return BarnardModule.joinEvent(eventCode);
  }

  /**
   * Leave event mode and return to anonymous mode.
   */
  async leaveEvent(): Promise<void> {
    return BarnardModule.leaveEvent();
  }

  /**
   * Get exchanged TEKs for the specified event code.
   */
  async getExchangedTeks(eventCode: string): Promise<TekEntry[]> {
    return BarnardModule.getExchangedTeks(eventCode);
  }

  /**
   * Clear TEKs for the specified event code.
   */
  async clearTeksForEvent(eventCode: string): Promise<number> {
    return BarnardModule.clearTeksForEvent(eventCode);
  }

  /**
   * Clear all exchanged TEKs.
   */
  async clearAllTeks(): Promise<number> {
    return BarnardModule.clearAllTeks();
  }

  /**
   * Dispose of the manager and release resources.
   */
  dispose(): void {
    // Unsubscribe from all events
    this.subscriptions.forEach((sub) => sub.remove());
    this.subscriptions = [];

    // Call native dispose
    BarnardModule.dispose().catch((error) => {
      console.warn('Failed to dispose Barnard:', error);
    });
  }

  /**
   * Subscribe to detection events.
   *
   * @param callback - Function to call when a detection occurs
   * @returns Function to unsubscribe
   */
  onDetection(callback: (event: DetectionEvent) => void): () => void {
    return this.addEventListener('BarnardDetection', callback);
  }

  /**
   * Subscribe to state change events.
   *
   * @param callback - Function to call when state changes
   * @returns Function to unsubscribe
   */
  onStateChange(callback: (event: StateEvent) => void): () => void {
    return this.addEventListener('BarnardState', callback);
  }

  /**
   * Subscribe to constraint violation events.
   *
   * @param callback - Function to call when a constraint is violated
   * @returns Function to unsubscribe
   */
  onConstraint(callback: (event: ConstraintEvent) => void): () => void {
    return this.addEventListener('BarnardConstraint', callback);
  }

  /**
   * Subscribe to error events.
   *
   * @param callback - Function to call when an error occurs
   * @returns Function to unsubscribe
   */
  onError(callback: (event: ErrorEvent) => void): () => void {
    return this.addEventListener('BarnardError', callback);
  }

  /**
   * Subscribe to debug events.
   *
   * @param callback - Function to call when a debug event occurs
   * @returns Function to unsubscribe
   */
  onDebug(callback: (event: DebugEvent) => void): () => void {
    return this.addEventListener('BarnardDebug', callback);
  }

  /**
   * Subscribe to all events.
   *
   * @param callback - Function to call when any event occurs
   * @returns Function to unsubscribe
   */
  onEvent(callback: (event: BarnardEvent) => void): () => void {
    const detectionUnsub = this.onDetection(callback);
    const stateUnsub = this.onStateChange(callback);
    const constraintUnsub = this.onConstraint(callback);
    const errorUnsub = this.onError(callback);
    const debugUnsub = this.onDebug(callback);

    return () => {
      detectionUnsub();
      stateUnsub();
      constraintUnsub();
      errorUnsub();
      debugUnsub();
    };
  }

  /**
   * Internal helper to subscribe to native events.
   */
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
