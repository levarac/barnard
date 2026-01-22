/**
 * React Native Barnard SDK
 *
 * BLE Scan/Advertise + GATT-based RPID detection for React Native.
 */

export { BarnardManager } from './BarnardManager';

export type {
  TransportKind,
  BarnardCapabilities,
  BarnardState,
  ScanConfig,
  AdvertiseConfig,
  AutoConfig,
  AutoStartResult,
  BarnardIssueSeverity,
  BarnardIssue,
  BaseEvent,
  DetectionEvent,
  StateEvent,
  ConstraintEvent,
  ErrorEvent,
  DebugLevel,
  DebugEvent,
  BarnardEvent,
} from './types';
