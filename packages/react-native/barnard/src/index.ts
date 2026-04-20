/**
 * React Native Barnard SDK
 *
 * BLE Scan/Advertise + GATT-based RPID detection for React Native.
 */

export { BarnardManager } from './BarnardManager';

export type {
  TransportKind,
  EventMode,
  EventModeState,
  BarnardCapabilities,
  BarnardState,
  ScanConfig,
  AdvertiseConfig,
  AutoConfig,
  AutoStartResult,
  BarnardIssueSeverity,
  BarnardIssue,
  TekEntry,
  BaseEvent,
  DetectionEvent,
  StateEvent,
  ConstraintEvent,
  ErrorEvent,
  DebugLevel,
  DebugEvent,
  BarnardEvent,
} from './types';
