/**
 * React Native Barnard SDK (v2)
 *
 * BLE Scan/Advertise + v2 GATT (B002 RPID + B003 displayId + B004 EventCodeHash).
 * TEK is never transmitted over BLE.
 */

export { BarnardManager } from './BarnardManager';
export { BarnardIdentity } from './BarnardIdentity';

export type {
  TransportKind,
  EninMode,
  BeaconChainConfig,
  BarnardConfig,
  BarnardCapabilities,
  BarnardPermissionDecision,
  BarnardPermissionStatus,
  BarnardState,
  ScanConfig,
  AdvertiseConfig,
  AutoConfig,
  AutoStartResult,
  BarnardIssueSeverity,
  BarnardIssue,
  BaseEvent,
  DetectionEvent,
  RssiUpdateEvent,
  RssiSummary,
  StateEvent,
  ConstraintEvent,
  ErrorEvent,
  DebugLevel,
  DebugEvent,
  BarnardEvent,
  BarnardSignature,
} from './types';
