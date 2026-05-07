/**
 * Transport kind for proximity detection.
 */
export type TransportKind = 'ble' | 'uwb' | 'thread' | 'unknown';

/**
 * Platform capabilities for Barnard SDK.
 */
export interface BarnardCapabilities {
  supportedTransports: TransportKind[];
  supportsConnectionlessRpid: boolean;
  supportsGattFallback: boolean;
  supportsBackground: boolean;
  supportsHighRateRssi: boolean;
}

export type BarnardPermissionDecision =
  | 'granted'
  | 'denied'
  | 'notDetermined'
  | 'restricted'
  | 'unsupported'
  | 'unknown';

export interface BarnardPermissionStatus {
  platform: string;
  permissions: Record<string, BarnardPermissionDecision>;
  requiredPermissions: string[];
  missingPermissions: string[];
  canScan: boolean;
  canAdvertise: boolean;
}

/**
 * Current state of scanning and advertising operations.
 *
 * v2: `eventMode` removed. Presence of `eventCode` signals whether an event
 * is joined.
 */
export interface BarnardState {
  isScanning: boolean;
  isAdvertising: boolean;

  /** Active event code when joined; omitted or null otherwise. */
  eventCode?: string | null;
}

/**
 * Configuration for scan operations.
 */
export interface ScanConfig {
  allowDuplicates?: boolean;
}

/**
 * Configuration for advertise operations.
 */
export interface AdvertiseConfig {
  formatVersion?: number;
}

/**
 * Configuration for auto mode (scan + advertise).
 */
export interface AutoConfig {
  scan?: ScanConfig;
  advertise?: AdvertiseConfig;
}

export interface AutoStartResult {
  scanningStarted: boolean;
  advertisingStarted: boolean;
  issues: BarnardIssue[];
}

export type BarnardIssueSeverity = 'info' | 'warn' | 'error';

export interface BarnardIssue {
  severity: BarnardIssueSeverity;
  code: string;
  message?: string;
}

export interface BaseEvent {
  /** ISO 8601 timestamp with fractional seconds. */
  timestamp: string;
}

/**
 * v2 Detection event.
 *
 * Byte-valued fields are lowercase hex strings at the native-bridge boundary.
 */
export interface DetectionEvent extends BaseEvent {
  type: 'detection';

  transport: TransportKind;

  /** RPID payload format version. */
  formatVersion: number;

  /** 34-char lowercase hex: `[formatVersion(1) + RPI(16)]` = 17 bytes. */
  rpid: string;

  /**
   * 34-char lowercase hex of this device's own RPID at the observation
   * timestamp (atomic snapshot with `enin`).
   */
  reporterRpid: string;

  /**
   * 8-char lowercase hex = `SHA256(peerTEK)[0:4]`, or null when the B003
   * GATT read failed. The detection is still emitted on B003 failure.
   */
  detectedDisplayId: string | null;

  /** ENIN at the observation timestamp. */
  enin: number;

  /** RSSI in dBm. */
  rssi: number;

  /** 34-char lowercase hex of the raw advertised RPID payload. */
  payloadRaw?: string | null;

  /** Debug-only peer local name. */
  debugLocalName?: string | null;

  /** Non-normative RSSI summary when the emitter aggregates. */
  rssiSummary?: RssiSummary | null;
}

export interface RssiSummary {
  count: number;
  min: number;
  max: number;
  mean: number;
}

/**
 * High-frequency RSSI update for a peer that has completed GATT exchange.
 *
 * Carries the same atomic `(enin, reporterRpid)` snapshot semantics as
 * `DetectionEvent` — both are derived natively from the observation
 * timestamp, so consumers can bucket Detection and RssiUpdate samples
 * together by `(rpid, enin)` without client-side timestamp math.
 */
export interface RssiUpdateEvent extends BaseEvent {
  type: 'rssi_update';
  /** 34-char lowercase hex RPID wire form of the observed peer. */
  rpid: string;
  /** 34-char lowercase hex RPID wire form of the reporter at observation time. */
  reporterRpid: string;
  /** ENIN at the observation timestamp (atomic with `reporterRpid`). */
  enin: number;
  rssi: number;
  /** v2 displayId (8-char hex) if cached from prior GATT; else null. */
  detectedDisplayId?: string | null;
}

export interface StateEvent extends BaseEvent {
  type: 'state';
  state: BarnardState;
  reasonCode?: string | null;
}

export interface ConstraintEvent extends BaseEvent {
  type: 'constraint';
  code: string;
  message?: string | null;
  requiredAction?: string | null;
}

export interface ErrorEvent extends BaseEvent {
  type: 'error';
  code: string;
  message: string;
  recoverable?: boolean | null;
}

export type DebugLevel = 'trace' | 'info' | 'warn' | 'error';

export interface DebugEvent extends BaseEvent {
  type: 'debug';
  level: DebugLevel;
  name: string;
  data?: Record<string, any> | null;
}

export type BarnardEvent =
  | DetectionEvent
  | RssiUpdateEvent
  | StateEvent
  | ConstraintEvent
  | ErrorEvent
  | DebugEvent;
