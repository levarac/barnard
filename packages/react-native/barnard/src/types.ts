/**
 * Transport kind for proximity detection.
 */
export type TransportKind = 'ble' | 'uwb' | 'thread' | 'unknown';

/**
 * Platform capabilities for Barnard SDK.
 */
export interface BarnardCapabilities {
  /**
   * List of supported transport types.
   */
  supportedTransports: TransportKind[];

  /**
   * Whether this transport can carry RPID without connecting (connectionless).
   */
  supportsConnectionlessRpid: boolean;

  /**
   * Whether this transport supports an optional GATT-like connection fallback.
   */
  supportsGattFallback: boolean;

  /**
   * Whether background operation is supported by the implementation.
   */
  supportsBackground: boolean;

  /**
   * Whether this implementation can produce high-rate RSSI observations.
   */
  supportsHighRateRssi: boolean;
}

/**
 * Current state of scanning and advertising operations.
 */
export interface BarnardState {
  /**
   * Whether scanning is currently active.
   */
  isScanning: boolean;

  /**
   * Whether advertising is currently active.
   */
  isAdvertising: boolean;

  /**
   * Current operating mode.
   */
  eventMode?: EventMode;

  /**
   * Active event code when in event mode.
   */
  eventCode?: string;
}

/**
 * Operating mode for resolvable ID behavior.
 */
export type EventMode = 'anonymous' | 'event';

/**
 * Current event mode details.
 */
export interface EventModeState {
  mode: EventMode;
  eventCode?: string;
}

/**
 * Configuration for scan operations.
 */
export interface ScanConfig {
  /**
   * Allow duplicate detections (recommended for better RSSI tracking).
   * Default: true
   */
  allowDuplicates?: boolean;
}

/**
 * Configuration for advertise operations.
 */
export interface AdvertiseConfig {
  /**
   * RPID payload format version.
   * Default: 1
   */
  formatVersion?: number;
}

/**
 * Configuration for auto mode (scan + advertise).
 */
export interface AutoConfig {
  /**
   * Scan configuration.
   */
  scan?: ScanConfig;

  /**
   * Advertise configuration.
   */
  advertise?: AdvertiseConfig;
}

/**
 * Result from starting auto mode.
 */
export interface AutoStartResult {
  /**
   * Whether scanning was successfully started.
   */
  scanningStarted: boolean;

  /**
   * Whether advertising was successfully started.
   */
  advertisingStarted: boolean;

  /**
   * List of non-fatal issues encountered during startup.
   */
  issues: BarnardIssue[];
}

/**
 * Issue severity level.
 */
export type BarnardIssueSeverity = 'info' | 'warn' | 'error';

/**
 * Non-fatal issue reported during operations.
 */
export interface BarnardIssue {
  /**
   * Severity level.
   */
  severity: BarnardIssueSeverity;

  /**
   * Machine-readable code.
   */
  code: string;

  /**
   * Optional human-readable message.
   */
  message?: string;
}

/**
 * Exchanged TEK entry (event mode only).
 */
export interface TekEntry {
  /**
   * Base64-encoded 16-byte TEK.
   */
  tek: string;

  /**
   * Base64-encoded 8-byte event code hash.
   */
  eventCodeHash: string;

  /**
   * ISO 8601 timestamp when first exchanged.
   */
  exchangedAt: string;

  /**
   * ISO 8601 timestamp when last seen.
   */
  lastSeenAt: string;

  /**
   * Human-readable ID derived from TEK.
   */
  displayId: string;
}

/**
 * Base event type with timestamp.
 */
export interface BaseEvent {
  /**
   * ISO 8601 timestamp with fractional seconds.
   */
  timestamp: string;
}

/**
 * RPID detection event.
 */
export interface DetectionEvent extends BaseEvent {
  type: 'detection';

  /**
   * Transport that detected the RPID.
   */
  transport: TransportKind;

  /**
   * RPID payload format version.
   */
  formatVersion: number;

  /**
   * Base64-encoded RPID (16 bytes).
   */
  rpid: string;

  /**
   * Hex-encoded display ID (first 4 bytes of RPID).
   */
  displayId: string;

  /**
   * RSSI value in dBm.
   */
  rssi: number;

  /**
   * Optional base64-encoded raw payload.
   */
  payloadRaw?: string;

  /**
   * Optional resolved TEK (base64) when resolution succeeded.
   */
  resolvedTek?: string;

  /**
   * Optional resolved display ID derived from resolved TEK.
   */
  resolvedDisplayId?: string;

  /**
   * Optional debug-only peer local name.
   */
  debugLocalName?: string;
}

/**
 * State change event.
 */
export interface StateEvent extends BaseEvent {
  type: 'state';

  /**
   * New state.
   */
  state: BarnardState;

  /**
   * Optional reason code for the state change.
   */
  reasonCode?: string;
}

/**
 * Constraint violation event (e.g., permissions, Bluetooth disabled).
 */
export interface ConstraintEvent extends BaseEvent {
  type: 'constraint';

  /**
   * Machine-readable constraint code.
   */
  code: string;

  /**
   * Optional human-readable message.
   */
  message?: string;

  /**
   * Optional suggested action to resolve the constraint.
   */
  requiredAction?: string;
}

/**
 * Error event.
 */
export interface ErrorEvent extends BaseEvent {
  type: 'error';

  /**
   * Machine-readable error code.
   */
  code: string;

  /**
   * Human-readable error message.
   */
  message: string;

  /**
   * Whether the error is recoverable.
   */
  recoverable?: boolean;
}

/**
 * Debug level.
 */
export type DebugLevel = 'trace' | 'info' | 'warn' | 'error';

/**
 * Debug event for troubleshooting.
 */
export interface DebugEvent extends BaseEvent {
  type: 'debug';

  /**
   * Debug level.
   */
  level: DebugLevel;

  /**
   * Event name.
   */
  name: string;

  /**
   * Optional structured data.
   */
  data?: Record<string, any>;
}

/**
 * Union of all event types.
 */
export type BarnardEvent =
  | DetectionEvent
  | StateEvent
  | ConstraintEvent
  | ErrorEvent
  | DebugEvent;
