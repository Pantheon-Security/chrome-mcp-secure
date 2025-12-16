/**
 * Compliance-grade logging for enterprise environments
 *
 * Supports:
 * - CEF (Common Event Format) for SIEM integration
 * - RFC 5424 Syslog format
 * - OWASP logging guidelines
 * - Correlation IDs for request tracing
 *
 * @module compliance-logger
 */

import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import * as dgram from 'dgram';
import { mkdirSecure, writeFileSecure, PERMISSION_MODES } from './file-permissions.js';

// ============================================================================
// Types and Interfaces
// ============================================================================

/**
 * CEF Severity levels (0-10)
 * Maps to standard SIEM severity ratings
 */
export enum CEFSeverity {
  UNKNOWN = 0,
  LOW = 3,
  MEDIUM = 5,
  HIGH = 7,
  VERY_HIGH = 8,
  CRITICAL = 10
}

/**
 * Syslog severity levels (RFC 5424)
 */
export enum SyslogSeverity {
  EMERGENCY = 0,   // System is unusable
  ALERT = 1,       // Action must be taken immediately
  CRITICAL = 2,    // Critical conditions
  ERROR = 3,       // Error conditions
  WARNING = 4,     // Warning conditions
  NOTICE = 5,      // Normal but significant condition
  INFO = 6,        // Informational messages
  DEBUG = 7        // Debug-level messages
}

/**
 * Syslog facility codes (RFC 5424)
 */
export enum SyslogFacility {
  KERN = 0,
  USER = 1,
  MAIL = 2,
  DAEMON = 3,
  AUTH = 4,
  SYSLOG = 5,
  LPR = 6,
  NEWS = 7,
  UUCP = 8,
  CRON = 9,
  AUTHPRIV = 10,
  FTP = 11,
  LOCAL0 = 16,
  LOCAL1 = 17,
  LOCAL2 = 18,
  LOCAL3 = 19,
  LOCAL4 = 20,
  LOCAL5 = 21,
  LOCAL6 = 22,
  LOCAL7 = 23
}

/**
 * OWASP-recommended event categories
 */
export type EventCategory =
  | 'authentication'      // Login/logout, auth failures
  | 'authorization'       // Access control decisions
  | 'input_validation'    // Input validation failures
  | 'application_error'   // Application errors
  | 'system'              // System events
  | 'audit'               // Audit trail events
  | 'security'            // Security events (attacks, anomalies)
  | 'data_access'         // Sensitive data access
  | 'configuration'       // Config changes
  | 'credential';         // Credential operations

/**
 * Event outcome per OWASP guidelines
 */
export type EventOutcome = 'success' | 'failure' | 'unknown';

/**
 * Compliance log event structure
 */
export interface ComplianceEvent {
  // Required fields
  timestamp: string;
  category: EventCategory;
  action: string;
  outcome: EventOutcome;
  severity: CEFSeverity;

  // Actor information
  actor?: {
    type: 'user' | 'system' | 'api' | 'service';
    id?: string;
    name?: string;
    ip?: string;
  };

  // Target/resource information
  target?: {
    type: string;
    id?: string;
    name?: string;
    url?: string;
  };

  // Request context
  request?: {
    correlationId: string;
    method?: string;
    path?: string;
    userAgent?: string;
  };

  // Additional details
  message: string;
  details?: Record<string, unknown>;

  // Error information
  error?: {
    code?: string;
    message?: string;
    stack?: string;
  };

  // Compliance metadata
  compliance?: {
    standard?: string;   // e.g., 'SOC2', 'GDPR', 'PCI-DSS'
    control?: string;    // e.g., 'CC6.1', 'A.12.4.1'
    dataClassification?: string;
  };
}

/**
 * Output format configuration
 */
export type OutputFormat = 'json' | 'cef' | 'syslog' | 'jsonl';

/**
 * Logger configuration
 */
export interface ComplianceLoggerConfig {
  // Output settings
  format: OutputFormat;
  outputDir?: string;

  // Syslog settings
  syslog?: {
    host: string;
    port: number;
    facility: SyslogFacility;
    protocol: 'udp' | 'tcp';
  };

  // CEF settings
  cef?: {
    deviceVendor: string;
    deviceProduct: string;
    deviceVersion: string;
  };

  // Filtering
  minSeverity: CEFSeverity;
  categories?: EventCategory[];

  // Features
  includeStackTraces: boolean;
  maskSensitiveData: boolean;

  // File rotation
  maxFileSizeMB: number;
  maxFiles: number;
}

// ============================================================================
// Sensitive Data Masking
// ============================================================================

const SENSITIVE_KEYS = new Set([
  'password', 'passwd', 'pwd', 'secret', 'token', 'apikey', 'api_key',
  'apiKey', 'auth', 'authorization', 'bearer', 'credential', 'credentials',
  'private_key', 'privateKey', 'access_token', 'accessToken', 'refresh_token',
  'refreshToken', 'session', 'cookie', 'csrf', 'ssn', 'credit_card', 'cvv'
]);

function isSensitiveKey(key: string): boolean {
  const lower = key.toLowerCase();
  return SENSITIVE_KEYS.has(lower) ||
         lower.includes('password') ||
         lower.includes('secret') ||
         lower.includes('token') ||
         lower.includes('key') ||
         lower.includes('auth');
}

function maskValue(value: unknown): unknown {
  if (typeof value === 'string') {
    if (value.length <= 4) return '****';
    return value.substring(0, 2) + '****' + value.substring(value.length - 2);
  }
  return '****';
}

function maskSensitiveData(obj: Record<string, unknown>): Record<string, unknown> {
  const result: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(obj)) {
    if (isSensitiveKey(key)) {
      result[key] = maskValue(value);
    } else if (value && typeof value === 'object' && !Array.isArray(value)) {
      result[key] = maskSensitiveData(value as Record<string, unknown>);
    } else if (Array.isArray(value)) {
      result[key] = value.map(item =>
        item && typeof item === 'object' ? maskSensitiveData(item as Record<string, unknown>) : item
      );
    } else {
      result[key] = value;
    }
  }

  return result;
}

// ============================================================================
// Correlation ID Management
// ============================================================================

let currentCorrelationId: string | null = null;

/**
 * Generate a new correlation ID
 */
export function generateCorrelationId(): string {
  return `${Date.now()}-${crypto.randomBytes(8).toString('hex')}`;
}

/**
 * Set the current correlation ID for the request context
 */
export function setCorrelationId(id: string): void {
  currentCorrelationId = id;
}

/**
 * Get the current correlation ID
 */
export function getCorrelationId(): string {
  if (!currentCorrelationId) {
    currentCorrelationId = generateCorrelationId();
  }
  return currentCorrelationId;
}

/**
 * Clear the correlation ID (call at end of request)
 */
export function clearCorrelationId(): void {
  currentCorrelationId = null;
}

// ============================================================================
// Format Generators
// ============================================================================

/**
 * Generate CEF (Common Event Format) string
 * Format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
 */
function formatCEF(event: ComplianceEvent, config: ComplianceLoggerConfig): string {
  const cefConfig = config.cef || {
    deviceVendor: 'Pantheon-Security',
    deviceProduct: 'Chrome-MCP-Secure',
    deviceVersion: '2.3.0'
  };

  // Escape CEF special characters
  const escape = (str: string): string =>
    str.replace(/\\/g, '\\\\').replace(/\|/g, '\\|');

  // Map severity to CEF (0-10)
  const severity = event.severity;

  // Build signature ID from category and action
  const signatureId = `${event.category}:${event.action}`;

  // Build extension fields
  const ext: string[] = [];

  ext.push(`rt=${new Date(event.timestamp).getTime()}`);
  ext.push(`outcome=${event.outcome}`);
  ext.push(`msg=${escape(event.message)}`);

  if (event.actor) {
    if (event.actor.id) ext.push(`suid=${escape(event.actor.id)}`);
    if (event.actor.name) ext.push(`suser=${escape(event.actor.name)}`);
    if (event.actor.ip) ext.push(`src=${event.actor.ip}`);
  }

  if (event.target) {
    if (event.target.type) ext.push(`destinationServiceName=${escape(event.target.type)}`);
    if (event.target.id) ext.push(`duid=${escape(event.target.id)}`);
    if (event.target.url) ext.push(`request=${escape(event.target.url)}`);
  }

  if (event.request?.correlationId) {
    ext.push(`cn1=${escape(event.request.correlationId)}`);
    ext.push(`cn1Label=correlationId`);
  }

  if (event.error?.code) {
    ext.push(`reason=${escape(event.error.code)}`);
  }

  // Add custom details as cs fields
  if (event.details) {
    let csIndex = 1;
    for (const [key, value] of Object.entries(event.details)) {
      if (csIndex > 6) break; // CEF supports cs1-cs6
      ext.push(`cs${csIndex}=${escape(String(value))}`);
      ext.push(`cs${csIndex}Label=${escape(key)}`);
      csIndex++;
    }
  }

  return `CEF:0|${escape(cefConfig.deviceVendor)}|${escape(cefConfig.deviceProduct)}|${escape(cefConfig.deviceVersion)}|${escape(signatureId)}|${escape(event.action)}|${severity}|${ext.join(' ')}`;
}

/**
 * Generate RFC 5424 Syslog format
 */
function formatSyslog(event: ComplianceEvent, config: ComplianceLoggerConfig): string {
  const facility = config.syslog?.facility || SyslogFacility.LOCAL0;

  // Map CEF severity to syslog severity
  const severityMap: Record<CEFSeverity, SyslogSeverity> = {
    [CEFSeverity.UNKNOWN]: SyslogSeverity.INFO,
    [CEFSeverity.LOW]: SyslogSeverity.NOTICE,
    [CEFSeverity.MEDIUM]: SyslogSeverity.WARNING,
    [CEFSeverity.HIGH]: SyslogSeverity.ERROR,
    [CEFSeverity.VERY_HIGH]: SyslogSeverity.CRITICAL,
    [CEFSeverity.CRITICAL]: SyslogSeverity.ALERT
  };

  const syslogSeverity = severityMap[event.severity];
  const priority = facility * 8 + syslogSeverity;

  const hostname = process.env.HOSTNAME || 'localhost';
  const appName = 'chrome-mcp-secure';
  const procId = process.pid;
  const msgId = event.request?.correlationId || '-';

  // RFC 5424 structured data
  const sd: string[] = [];

  // Add event metadata
  sd.push(`[event@47450 category="${event.category}" action="${event.action}" outcome="${event.outcome}"]`);

  if (event.actor?.id) {
    sd.push(`[actor@47450 type="${event.actor.type}" id="${event.actor.id}"]`);
  }

  if (event.compliance?.standard) {
    sd.push(`[compliance@47450 standard="${event.compliance.standard}" control="${event.compliance.control || '-'}"]`);
  }

  const structuredData = sd.length > 0 ? sd.join('') : '-';

  // RFC 5424 format: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
  return `<${priority}>1 ${event.timestamp} ${hostname} ${appName} ${procId} ${msgId} ${structuredData} ${event.message}`;
}

/**
 * Format as JSON (single line)
 */
function formatJSON(event: ComplianceEvent): string {
  return JSON.stringify(event);
}

// ============================================================================
// Compliance Logger Class
// ============================================================================

class ComplianceLogger {
  private config: ComplianceLoggerConfig;
  private syslogClient: dgram.Socket | null = null;
  private currentLogFile: string | null = null;
  private writeQueue: string[] = [];
  private flushTimer: NodeJS.Timeout | null = null;
  private currentFileSize: number = 0;

  constructor(config?: Partial<ComplianceLoggerConfig>) {
    this.config = {
      format: (process.env.COMPLIANCE_LOG_FORMAT as OutputFormat) || 'jsonl',
      outputDir: process.env.COMPLIANCE_LOG_DIR || path.join(process.cwd(), 'logs', 'compliance'),
      minSeverity: CEFSeverity.UNKNOWN,
      includeStackTraces: process.env.NODE_ENV !== 'production',
      maskSensitiveData: true,
      maxFileSizeMB: 100,
      maxFiles: 10,
      ...config
    };

    // Parse environment overrides
    if (process.env.COMPLIANCE_MIN_SEVERITY) {
      this.config.minSeverity = parseInt(process.env.COMPLIANCE_MIN_SEVERITY) as CEFSeverity;
    }

    // Initialize syslog if configured
    if (process.env.SYSLOG_HOST || config?.syslog) {
      this.config.syslog = {
        host: process.env.SYSLOG_HOST || config?.syslog?.host || 'localhost',
        port: parseInt(process.env.SYSLOG_PORT || '514'),
        facility: SyslogFacility.LOCAL0,
        protocol: 'udp',
        ...config?.syslog
      };
      this.initSyslog();
    }

    // Initialize CEF config
    if (process.env.CEF_DEVICE_VENDOR) {
      this.config.cef = {
        deviceVendor: process.env.CEF_DEVICE_VENDOR || 'Pantheon-Security',
        deviceProduct: process.env.CEF_DEVICE_PRODUCT || 'Chrome-MCP-Secure',
        deviceVersion: process.env.CEF_DEVICE_VERSION || '2.3.0',
      };
    }

    this.ensureLogDir();
  }

  private ensureLogDir(): void {
    if (this.config.outputDir) {
      mkdirSecure(this.config.outputDir, PERMISSION_MODES.OWNER_FULL);
    }
  }

  private initSyslog(): void {
    if (this.config.syslog?.protocol === 'udp') {
      this.syslogClient = dgram.createSocket('udp4');
    }
  }

  private getLogFilePath(): string {
    const date = new Date().toISOString().split('T')[0];
    const ext = this.config.format === 'jsonl' ? 'jsonl' :
                this.config.format === 'cef' ? 'cef' :
                this.config.format === 'syslog' ? 'log' : 'json';
    return path.join(this.config.outputDir!, `compliance-${date}.${ext}`);
  }

  private shouldRotate(): boolean {
    if (this.currentFileSize >= this.config.maxFileSizeMB * 1024 * 1024) {
      return true;
    }
    return false;
  }

  private rotateIfNeeded(): void {
    if (!this.shouldRotate()) return;

    const logFile = this.getLogFilePath();
    const rotatedFile = `${logFile}.${Date.now()}`;

    try {
      if (fs.existsSync(logFile)) {
        fs.renameSync(logFile, rotatedFile);
      }
      this.currentFileSize = 0;

      // Clean up old files
      this.cleanupOldFiles();
    } catch (error) {
      console.error(`Log rotation failed: ${error}`);
    }
  }

  private cleanupOldFiles(): void {
    if (!this.config.outputDir) return;

    try {
      const files = fs.readdirSync(this.config.outputDir)
        .filter(f => f.startsWith('compliance-'))
        .map(f => ({
          name: f,
          path: path.join(this.config.outputDir!, f),
          mtime: fs.statSync(path.join(this.config.outputDir!, f)).mtime.getTime()
        }))
        .sort((a, b) => b.mtime - a.mtime);

      // Keep only maxFiles
      const toDelete = files.slice(this.config.maxFiles);
      for (const file of toDelete) {
        fs.unlinkSync(file.path);
      }
    } catch (error) {
      console.error(`Log cleanup failed: ${error}`);
    }
  }

  private formatEvent(event: ComplianceEvent): string {
    switch (this.config.format) {
      case 'cef':
        return formatCEF(event, this.config);
      case 'syslog':
        return formatSyslog(event, this.config);
      case 'json':
      case 'jsonl':
      default:
        return formatJSON(event);
    }
  }

  private async writeToFile(formatted: string): Promise<void> {
    this.writeQueue.push(formatted);
    this.scheduleFlush();
  }

  private scheduleFlush(): void {
    if (this.flushTimer) return;

    this.flushTimer = setTimeout(() => {
      this.flushTimer = null;
      this.flush();
    }, 100);
  }

  private flush(): void {
    if (this.writeQueue.length === 0) return;

    this.rotateIfNeeded();

    const logFile = this.getLogFilePath();
    const content = this.writeQueue.join('\n') + '\n';
    this.writeQueue = [];

    try {
      fs.appendFileSync(logFile, content);
      this.currentFileSize += Buffer.byteLength(content);
    } catch (error) {
      console.error(`Compliance log write failed: ${error}`);
    }
  }

  private sendToSyslog(formatted: string): void {
    if (!this.syslogClient || !this.config.syslog) return;

    const message = Buffer.from(formatted);
    this.syslogClient.send(message, this.config.syslog.port, this.config.syslog.host, (err) => {
      if (err) {
        console.error(`Syslog send failed: ${err}`);
      }
    });
  }

  /**
   * Log a compliance event
   */
  log(event: Omit<ComplianceEvent, 'timestamp' | 'request'> & { request?: Partial<ComplianceEvent['request']> }): void {
    // Check minimum severity
    if (event.severity < this.config.minSeverity) return;

    // Check category filter
    if (this.config.categories && !this.config.categories.includes(event.category)) {
      return;
    }

    // Build full event
    const fullEvent: ComplianceEvent = {
      ...event,
      timestamp: new Date().toISOString(),
      request: {
        correlationId: event.request?.correlationId || getCorrelationId(),
        ...event.request
      }
    };

    // Mask sensitive data if enabled
    if (this.config.maskSensitiveData && fullEvent.details) {
      fullEvent.details = maskSensitiveData(fullEvent.details);
    }

    // Remove stack traces in production if configured
    if (!this.config.includeStackTraces && fullEvent.error?.stack) {
      delete fullEvent.error.stack;
    }

    // Format the event
    const formatted = this.formatEvent(fullEvent);

    // Write to file
    this.writeToFile(formatted);

    // Send to syslog if configured
    if (this.config.syslog) {
      const syslogFormatted = formatSyslog(fullEvent, this.config);
      this.sendToSyslog(syslogFormatted);
    }
  }

  // ============================================================================
  // Convenience Methods for Common Events
  // ============================================================================

  /**
   * Log authentication event
   */
  authentication(action: string, outcome: EventOutcome, details?: {
    userId?: string;
    username?: string;
    method?: string;
    reason?: string;
    ip?: string;
  }): void {
    this.log({
      category: 'authentication',
      action,
      outcome,
      severity: outcome === 'failure' ? CEFSeverity.HIGH : CEFSeverity.LOW,
      message: `Authentication ${action}: ${outcome}`,
      actor: details?.userId ? {
        type: 'user',
        id: details.userId,
        name: details.username,
        ip: details.ip
      } : undefined,
      details: details ? { method: details.method, reason: details.reason } : undefined,
      error: outcome === 'failure' && details?.reason ? { message: details.reason } : undefined
    });
  }

  /**
   * Log authorization event
   */
  authorization(action: string, outcome: EventOutcome, details?: {
    userId?: string;
    resource?: string;
    permission?: string;
    reason?: string;
  }): void {
    this.log({
      category: 'authorization',
      action,
      outcome,
      severity: outcome === 'failure' ? CEFSeverity.MEDIUM : CEFSeverity.LOW,
      message: `Authorization ${action} for ${details?.resource || 'resource'}: ${outcome}`,
      actor: details?.userId ? { type: 'user', id: details.userId } : undefined,
      target: details?.resource ? { type: 'resource', name: details.resource } : undefined,
      details: details ? { permission: details.permission, reason: details.reason } : undefined
    });
  }

  /**
   * Log credential operation
   */
  credential(action: string, outcome: EventOutcome, details?: {
    credentialId?: string;
    credentialType?: string;
    domain?: string;
    reason?: string;
  }): void {
    this.log({
      category: 'credential',
      action,
      outcome,
      severity: outcome === 'failure' ? CEFSeverity.HIGH : CEFSeverity.MEDIUM,
      message: `Credential ${action}: ${outcome}`,
      target: {
        type: 'credential',
        id: details?.credentialId,
        name: details?.credentialType
      },
      details: details ? { domain: details.domain, reason: details.reason } : undefined,
      error: outcome === 'failure' && details?.reason ? { message: details.reason } : undefined
    });
  }

  /**
   * Log tool execution
   */
  tool(toolName: string, outcome: EventOutcome, details?: {
    durationMs?: number;
    url?: string;
    selector?: string;
    error?: string;
  }): void {
    this.log({
      category: 'audit',
      action: `tool:${toolName}`,
      outcome,
      severity: outcome === 'failure' ? CEFSeverity.MEDIUM : CEFSeverity.LOW,
      message: `Tool ${toolName} executed: ${outcome}`,
      target: details?.url ? { type: 'url', url: details.url } : undefined,
      details: details ? {
        durationMs: details.durationMs,
        selector: details.selector
      } : undefined,
      error: details?.error ? { message: details.error } : undefined
    });
  }

  /**
   * Log security event
   */
  security(action: string, severity: CEFSeverity, details?: {
    threat?: string;
    source?: string;
    indicator?: string;
    blocked?: boolean;
  }): void {
    this.log({
      category: 'security',
      action,
      outcome: details?.blocked ? 'success' : 'unknown',
      severity,
      message: `Security event: ${action}`,
      details: details as Record<string, unknown>
    });
  }

  /**
   * Log data access
   */
  dataAccess(action: string, outcome: EventOutcome, details?: {
    dataType?: string;
    classification?: string;
    purpose?: string;
  }): void {
    this.log({
      category: 'data_access',
      action,
      outcome,
      severity: CEFSeverity.MEDIUM,
      message: `Data access: ${action}`,
      details: details as Record<string, unknown>,
      compliance: details?.classification ? {
        dataClassification: details.classification
      } : undefined
    });
  }

  /**
   * Log system event
   */
  system(action: string, outcome: EventOutcome, details?: {
    component?: string;
    version?: string;
    reason?: string;
  }): void {
    this.log({
      category: 'system',
      action,
      outcome,
      severity: outcome === 'failure' ? CEFSeverity.HIGH : CEFSeverity.LOW,
      message: `System ${action}: ${outcome}`,
      details: details as Record<string, unknown>
    });
  }

  /**
   * Flush pending logs and close connections
   */
  async close(): Promise<void> {
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = null;
    }

    this.flush();

    if (this.syslogClient) {
      this.syslogClient.close();
      this.syslogClient = null;
    }
  }
}

// ============================================================================
// Singleton Export
// ============================================================================

export const complianceLog = new ComplianceLogger();

/**
 * Create a new compliance logger with custom config
 */
export function createComplianceLogger(config?: Partial<ComplianceLoggerConfig>): ComplianceLogger {
  return new ComplianceLogger(config);
}

// Types are exported via their interface declarations above
