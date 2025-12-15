/**
 * Compliance Audit Logger for Chrome MCP Server
 *
 * Enterprise-grade audit logging that meets SOC 2, GDPR, and regulatory requirements:
 * - Structured event schema with full attribution
 * - Hash-chained integrity for tamper detection
 * - Multiple output formats (JSONL, CEF, JSON-LD)
 * - Configurable destinations (file, webhook, syslog, S3)
 *
 * Part of Phase 1: Logging & Audit Foundation (v2.3.0)
 *
 * @author Pantheon Security
 */

import crypto from "crypto";
import path from "path";
import os from "os";
import { mkdirSecure, writeFileSecure, appendFileSecure, PERMISSION_MODES } from "../file-permissions.js";

/**
 * Event categories for compliance classification
 */
export type AuditCategory =
  | "auth"      // Authentication events
  | "access"    // Data access events
  | "modify"    // Data modification events
  | "delete"    // Data deletion events
  | "export"    // Data export events
  | "admin"     // Administrative actions
  | "security"  // Security-related events
  | "error"     // Error events
  | "system";   // System events

/**
 * Outcome of an audited action
 */
export type AuditOutcome = "success" | "failure" | "partial" | "denied";

/**
 * Severity levels for events
 */
export type AuditSeverity = "info" | "low" | "medium" | "high" | "critical";

/**
 * Actor information - who performed the action
 */
export interface AuditActor {
  /** Type of actor */
  type: "user" | "system" | "api" | "service";
  /** Actor identifier */
  id: string;
  /** Session ID if applicable */
  sessionId?: string;
  /** Client ID (MCP client) */
  clientId?: string;
  /** IP address if available */
  ip?: string;
  /** User agent if available */
  userAgent?: string;
  /** Additional actor metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Resource information - what was affected
 */
export interface AuditResource {
  /** Type of resource */
  type: string;
  /** Resource identifier */
  id: string;
  /** Human-readable name */
  name?: string;
  /** Resource location/path */
  path?: string;
  /** Additional resource metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Compliance audit event structure
 */
export interface ComplianceAuditEvent {
  /** Unique event ID (UUID v4) */
  id: string;
  /** Event version for schema evolution */
  version: string;
  /** ISO 8601 timestamp with timezone */
  timestamp: string;
  /** Monotonic sequence number for ordering */
  sequence: number;
  /** Event category */
  category: AuditCategory;
  /** Specific action performed */
  action: string;
  /** Severity level */
  severity: AuditSeverity;
  /** Actor who performed the action */
  actor: AuditActor;
  /** Resource affected */
  resource: AuditResource;
  /** Outcome of the action */
  outcome: AuditOutcome;
  /** Duration in milliseconds (if applicable) */
  durationMs?: number;
  /** Additional event details */
  details: Record<string, unknown>;
  /** Compliance tags */
  compliance?: {
    /** Relevant frameworks */
    frameworks?: string[];
    /** Data classification */
    dataClassification?: string;
    /** Retention requirement */
    retentionDays?: number;
  };
  /** Environment information */
  environment: {
    /** Hostname */
    hostname: string;
    /** Service name */
    service: string;
    /** Service version */
    serviceVersion: string;
    /** Environment (prod, staging, dev) */
    env: string;
  };
  /** Hash of previous event for chain integrity */
  previousHash: string;
  /** Hash of this event */
  hash: string;
}

/**
 * Audit logger configuration
 */
export interface AuditLoggerConfig {
  /** Enable audit logging */
  enabled: boolean;
  /** Output format */
  format: "jsonl" | "cef" | "json-ld";
  /** Log directory */
  logDir: string;
  /** Service name */
  serviceName: string;
  /** Service version */
  serviceVersion: string;
  /** Environment */
  environment: string;
  /** Minimum severity to log */
  minSeverity: AuditSeverity;
  /** Include hash chain */
  enableHashChain: boolean;
  /** Flush interval in milliseconds */
  flushIntervalMs: number;
  /** Max buffer size before forced flush */
  maxBufferSize: number;
}

/**
 * Get default configuration from environment
 */
function getDefaultConfig(): AuditLoggerConfig {
  return {
    enabled: process.env.CHROME_MCP_AUDIT_ENABLED !== "false",
    format: (process.env.CHROME_MCP_AUDIT_FORMAT as AuditLoggerConfig["format"]) || "jsonl",
    logDir: process.env.CHROME_MCP_AUDIT_DIR || path.join(os.homedir(), ".chrome-mcp", "audit"),
    serviceName: "chrome-mcp-secure",
    serviceVersion: process.env.npm_package_version || "2.3.0",
    environment: process.env.NODE_ENV || "production",
    minSeverity: (process.env.CHROME_MCP_AUDIT_MIN_SEVERITY as AuditSeverity) || "info",
    enableHashChain: process.env.CHROME_MCP_AUDIT_HASH_CHAIN !== "false",
    flushIntervalMs: parseInt(process.env.CHROME_MCP_AUDIT_FLUSH_INTERVAL || "5000", 10),
    maxBufferSize: parseInt(process.env.CHROME_MCP_AUDIT_MAX_BUFFER || "100", 10),
  };
}

/**
 * Severity ordering for filtering
 */
const SEVERITY_ORDER: Record<AuditSeverity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

/**
 * Generate UUID v4
 */
function generateUUID(): string {
  return crypto.randomUUID();
}

/**
 * Compute SHA-256 hash
 */
function computeHash(data: string): string {
  return crypto.createHash("sha256").update(data).digest("hex");
}

/**
 * Compliance Audit Logger
 */
export class ComplianceAuditLogger {
  private config: AuditLoggerConfig;
  private buffer: ComplianceAuditEvent[] = [];
  private flushTimer: NodeJS.Timeout | null = null;
  private sequence: number = 0;
  private lastHash: string = "0".repeat(64);
  private currentLogFile: string = "";
  private initialized: boolean = false;
  private closed: boolean = false;

  constructor(config?: Partial<AuditLoggerConfig>) {
    this.config = { ...getDefaultConfig(), ...config };
  }

  /**
   * Initialize the audit logger
   */
  async initialize(): Promise<void> {
    if (this.initialized || !this.config.enabled) return;

    // Create log directory
    mkdirSecure(this.config.logDir, PERMISSION_MODES.OWNER_FULL);

    // Set up current log file
    this.updateLogFile();

    // Load last hash from existing log for chain continuity
    await this.loadLastHash();

    // Start flush timer
    this.startFlushTimer();

    this.initialized = true;
  }

  /**
   * Update log file path based on current date
   */
  private updateLogFile(): void {
    const date = new Date().toISOString().split("T")[0];
    const extension = this.config.format === "cef" ? "cef" : "jsonl";
    this.currentLogFile = path.join(this.config.logDir, `audit-${date}.${extension}`);
  }

  /**
   * Load the last hash from existing log file
   */
  private async loadLastHash(): Promise<void> {
    try {
      const fs = await import("fs");
      if (fs.existsSync(this.currentLogFile)) {
        const content = fs.readFileSync(this.currentLogFile, "utf-8");
        const lines = content.trim().split("\n").filter(Boolean);
        if (lines.length > 0) {
          const lastLine = lines[lines.length - 1];
          try {
            const lastEvent = JSON.parse(lastLine);
            if (lastEvent.hash) {
              this.lastHash = lastEvent.hash;
              this.sequence = lastEvent.sequence + 1;
            }
          } catch {
            // Non-JSON format, skip
          }
        }
      }
    } catch {
      // File doesn't exist or can't be read, start fresh
    }
  }

  /**
   * Start the flush timer
   */
  private startFlushTimer(): void {
    if (this.flushTimer) return;

    this.flushTimer = setInterval(() => {
      this.flush().catch((err) => {
        console.error(`Audit log flush failed: ${err}`);
      });
    }, this.config.flushIntervalMs);
  }

  /**
   * Stop the flush timer
   */
  private stopFlushTimer(): void {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }
  }

  /**
   * Check if severity meets minimum threshold
   */
  private shouldLog(severity: AuditSeverity): boolean {
    return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[this.config.minSeverity];
  }

  /**
   * Log an audit event
   */
  async log(params: {
    category: AuditCategory;
    action: string;
    severity?: AuditSeverity;
    actor: Partial<AuditActor>;
    resource: Partial<AuditResource>;
    outcome: AuditOutcome;
    durationMs?: number;
    details?: Record<string, unknown>;
    compliance?: ComplianceAuditEvent["compliance"];
  }): Promise<ComplianceAuditEvent | null> {
    if (!this.config.enabled || this.closed) return null;

    const severity = params.severity || "info";
    if (!this.shouldLog(severity)) return null;

    await this.initialize();

    // Check if date changed (new log file)
    const currentDate = new Date().toISOString().split("T")[0];
    if (!this.currentLogFile.includes(currentDate)) {
      await this.flush();
      this.updateLogFile();
    }

    // Build the event
    const event: Omit<ComplianceAuditEvent, "hash"> = {
      id: generateUUID(),
      version: "1.0",
      timestamp: new Date().toISOString(),
      sequence: this.sequence++,
      category: params.category,
      action: params.action,
      severity,
      actor: {
        type: params.actor.type || "system",
        id: params.actor.id || "unknown",
        sessionId: params.actor.sessionId,
        clientId: params.actor.clientId,
        ip: params.actor.ip,
        userAgent: params.actor.userAgent,
        metadata: params.actor.metadata,
      },
      resource: {
        type: params.resource.type || "unknown",
        id: params.resource.id || "unknown",
        name: params.resource.name,
        path: params.resource.path,
        metadata: params.resource.metadata,
      },
      outcome: params.outcome,
      durationMs: params.durationMs,
      details: params.details || {},
      compliance: params.compliance,
      environment: {
        hostname: os.hostname(),
        service: this.config.serviceName,
        serviceVersion: this.config.serviceVersion,
        env: this.config.environment,
      },
      previousHash: this.lastHash,
    };

    // Compute hash for chain integrity
    const hashInput = JSON.stringify(event);
    const hash = this.config.enableHashChain ? computeHash(hashInput) : "";

    const fullEvent: ComplianceAuditEvent = {
      ...event,
      hash,
    };

    // Update last hash
    if (this.config.enableHashChain) {
      this.lastHash = hash;
    }

    // Add to buffer
    this.buffer.push(fullEvent);

    // Force flush if buffer is full
    if (this.buffer.length >= this.config.maxBufferSize) {
      await this.flush();
    }

    return fullEvent;
  }

  /**
   * Convenience methods for common event types
   */

  async logAuth(params: {
    action: string;
    actor: Partial<AuditActor>;
    outcome: AuditOutcome;
    details?: Record<string, unknown>;
  }): Promise<ComplianceAuditEvent | null> {
    return this.log({
      category: "auth",
      action: params.action,
      severity: params.outcome === "failure" ? "medium" : "info",
      actor: params.actor,
      resource: { type: "auth", id: "session" },
      outcome: params.outcome,
      details: params.details,
      compliance: { frameworks: ["SOC2", "ISO27001"] },
    });
  }

  async logAccess(params: {
    action: string;
    actor: Partial<AuditActor>;
    resource: Partial<AuditResource>;
    outcome: AuditOutcome;
    details?: Record<string, unknown>;
  }): Promise<ComplianceAuditEvent | null> {
    return this.log({
      category: "access",
      action: params.action,
      severity: "info",
      actor: params.actor,
      resource: params.resource,
      outcome: params.outcome,
      details: params.details,
      compliance: { frameworks: ["SOC2", "GDPR"] },
    });
  }

  async logModify(params: {
    action: string;
    actor: Partial<AuditActor>;
    resource: Partial<AuditResource>;
    outcome: AuditOutcome;
    details?: Record<string, unknown>;
  }): Promise<ComplianceAuditEvent | null> {
    return this.log({
      category: "modify",
      action: params.action,
      severity: "low",
      actor: params.actor,
      resource: params.resource,
      outcome: params.outcome,
      details: params.details,
      compliance: { frameworks: ["SOC2", "GDPR"] },
    });
  }

  async logDelete(params: {
    action: string;
    actor: Partial<AuditActor>;
    resource: Partial<AuditResource>;
    outcome: AuditOutcome;
    details?: Record<string, unknown>;
  }): Promise<ComplianceAuditEvent | null> {
    return this.log({
      category: "delete",
      action: params.action,
      severity: "medium",
      actor: params.actor,
      resource: params.resource,
      outcome: params.outcome,
      details: params.details,
      compliance: { frameworks: ["SOC2", "GDPR"], retentionDays: 365 },
    });
  }

  async logExport(params: {
    action: string;
    actor: Partial<AuditActor>;
    resource: Partial<AuditResource>;
    outcome: AuditOutcome;
    details?: Record<string, unknown>;
  }): Promise<ComplianceAuditEvent | null> {
    return this.log({
      category: "export",
      action: params.action,
      severity: "medium",
      actor: params.actor,
      resource: params.resource,
      outcome: params.outcome,
      details: params.details,
      compliance: { frameworks: ["GDPR", "CCPA"] },
    });
  }

  async logSecurity(params: {
    action: string;
    severity: AuditSeverity;
    actor: Partial<AuditActor>;
    resource: Partial<AuditResource>;
    outcome: AuditOutcome;
    details?: Record<string, unknown>;
  }): Promise<ComplianceAuditEvent | null> {
    return this.log({
      category: "security",
      action: params.action,
      severity: params.severity,
      actor: params.actor,
      resource: params.resource,
      outcome: params.outcome,
      details: params.details,
      compliance: { frameworks: ["SOC2", "ISO27001", "PCI-DSS"] },
    });
  }

  async logError(params: {
    action: string;
    actor: Partial<AuditActor>;
    resource: Partial<AuditResource>;
    error: Error | string;
    details?: Record<string, unknown>;
  }): Promise<ComplianceAuditEvent | null> {
    const errorMessage = params.error instanceof Error ? params.error.message : params.error;
    const errorStack = params.error instanceof Error ? params.error.stack : undefined;

    return this.log({
      category: "error",
      action: params.action,
      severity: "high",
      actor: params.actor,
      resource: params.resource,
      outcome: "failure",
      details: {
        ...params.details,
        error: errorMessage,
        stack: errorStack,
      },
    });
  }

  async logSystem(params: {
    action: string;
    details?: Record<string, unknown>;
  }): Promise<ComplianceAuditEvent | null> {
    return this.log({
      category: "system",
      action: params.action,
      severity: "info",
      actor: { type: "system", id: "chrome-mcp-secure" },
      resource: { type: "system", id: "server" },
      outcome: "success",
      details: params.details,
    });
  }

  /**
   * Flush buffer to disk
   */
  async flush(): Promise<void> {
    if (this.buffer.length === 0) return;

    const events = [...this.buffer];
    this.buffer = [];

    try {
      const { formatEvent } = await import("./formats/cef.js");
      const { formatEventJsonLD } = await import("./formats/json-ld.js");

      let content: string;

      switch (this.config.format) {
        case "cef":
          content = events.map((e) => formatEvent(e)).join("\n") + "\n";
          break;
        case "json-ld":
          content = events.map((e) => JSON.stringify(formatEventJsonLD(e))).join("\n") + "\n";
          break;
        default:
          content = events.map((e) => JSON.stringify(e)).join("\n") + "\n";
      }

      appendFileSecure(this.currentLogFile, content, PERMISSION_MODES.OWNER_READ_WRITE);
    } catch (error) {
      // Re-add events to buffer on failure
      this.buffer = [...events, ...this.buffer];
      throw error;
    }
  }

  /**
   * Get buffered events (for testing/debugging)
   */
  getBufferedEvents(): ComplianceAuditEvent[] {
    return [...this.buffer];
  }

  /**
   * Get current log file path
   */
  getCurrentLogFile(): string {
    return this.currentLogFile;
  }

  /**
   * Get logger statistics
   */
  getStats(): {
    enabled: boolean;
    initialized: boolean;
    bufferedEvents: number;
    sequence: number;
    lastHash: string;
    currentLogFile: string;
  } {
    return {
      enabled: this.config.enabled,
      initialized: this.initialized,
      bufferedEvents: this.buffer.length,
      sequence: this.sequence,
      lastHash: this.lastHash.substring(0, 16) + "...",
      currentLogFile: this.currentLogFile,
    };
  }

  /**
   * Close the logger
   */
  async close(): Promise<void> {
    if (this.closed) return;

    this.stopFlushTimer();
    await this.flush();
    this.closed = true;
  }
}

/**
 * Global audit logger instance
 */
let globalAuditLogger: ComplianceAuditLogger | null = null;

/**
 * Get or create the global compliance audit logger
 */
export function getComplianceAuditLogger(): ComplianceAuditLogger {
  if (!globalAuditLogger) {
    globalAuditLogger = new ComplianceAuditLogger();
  }
  return globalAuditLogger;
}

/**
 * Convenience function to log a compliance event
 */
export async function logComplianceEvent(params: Parameters<ComplianceAuditLogger["log"]>[0]): Promise<ComplianceAuditEvent | null> {
  return getComplianceAuditLogger().log(params);
}
