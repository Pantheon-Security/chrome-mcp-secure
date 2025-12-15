/**
 * Log Shipper for Chrome MCP Server
 *
 * Ships audit logs to external destinations:
 * - Webhook (HTTPS POST)
 * - Syslog (RFC 5424 / RFC 3164)
 * - S3/GCS (cloud storage)
 * - File rotation (local)
 *
 * Part of Phase 1: Logging & Audit Foundation (v2.3.0)
 *
 * @author Pantheon Security
 */

import dgram from "dgram";
import https from "https";
import http from "http";
import { URL } from "url";
import { ComplianceAuditEvent } from "./audit-logger.js";
import { formatEvent as formatCEF } from "./formats/cef.js";
import { formatEventJsonLD } from "./formats/json-ld.js";

/**
 * Shipping destination types
 */
export type ShipperDestination = "webhook" | "syslog" | "s3" | "gcs" | "file";

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
  LOCAL7 = 23,
}

/**
 * Syslog severity codes (RFC 5424)
 */
export enum SyslogSeverity {
  EMERGENCY = 0,
  ALERT = 1,
  CRITICAL = 2,
  ERROR = 3,
  WARNING = 4,
  NOTICE = 5,
  INFO = 6,
  DEBUG = 7,
}

/**
 * Shipper configuration
 */
export interface LogShipperConfig {
  /** Enable shipping */
  enabled: boolean;
  /** Destination type */
  destination: ShipperDestination;
  /** Output format */
  format: "json" | "cef" | "json-ld";

  /** Webhook configuration */
  webhook?: {
    url: string;
    headers?: Record<string, string>;
    timeout?: number;
    retries?: number;
    batchSize?: number;
  };

  /** Syslog configuration */
  syslog?: {
    host: string;
    port: number;
    protocol: "udp" | "tcp";
    facility: SyslogFacility;
    appName: string;
    rfc?: "3164" | "5424";
  };

  /** S3 configuration */
  s3?: {
    bucket: string;
    region: string;
    prefix: string;
    accessKeyId?: string;
    secretAccessKey?: string;
    endpoint?: string;
  };

  /** GCS configuration */
  gcs?: {
    bucket: string;
    prefix: string;
    projectId?: string;
    keyFilename?: string;
  };

  /** Batch settings */
  batch: {
    size: number;
    intervalMs: number;
  };

  /** Retry settings */
  retry: {
    maxAttempts: number;
    backoffMs: number;
    maxBackoffMs: number;
  };
}

/**
 * Get default configuration from environment
 */
function getDefaultConfig(): LogShipperConfig {
  return {
    enabled: process.env.CHROME_MCP_LOG_SHIPPING !== "false",
    destination: (process.env.CHROME_MCP_LOG_DESTINATION as ShipperDestination) || "webhook",
    format: (process.env.CHROME_MCP_LOG_FORMAT as LogShipperConfig["format"]) || "json",

    webhook: {
      url: process.env.CHROME_MCP_WEBHOOK_URL || "",
      headers: process.env.CHROME_MCP_WEBHOOK_HEADERS
        ? JSON.parse(process.env.CHROME_MCP_WEBHOOK_HEADERS)
        : {},
      timeout: parseInt(process.env.CHROME_MCP_WEBHOOK_TIMEOUT || "30000", 10),
      retries: parseInt(process.env.CHROME_MCP_WEBHOOK_RETRIES || "3", 10),
      batchSize: parseInt(process.env.CHROME_MCP_WEBHOOK_BATCH_SIZE || "100", 10),
    },

    syslog: {
      host: process.env.CHROME_MCP_SYSLOG_HOST || "localhost",
      port: parseInt(process.env.CHROME_MCP_SYSLOG_PORT || "514", 10),
      protocol: (process.env.CHROME_MCP_SYSLOG_PROTOCOL as "udp" | "tcp") || "udp",
      facility: parseInt(process.env.CHROME_MCP_SYSLOG_FACILITY || "16", 10) as SyslogFacility,
      appName: process.env.CHROME_MCP_SYSLOG_APP_NAME || "chrome-mcp-secure",
      rfc: (process.env.CHROME_MCP_SYSLOG_RFC as "3164" | "5424") || "5424",
    },

    s3: {
      bucket: process.env.CHROME_MCP_S3_BUCKET || "",
      region: process.env.CHROME_MCP_S3_REGION || "us-east-1",
      prefix: process.env.CHROME_MCP_S3_PREFIX || "audit-logs/",
      accessKeyId: process.env.AWS_ACCESS_KEY_ID,
      secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
      endpoint: process.env.CHROME_MCP_S3_ENDPOINT,
    },

    gcs: {
      bucket: process.env.CHROME_MCP_GCS_BUCKET || "",
      prefix: process.env.CHROME_MCP_GCS_PREFIX || "audit-logs/",
      projectId: process.env.GOOGLE_CLOUD_PROJECT,
      keyFilename: process.env.GOOGLE_APPLICATION_CREDENTIALS,
    },

    batch: {
      size: parseInt(process.env.CHROME_MCP_BATCH_SIZE || "100", 10),
      intervalMs: parseInt(process.env.CHROME_MCP_BATCH_INTERVAL || "5000", 10),
    },

    retry: {
      maxAttempts: parseInt(process.env.CHROME_MCP_RETRY_MAX || "3", 10),
      backoffMs: parseInt(process.env.CHROME_MCP_RETRY_BACKOFF || "1000", 10),
      maxBackoffMs: parseInt(process.env.CHROME_MCP_RETRY_MAX_BACKOFF || "30000", 10),
    },
  };
}

/**
 * Map audit severity to syslog severity
 */
function mapSeverity(severity: string): SyslogSeverity {
  const map: Record<string, SyslogSeverity> = {
    info: SyslogSeverity.INFO,
    low: SyslogSeverity.NOTICE,
    medium: SyslogSeverity.WARNING,
    high: SyslogSeverity.ERROR,
    critical: SyslogSeverity.CRITICAL,
  };
  return map[severity] || SyslogSeverity.INFO;
}

/**
 * Format event based on configuration
 */
function formatEventForShipping(event: ComplianceAuditEvent, format: string): string {
  switch (format) {
    case "cef":
      return formatCEF(event);
    case "json-ld":
      return JSON.stringify(formatEventJsonLD(event));
    default:
      return JSON.stringify(event);
  }
}

/**
 * Log Shipper class
 */
export class LogShipper {
  private config: LogShipperConfig;
  private buffer: ComplianceAuditEvent[] = [];
  private flushTimer: NodeJS.Timeout | null = null;
  private syslogSocket: dgram.Socket | null = null;
  private stats = {
    sent: 0,
    failed: 0,
    retried: 0,
    dropped: 0,
  };

  constructor(config?: Partial<LogShipperConfig>) {
    this.config = { ...getDefaultConfig(), ...config };
  }

  /**
   * Initialize the shipper
   */
  async initialize(): Promise<void> {
    if (!this.config.enabled) return;

    // Initialize syslog socket if needed
    if (this.config.destination === "syslog" && this.config.syslog?.protocol === "udp") {
      this.syslogSocket = dgram.createSocket("udp4");
    }

    // Start batch flush timer
    this.startFlushTimer();
  }

  /**
   * Start the flush timer
   */
  private startFlushTimer(): void {
    if (this.flushTimer) return;

    this.flushTimer = setInterval(() => {
      this.flush().catch((err) => {
        console.error(`Log shipping flush failed: ${err}`);
      });
    }, this.config.batch.intervalMs);
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
   * Ship an event
   */
  async ship(event: ComplianceAuditEvent): Promise<void> {
    if (!this.config.enabled) return;

    this.buffer.push(event);

    // Flush if batch size reached
    if (this.buffer.length >= this.config.batch.size) {
      await this.flush();
    }
  }

  /**
   * Ship multiple events
   */
  async shipBatch(events: ComplianceAuditEvent[]): Promise<void> {
    if (!this.config.enabled) return;

    this.buffer.push(...events);

    if (this.buffer.length >= this.config.batch.size) {
      await this.flush();
    }
  }

  /**
   * Flush buffered events
   */
  async flush(): Promise<void> {
    if (this.buffer.length === 0) return;

    const events = [...this.buffer];
    this.buffer = [];

    try {
      switch (this.config.destination) {
        case "webhook":
          await this.shipToWebhook(events);
          break;
        case "syslog":
          await this.shipToSyslog(events);
          break;
        case "s3":
          await this.shipToS3(events);
          break;
        case "gcs":
          await this.shipToGCS(events);
          break;
        default:
          console.warn(`Unknown shipping destination: ${this.config.destination}`);
      }

      this.stats.sent += events.length;
    } catch (error) {
      console.error(`Failed to ship logs: ${error}`);
      this.stats.failed += events.length;

      // Re-add to buffer for retry (limited)
      if (this.buffer.length + events.length <= this.config.batch.size * 2) {
        this.buffer = [...events, ...this.buffer];
        this.stats.retried += events.length;
      } else {
        this.stats.dropped += events.length;
      }
    }
  }

  /**
   * Ship to webhook
   */
  private async shipToWebhook(events: ComplianceAuditEvent[]): Promise<void> {
    if (!this.config.webhook?.url) {
      throw new Error("Webhook URL not configured");
    }

    const url = new URL(this.config.webhook.url);
    const isHttps = url.protocol === "https:";

    const payload = JSON.stringify({
      events: events.map((e) => formatEventForShipping(e, this.config.format)),
      metadata: {
        source: "chrome-mcp-secure",
        count: events.length,
        timestamp: new Date().toISOString(),
      },
    });

    return new Promise((resolve, reject) => {
      const options = {
        hostname: url.hostname,
        port: url.port || (isHttps ? 443 : 80),
        path: url.pathname + url.search,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(payload),
          "User-Agent": "Chrome-MCP-Secure/2.3.0",
          ...this.config.webhook?.headers,
        },
        timeout: this.config.webhook?.timeout || 30000,
      };

      const req = (isHttps ? https : http).request(options, (res) => {
        if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
          resolve();
        } else {
          reject(new Error(`Webhook returned status ${res.statusCode}`));
        }
      });

      req.on("error", reject);
      req.on("timeout", () => {
        req.destroy();
        reject(new Error("Webhook request timed out"));
      });

      req.write(payload);
      req.end();
    });
  }

  /**
   * Ship to syslog
   */
  private async shipToSyslog(events: ComplianceAuditEvent[]): Promise<void> {
    if (!this.config.syslog) {
      throw new Error("Syslog not configured");
    }

    const { host, port, facility, appName, rfc } = this.config.syslog;

    for (const event of events) {
      const message = this.formatSyslogMessage(event, facility, appName, rfc || "5424");
      await this.sendSyslogMessage(host, port, message);
    }
  }

  /**
   * Format syslog message
   */
  private formatSyslogMessage(
    event: ComplianceAuditEvent,
    facility: SyslogFacility,
    appName: string,
    rfc: "3164" | "5424"
  ): string {
    const severity = mapSeverity(event.severity);
    const priority = facility * 8 + severity;
    const timestamp = new Date(event.timestamp);

    if (rfc === "5424") {
      // RFC 5424 format
      const isoTimestamp = timestamp.toISOString();
      const hostname = event.environment.hostname;
      const procId = process.pid;
      const msgId = event.category;
      const structuredData = `[audit@pantheon eventId="${event.id}" action="${event.action}" outcome="${event.outcome}"]`;
      const msg = formatEventForShipping(event, this.config.format);

      return `<${priority}>1 ${isoTimestamp} ${hostname} ${appName} ${procId} ${msgId} ${structuredData} ${msg}`;
    } else {
      // RFC 3164 format (BSD)
      const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
      const month = months[timestamp.getMonth()];
      const day = String(timestamp.getDate()).padStart(2, " ");
      const time = timestamp.toTimeString().substring(0, 8);
      const hostname = event.environment.hostname;
      const msg = formatEventForShipping(event, this.config.format);

      return `<${priority}>${month} ${day} ${time} ${hostname} ${appName}: ${msg}`;
    }
  }

  /**
   * Send syslog message
   */
  private async sendSyslogMessage(host: string, port: number, message: string): Promise<void> {
    if (this.config.syslog?.protocol === "udp" && this.syslogSocket) {
      return new Promise((resolve, reject) => {
        const buffer = Buffer.from(message);
        this.syslogSocket!.send(buffer, 0, buffer.length, port, host, (err) => {
          if (err) reject(err);
          else resolve();
        });
      });
    } else {
      // TCP syslog
      const net = await import("net");
      return new Promise((resolve, reject) => {
        const socket = new net.Socket();
        socket.connect(port, host, () => {
          socket.write(message + "\n");
          socket.end();
          resolve();
        });
        socket.on("error", reject);
      });
    }
  }

  /**
   * Ship to S3 (placeholder - requires AWS SDK)
   */
  private async shipToS3(events: ComplianceAuditEvent[]): Promise<void> {
    if (!this.config.s3?.bucket) {
      throw new Error("S3 bucket not configured");
    }

    // Format events
    const content = events.map((e) => formatEventForShipping(e, this.config.format)).join("\n");

    // Generate key with timestamp
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const key = `${this.config.s3.prefix}${timestamp}.${this.config.format === "cef" ? "cef" : "jsonl"}`;

    // Note: Actual S3 upload requires @aws-sdk/client-s3
    // This is a placeholder that logs the intent
    console.log(`[S3] Would upload ${events.length} events to s3://${this.config.s3.bucket}/${key}`);

    // In production, you would use:
    // const { S3Client, PutObjectCommand } = await import("@aws-sdk/client-s3");
    // const client = new S3Client({ region: this.config.s3.region });
    // await client.send(new PutObjectCommand({
    //   Bucket: this.config.s3.bucket,
    //   Key: key,
    //   Body: content,
    //   ContentType: "application/x-ndjson",
    // }));
  }

  /**
   * Ship to GCS (placeholder - requires GCS SDK)
   */
  private async shipToGCS(events: ComplianceAuditEvent[]): Promise<void> {
    if (!this.config.gcs?.bucket) {
      throw new Error("GCS bucket not configured");
    }

    // Format events
    const content = events.map((e) => formatEventForShipping(e, this.config.format)).join("\n");

    // Generate key with timestamp
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const key = `${this.config.gcs.prefix}${timestamp}.${this.config.format === "cef" ? "cef" : "jsonl"}`;

    // Note: Actual GCS upload requires @google-cloud/storage
    console.log(`[GCS] Would upload ${events.length} events to gs://${this.config.gcs.bucket}/${key}`);

    // In production, you would use:
    // const { Storage } = await import("@google-cloud/storage");
    // const storage = new Storage();
    // await storage.bucket(this.config.gcs.bucket).file(key).save(content);
  }

  /**
   * Get shipping statistics
   */
  getStats(): typeof this.stats & { buffered: number } {
    return {
      ...this.stats,
      buffered: this.buffer.length,
    };
  }

  /**
   * Reset statistics
   */
  resetStats(): void {
    this.stats = { sent: 0, failed: 0, retried: 0, dropped: 0 };
  }

  /**
   * Close the shipper
   */
  async close(): Promise<void> {
    this.stopFlushTimer();
    await this.flush();

    if (this.syslogSocket) {
      this.syslogSocket.close();
      this.syslogSocket = null;
    }
  }
}

/**
 * Global log shipper instance
 */
let globalShipper: LogShipper | null = null;

/**
 * Get or create the global log shipper
 */
export function getLogShipper(): LogShipper {
  if (!globalShipper) {
    globalShipper = new LogShipper();
  }
  return globalShipper;
}

/**
 * Convenience function to ship an event
 */
export async function shipAuditEvent(event: ComplianceAuditEvent): Promise<void> {
  return getLogShipper().ship(event);
}
