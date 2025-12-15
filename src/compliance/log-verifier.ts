/**
 * Log Verifier for Chrome MCP Server
 *
 * Verifies audit log integrity:
 * - Hash chain validation
 * - Sequence continuity checking
 * - Gap detection
 * - Tampering detection
 * - Verification reports
 *
 * Part of Phase 1: Logging & Audit Foundation (v2.3.0)
 *
 * @author Pantheon Security
 */

import fs from "fs";
import path from "path";
import crypto from "crypto";
import zlib from "zlib";
import { promisify } from "util";
import readline from "readline";
import { ComplianceAuditEvent } from "./audit-logger.js";

const gunzip = promisify(zlib.gunzip);

/**
 * Verification result for a single event
 */
export interface EventVerification {
  eventId: string;
  sequence: number;
  timestamp: string;
  hashValid: boolean;
  chainValid: boolean;
  sequenceValid: boolean;
  errors: string[];
}

/**
 * Verification result for a log file
 */
export interface FileVerification {
  filePath: string;
  fileName: string;
  totalEvents: number;
  validEvents: number;
  invalidEvents: number;
  hashChainValid: boolean;
  sequenceValid: boolean;
  firstEvent: string | null;
  lastEvent: string | null;
  firstSequence: number | null;
  lastSequence: number | null;
  gaps: Array<{ from: number; to: number }>;
  errors: string[];
  events?: EventVerification[];
}

/**
 * Full verification report
 */
export interface VerificationReport {
  timestamp: string;
  logDir: string;
  dateRange: {
    from: string | null;
    to: string | null;
  };
  summary: {
    totalFiles: number;
    validFiles: number;
    invalidFiles: number;
    totalEvents: number;
    validEvents: number;
    invalidEvents: number;
    hashChainIntact: boolean;
    sequenceIntact: boolean;
  };
  files: FileVerification[];
  crossFileGaps: Array<{
    fromFile: string;
    toFile: string;
    fromSequence: number;
    toSequence: number;
  }>;
  recommendations: string[];
}

/**
 * Compute expected hash for an event
 */
function computeExpectedHash(event: Omit<ComplianceAuditEvent, "hash">): string {
  const hashInput = JSON.stringify(event);
  return crypto.createHash("sha256").update(hashInput).digest("hex");
}

/**
 * Parse a log line to event
 */
function parseLogLine(line: string): ComplianceAuditEvent | null {
  try {
    const event = JSON.parse(line);

    // Validate required fields
    if (!event.id || !event.timestamp || !event.sequence === undefined) {
      return null;
    }

    return event as ComplianceAuditEvent;
  } catch {
    return null;
  }
}

/**
 * Read events from a log file
 */
async function readLogFile(filePath: string): Promise<ComplianceAuditEvent[]> {
  const events: ComplianceAuditEvent[] = [];

  let content: string;

  if (filePath.endsWith(".gz")) {
    const compressed = fs.readFileSync(filePath);
    const decompressed = await gunzip(compressed);
    content = decompressed.toString("utf-8");
  } else {
    content = fs.readFileSync(filePath, "utf-8");
  }

  const lines = content.split("\n").filter(Boolean);

  for (const line of lines) {
    const event = parseLogLine(line);
    if (event) {
      events.push(event);
    }
  }

  return events;
}

/**
 * Verify a single event's hash
 */
function verifyEventHash(event: ComplianceAuditEvent): boolean {
  if (!event.hash) {
    return true; // Hash chain disabled
  }

  const { hash, ...eventWithoutHash } = event;
  const expectedHash = computeExpectedHash(eventWithoutHash);

  return hash === expectedHash;
}

/**
 * Verify hash chain between events
 */
function verifyHashChain(currentEvent: ComplianceAuditEvent, previousEvent: ComplianceAuditEvent | null): boolean {
  if (!currentEvent.previousHash) {
    return true; // Hash chain disabled
  }

  if (!previousEvent) {
    // First event should have zero hash as previous
    return currentEvent.previousHash === "0".repeat(64);
  }

  return currentEvent.previousHash === previousEvent.hash;
}

/**
 * Log Verifier class
 */
export class LogVerifier {
  private logDir: string;

  constructor(logDir?: string) {
    this.logDir = logDir || path.join(
      process.env.HOME || process.env.USERPROFILE || "/tmp",
      ".chrome-mcp",
      "audit"
    );
  }

  /**
   * Verify a single log file
   */
  async verifyFile(filePath: string, includeEvents: boolean = false): Promise<FileVerification> {
    const result: FileVerification = {
      filePath,
      fileName: path.basename(filePath),
      totalEvents: 0,
      validEvents: 0,
      invalidEvents: 0,
      hashChainValid: true,
      sequenceValid: true,
      firstEvent: null,
      lastEvent: null,
      firstSequence: null,
      lastSequence: null,
      gaps: [],
      errors: [],
      events: includeEvents ? [] : undefined,
    };

    try {
      const events = await readLogFile(filePath);
      result.totalEvents = events.length;

      if (events.length === 0) {
        result.errors.push("File contains no valid events");
        return result;
      }

      let previousEvent: ComplianceAuditEvent | null = null;
      let previousSequence: number | null = null;

      for (const event of events) {
        const eventVerification: EventVerification = {
          eventId: event.id,
          sequence: event.sequence,
          timestamp: event.timestamp,
          hashValid: true,
          chainValid: true,
          sequenceValid: true,
          errors: [],
        };

        // Verify hash
        if (!verifyEventHash(event)) {
          eventVerification.hashValid = false;
          eventVerification.errors.push("Hash verification failed");
          result.hashChainValid = false;
        }

        // Verify chain
        if (!verifyHashChain(event, previousEvent)) {
          eventVerification.chainValid = false;
          eventVerification.errors.push("Hash chain broken");
          result.hashChainValid = false;
        }

        // Verify sequence
        if (previousSequence !== null && event.sequence !== previousSequence + 1) {
          eventVerification.sequenceValid = false;
          eventVerification.errors.push(`Sequence gap: expected ${previousSequence + 1}, got ${event.sequence}`);
          result.sequenceValid = false;
          result.gaps.push({ from: previousSequence, to: event.sequence });
        }

        if (eventVerification.errors.length > 0) {
          result.invalidEvents++;
        } else {
          result.validEvents++;
        }

        if (includeEvents) {
          result.events!.push(eventVerification);
        }

        // Track first/last
        if (result.firstEvent === null) {
          result.firstEvent = event.timestamp;
          result.firstSequence = event.sequence;
        }
        result.lastEvent = event.timestamp;
        result.lastSequence = event.sequence;

        previousEvent = event;
        previousSequence = event.sequence;
      }
    } catch (error) {
      result.errors.push(`Failed to read file: ${error}`);
    }

    return result;
  }

  /**
   * Get all log files in directory
   */
  async getLogFiles(): Promise<string[]> {
    if (!fs.existsSync(this.logDir)) {
      return [];
    }

    const files = fs.readdirSync(this.logDir);
    return files
      .filter((f) => f.startsWith("audit-") && (f.endsWith(".jsonl") || f.endsWith(".jsonl.gz")))
      .map((f) => path.join(this.logDir, f))
      .sort();
  }

  /**
   * Verify all log files
   */
  async verifyAll(options?: {
    from?: Date;
    to?: Date;
    includeEvents?: boolean;
  }): Promise<VerificationReport> {
    const report: VerificationReport = {
      timestamp: new Date().toISOString(),
      logDir: this.logDir,
      dateRange: {
        from: options?.from?.toISOString() || null,
        to: options?.to?.toISOString() || null,
      },
      summary: {
        totalFiles: 0,
        validFiles: 0,
        invalidFiles: 0,
        totalEvents: 0,
        validEvents: 0,
        invalidEvents: 0,
        hashChainIntact: true,
        sequenceIntact: true,
      },
      files: [],
      crossFileGaps: [],
      recommendations: [],
    };

    const logFiles = await this.getLogFiles();
    report.summary.totalFiles = logFiles.length;

    if (logFiles.length === 0) {
      report.recommendations.push("No audit log files found");
      return report;
    }

    let previousFileLastSequence: number | null = null;
    let previousFileName: string | null = null;

    for (const filePath of logFiles) {
      // Filter by date if specified
      if (options?.from || options?.to) {
        const fileName = path.basename(filePath);
        const dateMatch = fileName.match(/audit-(\d{4}-\d{2}-\d{2})/);
        if (dateMatch) {
          const fileDate = new Date(dateMatch[1]);
          if (options?.from && fileDate < options.from) continue;
          if (options?.to && fileDate > options.to) continue;
        }
      }

      const fileResult = await this.verifyFile(filePath, options?.includeEvents);
      report.files.push(fileResult);

      // Update summary
      report.summary.totalEvents += fileResult.totalEvents;
      report.summary.validEvents += fileResult.validEvents;
      report.summary.invalidEvents += fileResult.invalidEvents;

      if (fileResult.errors.length > 0 || !fileResult.hashChainValid || !fileResult.sequenceValid) {
        report.summary.invalidFiles++;
        if (!fileResult.hashChainValid) report.summary.hashChainIntact = false;
        if (!fileResult.sequenceValid) report.summary.sequenceIntact = false;
      } else {
        report.summary.validFiles++;
      }

      // Check cross-file sequence continuity
      if (previousFileLastSequence !== null && fileResult.firstSequence !== null) {
        if (fileResult.firstSequence !== previousFileLastSequence + 1) {
          report.crossFileGaps.push({
            fromFile: previousFileName!,
            toFile: path.basename(filePath),
            fromSequence: previousFileLastSequence,
            toSequence: fileResult.firstSequence,
          });
          report.summary.sequenceIntact = false;
        }
      }

      previousFileLastSequence = fileResult.lastSequence;
      previousFileName = path.basename(filePath);
    }

    // Generate recommendations
    if (!report.summary.hashChainIntact) {
      report.recommendations.push("Hash chain integrity compromised - potential tampering detected");
      report.recommendations.push("Review invalid events for unauthorized modifications");
    }

    if (!report.summary.sequenceIntact) {
      report.recommendations.push("Sequence gaps detected - potential missing events");
      report.recommendations.push("Check for log rotation issues or system restarts");
    }

    if (report.summary.invalidEvents > 0) {
      report.recommendations.push(`${report.summary.invalidEvents} events failed verification`);
    }

    if (report.summary.validFiles === report.summary.totalFiles && report.summary.hashChainIntact) {
      report.recommendations.push("All audit logs verified successfully - integrity intact");
    }

    return report;
  }

  /**
   * Verify a specific date range
   */
  async verifyDateRange(from: Date, to: Date): Promise<VerificationReport> {
    return this.verifyAll({ from, to });
  }

  /**
   * Quick verification (summary only)
   */
  async quickVerify(): Promise<{
    intact: boolean;
    totalEvents: number;
    issues: string[];
  }> {
    const report = await this.verifyAll();

    return {
      intact: report.summary.hashChainIntact && report.summary.sequenceIntact,
      totalEvents: report.summary.totalEvents,
      issues: report.recommendations.filter((r) => !r.includes("successfully")),
    };
  }

  /**
   * Find events in a time range
   */
  async findEvents(options: {
    from?: Date;
    to?: Date;
    category?: string;
    action?: string;
    actor?: string;
    limit?: number;
  }): Promise<ComplianceAuditEvent[]> {
    const results: ComplianceAuditEvent[] = [];
    const logFiles = await this.getLogFiles();

    for (const filePath of logFiles) {
      const events = await readLogFile(filePath);

      for (const event of events) {
        // Apply filters
        if (options.from && new Date(event.timestamp) < options.from) continue;
        if (options.to && new Date(event.timestamp) > options.to) continue;
        if (options.category && event.category !== options.category) continue;
        if (options.action && event.action !== options.action) continue;
        if (options.actor && event.actor.id !== options.actor) continue;

        results.push(event);

        if (options.limit && results.length >= options.limit) {
          return results;
        }
      }
    }

    return results;
  }

  /**
   * Generate verification certificate
   */
  async generateCertificate(): Promise<{
    timestamp: string;
    logDir: string;
    fileCount: number;
    eventCount: number;
    firstEvent: string | null;
    lastEvent: string | null;
    integrityHash: string;
    verified: boolean;
    signature: string;
  }> {
    const report = await this.verifyAll();

    const cert = {
      timestamp: new Date().toISOString(),
      logDir: this.logDir,
      fileCount: report.summary.totalFiles,
      eventCount: report.summary.totalEvents,
      firstEvent: report.files[0]?.firstEvent || null,
      lastEvent: report.files[report.files.length - 1]?.lastEvent || null,
      integrityHash: crypto
        .createHash("sha256")
        .update(JSON.stringify(report.summary))
        .digest("hex"),
      verified: report.summary.hashChainIntact && report.summary.sequenceIntact,
    };

    const signature = crypto
      .createHmac("sha256", process.env.CHROME_MCP_SIGNING_KEY || "default-key")
      .update(JSON.stringify(cert))
      .digest("hex");

    return { ...cert, signature };
  }
}

/**
 * Global verifier instance
 */
let globalVerifier: LogVerifier | null = null;

/**
 * Get or create the global log verifier
 */
export function getLogVerifier(logDir?: string): LogVerifier {
  if (!globalVerifier || logDir) {
    globalVerifier = new LogVerifier(logDir);
  }
  return globalVerifier;
}

/**
 * Quick verification function
 */
export async function verifyAuditLogs(logDir?: string): Promise<VerificationReport> {
  const verifier = new LogVerifier(logDir);
  return verifier.verifyAll();
}

/**
 * CLI-friendly verification output
 */
export function formatVerificationReport(report: VerificationReport): string {
  const lines: string[] = [
    "=".repeat(60),
    "AUDIT LOG VERIFICATION REPORT",
    "=".repeat(60),
    "",
    `Timestamp: ${report.timestamp}`,
    `Log Directory: ${report.logDir}`,
    "",
    "SUMMARY",
    "-".repeat(40),
    `Total Files: ${report.summary.totalFiles}`,
    `Valid Files: ${report.summary.validFiles}`,
    `Invalid Files: ${report.summary.invalidFiles}`,
    `Total Events: ${report.summary.totalEvents}`,
    `Valid Events: ${report.summary.validEvents}`,
    `Invalid Events: ${report.summary.invalidEvents}`,
    "",
    `Hash Chain Integrity: ${report.summary.hashChainIntact ? "✓ VALID" : "✗ BROKEN"}`,
    `Sequence Integrity: ${report.summary.sequenceIntact ? "✓ VALID" : "✗ GAPS DETECTED"}`,
    "",
  ];

  if (report.crossFileGaps.length > 0) {
    lines.push("CROSS-FILE GAPS");
    lines.push("-".repeat(40));
    for (const gap of report.crossFileGaps) {
      lines.push(`  ${gap.fromFile} (seq ${gap.fromSequence}) -> ${gap.toFile} (seq ${gap.toSequence})`);
    }
    lines.push("");
  }

  lines.push("RECOMMENDATIONS");
  lines.push("-".repeat(40));
  for (const rec of report.recommendations) {
    lines.push(`  • ${rec}`);
  }
  lines.push("");
  lines.push("=".repeat(60));

  return lines.join("\n");
}
