/**
 * Logging utilities for Chrome MCP server
 *
 * Provides structured logging with audit trail support
 * Includes automatic credential masking for security
 */

import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

/**
 * Patterns that indicate sensitive data
 */
const SENSITIVE_PATTERNS = [
  /password/i,
  /secret/i,
  /token/i,
  /apikey/i,
  /api_key/i,
  /credential/i,
  /auth/i,
  /bearer/i,
];

/**
 * Mask sensitive values in an object
 */
function maskSensitiveData(obj: Record<string, unknown>): Record<string, unknown> {
  const masked: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(obj)) {
    // Check if key matches sensitive patterns
    const isSensitiveKey = SENSITIVE_PATTERNS.some(pattern => pattern.test(key));

    if (isSensitiveKey && typeof value === 'string') {
      // Mask the value
      masked[key] = value.length > 4 ? value.slice(0, 4) + '****' : '****';
    } else if (value && typeof value === 'object' && !Array.isArray(value)) {
      // Recursively mask nested objects
      masked[key] = maskSensitiveData(value as Record<string, unknown>);
    } else {
      masked[key] = value;
    }
  }

  return masked;
}

interface LogEntry {
  timestamp: string;
  level: LogLevel;
  message: string;
  context?: Record<string, unknown>;
}

interface AuditEvent {
  timestamp: string;
  eventType: 'tool' | 'auth' | 'session' | 'security' | 'system';
  eventName: string;
  success: boolean;
  durationMs?: number;
  details?: Record<string, unknown>;
  previousHash?: string;
  hash?: string;
}

class Logger {
  private level: LogLevel;
  private useColors: boolean;

  constructor() {
    this.level = (process.env.LOG_LEVEL as LogLevel) || 'info';
    this.useColors = process.stdout.isTTY ?? false;
  }

  private shouldLog(level: LogLevel): boolean {
    const levels: LogLevel[] = ['debug', 'info', 'warn', 'error'];
    return levels.indexOf(level) >= levels.indexOf(this.level);
  }

  private formatMessage(level: LogLevel, message: string, context?: Record<string, unknown>): string {
    const timestamp = new Date().toISOString();
    const prefix = `[${timestamp}] [${level.toUpperCase()}]`;

    // Mask sensitive data in context
    const safeContext = context ? maskSensitiveData(context) : undefined;

    if (this.useColors) {
      const colors: Record<LogLevel, string> = {
        debug: '\x1b[36m',  // cyan
        info: '\x1b[32m',   // green
        warn: '\x1b[33m',   // yellow
        error: '\x1b[31m',  // red
      };
      const reset = '\x1b[0m';

      let formatted = `${colors[level]}${prefix}${reset} ${message}`;
      if (safeContext) {
        formatted += ` ${JSON.stringify(safeContext)}`;
      }
      return formatted;
    }

    let formatted = `${prefix} ${message}`;
    if (safeContext) {
      formatted += ` ${JSON.stringify(safeContext)}`;
    }
    return formatted;
  }

  debug(message: string, context?: Record<string, unknown>): void {
    if (this.shouldLog('debug')) {
      console.error(this.formatMessage('debug', message, context));
    }
  }

  info(message: string, context?: Record<string, unknown>): void {
    if (this.shouldLog('info')) {
      console.error(this.formatMessage('info', message, context));
    }
  }

  warn(message: string, context?: Record<string, unknown>): void {
    if (this.shouldLog('warn')) {
      console.error(this.formatMessage('warn', message, context));
    }
  }

  error(message: string, context?: Record<string, unknown>): void {
    if (this.shouldLog('error')) {
      console.error(this.formatMessage('error', message, context));
    }
  }

  success(message: string, context?: Record<string, unknown>): void {
    this.info(`✓ ${message}`, context);
  }

  // Alias for warn (used by crypto.ts)
  warning(message: string, context?: Record<string, unknown>): void {
    this.warn(message, context);
  }
}

class AuditLogger {
  private logDir: string;
  private currentFile: string | null = null;
  private lastHash: string | null = null;
  private queue: AuditEvent[] = [];
  private flushTimer: NodeJS.Timeout | null = null;
  private enabled: boolean;

  constructor() {
    this.logDir = process.env.AUDIT_LOG_DIR || path.join(process.cwd(), 'logs');
    this.enabled = process.env.AUDIT_LOGGING !== 'false';

    if (this.enabled) {
      this.ensureLogDir();
    }
  }

  private ensureLogDir(): void {
    if (!fs.existsSync(this.logDir)) {
      fs.mkdirSync(this.logDir, { recursive: true });
    }
  }

  private getLogFile(): string {
    const date = new Date().toISOString().split('T')[0];
    return path.join(this.logDir, `audit-${date}.jsonl`);
  }

  private computeHash(event: Omit<AuditEvent, 'hash'>): string {
    const data = JSON.stringify(event);
    return crypto.createHash('sha256').update(data).digest('hex').substring(0, 16);
  }

  private async flush(): Promise<void> {
    if (this.queue.length === 0) return;

    const events = [...this.queue];
    this.queue = [];

    const logFile = this.getLogFile();
    const lines = events.map(e => JSON.stringify(e)).join('\n') + '\n';

    try {
      fs.appendFileSync(logFile, lines);
    } catch (error) {
      // Log to stderr if audit logging fails
      console.error(`Audit log write failed: ${error}`);
    }
  }

  private scheduleFlush(): void {
    if (this.flushTimer) return;

    this.flushTimer = setTimeout(() => {
      this.flushTimer = null;
      this.flush();
    }, 1000);
  }

  private log(event: Omit<AuditEvent, 'timestamp' | 'previousHash' | 'hash'>): void {
    if (!this.enabled) return;

    // Mask sensitive data in details
    const safeDetails = event.details ? maskSensitiveData(event.details) : undefined;

    const fullEvent: AuditEvent = {
      ...event,
      details: safeDetails,
      timestamp: new Date().toISOString(),
      previousHash: this.lastHash || undefined,
    };

    fullEvent.hash = this.computeHash(fullEvent);
    this.lastHash = fullEvent.hash;

    this.queue.push(fullEvent);
    this.scheduleFlush();
  }

  tool(name: string, success: boolean, durationMs?: number, details?: Record<string, unknown>): void {
    this.log({
      eventType: 'tool',
      eventName: name,
      success,
      durationMs,
      details,
    });
  }

  session(eventName: string, success: boolean, details?: Record<string, unknown>): void {
    this.log({
      eventType: 'session',
      eventName,
      success,
      details,
    });
  }

  security(eventName: string, levelOrSuccess: 'info' | 'warning' | 'error' | boolean, details?: Record<string, unknown>): void {
    // Support both boolean (legacy) and string level (crypto.ts style)
    let success: boolean;
    if (typeof levelOrSuccess === 'boolean') {
      success = levelOrSuccess;
    } else {
      success = levelOrSuccess !== 'error';
    }

    this.log({
      eventType: 'security',
      eventName,
      success,
      details,
    });
  }

  system(eventName: string, success: boolean, details?: Record<string, unknown>): void {
    this.log({
      eventType: 'system',
      eventName,
      success,
      details,
    });
  }

  async close(): Promise<void> {
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = null;
    }
    await this.flush();
  }
}

// Singleton instances
export const log = new Logger();
export const audit = new AuditLogger();
