/**
 * Log Retention Manager for Chrome MCP Server
 *
 * Manages audit log lifecycle:
 * - Log rotation (daily/weekly/size-based)
 * - Compression of old logs
 * - Secure deletion after retention period
 * - Retention policy enforcement
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
import { mkdirSecure, writeFileSecure, PERMISSION_MODES } from "../file-permissions.js";

const gzip = promisify(zlib.gzip);
const gunzip = promisify(zlib.gunzip);

/**
 * Rotation strategy
 */
export type RotationStrategy = "daily" | "weekly" | "size" | "none";

/**
 * Retention manager configuration
 */
export interface RetentionConfig {
  /** Enable retention management */
  enabled: boolean;
  /** Log directory */
  logDir: string;
  /** Rotation strategy */
  rotation: RotationStrategy;
  /** Max file size in bytes (for size-based rotation) */
  maxSizeBytes: number;
  /** Retention period in days */
  retentionDays: number;
  /** Compress old logs */
  compress: boolean;
  /** Days before compression */
  compressAfterDays: number;
  /** Secure delete (overwrite before delete) */
  secureDelete: boolean;
  /** Archive directory (optional) */
  archiveDir?: string;
  /** Delete verification (create deletion certificates) */
  verifyDeletion: boolean;
}

/**
 * Log file metadata
 */
export interface LogFileInfo {
  path: string;
  name: string;
  size: number;
  created: Date;
  modified: Date;
  compressed: boolean;
  ageDays: number;
}

/**
 * Deletion certificate
 */
export interface DeletionCertificate {
  id: string;
  timestamp: string;
  filePath: string;
  fileName: string;
  fileSize: number;
  fileHash: string;
  deletionMethod: "secure_wipe" | "standard";
  verified: boolean;
  signature: string;
}

/**
 * Retention report
 */
export interface RetentionReport {
  timestamp: string;
  logDir: string;
  totalFiles: number;
  totalSize: number;
  filesRotated: number;
  filesCompressed: number;
  filesDeleted: number;
  bytesFreed: number;
  errors: string[];
  deletionCertificates: DeletionCertificate[];
}

/**
 * Get default configuration from environment
 */
function getDefaultConfig(): RetentionConfig {
  const homeDir = process.env.HOME || process.env.USERPROFILE || "/tmp";

  return {
    enabled: process.env.CHROME_MCP_RETENTION_ENABLED !== "false",
    logDir: process.env.CHROME_MCP_AUDIT_DIR || path.join(homeDir, ".chrome-mcp", "audit"),
    rotation: (process.env.CHROME_MCP_LOG_ROTATION as RotationStrategy) || "daily",
    maxSizeBytes: parseInt(process.env.CHROME_MCP_LOG_MAX_SIZE || String(100 * 1024 * 1024), 10), // 100MB
    retentionDays: parseInt(process.env.CHROME_MCP_LOG_RETENTION_DAYS || "365", 10),
    compress: process.env.CHROME_MCP_LOG_COMPRESS !== "false",
    compressAfterDays: parseInt(process.env.CHROME_MCP_LOG_COMPRESS_AFTER || "7", 10),
    secureDelete: process.env.CHROME_MCP_SECURE_DELETE !== "false",
    archiveDir: process.env.CHROME_MCP_LOG_ARCHIVE_DIR,
    verifyDeletion: process.env.CHROME_MCP_VERIFY_DELETION !== "false",
  };
}

/**
 * Calculate file age in days
 */
function getFileAgeDays(mtime: Date): number {
  const now = new Date();
  const diffMs = now.getTime() - mtime.getTime();
  return Math.floor(diffMs / (1000 * 60 * 60 * 24));
}

/**
 * Compute file hash
 */
async function computeFileHash(filePath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash("sha256");
    const stream = fs.createReadStream(filePath);

    stream.on("data", (data) => hash.update(data));
    stream.on("end", () => resolve(hash.digest("hex")));
    stream.on("error", reject);
  });
}

/**
 * Securely overwrite file before deletion
 */
async function secureWipe(filePath: string): Promise<void> {
  const stats = fs.statSync(filePath);
  const size = stats.size;

  // Overwrite with random data
  const fd = fs.openSync(filePath, "r+");
  try {
    const buffer = crypto.randomBytes(Math.min(size, 1024 * 1024)); // 1MB chunks

    for (let offset = 0; offset < size; offset += buffer.length) {
      const writeSize = Math.min(buffer.length, size - offset);
      fs.writeSync(fd, buffer, 0, writeSize, offset);
    }

    // Overwrite with zeros
    const zeros = Buffer.alloc(Math.min(size, 1024 * 1024));
    for (let offset = 0; offset < size; offset += zeros.length) {
      const writeSize = Math.min(zeros.length, size - offset);
      fs.writeSync(fd, zeros, 0, writeSize, offset);
    }

    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * Generate deletion certificate
 */
function generateDeletionCertificate(
  filePath: string,
  fileSize: number,
  fileHash: string,
  secureDelete: boolean
): DeletionCertificate {
  const cert: Omit<DeletionCertificate, "signature"> = {
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    filePath,
    fileName: path.basename(filePath),
    fileSize,
    fileHash,
    deletionMethod: secureDelete ? "secure_wipe" : "standard",
    verified: true,
  };

  // Sign the certificate
  const dataToSign = JSON.stringify(cert);
  const signature = crypto
    .createHmac("sha256", process.env.CHROME_MCP_SIGNING_KEY || "default-key")
    .update(dataToSign)
    .digest("hex");

  return { ...cert, signature };
}

/**
 * Log Retention Manager
 */
export class RetentionManager {
  private config: RetentionConfig;
  private deletionCertificates: DeletionCertificate[] = [];

  constructor(config?: Partial<RetentionConfig>) {
    this.config = { ...getDefaultConfig(), ...config };
  }

  /**
   * Initialize the retention manager
   */
  async initialize(): Promise<void> {
    if (!this.config.enabled) return;

    // Ensure directories exist
    mkdirSecure(this.config.logDir, PERMISSION_MODES.OWNER_FULL);

    if (this.config.archiveDir) {
      mkdirSecure(this.config.archiveDir, PERMISSION_MODES.OWNER_FULL);
    }
  }

  /**
   * Get all log files in the directory
   */
  async getLogFiles(): Promise<LogFileInfo[]> {
    if (!fs.existsSync(this.config.logDir)) {
      return [];
    }

    const files = fs.readdirSync(this.config.logDir);
    const logFiles: LogFileInfo[] = [];

    for (const file of files) {
      // Match audit log files
      if (!file.startsWith("audit-") && !file.endsWith(".jsonl") && !file.endsWith(".cef")) {
        continue;
      }

      const filePath = path.join(this.config.logDir, file);
      const stats = fs.statSync(filePath);

      if (!stats.isFile()) continue;

      logFiles.push({
        path: filePath,
        name: file,
        size: stats.size,
        created: stats.birthtime,
        modified: stats.mtime,
        compressed: file.endsWith(".gz"),
        ageDays: getFileAgeDays(stats.mtime),
      });
    }

    // Sort by modified date (oldest first)
    return logFiles.sort((a, b) => a.modified.getTime() - b.modified.getTime());
  }

  /**
   * Check if rotation is needed for current log
   */
  async needsRotation(currentLogFile: string): Promise<boolean> {
    if (!fs.existsSync(currentLogFile)) {
      return false;
    }

    const stats = fs.statSync(currentLogFile);

    switch (this.config.rotation) {
      case "daily": {
        const fileDate = stats.mtime.toISOString().split("T")[0];
        const today = new Date().toISOString().split("T")[0];
        return fileDate !== today;
      }

      case "weekly": {
        const fileWeek = getWeekNumber(stats.mtime);
        const currentWeek = getWeekNumber(new Date());
        return fileWeek !== currentWeek;
      }

      case "size":
        return stats.size >= this.config.maxSizeBytes;

      default:
        return false;
    }
  }

  /**
   * Rotate the current log file
   */
  async rotateLog(currentLogFile: string): Promise<string | null> {
    if (!fs.existsSync(currentLogFile)) {
      return null;
    }

    const stats = fs.statSync(currentLogFile);
    const ext = path.extname(currentLogFile);
    const baseName = path.basename(currentLogFile, ext);
    const timestamp = stats.mtime.toISOString().replace(/[:.]/g, "-");
    const newName = `${baseName}-${timestamp}${ext}`;
    const newPath = path.join(this.config.logDir, newName);

    fs.renameSync(currentLogFile, newPath);

    return newPath;
  }

  /**
   * Compress old log files
   */
  async compressOldLogs(): Promise<number> {
    const files = await this.getLogFiles();
    let compressed = 0;

    for (const file of files) {
      // Skip already compressed files
      if (file.compressed) continue;

      // Skip files not old enough
      if (file.ageDays < this.config.compressAfterDays) continue;

      try {
        await this.compressFile(file.path);
        compressed++;
      } catch (error) {
        console.error(`Failed to compress ${file.name}: ${error}`);
      }
    }

    return compressed;
  }

  /**
   * Compress a single file
   */
  async compressFile(filePath: string): Promise<string> {
    const content = fs.readFileSync(filePath);
    const compressed = await gzip(content);
    const compressedPath = filePath + ".gz";

    writeFileSecure(compressedPath, compressed, PERMISSION_MODES.OWNER_READ_WRITE);

    // Securely delete original
    if (this.config.secureDelete) {
      await secureWipe(filePath);
    }
    fs.unlinkSync(filePath);

    return compressedPath;
  }

  /**
   * Decompress a file (for reading)
   */
  async decompressFile(filePath: string): Promise<Buffer> {
    const compressed = fs.readFileSync(filePath);
    return gunzip(compressed);
  }

  /**
   * Delete old log files past retention period
   */
  async deleteOldLogs(): Promise<DeletionCertificate[]> {
    const files = await this.getLogFiles();
    const certificates: DeletionCertificate[] = [];

    for (const file of files) {
      // Skip files within retention period
      if (file.ageDays <= this.config.retentionDays) continue;

      try {
        const cert = await this.deleteLogFile(file.path);
        if (cert) {
          certificates.push(cert);
        }
      } catch (error) {
        console.error(`Failed to delete ${file.name}: ${error}`);
      }
    }

    return certificates;
  }

  /**
   * Delete a single log file with certificate
   */
  async deleteLogFile(filePath: string): Promise<DeletionCertificate | null> {
    if (!fs.existsSync(filePath)) {
      return null;
    }

    const stats = fs.statSync(filePath);
    const fileHash = await computeFileHash(filePath);

    // Archive if configured
    if (this.config.archiveDir) {
      const archivePath = path.join(this.config.archiveDir, path.basename(filePath));
      fs.copyFileSync(filePath, archivePath);
    }

    // Secure wipe if enabled
    if (this.config.secureDelete) {
      await secureWipe(filePath);
    }

    // Delete the file
    fs.unlinkSync(filePath);

    // Generate deletion certificate
    if (this.config.verifyDeletion) {
      const cert = generateDeletionCertificate(
        filePath,
        stats.size,
        fileHash,
        this.config.secureDelete
      );
      this.deletionCertificates.push(cert);
      return cert;
    }

    return null;
  }

  /**
   * Run full retention maintenance
   */
  async runMaintenance(): Promise<RetentionReport> {
    const report: RetentionReport = {
      timestamp: new Date().toISOString(),
      logDir: this.config.logDir,
      totalFiles: 0,
      totalSize: 0,
      filesRotated: 0,
      filesCompressed: 0,
      filesDeleted: 0,
      bytesFreed: 0,
      errors: [],
      deletionCertificates: [],
    };

    try {
      // Get initial state
      const filesBefore = await this.getLogFiles();
      report.totalFiles = filesBefore.length;
      report.totalSize = filesBefore.reduce((sum, f) => sum + f.size, 0);

      // Compress old logs
      if (this.config.compress) {
        report.filesCompressed = await this.compressOldLogs();
      }

      // Delete old logs
      const deletionCerts = await this.deleteOldLogs();
      report.filesDeleted = deletionCerts.length;
      report.deletionCertificates = deletionCerts;

      // Calculate bytes freed
      const filesAfter = await this.getLogFiles();
      const sizeAfter = filesAfter.reduce((sum, f) => sum + f.size, 0);
      report.bytesFreed = report.totalSize - sizeAfter;
    } catch (error) {
      report.errors.push(String(error));
    }

    return report;
  }

  /**
   * Get retention statistics
   */
  async getStats(): Promise<{
    totalFiles: number;
    totalSize: number;
    oldestFile: Date | null;
    newestFile: Date | null;
    compressedFiles: number;
    filesOverRetention: number;
  }> {
    const files = await this.getLogFiles();

    return {
      totalFiles: files.length,
      totalSize: files.reduce((sum, f) => sum + f.size, 0),
      oldestFile: files.length > 0 ? files[0].modified : null,
      newestFile: files.length > 0 ? files[files.length - 1].modified : null,
      compressedFiles: files.filter((f) => f.compressed).length,
      filesOverRetention: files.filter((f) => f.ageDays > this.config.retentionDays).length,
    };
  }

  /**
   * Get deletion certificates
   */
  getDeletionCertificates(): DeletionCertificate[] {
    return [...this.deletionCertificates];
  }

  /**
   * Verify a deletion certificate
   */
  verifyCertificate(cert: DeletionCertificate): boolean {
    const { signature, ...data } = cert;
    const dataToVerify = JSON.stringify(data);
    const expectedSignature = crypto
      .createHmac("sha256", process.env.CHROME_MCP_SIGNING_KEY || "default-key")
      .update(dataToVerify)
      .digest("hex");

    return signature === expectedSignature;
  }

  /**
   * Save deletion certificates to file
   */
  async saveCertificates(): Promise<void> {
    if (this.deletionCertificates.length === 0) return;

    const certPath = path.join(this.config.logDir, "deletion-certificates.jsonl");
    const content = this.deletionCertificates
      .map((c) => JSON.stringify(c))
      .join("\n") + "\n";

    fs.appendFileSync(certPath, content, { mode: 0o600 });
  }

  /**
   * Get configuration
   */
  getConfig(): RetentionConfig {
    return { ...this.config };
  }
}

/**
 * Get ISO week number
 */
function getWeekNumber(date: Date): string {
  const d = new Date(Date.UTC(date.getFullYear(), date.getMonth(), date.getDate()));
  const dayNum = d.getUTCDay() || 7;
  d.setUTCDate(d.getUTCDate() + 4 - dayNum);
  const yearStart = new Date(Date.UTC(d.getUTCFullYear(), 0, 1));
  const weekNo = Math.ceil(((d.getTime() - yearStart.getTime()) / 86400000 + 1) / 7);
  return `${d.getUTCFullYear()}-W${String(weekNo).padStart(2, "0")}`;
}

/**
 * Global retention manager instance
 */
let globalManager: RetentionManager | null = null;

/**
 * Get or create the global retention manager
 */
export function getRetentionManager(): RetentionManager {
  if (!globalManager) {
    globalManager = new RetentionManager();
  }
  return globalManager;
}

/**
 * Run retention maintenance
 */
export async function runRetentionMaintenance(): Promise<RetentionReport> {
  const manager = getRetentionManager();
  await manager.initialize();
  return manager.runMaintenance();
}
