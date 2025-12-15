/**
 * Compliance Module for Chrome MCP Server
 *
 * Phase 1: Logging & Audit Foundation (v2.3.0)
 *
 * Provides enterprise-grade audit logging, log shipping,
 * retention management, and integrity verification.
 *
 * @author Pantheon Security
 */

// Audit Logger
export {
  ComplianceAuditLogger,
  ComplianceAuditEvent,
  AuditCategory,
  AuditSeverity,
  AuditOutcome,
  AuditActor,
  AuditResource,
  AuditLoggerConfig,
  getComplianceAuditLogger,
  logComplianceEvent,
} from "./audit-logger.js";

// Log Formats
export { formatEvent as formatCEF, parseCEFLine, CEF_METADATA } from "./formats/cef.js";
export { formatEventJsonLD, formatEventsAsGraph, AUDIT_CONTEXT, JSONLD_METADATA } from "./formats/json-ld.js";

// Log Shipper
export {
  LogShipper,
  LogShipperConfig,
  ShipperDestination,
  SyslogFacility,
  SyslogSeverity,
  getLogShipper,
  shipAuditEvent,
} from "./log-shipper.js";

// Retention Manager
export {
  RetentionManager,
  RetentionConfig,
  RotationStrategy,
  LogFileInfo,
  DeletionCertificate,
  RetentionReport,
  getRetentionManager,
  runRetentionMaintenance,
} from "./retention-manager.js";

// Log Verifier
export {
  LogVerifier,
  VerificationReport,
  FileVerification,
  EventVerification,
  getLogVerifier,
  verifyAuditLogs,
  formatVerificationReport,
} from "./log-verifier.js";
