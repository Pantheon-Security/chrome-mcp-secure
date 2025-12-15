/**
 * Common Event Format (CEF) Formatter
 *
 * Formats audit events in CEF format for SIEM integration.
 * CEF is widely supported by Splunk, ArcSight, QRadar, LogRhythm, etc.
 *
 * CEF Format:
 * CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
 *
 * @author Pantheon Security
 */

import { ComplianceAuditEvent, AuditSeverity } from "../audit-logger.js";

/**
 * CEF severity mapping (0-10 scale)
 */
const CEF_SEVERITY: Record<AuditSeverity, number> = {
  info: 1,
  low: 3,
  medium: 5,
  high: 7,
  critical: 10,
};

/**
 * Escape special characters for CEF format
 * CEF requires escaping: \ = newline
 */
function escapeValue(value: string): string {
  return value
    .replace(/\\/g, "\\\\")
    .replace(/=/g, "\\=")
    .replace(/\n/g, "\\n")
    .replace(/\r/g, "\\r");
}

/**
 * Escape special characters for CEF header
 * CEF headers require escaping: \ |
 */
function escapeHeader(value: string): string {
  return value
    .replace(/\\/g, "\\\\")
    .replace(/\|/g, "\\|");
}

/**
 * Format a timestamp for CEF (milliseconds since epoch)
 */
function formatTimestamp(isoTimestamp: string): number {
  return new Date(isoTimestamp).getTime();
}

/**
 * Map audit category to CEF signature ID
 */
function getSignatureId(category: string, action: string): string {
  const categoryMap: Record<string, number> = {
    auth: 1000,
    access: 2000,
    modify: 3000,
    delete: 4000,
    export: 5000,
    admin: 6000,
    security: 7000,
    error: 8000,
    system: 9000,
  };

  const base = categoryMap[category] || 9000;
  // Create a simple hash of the action for unique ID
  const actionHash = action.split("").reduce((acc, char) => acc + char.charCodeAt(0), 0) % 1000;

  return String(base + actionHash);
}

/**
 * Build CEF extension string from event details
 */
function buildExtension(event: ComplianceAuditEvent): string {
  const extensions: string[] = [];

  // Standard CEF extension fields
  extensions.push(`rt=${formatTimestamp(event.timestamp)}`);
  extensions.push(`cat=${escapeValue(event.category)}`);
  extensions.push(`act=${escapeValue(event.action)}`);
  extensions.push(`outcome=${escapeValue(event.outcome)}`);

  // Actor information
  if (event.actor.type) {
    extensions.push(`suser=${escapeValue(event.actor.id)}`);
    extensions.push(`suid=${escapeValue(event.actor.id)}`);
  }
  if (event.actor.ip) {
    extensions.push(`src=${escapeValue(event.actor.ip)}`);
  }
  if (event.actor.sessionId) {
    extensions.push(`cs1=${escapeValue(event.actor.sessionId)}`);
    extensions.push(`cs1Label=SessionId`);
  }
  if (event.actor.clientId) {
    extensions.push(`cs2=${escapeValue(event.actor.clientId)}`);
    extensions.push(`cs2Label=ClientId`);
  }

  // Resource information
  if (event.resource.type) {
    extensions.push(`destinationServiceName=${escapeValue(event.resource.type)}`);
  }
  if (event.resource.id) {
    extensions.push(`duid=${escapeValue(event.resource.id)}`);
  }
  if (event.resource.name) {
    extensions.push(`fname=${escapeValue(event.resource.name)}`);
  }
  if (event.resource.path) {
    extensions.push(`filePath=${escapeValue(event.resource.path)}`);
  }

  // Duration
  if (event.durationMs !== undefined) {
    extensions.push(`cn1=${event.durationMs}`);
    extensions.push(`cn1Label=DurationMs`);
  }

  // Sequence and hash chain
  extensions.push(`cn2=${event.sequence}`);
  extensions.push(`cn2Label=Sequence`);

  if (event.hash) {
    extensions.push(`cs3=${escapeValue(event.hash.substring(0, 32))}`);
    extensions.push(`cs3Label=EventHash`);
  }

  // Environment
  extensions.push(`dhost=${escapeValue(event.environment.hostname)}`);
  extensions.push(`dvchost=${escapeValue(event.environment.hostname)}`);

  // Compliance frameworks
  if (event.compliance?.frameworks) {
    extensions.push(`cs4=${escapeValue(event.compliance.frameworks.join(","))}`);
    extensions.push(`cs4Label=ComplianceFrameworks`);
  }

  // Event ID
  extensions.push(`externalId=${escapeValue(event.id)}`);

  // Custom details (flatten first level)
  if (event.details) {
    const detailKeys = Object.keys(event.details).slice(0, 5); // Limit to 5 custom fields
    detailKeys.forEach((key, index) => {
      const value = event.details[key];
      if (value !== undefined && value !== null) {
        const stringValue = typeof value === "string" ? value : JSON.stringify(value);
        extensions.push(`cs${5 + index}=${escapeValue(stringValue.substring(0, 255))}`);
        extensions.push(`cs${5 + index}Label=${escapeValue(key)}`);
      }
    });
  }

  return extensions.join(" ");
}

/**
 * Format a compliance audit event as CEF
 */
export function formatEvent(event: ComplianceAuditEvent): string {
  const cefVersion = 0;
  const deviceVendor = "Pantheon Security";
  const deviceProduct = "Chrome MCP Secure";
  const deviceVersion = event.environment.serviceVersion;
  const signatureId = getSignatureId(event.category, event.action);
  const name = `${event.category}.${event.action}`;
  const severity = CEF_SEVERITY[event.severity];
  const extension = buildExtension(event);

  return `CEF:${cefVersion}|${escapeHeader(deviceVendor)}|${escapeHeader(deviceProduct)}|${escapeHeader(deviceVersion)}|${signatureId}|${escapeHeader(name)}|${severity}|${extension}`;
}

/**
 * Format multiple events
 */
export function formatEvents(events: ComplianceAuditEvent[]): string {
  return events.map(formatEvent).join("\n");
}

/**
 * Parse a CEF line back to an object (basic parsing)
 */
export function parseCEFLine(line: string): Record<string, string> | null {
  if (!line.startsWith("CEF:")) {
    return null;
  }

  const parts = line.split("|");
  if (parts.length < 8) {
    return null;
  }

  const result: Record<string, string> = {
    cefVersion: parts[0].replace("CEF:", ""),
    deviceVendor: parts[1],
    deviceProduct: parts[2],
    deviceVersion: parts[3],
    signatureId: parts[4],
    name: parts[5],
    severity: parts[6],
  };

  // Parse extension
  const extension = parts.slice(7).join("|");
  const extParts = extension.split(/\s+(?=\w+=)/);

  for (const part of extParts) {
    const eqIndex = part.indexOf("=");
    if (eqIndex > 0) {
      const key = part.substring(0, eqIndex);
      const value = part.substring(eqIndex + 1);
      result[key] = value
        .replace(/\\=/g, "=")
        .replace(/\\n/g, "\n")
        .replace(/\\\\/g, "\\");
    }
  }

  return result;
}

/**
 * CEF format metadata
 */
export const CEF_METADATA = {
  version: 0,
  vendor: "Pantheon Security",
  product: "Chrome MCP Secure",
  supportedFields: [
    "rt",           // Receipt time
    "cat",          // Category
    "act",          // Action
    "outcome",      // Outcome
    "suser",        // Source user
    "suid",         // Source user ID
    "src",          // Source IP
    "dhost",        // Destination host
    "dvchost",      // Device host
    "fname",        // Filename
    "filePath",     // File path
    "externalId",   // External ID
    "cn1-cn3",      // Custom numbers
    "cs1-cs10",     // Custom strings
  ],
};
