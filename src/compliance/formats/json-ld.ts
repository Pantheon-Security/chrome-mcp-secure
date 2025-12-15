/**
 * JSON-LD Formatter for Compliance Audit Events
 *
 * Formats audit events in JSON-LD (Linked Data) format for:
 * - Compliance management tools
 * - Knowledge graphs
 * - Semantic web integration
 * - Machine-readable audit trails
 *
 * Uses schema.org and custom security ontology.
 *
 * @author Pantheon Security
 */

import { ComplianceAuditEvent, AuditCategory, AuditSeverity } from "../audit-logger.js";

/**
 * JSON-LD Context for audit events
 */
export const AUDIT_CONTEXT = {
  "@context": {
    "@version": 1.1,
    "@vocab": "https://schema.org/",
    "sec": "https://w3id.org/security#",
    "audit": "https://pantheonsecurity.io/ontology/audit#",

    // Standard schema.org mappings
    "identifier": "identifier",
    "dateCreated": "dateCreated",
    "agent": "agent",
    "object": "object",
    "result": "result",
    "description": "description",
    "duration": "duration",

    // Custom audit ontology
    "eventId": "audit:eventId",
    "eventVersion": "audit:eventVersion",
    "category": "audit:category",
    "action": "audit:action",
    "severity": "audit:severity",
    "outcome": "audit:outcome",
    "sequence": "audit:sequence",
    "previousHash": "sec:previousHash",
    "hash": "sec:hash",
    "actor": "audit:actor",
    "resource": "audit:resource",
    "compliance": "audit:compliance",
    "environment": "audit:environment",

    // Actor properties
    "actorType": "audit:actorType",
    "actorId": "audit:actorId",
    "sessionId": "audit:sessionId",
    "clientId": "audit:clientId",
    "ipAddress": "audit:ipAddress",

    // Resource properties
    "resourceType": "audit:resourceType",
    "resourceId": "audit:resourceId",
    "resourceName": "audit:resourceName",
    "resourcePath": "audit:resourcePath",

    // Compliance properties
    "frameworks": "audit:frameworks",
    "dataClassification": "audit:dataClassification",
    "retentionDays": "audit:retentionDays",

    // Environment properties
    "hostname": "audit:hostname",
    "service": "audit:service",
    "serviceVersion": "audit:serviceVersion",
    "env": "audit:env",
  },
};

/**
 * Category to schema.org type mapping
 */
const CATEGORY_TYPE_MAP: Record<AuditCategory, string> = {
  auth: "AuthenticateAction",
  access: "ReadAction",
  modify: "UpdateAction",
  delete: "DeleteAction",
  export: "DownloadAction",
  admin: "ControlAction",
  security: "AssessAction",
  error: "FailAction",
  system: "Action",
};

/**
 * Severity to risk level mapping
 */
const SEVERITY_RISK_MAP: Record<AuditSeverity, string> = {
  info: "Informational",
  low: "Low",
  medium: "Medium",
  high: "High",
  critical: "Critical",
};

/**
 * JSON-LD formatted audit event
 */
export interface JsonLDAuditEvent {
  "@context": typeof AUDIT_CONTEXT["@context"];
  "@type": string;
  "@id": string;
  eventId: string;
  eventVersion: string;
  dateCreated: string;
  category: string;
  action: string;
  severity: string;
  sequence: number;
  actor: {
    "@type": string;
    actorType: string;
    actorId: string;
    sessionId?: string;
    clientId?: string;
    ipAddress?: string;
  };
  resource: {
    "@type": string;
    resourceType: string;
    resourceId: string;
    resourceName?: string;
    resourcePath?: string;
  };
  outcome: string;
  result?: {
    "@type": string;
    description: string;
  };
  duration?: string;
  compliance?: {
    "@type": string;
    frameworks?: string[];
    dataClassification?: string;
    retentionDays?: number;
  };
  environment: {
    "@type": string;
    hostname: string;
    service: string;
    serviceVersion: string;
    env: string;
  };
  previousHash: string;
  hash: string;
  description?: string;
}

/**
 * Format a compliance audit event as JSON-LD
 */
export function formatEventJsonLD(event: ComplianceAuditEvent): JsonLDAuditEvent {
  const schemaType = CATEGORY_TYPE_MAP[event.category] || "Action";

  const jsonLd: JsonLDAuditEvent = {
    "@context": AUDIT_CONTEXT["@context"],
    "@type": schemaType,
    "@id": `urn:uuid:${event.id}`,
    eventId: event.id,
    eventVersion: event.version,
    dateCreated: event.timestamp,
    category: event.category,
    action: event.action,
    severity: SEVERITY_RISK_MAP[event.severity],
    sequence: event.sequence,
    actor: {
      "@type": "Person",
      actorType: event.actor.type,
      actorId: event.actor.id,
      ...(event.actor.sessionId && { sessionId: event.actor.sessionId }),
      ...(event.actor.clientId && { clientId: event.actor.clientId }),
      ...(event.actor.ip && { ipAddress: event.actor.ip }),
    },
    resource: {
      "@type": "Thing",
      resourceType: event.resource.type,
      resourceId: event.resource.id,
      ...(event.resource.name && { resourceName: event.resource.name }),
      ...(event.resource.path && { resourcePath: event.resource.path }),
    },
    outcome: event.outcome,
    environment: {
      "@type": "SoftwareApplication",
      hostname: event.environment.hostname,
      service: event.environment.service,
      serviceVersion: event.environment.serviceVersion,
      env: event.environment.env,
    },
    previousHash: event.previousHash,
    hash: event.hash,
  };

  // Add duration if present
  if (event.durationMs !== undefined) {
    jsonLd.duration = `PT${event.durationMs / 1000}S`; // ISO 8601 duration
  }

  // Add result if outcome is failure
  if (event.outcome === "failure" && event.details.error) {
    jsonLd.result = {
      "@type": "ActionStatus",
      description: String(event.details.error),
    };
  }

  // Add compliance info if present
  if (event.compliance) {
    jsonLd.compliance = {
      "@type": "audit:ComplianceInfo",
      ...(event.compliance.frameworks && { frameworks: event.compliance.frameworks }),
      ...(event.compliance.dataClassification && { dataClassification: event.compliance.dataClassification }),
      ...(event.compliance.retentionDays && { retentionDays: event.compliance.retentionDays }),
    };
  }

  // Add description from details if present
  if (event.details.message || event.details.description) {
    jsonLd.description = String(event.details.message || event.details.description);
  }

  return jsonLd;
}

/**
 * Format multiple events as a JSON-LD graph
 */
export function formatEventsAsGraph(events: ComplianceAuditEvent[]): object {
  return {
    "@context": AUDIT_CONTEXT["@context"],
    "@graph": events.map((event) => {
      const formatted = formatEventJsonLD(event);
      // Remove context from individual items (it's at the graph level)
      const { "@context": _, ...rest } = formatted;
      return rest;
    }),
  };
}

/**
 * Create a JSON-LD frame for querying specific event types
 */
export function createEventFrame(category?: AuditCategory): object {
  return {
    "@context": AUDIT_CONTEXT["@context"],
    "@type": category ? CATEGORY_TYPE_MAP[category] : "Action",
    actor: {},
    resource: {},
  };
}

/**
 * Validate that an object is a valid JSON-LD audit event
 */
export function isValidJsonLDAuditEvent(obj: unknown): obj is JsonLDAuditEvent {
  if (!obj || typeof obj !== "object") return false;

  const event = obj as Record<string, unknown>;

  return (
    typeof event["@type"] === "string" &&
    typeof event["@id"] === "string" &&
    typeof event.eventId === "string" &&
    typeof event.dateCreated === "string" &&
    typeof event.category === "string" &&
    typeof event.action === "string" &&
    typeof event.outcome === "string" &&
    typeof event.actor === "object" &&
    typeof event.resource === "object" &&
    typeof event.environment === "object"
  );
}

/**
 * JSON-LD format metadata
 */
export const JSONLD_METADATA = {
  version: "1.1",
  context: "https://pantheonsecurity.io/ontology/audit/context.jsonld",
  schemaOrg: "https://schema.org/",
  securityOntology: "https://w3id.org/security#",
  supportedTypes: Object.values(CATEGORY_TYPE_MAP),
};
