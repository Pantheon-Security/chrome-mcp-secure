/**
 * Secrets Scanner for Chrome MCP Server
 *
 * Detects and prevents credential exposure in:
 * - Page content
 * - Form values
 * - JavaScript evaluation results
 * - Screenshots (metadata)
 *
 * Patterns derived from: TruffleHog, GitLeaks, MEDUSA
 * Adapted from Pantheon Security's notebooklm-mcp-secure.
 */

import { log, audit } from "./logger.js";

/**
 * Secret detection result
 */
export interface SecretMatch {
  type: string;
  pattern: string;
  match: string;
  redacted: string;
  line?: number;
  column?: number;
  severity: "critical" | "high" | "medium" | "low";
}

/**
 * Secret pattern definition
 */
interface SecretPattern {
  name: string;
  pattern: RegExp;
  severity: "critical" | "high" | "medium" | "low";
  description: string;
  redactFn?: (match: string) => string;
}

/**
 * Secret detection patterns
 * Based on TruffleHog, GitLeaks, and custom patterns
 */
const SECRET_PATTERNS: SecretPattern[] = [
  // === CRITICAL: High-value secrets ===

  // AWS
  {
    name: "AWS Access Key ID",
    pattern: /\b(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b/g,
    severity: "critical",
    description: "AWS Access Key ID",
  },
  {
    name: "AWS Secret Access Key",
    pattern: /\b[A-Za-z0-9/+=]{40}\b(?=.*aws|.*secret|.*key)/gi,
    severity: "critical",
    description: "Potential AWS Secret Access Key",
  },

  // Google
  {
    name: "Google API Key",
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    severity: "critical",
    description: "Google API Key",
  },
  {
    name: "Google OAuth Client ID",
    pattern: /\b[0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com\b/g,
    severity: "high",
    description: "Google OAuth Client ID",
  },
  {
    name: "Google OAuth Client Secret",
    pattern: /\bGOCspx-[A-Za-z0-9_-]{28}\b/g,
    severity: "critical",
    description: "Google OAuth Client Secret",
  },

  // GitHub
  {
    name: "GitHub Personal Access Token",
    pattern: /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b/g,
    severity: "critical",
    description: "GitHub Personal Access Token",
  },
  {
    name: "GitHub OAuth Token",
    pattern: /\bgho_[A-Za-z0-9]{36}\b/g,
    severity: "critical",
    description: "GitHub OAuth Access Token",
  },

  // Slack
  {
    name: "Slack Bot Token",
    pattern: /\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}\b/g,
    severity: "critical",
    description: "Slack Bot Token",
  },
  {
    name: "Slack User Token",
    pattern: /\bxoxp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}\b/g,
    severity: "critical",
    description: "Slack User Token",
  },
  {
    name: "Slack Webhook URL",
    pattern: /\bhttps:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[a-zA-Z0-9]{24}\b/g,
    severity: "high",
    description: "Slack Webhook URL",
  },

  // Stripe
  {
    name: "Stripe API Key",
    pattern: /\b(sk|pk)_(test|live)_[0-9a-zA-Z]{24,}\b/g,
    severity: "critical",
    description: "Stripe API Key",
  },

  // OpenAI
  {
    name: "OpenAI API Key",
    pattern: /\bsk-[A-Za-z0-9]{48}\b/g,
    severity: "critical",
    description: "OpenAI API Key",
  },

  // Anthropic
  {
    name: "Anthropic API Key",
    pattern: /\bsk-ant-[A-Za-z0-9_-]{40,}\b/g,
    severity: "critical",
    description: "Anthropic API Key",
  },

  // === HIGH: Authentication credentials ===

  // Private Keys
  {
    name: "RSA Private Key",
    pattern: /-----BEGIN RSA PRIVATE KEY-----[\s\S]*?-----END RSA PRIVATE KEY-----/g,
    severity: "critical",
    description: "RSA Private Key",
  },
  {
    name: "EC Private Key",
    pattern: /-----BEGIN EC PRIVATE KEY-----[\s\S]*?-----END EC PRIVATE KEY-----/g,
    severity: "critical",
    description: "EC Private Key",
  },
  {
    name: "Generic Private Key",
    pattern: /-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----/g,
    severity: "critical",
    description: "Private Key",
  },
  {
    name: "SSH Private Key",
    pattern: /-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?-----END OPENSSH PRIVATE KEY-----/g,
    severity: "critical",
    description: "OpenSSH Private Key",
  },
  {
    name: "PGP Private Key",
    pattern: /-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]*?-----END PGP PRIVATE KEY BLOCK-----/g,
    severity: "critical",
    description: "PGP Private Key Block",
  },

  // JWT
  {
    name: "JSON Web Token",
    pattern: /\beyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\b/g,
    severity: "high",
    description: "JSON Web Token (JWT)",
  },

  // Database Connection Strings
  {
    name: "PostgreSQL Connection String",
    pattern: /\bpostgres(?:ql)?:\/\/[^:]+:[^@]+@[^/]+\/[^\s]+/gi,
    severity: "critical",
    description: "PostgreSQL Connection String with credentials",
  },
  {
    name: "MongoDB Connection String",
    pattern: /\bmongodb(?:\+srv)?:\/\/[^:]+:[^@]+@[^/]+/gi,
    severity: "critical",
    description: "MongoDB Connection String with credentials",
  },
  {
    name: "MySQL Connection String",
    pattern: /\bmysql:\/\/[^:]+:[^@]+@[^/]+/gi,
    severity: "critical",
    description: "MySQL Connection String with credentials",
  },

  // === MEDIUM: Potentially sensitive ===

  // Generic password patterns
  {
    name: "Password in URL",
    pattern: /\b[a-zA-Z]+:\/\/[^:]+:([^@]+)@/g,
    severity: "high",
    description: "Password in URL",
    redactFn: (match) => match.replace(/:([^@]+)@/, ":****@"),
  },
  {
    name: "Password Assignment",
    pattern: /(?:password|passwd|pwd|secret|token|api_key|apikey|api-key)\s*[:=]\s*["']?([^\s"']{8,})["']?/gi,
    severity: "medium",
    description: "Password or secret assignment",
  },

  // Generic API key patterns
  {
    name: "Generic API Key",
    pattern: /\b[a-zA-Z0-9_-]*api[_-]?key[a-zA-Z0-9_-]*\s*[:=]\s*["']?([^\s"']{16,})["']?/gi,
    severity: "medium",
    description: "Generic API key pattern",
  },

  // Bearer tokens
  {
    name: "Bearer Token",
    pattern: /\bBearer\s+[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/gi,
    severity: "high",
    description: "Bearer Authorization Token",
  },

  // Basic Auth
  {
    name: "Basic Auth Header",
    pattern: /\bBasic\s+[A-Za-z0-9+/=]{20,}\b/gi,
    severity: "high",
    description: "Basic Authentication Header",
  },

  // Credit Card Numbers (common patterns)
  {
    name: "Credit Card Number",
    pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/g,
    severity: "critical",
    description: "Credit Card Number",
  },

  // Social Security Numbers
  {
    name: "SSN",
    pattern: /\b\d{3}-\d{2}-\d{4}\b/g,
    severity: "critical",
    description: "Social Security Number",
  },
];

/**
 * Secrets Scanner Configuration
 */
export interface SecretsConfig {
  /** Enable secrets scanning (default: true) */
  enabled: boolean;
  /** Block output containing secrets (default: false - just warn) */
  blockOnDetection: boolean;
  /** Auto-redact secrets in output (default: true) */
  autoRedact: boolean;
  /** Minimum severity to report (default: low) */
  minSeverity: "critical" | "high" | "medium" | "low";
  /** Custom patterns to add */
  customPatterns: SecretPattern[];
  /** Patterns to ignore (by name) */
  ignoredPatterns: string[];
}

/**
 * Get secrets scanner configuration from environment
 */
function getSecretsConfig(): SecretsConfig {
  const minSeverity = (process.env.CHROME_MCP_SECRETS_MIN_SEVERITY || "low") as SecretsConfig["minSeverity"];
  return {
    enabled: process.env.CHROME_MCP_SECRETS_SCANNING !== "false",
    blockOnDetection: process.env.CHROME_MCP_SECRETS_BLOCK === "true",
    autoRedact: process.env.CHROME_MCP_SECRETS_REDACT !== "false",
    minSeverity,
    customPatterns: [],
    ignoredPatterns: (process.env.CHROME_MCP_SECRETS_IGNORE || "").split(",").filter(Boolean),
  };
}

/**
 * Severity level ordering
 */
const SEVERITY_ORDER: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

/**
 * Secrets Scanner Class
 */
export class SecretsScanner {
  private config: SecretsConfig;
  private patterns: SecretPattern[];
  private stats = {
    scanned: 0,
    secretsFound: 0,
    blocked: 0,
    redacted: 0,
  };

  constructor(config?: Partial<SecretsConfig>) {
    this.config = { ...getSecretsConfig(), ...config };
    this.patterns = [...SECRET_PATTERNS, ...this.config.customPatterns].filter(
      (p) => !this.config.ignoredPatterns.includes(p.name)
    );
  }

  /**
   * Scan text for secrets
   */
  scan(text: string): SecretMatch[] {
    if (!this.config.enabled || !text) {
      return [];
    }

    this.stats.scanned++;
    const matches: SecretMatch[] = [];
    const minSeverityLevel = SEVERITY_ORDER[this.config.minSeverity];

    for (const pattern of this.patterns) {
      // Skip if below minimum severity
      if (SEVERITY_ORDER[pattern.severity] < minSeverityLevel) {
        continue;
      }

      // Reset regex state
      pattern.pattern.lastIndex = 0;

      let match: RegExpExecArray | null;
      while ((match = pattern.pattern.exec(text)) !== null) {
        const matchedText = match[0];

        // Calculate line and column
        const beforeMatch = text.substring(0, match.index);
        const lines = beforeMatch.split("\n");
        const line = lines.length;
        const column = lines[lines.length - 1].length + 1;

        // Generate redacted version
        const redacted = pattern.redactFn
          ? pattern.redactFn(matchedText)
          : this.defaultRedact(matchedText, pattern.name);

        matches.push({
          type: pattern.name,
          pattern: pattern.description,
          match: matchedText,
          redacted,
          line,
          column,
          severity: pattern.severity,
        });

        this.stats.secretsFound++;
      }
    }

    return matches;
  }

  /**
   * Scan and optionally redact secrets
   */
  async scanAndRedact(text: string): Promise<{
    clean: string;
    secrets: SecretMatch[];
    blocked: boolean;
  }> {
    const secrets = this.scan(text);

    if (secrets.length === 0) {
      return { clean: text, secrets: [], blocked: false };
    }

    // Log the detection
    const criticalCount = secrets.filter((s) => s.severity === "critical").length;
    const highCount = secrets.filter((s) => s.severity === "high").length;

    if (criticalCount > 0 || highCount > 0) {
      log.warn(`Secrets detected: ${criticalCount} critical, ${highCount} high`);
      for (const secret of secrets.filter((s) => s.severity === "critical" || s.severity === "high")) {
        log.warn(`   - ${secret.type} at line ${secret.line}`);
      }
    }

    // Audit log
    await audit.security("secrets_detected", criticalCount > 0 ? "error" : "warning", {
      count: secrets.length,
      types: [...new Set(secrets.map((s) => s.type))],
      severities: {
        critical: criticalCount,
        high: highCount,
        medium: secrets.filter((s) => s.severity === "medium").length,
        low: secrets.filter((s) => s.severity === "low").length,
      },
    });

    // Check if we should block
    if (this.config.blockOnDetection && (criticalCount > 0 || highCount > 0)) {
      this.stats.blocked++;
      return {
        clean: "[BLOCKED: Sensitive data detected]",
        secrets,
        blocked: true,
      };
    }

    // Redact if enabled
    let clean = text;
    if (this.config.autoRedact) {
      // Sort by position descending to avoid offset issues
      const sortedSecrets = [...secrets].sort((a, b) => {
        const posA = text.indexOf(a.match);
        const posB = text.indexOf(b.match);
        return posB - posA;
      });

      for (const secret of sortedSecrets) {
        clean = clean.replace(secret.match, secret.redacted);
        this.stats.redacted++;
      }
    }

    return { clean, secrets, blocked: false };
  }

  /**
   * Default redaction function
   */
  private defaultRedact(value: string, type: string): string {
    if (value.length <= 8) {
      return `[REDACTED:${type}]`;
    }

    // Show first 4 and last 4 characters
    const prefix = value.substring(0, 4);
    const suffix = value.substring(value.length - 4);
    const middleLength = value.length - 8;

    return `${prefix}${"*".repeat(Math.min(middleLength, 8))}${suffix}`;
  }

  /**
   * Add a custom pattern
   */
  addPattern(pattern: SecretPattern): void {
    this.patterns.push(pattern);
    this.config.customPatterns.push(pattern);
  }

  /**
   * Ignore a pattern by name
   */
  ignorePattern(name: string): void {
    this.config.ignoredPatterns.push(name);
    this.patterns = this.patterns.filter((p) => p.name !== name);
  }

  /**
   * Get scanning statistics
   */
  getStats(): typeof this.stats & { patterns: number } {
    return {
      ...this.stats,
      patterns: this.patterns.length,
    };
  }

  /**
   * Reset statistics
   */
  resetStats(): void {
    this.stats = {
      scanned: 0,
      secretsFound: 0,
      blocked: 0,
      redacted: 0,
    };
  }

  /**
   * Check if scanning is enabled
   */
  isEnabled(): boolean {
    return this.config.enabled;
  }
}

/**
 * Global secrets scanner instance
 */
let globalScanner: SecretsScanner | null = null;

/**
 * Get or create the global secrets scanner
 */
export function getSecretsScanner(): SecretsScanner {
  if (!globalScanner) {
    globalScanner = new SecretsScanner();
  }
  return globalScanner;
}

/**
 * Convenience function to scan text for secrets
 */
export function scanForSecrets(text: string): SecretMatch[] {
  return getSecretsScanner().scan(text);
}

/**
 * Convenience function to scan and redact secrets
 */
export async function scanAndRedactSecrets(text: string): Promise<{
  clean: string;
  secrets: SecretMatch[];
  blocked: boolean;
}> {
  return getSecretsScanner().scanAndRedact(text);
}
