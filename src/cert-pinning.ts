/**
 * Certificate Pinning for Chrome MCP Server
 *
 * Provides certificate validation for sensitive domains:
 * - HPKP-style pin validation
 * - Certificate chain verification
 * - Domain-specific security policies
 * - Audit logging for pin failures
 *
 * Adapted from Pantheon Security's notebooklm-mcp-secure.
 */

import crypto from "crypto";
import https from "https";
import tls from "tls";
import { log, audit } from "./logger.js";

/**
 * Certificate pin configuration
 */
export interface CertificatePin {
  /** Domain this pin applies to */
  domain: string;
  /** SHA256 fingerprints of allowed certificates (SPKI pins) */
  pins: string[];
  /** Include subdomains in pin (default: true) */
  includeSubdomains?: boolean;
  /** Enforce pin (block on failure) or report only (default: true) */
  enforce?: boolean;
  /** Expiration date for pins (optional) */
  expiresAt?: Date;
  /** Description/notes for this pin */
  description?: string;
}

/**
 * Pin validation result
 */
export interface PinValidationResult {
  valid: boolean;
  domain: string;
  matchedPin?: string;
  certificateChain: Array<{
    subject: string;
    issuer: string;
    fingerprint: string;
    validFrom: Date;
    validTo: Date;
  }>;
  error?: string;
  enforced: boolean;
}

/**
 * Certificate pinning configuration
 */
export interface CertPinningConfig {
  /** Enable certificate pinning (default: true) */
  enabled: boolean;
  /** Built-in pins for sensitive services */
  builtInPins: CertificatePin[];
  /** Custom user-defined pins */
  customPins: CertificatePin[];
  /** Cache validated pins (milliseconds) */
  cacheTtlMs: number;
  /** Report-only mode (don't block on failures) */
  reportOnly: boolean;
}

/**
 * Default pins for common sensitive services
 * Note: These are example pins - in production, you should verify current pins
 */
const DEFAULT_SENSITIVE_DOMAINS: CertificatePin[] = [
  {
    domain: "accounts.google.com",
    pins: [], // Populated dynamically or configured
    includeSubdomains: true,
    enforce: true,
    description: "Google authentication services",
  },
  {
    domain: "github.com",
    pins: [],
    includeSubdomains: true,
    enforce: true,
    description: "GitHub services",
  },
  {
    domain: "login.microsoftonline.com",
    pins: [],
    includeSubdomains: true,
    enforce: true,
    description: "Microsoft authentication",
  },
  {
    domain: "api.anthropic.com",
    pins: [],
    includeSubdomains: true,
    enforce: true,
    description: "Anthropic API",
  },
  {
    domain: "api.openai.com",
    pins: [],
    includeSubdomains: true,
    enforce: true,
    description: "OpenAI API",
  },
];

/**
 * Get certificate pinning configuration from environment
 */
function getCertPinningConfig(): CertPinningConfig {
  return {
    enabled: process.env.CHROME_MCP_CERT_PINNING !== "false",
    builtInPins: DEFAULT_SENSITIVE_DOMAINS,
    customPins: parseCustomPins(process.env.CHROME_MCP_CERT_PINS),
    cacheTtlMs: parseInt(process.env.CHROME_MCP_CERT_CACHE_TTL || "3600000", 10), // 1 hour
    reportOnly: process.env.CHROME_MCP_CERT_REPORT_ONLY === "true",
  };
}

/**
 * Parse custom pins from environment variable
 * Format: domain1:pin1,pin2;domain2:pin3,pin4
 */
function parseCustomPins(envValue?: string): CertificatePin[] {
  if (!envValue) return [];

  const pins: CertificatePin[] = [];

  try {
    const entries = envValue.split(";");
    for (const entry of entries) {
      const [domain, pinList] = entry.split(":");
      if (domain && pinList) {
        pins.push({
          domain: domain.trim(),
          pins: pinList.split(",").map((p) => p.trim()),
          includeSubdomains: true,
          enforce: true,
        });
      }
    }
  } catch (error) {
    log.warn(`Failed to parse custom certificate pins: ${error}`);
  }

  return pins;
}

/**
 * Certificate Pinning Manager
 */
export class CertificatePinningManager {
  private config: CertPinningConfig;
  private pinCache: Map<string, { pins: string[]; expiresAt: number }> = new Map();
  private validationCache: Map<string, { result: PinValidationResult; expiresAt: number }> = new Map();
  private stats = {
    validations: 0,
    passes: 0,
    failures: 0,
    cacheHits: 0,
  };

  constructor(config?: Partial<CertPinningConfig>) {
    this.config = { ...getCertPinningConfig(), ...config };
  }

  /**
   * Check if a domain has pin configuration
   */
  hasPins(domain: string): boolean {
    return this.findPinConfig(domain) !== null;
  }

  /**
   * Find pin configuration for a domain
   */
  private findPinConfig(domain: string): CertificatePin | null {
    const allPins = [...this.config.builtInPins, ...this.config.customPins];

    // Exact match first
    let config = allPins.find((p) => p.domain === domain);
    if (config && config.pins.length > 0) return config;

    // Check subdomain matches
    for (const pin of allPins) {
      if (pin.includeSubdomains && domain.endsWith(`.${pin.domain}`)) {
        if (pin.pins.length > 0) return pin;
      }
    }

    return null;
  }

  /**
   * Calculate SPKI fingerprint from certificate
   */
  private calculateSPKIFingerprint(cert: tls.PeerCertificate): string {
    // Get the public key from the certificate
    const publicKey = cert.pubkey;
    if (!publicKey) {
      // Fallback to full certificate fingerprint
      return cert.fingerprint256?.replace(/:/g, "").toLowerCase() || "";
    }

    // Calculate SHA256 of the public key (SPKI pin)
    const hash = crypto.createHash("sha256").update(publicKey).digest("base64");
    return hash;
  }

  /**
   * Validate certificate chain against pins
   */
  async validateCertificate(domain: string, port: number = 443): Promise<PinValidationResult> {
    if (!this.config.enabled) {
      return {
        valid: true,
        domain,
        certificateChain: [],
        enforced: false,
      };
    }

    this.stats.validations++;

    // Check cache
    const cacheKey = `${domain}:${port}`;
    const cached = this.validationCache.get(cacheKey);
    if (cached && cached.expiresAt > Date.now()) {
      this.stats.cacheHits++;
      return cached.result;
    }

    // Find pin configuration
    const pinConfig = this.findPinConfig(domain);
    const enforced = pinConfig?.enforce ?? false;

    // If no pins configured, pass through
    if (!pinConfig || pinConfig.pins.length === 0) {
      const result: PinValidationResult = {
        valid: true,
        domain,
        certificateChain: [],
        enforced: false,
      };
      this.cacheResult(cacheKey, result);
      return result;
    }

    // Check if pins expired
    if (pinConfig.expiresAt && new Date() > pinConfig.expiresAt) {
      log.warn(`Certificate pins for ${domain} have expired`);
      const result: PinValidationResult = {
        valid: true, // Don't block on expired pins
        domain,
        certificateChain: [],
        enforced: false,
        error: "Pins expired",
      };
      return result;
    }

    return new Promise((resolve) => {
      const result: PinValidationResult = {
        valid: false,
        domain,
        certificateChain: [],
        enforced: enforced && !this.config.reportOnly,
      };

      try {
        const options: https.RequestOptions = {
          hostname: domain,
          port,
          method: "HEAD",
          timeout: 10000,
          rejectUnauthorized: true, // Ensure proper cert validation
        };

        const req = https.request(options, (res) => {
          const socket = res.socket as tls.TLSSocket;
          const cert = socket.getPeerCertificate(true);

          if (!cert || !cert.subject) {
            result.error = "No certificate received";
            this.handleValidationResult(result, pinConfig);
            resolve(result);
            return;
          }

          // Build certificate chain
          let currentCert: tls.PeerCertificate | tls.DetailedPeerCertificate = cert;
          const chain: PinValidationResult["certificateChain"] = [];
          const seenFingerprints = new Set<string>();

          while (currentCert && !seenFingerprints.has(currentCert.fingerprint256)) {
            seenFingerprints.add(currentCert.fingerprint256);

            const fingerprint = this.calculateSPKIFingerprint(currentCert);
            chain.push({
              subject: typeof currentCert.subject === "object"
                ? currentCert.subject.CN || JSON.stringify(currentCert.subject)
                : String(currentCert.subject),
              issuer: typeof currentCert.issuer === "object"
                ? currentCert.issuer.CN || JSON.stringify(currentCert.issuer)
                : String(currentCert.issuer),
              fingerprint,
              validFrom: new Date(currentCert.valid_from),
              validTo: new Date(currentCert.valid_to),
            });

            // Check if any pin matches
            if (pinConfig.pins.includes(fingerprint)) {
              result.valid = true;
              result.matchedPin = fingerprint;
            }

            // Move to issuer certificate
            if ("issuerCertificate" in currentCert && currentCert.issuerCertificate) {
              // Avoid infinite loop for self-signed certs
              if (currentCert.issuerCertificate.fingerprint256 === currentCert.fingerprint256) {
                break;
              }
              currentCert = currentCert.issuerCertificate;
            } else {
              break;
            }
          }

          result.certificateChain = chain;

          if (!result.valid) {
            result.error = "No matching pin found in certificate chain";
          }

          this.handleValidationResult(result, pinConfig);
          this.cacheResult(cacheKey, result);
          resolve(result);
        });

        req.on("error", (error) => {
          result.error = `Connection error: ${error.message}`;
          this.handleValidationResult(result, pinConfig);
          resolve(result);
        });

        req.on("timeout", () => {
          req.destroy();
          result.error = "Connection timeout";
          this.handleValidationResult(result, pinConfig);
          resolve(result);
        });

        req.end();
      } catch (error) {
        result.error = `Validation error: ${error instanceof Error ? error.message : String(error)}`;
        this.handleValidationResult(result, pinConfig);
        resolve(result);
      }
    });
  }

  /**
   * Handle validation result - logging and audit
   */
  private async handleValidationResult(result: PinValidationResult, pinConfig: CertificatePin): Promise<void> {
    if (result.valid) {
      this.stats.passes++;
      log.debug(`Certificate pin validation passed for ${result.domain}`);
    } else {
      this.stats.failures++;
      log.warn(`Certificate pin validation FAILED for ${result.domain}: ${result.error}`);

      await audit.security("cert_pin_failure", result.enforced ? "error" : "warning", {
        domain: result.domain,
        error: result.error,
        enforced: result.enforced,
        chain_length: result.certificateChain.length,
        expected_pins: pinConfig.pins.slice(0, 3), // Don't log all pins
        actual_fingerprints: result.certificateChain.map((c) => c.fingerprint.substring(0, 16) + "..."),
      });
    }
  }

  /**
   * Cache validation result
   */
  private cacheResult(key: string, result: PinValidationResult): void {
    this.validationCache.set(key, {
      result,
      expiresAt: Date.now() + this.config.cacheTtlMs,
    });
  }

  /**
   * Add a custom pin for a domain
   */
  addPin(pin: CertificatePin): void {
    // Remove existing pin for domain
    this.config.customPins = this.config.customPins.filter((p) => p.domain !== pin.domain);
    this.config.customPins.push(pin);

    // Clear cache for this domain
    for (const key of this.validationCache.keys()) {
      if (key.startsWith(pin.domain)) {
        this.validationCache.delete(key);
      }
    }

    log.info(`Added certificate pin for ${pin.domain}`);
  }

  /**
   * Remove pin for a domain
   */
  removePin(domain: string): boolean {
    const initialLength = this.config.customPins.length;
    this.config.customPins = this.config.customPins.filter((p) => p.domain !== domain);

    if (this.config.customPins.length < initialLength) {
      // Clear cache
      for (const key of this.validationCache.keys()) {
        if (key.startsWith(domain)) {
          this.validationCache.delete(key);
        }
      }
      log.info(`Removed certificate pin for ${domain}`);
      return true;
    }

    return false;
  }

  /**
   * Fetch and return current certificate pins for a domain
   * Useful for initial pin setup
   */
  async fetchCurrentPins(domain: string, port: number = 443): Promise<string[]> {
    return new Promise((resolve, reject) => {
      const pins: string[] = [];

      const options: https.RequestOptions = {
        hostname: domain,
        port,
        method: "HEAD",
        timeout: 10000,
        rejectUnauthorized: true,
      };

      const req = https.request(options, (res) => {
        const socket = res.socket as tls.TLSSocket;
        const cert = socket.getPeerCertificate(true);

        if (!cert) {
          reject(new Error("No certificate received"));
          return;
        }

        // Collect pins from chain
        let currentCert: tls.PeerCertificate | tls.DetailedPeerCertificate = cert;
        const seenFingerprints = new Set<string>();

        while (currentCert && !seenFingerprints.has(currentCert.fingerprint256)) {
          seenFingerprints.add(currentCert.fingerprint256);
          pins.push(this.calculateSPKIFingerprint(currentCert));

          if ("issuerCertificate" in currentCert && currentCert.issuerCertificate) {
            if (currentCert.issuerCertificate.fingerprint256 === currentCert.fingerprint256) {
              break;
            }
            currentCert = currentCert.issuerCertificate;
          } else {
            break;
          }
        }

        resolve(pins);
      });

      req.on("error", (error) => reject(error));
      req.on("timeout", () => {
        req.destroy();
        reject(new Error("Timeout"));
      });

      req.end();
    });
  }

  /**
   * Get pinning statistics
   */
  getStats(): typeof this.stats & { cachedDomains: number; configuredPins: number } {
    return {
      ...this.stats,
      cachedDomains: this.validationCache.size,
      configuredPins: this.config.builtInPins.length + this.config.customPins.length,
    };
  }

  /**
   * Clear validation cache
   */
  clearCache(): void {
    this.validationCache.clear();
    log.info("Certificate validation cache cleared");
  }

  /**
   * Get configured pins for a domain (for debugging)
   */
  getPinsForDomain(domain: string): CertificatePin | null {
    return this.findPinConfig(domain);
  }

  /**
   * Check if pinning is enabled
   */
  isEnabled(): boolean {
    return this.config.enabled;
  }

  /**
   * Get status information
   */
  getStatus(): {
    enabled: boolean;
    reportOnly: boolean;
    builtInDomains: string[];
    customDomains: string[];
    cachedValidations: number;
  } {
    return {
      enabled: this.config.enabled,
      reportOnly: this.config.reportOnly,
      builtInDomains: this.config.builtInPins.map((p) => p.domain),
      customDomains: this.config.customPins.map((p) => p.domain),
      cachedValidations: this.validationCache.size,
    };
  }
}

/**
 * Global certificate pinning manager instance
 */
let globalManager: CertificatePinningManager | null = null;

/**
 * Get or create the global certificate pinning manager
 */
export function getCertificatePinningManager(): CertificatePinningManager {
  if (!globalManager) {
    globalManager = new CertificatePinningManager();
  }
  return globalManager;
}

/**
 * Convenience function to validate a domain's certificate
 */
export async function validateDomainCertificate(
  domain: string,
  port: number = 443
): Promise<PinValidationResult> {
  return getCertificatePinningManager().validateCertificate(domain, port);
}

/**
 * Check if navigation to a URL should be allowed based on cert pinning
 */
export async function checkNavigationSecurity(url: string): Promise<{
  allowed: boolean;
  reason?: string;
  validation?: PinValidationResult;
}> {
  try {
    const parsed = new URL(url);

    // Only check HTTPS URLs
    if (parsed.protocol !== "https:") {
      return { allowed: true };
    }

    const manager = getCertificatePinningManager();

    // Only validate if we have pins for this domain
    if (!manager.hasPins(parsed.hostname)) {
      return { allowed: true };
    }

    const validation = await manager.validateCertificate(
      parsed.hostname,
      parsed.port ? parseInt(parsed.port, 10) : 443
    );

    if (!validation.valid && validation.enforced) {
      return {
        allowed: false,
        reason: `Certificate pin validation failed: ${validation.error}`,
        validation,
      };
    }

    return { allowed: true, validation };
  } catch (error) {
    // Don't block on URL parsing errors
    return { allowed: true };
  }
}
