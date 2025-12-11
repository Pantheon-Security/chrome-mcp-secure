/**
 * Screenshot Redaction for Chrome MCP Server
 *
 * Automatically redacts sensitive information from screenshots:
 * - Password fields (type="password")
 * - Credit card inputs
 * - SSN fields
 * - Custom redaction patterns
 * - Configurable redaction overlays
 *
 * Works by injecting CSS overlays before screenshot capture.
 * Adapted from Pantheon Security's notebooklm-mcp-secure.
 */

import { log, audit } from "./logger.js";

/**
 * Redaction target configuration
 */
export interface RedactionTarget {
  /** Unique identifier for this target */
  id: string;
  /** CSS selector to match elements */
  selector: string;
  /** Description of what this targets */
  description: string;
  /** Whether to redact (default: true) */
  enabled: boolean;
  /** Custom overlay color (default: black) */
  overlayColor?: string;
  /** Custom overlay text (default: "[REDACTED]") */
  overlayText?: string;
  /** Match by attribute patterns */
  attributePatterns?: Array<{
    attribute: string;
    pattern: RegExp;
  }>;
}

/**
 * Redaction result
 */
export interface RedactionResult {
  redacted: boolean;
  elementsRedacted: number;
  targetsMatched: string[];
  cssInjected: string;
  warnings: string[];
}

/**
 * Screenshot redaction configuration
 */
export interface ScreenshotRedactionConfig {
  /** Enable screenshot redaction (default: true) */
  enabled: boolean;
  /** Default overlay color */
  overlayColor: string;
  /** Default overlay text */
  overlayText: string;
  /** Built-in redaction targets */
  builtInTargets: RedactionTarget[];
  /** Custom user-defined targets */
  customTargets: RedactionTarget[];
  /** Also blur surrounding area (pixels) */
  blurRadius: number;
}

/**
 * Default redaction targets for sensitive fields
 */
const DEFAULT_REDACTION_TARGETS: RedactionTarget[] = [
  // Password fields
  {
    id: "password-inputs",
    selector: "input[type=\"password\"]",
    description: "Password input fields",
    enabled: true,
    overlayColor: "#000000",
    overlayText: "PASSWORD",
  },
  {
    id: "password-labels",
    selector: "input[type=\"password\"] + label, label[for*=\"password\" i], label[for*=\"passwd\" i]",
    description: "Password field labels",
    enabled: false, // Labels usually don't contain sensitive data
  },

  // Credit card fields
  {
    id: "credit-card-number",
    selector: "input[autocomplete=\"cc-number\"], input[name*=\"card\" i][name*=\"number\" i], input[id*=\"card\" i][id*=\"number\" i], input[data-card=\"number\"]",
    description: "Credit card number fields",
    enabled: true,
    overlayColor: "#1a1a1a",
    overlayText: "CARD NUMBER",
  },
  {
    id: "credit-card-cvv",
    selector: "input[autocomplete=\"cc-csc\"], input[name*=\"cvv\" i], input[name*=\"cvc\" i], input[name*=\"csc\" i], input[id*=\"cvv\" i], input[id*=\"cvc\" i]",
    description: "Credit card CVV/CVC fields",
    enabled: true,
    overlayColor: "#1a1a1a",
    overlayText: "CVV",
  },
  {
    id: "credit-card-expiry",
    selector: "input[autocomplete=\"cc-exp\"], input[name*=\"expir\" i], input[id*=\"expir\" i]",
    description: "Credit card expiry fields",
    enabled: true,
    overlayColor: "#1a1a1a",
    overlayText: "EXPIRY",
  },

  // SSN/Tax ID fields
  {
    id: "ssn-fields",
    selector: "input[name*=\"ssn\" i], input[name*=\"social\" i][name*=\"security\" i], input[id*=\"ssn\" i], input[autocomplete=\"ssn\"]",
    description: "Social Security Number fields",
    enabled: true,
    overlayColor: "#2a2a2a",
    overlayText: "SSN",
  },
  {
    id: "tax-id-fields",
    selector: "input[name*=\"tax\" i][name*=\"id\" i], input[name*=\"ein\" i], input[id*=\"tax\" i][id*=\"id\" i]",
    description: "Tax ID/EIN fields",
    enabled: true,
    overlayColor: "#2a2a2a",
    overlayText: "TAX ID",
  },

  // Bank account fields
  {
    id: "bank-account",
    selector: "input[name*=\"account\" i][name*=\"number\" i], input[id*=\"account\" i][id*=\"number\" i], input[autocomplete=\"account-number\"]",
    description: "Bank account number fields",
    enabled: true,
    overlayColor: "#2a2a2a",
    overlayText: "ACCOUNT",
  },
  {
    id: "routing-number",
    selector: "input[name*=\"routing\" i], input[id*=\"routing\" i], input[autocomplete=\"routing-number\"]",
    description: "Bank routing number fields",
    enabled: true,
    overlayColor: "#2a2a2a",
    overlayText: "ROUTING",
  },

  // API keys and tokens (visible inputs)
  {
    id: "api-key-fields",
    selector: "input[name*=\"api\" i][name*=\"key\" i], input[id*=\"api\" i][id*=\"key\" i], input[name*=\"token\" i], input[id*=\"token\" i]:not([type=\"hidden\"])",
    description: "API key and token fields",
    enabled: true,
    overlayColor: "#3a3a3a",
    overlayText: "API KEY",
  },

  // Secret/private key fields
  {
    id: "secret-fields",
    selector: "input[name*=\"secret\" i], input[id*=\"secret\" i], textarea[name*=\"private\" i][name*=\"key\" i]",
    description: "Secret and private key fields",
    enabled: true,
    overlayColor: "#3a3a3a",
    overlayText: "SECRET",
  },

  // OAuth/Auth tokens
  {
    id: "oauth-fields",
    selector: "input[name*=\"oauth\" i], input[name*=\"bearer\" i], input[id*=\"oauth\" i], input[id*=\"bearer\" i]",
    description: "OAuth token fields",
    enabled: true,
    overlayColor: "#3a3a3a",
    overlayText: "TOKEN",
  },

  // Two-factor/MFA codes (usually okay to show, but option to redact)
  {
    id: "mfa-fields",
    selector: "input[name*=\"otp\" i], input[name*=\"totp\" i], input[name*=\"2fa\" i], input[autocomplete=\"one-time-code\"]",
    description: "Two-factor authentication fields",
    enabled: false, // Disabled by default
    overlayColor: "#4a4a4a",
    overlayText: "MFA",
  },

  // PIN fields
  {
    id: "pin-fields",
    selector: "input[name*=\"pin\" i][type=\"password\"], input[name*=\"pin\" i][inputmode=\"numeric\"], input[autocomplete=\"pin\"]",
    description: "PIN entry fields",
    enabled: true,
    overlayColor: "#4a4a4a",
    overlayText: "PIN",
  },
];

/**
 * Get screenshot redaction configuration from environment
 */
function getRedactionConfig(): ScreenshotRedactionConfig {
  return {
    enabled: process.env.CHROME_MCP_SCREENSHOT_REDACTION !== "false",
    overlayColor: process.env.CHROME_MCP_REDACTION_COLOR || "#000000",
    overlayText: process.env.CHROME_MCP_REDACTION_TEXT || "[REDACTED]",
    builtInTargets: DEFAULT_REDACTION_TARGETS,
    customTargets: parseCustomTargets(process.env.CHROME_MCP_REDACTION_SELECTORS),
    blurRadius: parseInt(process.env.CHROME_MCP_REDACTION_BLUR || "0", 10),
  };
}

/**
 * Parse custom redaction targets from environment
 * Format: selector1:description1;selector2:description2
 */
function parseCustomTargets(envValue?: string): RedactionTarget[] {
  if (!envValue) return [];

  const targets: RedactionTarget[] = [];

  try {
    const entries = envValue.split(";");
    for (let i = 0; i < entries.length; i++) {
      const [selector, description] = entries[i].split(":");
      if (selector) {
        targets.push({
          id: `custom-${i}`,
          selector: selector.trim(),
          description: description?.trim() || "Custom redaction target",
          enabled: true,
        });
      }
    }
  } catch (error) {
    log.warn(`Failed to parse custom redaction selectors: ${error}`);
  }

  return targets;
}

/**
 * Screenshot Redaction Manager
 */
export class ScreenshotRedactionManager {
  private config: ScreenshotRedactionConfig;
  private stats = {
    screenshotsProcessed: 0,
    elementsRedacted: 0,
    targetsUsed: new Set<string>(),
  };

  constructor(config?: Partial<ScreenshotRedactionConfig>) {
    this.config = { ...getRedactionConfig(), ...config };
  }

  /**
   * Get CSS to inject for redacting sensitive elements
   */
  getRedactionCSS(): string {
    if (!this.config.enabled) {
      return "";
    }

    const enabledTargets = this.getEnabledTargets();

    if (enabledTargets.length === 0) {
      return "";
    }

    const cssRules: string[] = [];

    // Create CSS for each target
    for (const target of enabledTargets) {
      const color = target.overlayColor || this.config.overlayColor;
      const text = target.overlayText || this.config.overlayText;

      cssRules.push(`
/* Redaction: ${target.description} */
${target.selector} {
  position: relative !important;
  color: transparent !important;
  text-shadow: none !important;
  -webkit-text-security: none !important;
  background: ${color} !important;
}
${target.selector}::after {
  content: "${text}" !important;
  position: absolute !important;
  top: 50% !important;
  left: 50% !important;
  transform: translate(-50%, -50%) !important;
  color: #ffffff !important;
  font-size: 10px !important;
  font-weight: bold !important;
  font-family: monospace !important;
  letter-spacing: 1px !important;
  pointer-events: none !important;
  z-index: 999999 !important;
}
${target.selector}::placeholder {
  color: transparent !important;
}
`);

      // Add blur if configured
      if (this.config.blurRadius > 0) {
        cssRules.push(`
${target.selector} {
  filter: blur(${this.config.blurRadius}px) !important;
}
`);
      }
    }

    return cssRules.join("\n");
  }

  /**
   * Get JavaScript to inject for counting redacted elements
   */
  getRedactionScript(): string {
    const enabledTargets = this.getEnabledTargets();

    if (enabledTargets.length === 0) {
      return "return { count: 0, selectors: [] };";
    }

    const selectors = enabledTargets.map((t) => t.selector);

    return `
      const results = {
        count: 0,
        selectors: []
      };

      ${JSON.stringify(selectors)}.forEach((selector, index) => {
        try {
          const elements = document.querySelectorAll(selector);
          if (elements.length > 0) {
            results.count += elements.length;
            results.selectors.push({
              index,
              selector,
              count: elements.length
            });
          }
        } catch (e) {
          // Invalid selector, skip
        }
      });

      return results;
    `;
  }

  /**
   * Get enabled redaction targets
   */
  getEnabledTargets(): RedactionTarget[] {
    return [
      ...this.config.builtInTargets.filter((t) => t.enabled),
      ...this.config.customTargets.filter((t) => t.enabled),
    ];
  }

  /**
   * Process a screenshot request - returns CSS to inject
   */
  async prepareRedaction(): Promise<RedactionResult> {
    this.stats.screenshotsProcessed++;

    if (!this.config.enabled) {
      return {
        redacted: false,
        elementsRedacted: 0,
        targetsMatched: [],
        cssInjected: "",
        warnings: [],
      };
    }

    const css = this.getRedactionCSS();
    const enabledTargets = this.getEnabledTargets();

    for (const target of enabledTargets) {
      this.stats.targetsUsed.add(target.id);
    }

    return {
      redacted: true,
      elementsRedacted: 0, // Will be updated after injection
      targetsMatched: enabledTargets.map((t) => t.id),
      cssInjected: css,
      warnings: [],
    };
  }

  /**
   * Record redaction statistics after screenshot
   */
  async recordRedaction(elementsRedacted: number, targetIds: string[]): Promise<void> {
    this.stats.elementsRedacted += elementsRedacted;

    if (elementsRedacted > 0) {
      log.info(`Screenshot redaction: ${elementsRedacted} sensitive elements redacted`);
      await audit.security("screenshot_redaction", "info", {
        elements_redacted: elementsRedacted,
        targets: targetIds,
      });
    }
  }

  /**
   * Add a custom redaction target
   */
  addTarget(target: RedactionTarget): void {
    // Remove existing target with same ID
    this.config.customTargets = this.config.customTargets.filter((t) => t.id !== target.id);
    this.config.customTargets.push(target);
    log.info(`Added redaction target: ${target.id}`);
  }

  /**
   * Remove a custom redaction target
   */
  removeTarget(id: string): boolean {
    const initialLength = this.config.customTargets.length;
    this.config.customTargets = this.config.customTargets.filter((t) => t.id !== id);

    if (this.config.customTargets.length < initialLength) {
      log.info(`Removed redaction target: ${id}`);
      return true;
    }

    return false;
  }

  /**
   * Enable or disable a built-in target
   */
  setTargetEnabled(id: string, enabled: boolean): boolean {
    const target = this.config.builtInTargets.find((t) => t.id === id);
    if (target) {
      target.enabled = enabled;
      log.info(`${enabled ? "Enabled" : "Disabled"} redaction target: ${id}`);
      return true;
    }

    const customTarget = this.config.customTargets.find((t) => t.id === id);
    if (customTarget) {
      customTarget.enabled = enabled;
      log.info(`${enabled ? "Enabled" : "Disabled"} custom redaction target: ${id}`);
      return true;
    }

    return false;
  }

  /**
   * Get all available targets
   */
  getAllTargets(): RedactionTarget[] {
    return [...this.config.builtInTargets, ...this.config.customTargets];
  }

  /**
   * Get redaction statistics
   */
  getStats(): {
    screenshotsProcessed: number;
    elementsRedacted: number;
    uniqueTargetsUsed: number;
  } {
    return {
      screenshotsProcessed: this.stats.screenshotsProcessed,
      elementsRedacted: this.stats.elementsRedacted,
      uniqueTargetsUsed: this.stats.targetsUsed.size,
    };
  }

  /**
   * Reset statistics
   */
  resetStats(): void {
    this.stats = {
      screenshotsProcessed: 0,
      elementsRedacted: 0,
      targetsUsed: new Set(),
    };
  }

  /**
   * Check if redaction is enabled
   */
  isEnabled(): boolean {
    return this.config.enabled;
  }

  /**
   * Get status information
   */
  getStatus(): {
    enabled: boolean;
    enabledTargets: number;
    totalTargets: number;
    defaultColor: string;
    defaultText: string;
  } {
    return {
      enabled: this.config.enabled,
      enabledTargets: this.getEnabledTargets().length,
      totalTargets: this.getAllTargets().length,
      defaultColor: this.config.overlayColor,
      defaultText: this.config.overlayText,
    };
  }
}

/**
 * Global screenshot redaction manager instance
 */
let globalManager: ScreenshotRedactionManager | null = null;

/**
 * Get or create the global screenshot redaction manager
 */
export function getScreenshotRedactionManager(): ScreenshotRedactionManager {
  if (!globalManager) {
    globalManager = new ScreenshotRedactionManager();
  }
  return globalManager;
}

/**
 * Convenience function to get redaction CSS
 */
export function getRedactionCSS(): string {
  return getScreenshotRedactionManager().getRedactionCSS();
}

/**
 * Convenience function to prepare for screenshot with redaction
 */
export async function prepareScreenshotRedaction(): Promise<RedactionResult> {
  return getScreenshotRedactionManager().prepareRedaction();
}
