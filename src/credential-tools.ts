/**
 * Secure Credential MCP Tools for Chrome MCP Server
 *
 * Provides MCP tools for managing login credentials:
 * - store_credential: Store encrypted credentials
 * - list_credentials: List stored credentials (no passwords)
 * - delete_credential: Remove a credential
 * - secure_login: Perform login using stored credentials
 * - get_vault_status: Check vault encryption status
 *
 * Adapted from Pantheon Security's notebooklm-mcp-secure.
 */

import { z } from "zod";
import { getCredentialVault, StoredCredential, ActiveCredential } from "./credential-vault.js";
import { CDPClient } from "./cdp-client.js";
import { log, audit } from "./logger.js";
import { maskSensitive } from "./secure-memory.js";

/**
 * Tool definitions for credential management
 */
export const credentialToolSchemas = {
  store_credential: {
    name: "store_credential",
    description: "Securely store login credentials with post-quantum encryption. Credentials are encrypted at rest and wiped from memory after use.",
    inputSchema: z.object({
      name: z.string().describe("Friendly name for this credential (e.g., 'Google Work Account')"),
      type: z.enum(["google", "basic", "oauth", "api_key", "custom"]).describe("Type of credential"),
      username: z.string().optional().describe("Username or login ID"),
      email: z.string().email().optional().describe("Email address for login"),
      password: z.string().optional().describe("Password (will be encrypted)"),
      apiKey: z.string().optional().describe("API key (will be encrypted)"),
      domain: z.string().optional().describe("Associated domain (e.g., 'google.com')"),
      notes: z.string().optional().describe("Additional notes"),
    }),
  },

  list_credentials: {
    name: "list_credentials",
    description: "List all stored credentials. Returns metadata only - no passwords or API keys are exposed.",
    inputSchema: z.object({
      type: z.enum(["google", "basic", "oauth", "api_key", "custom"]).optional().describe("Filter by credential type"),
      domain: z.string().optional().describe("Filter by domain"),
    }),
  },

  get_credential: {
    name: "get_credential",
    description: "Get a specific credential by ID. Returns metadata only - use secure_login for authentication.",
    inputSchema: z.object({
      id: z.string().describe("Credential ID"),
    }),
  },

  delete_credential: {
    name: "delete_credential",
    description: "Permanently delete a stored credential.",
    inputSchema: z.object({
      id: z.string().describe("Credential ID to delete"),
    }),
  },

  update_credential: {
    name: "update_credential",
    description: "Update an existing credential. Only provided fields will be updated.",
    inputSchema: z.object({
      id: z.string().describe("Credential ID to update"),
      name: z.string().optional().describe("New friendly name"),
      username: z.string().optional().describe("New username"),
      email: z.string().email().optional().describe("New email"),
      password: z.string().optional().describe("New password (will be encrypted)"),
      apiKey: z.string().optional().describe("New API key (will be encrypted)"),
      domain: z.string().optional().describe("New domain"),
      notes: z.string().optional().describe("New notes"),
    }),
  },

  secure_login: {
    name: "secure_login",
    description: "Perform a secure login using stored credentials. Automatically fills in username/email and password fields, then submits the form.",
    inputSchema: z.object({
      credentialId: z.string().describe("ID of the stored credential to use"),
      usernameSelector: z.string().optional().default("input[type='email'], input[name='username'], input[name='email'], #email, #username").describe("CSS selector for username/email field"),
      passwordSelector: z.string().optional().default("input[type='password'], input[name='password'], #password").describe("CSS selector for password field"),
      submitSelector: z.string().optional().default("button[type='submit'], input[type='submit'], button:contains('Sign in'), button:contains('Log in')").describe("CSS selector for submit button"),
      delayMs: z.number().optional().default(500).describe("Delay between typing actions (ms)"),
      skipSubmit: z.boolean().optional().default(false).describe("If true, don't click submit - just fill fields"),
    }),
  },

  get_vault_status: {
    name: "get_vault_status",
    description: "Get the status of the credential vault including encryption configuration.",
    inputSchema: z.object({}),
  },
};

/**
 * Handle store_credential tool
 */
export async function handleStoreCredential(args: z.infer<typeof credentialToolSchemas.store_credential.inputSchema>): Promise<{ credentialId: string; message: string }> {
  const vault = getCredentialVault();

  const id = await vault.store({
    name: args.name,
    type: args.type,
    username: args.username,
    email: args.email,
    password: args.password,
    apiKey: args.apiKey,
    domain: args.domain,
    notes: args.notes,
  });

  return {
    credentialId: id,
    message: `Credential '${args.name}' stored securely with post-quantum encryption`,
  };
}

/**
 * Handle list_credentials tool
 */
export async function handleListCredentials(args: z.infer<typeof credentialToolSchemas.list_credentials.inputSchema>): Promise<Array<Omit<StoredCredential, "encryptedPassword" | "encryptedApiKey">>> {
  const vault = getCredentialVault();

  let credentials = await vault.list();

  // Apply filters
  if (args.type) {
    credentials = credentials.filter(c => c.type === args.type);
  }

  if (args.domain) {
    credentials = credentials.filter(c => c.domain && c.domain.includes(args.domain!));
  }

  return credentials;
}

/**
 * Handle get_credential tool
 */
export async function handleGetCredential(args: z.infer<typeof credentialToolSchemas.get_credential.inputSchema>): Promise<Omit<StoredCredential, "encryptedPassword" | "encryptedApiKey"> | null> {
  const vault = getCredentialVault();
  const credentials = await vault.list();

  const found = credentials.find(c => c.id === args.id);
  return found || null;
}

/**
 * Handle delete_credential tool
 */
export async function handleDeleteCredential(args: z.infer<typeof credentialToolSchemas.delete_credential.inputSchema>): Promise<{ success: boolean; message: string }> {
  const vault = getCredentialVault();

  const deleted = await vault.delete(args.id);

  return {
    success: deleted,
    message: deleted
      ? `Credential ${maskSensitive(args.id)} deleted`
      : `Credential ${maskSensitive(args.id)} not found`,
  };
}

/**
 * Handle update_credential tool
 */
export async function handleUpdateCredential(args: z.infer<typeof credentialToolSchemas.update_credential.inputSchema>): Promise<{ success: boolean; message: string }> {
  const vault = getCredentialVault();

  const { id, ...updates } = args;
  const updated = await vault.update(id, updates);

  return {
    success: updated,
    message: updated
      ? `Credential ${maskSensitive(id)} updated`
      : `Credential ${maskSensitive(id)} not found or update failed`,
  };
}

/**
 * Handle secure_login tool
 */
export async function handleSecureLogin(
  args: z.infer<typeof credentialToolSchemas.secure_login.inputSchema>,
  cdpClient: CDPClient
): Promise<{ success: boolean; message: string }> {
  const vault = getCredentialVault();

  // Get the credential
  const credential = await vault.get(args.credentialId);

  if (!credential) {
    return {
      success: false,
      message: `Credential ${maskSensitive(args.credentialId)} not found`,
    };
  }

  // Get the login value (email or username)
  const loginValue = credential.email || credential.username;
  if (!loginValue) {
    return {
      success: false,
      message: "Credential has no email or username",
    };
  }

  // Get the password
  if (!credential.password || credential.password.isWiped()) {
    return {
      success: false,
      message: "Credential password is not available or has expired",
    };
  }

  const password = credential.password.getValue();

  try {
    await audit.security("secure_login_started", "info", {
      credentialId: maskSensitive(args.credentialId),
      credentialName: credential.name,
      domain: credential.domain,
    });

    // Find and focus username field
    const usernameResult = await cdpClient.evaluate<{ found: boolean; selector?: string }>(`
      (function() {
        const selectors = ${JSON.stringify(args.usernameSelector)}.split(', ');
        for (const selector of selectors) {
          const el = document.querySelector(selector);
          if (el && el.offsetParent !== null) {
            el.focus();
            el.value = '';
            return { found: true, selector: selector };
          }
        }
        return { found: false };
      })()
    `);

    if (!usernameResult?.found) {
      return {
        success: false,
        message: "Could not find username/email field on page",
      };
    }

    // Type username with human-like delay
    await typeText(cdpClient, loginValue, args.delayMs || 500);

    // Small delay before password
    await sleep(300);

    // Find and focus password field
    const passwordResult = await cdpClient.evaluate<{ found: boolean; selector?: string }>(`
      (function() {
        const selectors = ${JSON.stringify(args.passwordSelector)}.split(', ');
        for (const selector of selectors) {
          const el = document.querySelector(selector);
          if (el && el.offsetParent !== null) {
            el.focus();
            el.value = '';
            return { found: true, selector: selector };
          }
        }
        return { found: false };
      })()
    `);

    if (!passwordResult?.found) {
      return {
        success: false,
        message: "Could not find password field on page",
      };
    }

    // Type password (credentials are logged as masked)
    log.info(`Typing password for ${credential.name} (${maskSensitive(password, 0)})`);
    await typeText(cdpClient, password, args.delayMs || 500);

    // Submit if requested
    if (!args.skipSubmit) {
      await sleep(300);

      const submitResult = await cdpClient.evaluate<{ clicked: boolean; selector?: string }>(`
        (function() {
          const selectors = ${JSON.stringify(args.submitSelector)}.split(', ');
          for (const selector of selectors) {
            try {
              const el = document.querySelector(selector);
              if (el && el.offsetParent !== null) {
                el.click();
                return { clicked: true, selector: selector };
              }
            } catch (e) {}
          }
          // Try form submit as fallback
          const form = document.querySelector('form');
          if (form) {
            form.submit();
            return { clicked: true, selector: 'form.submit()' };
          }
          return { clicked: false };
        })()
      `);

      if (!submitResult?.clicked) {
        log.warn("Could not find submit button - form may need manual submission");
      }
    }

    await audit.security("secure_login_completed", "info", {
      credentialId: maskSensitive(args.credentialId),
      credentialName: credential.name,
    });

    return {
      success: true,
      message: `Login form filled for ${credential.name}${args.skipSubmit ? " (not submitted)" : " and submitted"}`,
    };

  } catch (error) {
    await audit.security("secure_login_failed", "error", {
      credentialId: maskSensitive(args.credentialId),
      error: String(error),
    });

    return {
      success: false,
      message: `Login failed: ${error}`,
    };
  }
}

/**
 * Handle get_vault_status tool
 */
export async function handleGetVaultStatus(): Promise<{
  initialized: boolean;
  activeCredentials: number;
  encryption: {
    enabled: boolean;
    postQuantumEnabled: boolean;
    algorithm: string;
    pqAlgorithm: string | null;
    keySource: string;
  };
}> {
  const vault = getCredentialVault();
  const status = vault.getStatus();

  return {
    initialized: status.initialized,
    activeCredentials: status.activeCredentials,
    encryption: {
      enabled: status.encryptionStatus.enabled,
      postQuantumEnabled: status.encryptionStatus.postQuantumEnabled,
      algorithm: status.encryptionStatus.algorithm,
      pqAlgorithm: status.encryptionStatus.pqAlgorithm,
      keySource: status.encryptionStatus.classicalKeySource,
    },
  };
}

/**
 * Type text character by character with human-like delays
 */
async function typeText(cdpClient: CDPClient, text: string, baseDelayMs: number): Promise<void> {
  for (const char of text) {
    // Dispatch key events for the character
    await cdpClient.send("Input.dispatchKeyEvent", {
      type: "keyDown",
      text: char,
    });

    await cdpClient.send("Input.dispatchKeyEvent", {
      type: "keyUp",
    });

    // Random delay for human-like typing
    const delay = baseDelayMs * (0.5 + Math.random());
    await sleep(Math.floor(delay / 10)); // Much faster than base delay
  }
}

/**
 * Sleep helper
 */
function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Register all credential tools with MCP server
 */
export function getCredentialTools() {
  return Object.values(credentialToolSchemas);
}
