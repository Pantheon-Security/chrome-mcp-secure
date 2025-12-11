/**
 * Secure Credential Vault for Chrome MCP Server
 *
 * Provides encrypted storage and management for login credentials:
 * - Post-quantum encrypted at rest (ML-KEM-768 + ChaCha20-Poly1305)
 * - Auto-wiping credentials from memory after use
 * - Session-based credential access with expiration
 * - Audit logging of all credential operations
 *
 * Adapted from Pantheon Security's notebooklm-mcp-secure.
 */

import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { SecureStorage, getSecureStorage } from "./crypto.js";
import { SecureString, SecureCredential, maskSensitive } from "./secure-memory.js";
import { log, audit } from "./logger.js";
import { mkdirSecure, writeFileSecure, PERMISSION_MODES } from "./file-permissions.js";

/**
 * Stored credential format
 */
export interface StoredCredential {
  id: string;
  name: string;
  type: "google" | "basic" | "oauth" | "api_key" | "custom";
  username?: string;
  email?: string;
  encryptedPassword?: string; // Stored encrypted
  encryptedApiKey?: string;   // For API key type
  domain?: string;            // e.g., "google.com", "dashboard.example.com"
  notes?: string;
  createdAt: string;
  updatedAt: string;
  lastUsed?: string;
}

/**
 * Credential for use (decrypted, in-memory only)
 */
export interface ActiveCredential {
  id: string;
  name: string;
  type: StoredCredential["type"];
  username?: string;
  email?: string;
  password?: SecureCredential;
  apiKey?: SecureCredential;
  domain?: string;
}

/**
 * Vault configuration
 */
interface VaultConfig {
  vaultPath: string;
  credentialTTLMs: number;  // How long decrypted credentials stay in memory
  maxCredentials: number;
}

/**
 * Credential Vault class
 * Manages secure storage and retrieval of login credentials
 */
export class CredentialVault {
  private config: VaultConfig;
  private storage: SecureStorage;
  private activeCredentials: Map<string, ActiveCredential> = new Map();
  private cleanupTimers: Map<string, NodeJS.Timeout> = new Map();
  private initialized: boolean = false;

  constructor(config?: Partial<VaultConfig>) {
    const configDir = process.env.CHROME_MCP_CONFIG_DIR || path.join(os.homedir(), ".chrome-mcp");

    this.config = {
      vaultPath: path.join(configDir, "credentials"),
      credentialTTLMs: parseInt(process.env.CHROME_MCP_CREDENTIAL_TTL || "300000", 10), // 5 min default
      maxCredentials: parseInt(process.env.CHROME_MCP_MAX_CREDENTIALS || "50", 10),
      ...config,
    };

    this.storage = getSecureStorage();
  }

  /**
   * Initialize the vault
   */
  async initialize(): Promise<void> {
    if (this.initialized) return;

    log.info("Initializing credential vault...");

    // Ensure vault directory exists
    mkdirSecure(this.config.vaultPath, PERMISSION_MODES.OWNER_FULL);

    // Initialize secure storage
    await this.storage.initialize();

    this.initialized = true;
    log.success("Credential vault initialized");
    await audit.security("vault_initialized", "info", {});
  }

  /**
   * Store a new credential
   */
  async store(credential: Omit<StoredCredential, "id" | "createdAt" | "updatedAt" | "encryptedPassword" | "encryptedApiKey"> & {
    password?: string;
    apiKey?: string;
  }): Promise<string> {
    await this.initialize();

    // Generate unique ID
    const id = `cred_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
    const now = new Date().toISOString();

    // Create stored credential (password will be encrypted)
    const stored: StoredCredential = {
      id,
      name: credential.name,
      type: credential.type,
      username: credential.username,
      email: credential.email,
      domain: credential.domain,
      notes: credential.notes,
      createdAt: now,
      updatedAt: now,
    };

    // Encrypt password if provided
    if (credential.password) {
      stored.encryptedPassword = await this.encryptValue(credential.password);
    }

    // Encrypt API key if provided
    if (credential.apiKey) {
      stored.encryptedApiKey = await this.encryptValue(credential.apiKey);
    }

    // Save to encrypted storage
    const credPath = path.join(this.config.vaultPath, `${id}.json`);
    await this.storage.save(credPath, stored);

    log.info(`Stored credential: ${stored.name} (${maskSensitive(id)})`);
    await audit.security("credential_stored", "info", {
      credentialId: maskSensitive(id),
      name: stored.name,
      type: stored.type,
      domain: stored.domain,
    });

    return id;
  }

  /**
   * Retrieve and decrypt a credential
   */
  async get(id: string): Promise<ActiveCredential | null> {
    await this.initialize();

    // Check if already active in memory
    if (this.activeCredentials.has(id)) {
      const active = this.activeCredentials.get(id)!;

      // Check if credentials are still valid
      if (active.password && !active.password.isWiped()) {
        this.refreshTTL(id);
        return active;
      }

      // Credentials expired, remove from active
      this.cleanupCredential(id);
    }

    // Load from storage
    const credPath = path.join(this.config.vaultPath, `${id}.json`);
    const stored = await this.storage.loadJSON<StoredCredential>(credPath);

    if (!stored) {
      log.warn(`Credential not found: ${maskSensitive(id)}`);
      return null;
    }

    // Decrypt and create active credential
    const active: ActiveCredential = {
      id: stored.id,
      name: stored.name,
      type: stored.type,
      username: stored.username,
      email: stored.email,
      domain: stored.domain,
    };

    // Decrypt password
    if (stored.encryptedPassword) {
      const password = await this.decryptValue(stored.encryptedPassword);
      if (password) {
        active.password = new SecureCredential(password, this.config.credentialTTLMs);
      }
    }

    // Decrypt API key
    if (stored.encryptedApiKey) {
      const apiKey = await this.decryptValue(stored.encryptedApiKey);
      if (apiKey) {
        active.apiKey = new SecureCredential(apiKey, this.config.credentialTTLMs);
      }
    }

    // Store in active credentials
    this.activeCredentials.set(id, active);
    this.scheduleCleanup(id);

    // Update last used
    stored.lastUsed = new Date().toISOString();
    await this.storage.save(credPath, stored);

    log.info(`Retrieved credential: ${stored.name}`);
    await audit.security("credential_retrieved", "info", {
      credentialId: maskSensitive(id),
      name: stored.name,
      type: stored.type,
    });

    return active;
  }

  /**
   * List all stored credentials (without passwords)
   */
  async list(): Promise<Array<Omit<StoredCredential, "encryptedPassword" | "encryptedApiKey">>> {
    await this.initialize();

    const files = fs.readdirSync(this.config.vaultPath)
      .filter(f => f.endsWith(".json") || f.endsWith(".enc") || f.endsWith(".pqenc"));

    const credentials: Array<Omit<StoredCredential, "encryptedPassword" | "encryptedApiKey">> = [];
    const processedIds = new Set<string>();

    for (const file of files) {
      // Extract base ID from filename
      const baseName = file.replace(/\.(json|enc|pqenc)$/, "");
      if (processedIds.has(baseName)) continue;
      processedIds.add(baseName);

      // Pass base path - storage.loadJSON checks for .pqenc, .enc, then .json
      const credPath = path.join(this.config.vaultPath, baseName);
      const stored = await this.storage.loadJSON<StoredCredential>(credPath);

      if (stored) {
        // Return without sensitive fields
        const { encryptedPassword, encryptedApiKey, ...safe } = stored;
        credentials.push(safe);
      }
    }

    return credentials;
  }

  /**
   * Delete a credential
   */
  async delete(id: string): Promise<boolean> {
    await this.initialize();

    // Clean up active credential
    this.cleanupCredential(id);

    // Delete from storage
    const credPath = path.join(this.config.vaultPath, `${id}.json`);
    const deleted = await this.storage.delete(credPath);

    if (deleted) {
      log.info(`Deleted credential: ${maskSensitive(id)}`);
      await audit.security("credential_deleted", "info", {
        credentialId: maskSensitive(id),
      });
    }

    return deleted;
  }

  /**
   * Update a credential
   */
  async update(id: string, updates: Partial<Omit<StoredCredential, "id" | "createdAt"> & {
    password?: string;
    apiKey?: string;
  }>): Promise<boolean> {
    await this.initialize();

    const credPath = path.join(this.config.vaultPath, `${id}.json`);
    const stored = await this.storage.loadJSON<StoredCredential>(credPath);

    if (!stored) {
      log.warn(`Cannot update: credential not found: ${maskSensitive(id)}`);
      return false;
    }

    // Apply updates
    if (updates.name !== undefined) stored.name = updates.name;
    if (updates.type !== undefined) stored.type = updates.type;
    if (updates.username !== undefined) stored.username = updates.username;
    if (updates.email !== undefined) stored.email = updates.email;
    if (updates.domain !== undefined) stored.domain = updates.domain;
    if (updates.notes !== undefined) stored.notes = updates.notes;

    // Encrypt new password if provided
    if (updates.password !== undefined) {
      stored.encryptedPassword = await this.encryptValue(updates.password);
    }

    // Encrypt new API key if provided
    if (updates.apiKey !== undefined) {
      stored.encryptedApiKey = await this.encryptValue(updates.apiKey);
    }

    stored.updatedAt = new Date().toISOString();

    // Clear active credential to force reload
    this.cleanupCredential(id);

    // Save updated credential
    await this.storage.save(credPath, stored);

    log.info(`Updated credential: ${stored.name}`);
    await audit.security("credential_updated", "info", {
      credentialId: maskSensitive(id),
      name: stored.name,
      updatedFields: Object.keys(updates),
    });

    return true;
  }

  /**
   * Find credentials by domain
   */
  async findByDomain(domain: string): Promise<Array<Omit<StoredCredential, "encryptedPassword" | "encryptedApiKey">>> {
    const all = await this.list();
    return all.filter(c => c.domain && c.domain.includes(domain));
  }

  /**
   * Find credentials by type
   */
  async findByType(type: StoredCredential["type"]): Promise<Array<Omit<StoredCredential, "encryptedPassword" | "encryptedApiKey">>> {
    const all = await this.list();
    return all.filter(c => c.type === type);
  }

  /**
   * Encrypt a value using the secure storage
   */
  private async encryptValue(value: string): Promise<string> {
    // We store encrypted values as base64 of the JSON encrypted structure
    const tempPath = path.join(os.tmpdir(), `chrome-mcp-temp-${Date.now()}`);
    await this.storage.save(tempPath, value);

    // Read back the encrypted file
    const encryptedFile = [tempPath + ".pqenc", tempPath + ".enc", tempPath]
      .find(p => fs.existsSync(p));

    if (!encryptedFile) {
      throw new Error("Failed to encrypt value");
    }

    const encrypted = fs.readFileSync(encryptedFile, "utf-8");
    fs.unlinkSync(encryptedFile);

    return Buffer.from(encrypted).toString("base64");
  }

  /**
   * Decrypt a value
   */
  private async decryptValue(encryptedBase64: string): Promise<string | null> {
    try {
      const encrypted = Buffer.from(encryptedBase64, "base64").toString("utf-8");
      const tempPath = path.join(os.tmpdir(), `chrome-mcp-temp-${Date.now()}`);

      // Determine extension from encrypted data
      const data = JSON.parse(encrypted);
      const ext = data.pqAlgorithm ? ".pqenc" : ".enc";

      writeFileSecure(tempPath + ext, encrypted, PERMISSION_MODES.OWNER_READ_WRITE);

      const decrypted = await this.storage.load(tempPath);

      // Clean up temp file
      const files = [tempPath, tempPath + ".enc", tempPath + ".pqenc"];
      files.forEach(f => fs.existsSync(f) && fs.unlinkSync(f));

      return decrypted;
    } catch (error) {
      log.error(`Failed to decrypt value: ${error}`);
      return null;
    }
  }

  /**
   * Schedule cleanup of an active credential
   */
  private scheduleCleanup(id: string): void {
    // Clear any existing timer
    if (this.cleanupTimers.has(id)) {
      clearTimeout(this.cleanupTimers.get(id)!);
    }

    // Schedule new cleanup
    const timer = setTimeout(() => {
      this.cleanupCredential(id);
    }, this.config.credentialTTLMs);

    this.cleanupTimers.set(id, timer);
  }

  /**
   * Refresh TTL for an active credential
   */
  private refreshTTL(id: string): void {
    this.scheduleCleanup(id);
  }

  /**
   * Clean up an active credential from memory
   */
  private cleanupCredential(id: string): void {
    const active = this.activeCredentials.get(id);

    if (active) {
      // Wipe credentials from memory
      active.password?.wipe();
      active.apiKey?.wipe();

      this.activeCredentials.delete(id);
    }

    // Clear cleanup timer
    const timer = this.cleanupTimers.get(id);
    if (timer) {
      clearTimeout(timer);
      this.cleanupTimers.delete(id);
    }
  }

  /**
   * Clean up all active credentials
   */
  cleanup(): void {
    for (const id of this.activeCredentials.keys()) {
      this.cleanupCredential(id);
    }

    log.info("Cleaned up all active credentials");
  }

  /**
   * Get vault status
   */
  getStatus(): {
    initialized: boolean;
    activeCredentials: number;
    encryptionStatus: ReturnType<SecureStorage["getStatus"]>;
  } {
    return {
      initialized: this.initialized,
      activeCredentials: this.activeCredentials.size,
      encryptionStatus: this.storage.getStatus(),
    };
  }
}

// Global vault instance
let globalVault: CredentialVault | null = null;

/**
 * Get or create the global credential vault
 */
export function getCredentialVault(): CredentialVault {
  if (!globalVault) {
    globalVault = new CredentialVault();
  }
  return globalVault;
}
