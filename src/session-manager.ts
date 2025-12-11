/**
 * Session Manager for Chrome MCP Server
 *
 * Manages credential session lifecycle:
 * - Maximum session lifetime (hard limit)
 * - Inactivity timeout (auto-expire idle sessions)
 * - Credential refresh tracking
 * - Session audit logging
 *
 * Adapted from Pantheon Security's notebooklm-mcp-secure.
 */

import { log, audit } from "./logger.js";
import { getCredentialVault } from "./credential-vault.js";

/**
 * Session information
 */
export interface Session {
  id: string;
  credentialId: string;
  createdAt: number;
  lastActivity: number;
  loginDomain?: string;
  status: "active" | "expired" | "logged_out";
}

/**
 * Session manager configuration
 */
export interface SessionConfig {
  /** Maximum session lifetime in milliseconds (default: 8 hours) */
  maxLifetimeMs: number;
  /** Inactivity timeout in milliseconds (default: 30 minutes) */
  inactivityTimeoutMs: number;
  /** Check interval for expired sessions (default: 1 minute) */
  checkIntervalMs: number;
  /** Enable session management (default: true) */
  enabled: boolean;
}

/**
 * Get session configuration from environment
 */
function getSessionConfig(): SessionConfig {
  return {
    maxLifetimeMs: parseInt(process.env.CHROME_MCP_SESSION_MAX_LIFETIME || String(8 * 60 * 60 * 1000), 10), // 8 hours
    inactivityTimeoutMs: parseInt(process.env.CHROME_MCP_SESSION_INACTIVITY || String(30 * 60 * 1000), 10), // 30 minutes
    checkIntervalMs: parseInt(process.env.CHROME_MCP_SESSION_CHECK_INTERVAL || String(60 * 1000), 10), // 1 minute
    enabled: process.env.CHROME_MCP_SESSION_MANAGEMENT !== "false",
  };
}

/**
 * Session Manager Class
 */
export class SessionManager {
  private config: SessionConfig;
  private sessions: Map<string, Session> = new Map();
  private checkInterval: NodeJS.Timeout | null = null;
  private stats = {
    sessionsCreated: 0,
    sessionsExpired: 0,
    sessionsLoggedOut: 0,
    activityUpdates: 0,
  };

  constructor(config?: Partial<SessionConfig>) {
    this.config = { ...getSessionConfig(), ...config };

    if (this.config.enabled) {
      this.startExpirationChecker();
    }
  }

  /**
   * Create a new session for a credential
   */
  async createSession(credentialId: string, loginDomain?: string): Promise<Session> {
    const now = Date.now();
    const sessionId = `sess_${now}_${Math.random().toString(36).substring(2, 9)}`;

    const session: Session = {
      id: sessionId,
      credentialId,
      createdAt: now,
      lastActivity: now,
      loginDomain,
      status: "active",
    };

    this.sessions.set(sessionId, session);
    this.stats.sessionsCreated++;

    log.info(`Session created: ${sessionId.substring(0, 12)}*** for domain: ${loginDomain || "unknown"}`);
    await audit.security("session_created", "info", {
      sessionId: sessionId.substring(0, 12) + "***",
      credentialId: credentialId.substring(0, 8) + "***",
      domain: loginDomain,
      maxLifetimeMinutes: Math.round(this.config.maxLifetimeMs / 60000),
      inactivityTimeoutMinutes: Math.round(this.config.inactivityTimeoutMs / 60000),
    });

    return session;
  }

  /**
   * Update session activity (extends inactivity timeout)
   */
  updateActivity(sessionId: string): boolean {
    const session = this.sessions.get(sessionId);
    if (!session || session.status !== "active") {
      return false;
    }

    // Check if session has exceeded max lifetime
    const now = Date.now();
    if (now - session.createdAt > this.config.maxLifetimeMs) {
      this.expireSession(sessionId, "max_lifetime");
      return false;
    }

    session.lastActivity = now;
    this.stats.activityUpdates++;
    return true;
  }

  /**
   * Get session by ID
   */
  getSession(sessionId: string): Session | null {
    const session = this.sessions.get(sessionId);
    if (!session) return null;

    // Check if still valid
    if (session.status !== "active") {
      return null;
    }

    const now = Date.now();

    // Check max lifetime
    if (now - session.createdAt > this.config.maxLifetimeMs) {
      this.expireSession(sessionId, "max_lifetime");
      return null;
    }

    // Check inactivity
    if (now - session.lastActivity > this.config.inactivityTimeoutMs) {
      this.expireSession(sessionId, "inactivity");
      return null;
    }

    return session;
  }

  /**
   * Get all active sessions
   */
  getActiveSessions(): Session[] {
    const active: Session[] = [];
    const now = Date.now();

    for (const session of this.sessions.values()) {
      if (session.status !== "active") continue;

      // Check validity
      if (now - session.createdAt > this.config.maxLifetimeMs) {
        this.expireSession(session.id, "max_lifetime");
        continue;
      }

      if (now - session.lastActivity > this.config.inactivityTimeoutMs) {
        this.expireSession(session.id, "inactivity");
        continue;
      }

      active.push(session);
    }

    return active;
  }

  /**
   * Get sessions for a specific credential
   */
  getSessionsForCredential(credentialId: string): Session[] {
    return this.getActiveSessions().filter(s => s.credentialId === credentialId);
  }

  /**
   * Expire a session
   */
  private async expireSession(sessionId: string, reason: "max_lifetime" | "inactivity" | "manual"): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (!session || session.status !== "active") return;

    session.status = "expired";
    this.stats.sessionsExpired++;

    // Clean up credential from vault
    const vault = getCredentialVault();
    vault.cleanup();

    log.info(`Session expired: ${sessionId.substring(0, 12)}*** (reason: ${reason})`);
    await audit.security("session_expired", "info", {
      sessionId: sessionId.substring(0, 12) + "***",
      reason,
      lifetimeMinutes: Math.round((Date.now() - session.createdAt) / 60000),
      domain: session.loginDomain,
    });
  }

  /**
   * Manually logout a session
   */
  async logout(sessionId: string): Promise<boolean> {
    const session = this.sessions.get(sessionId);
    if (!session || session.status !== "active") {
      return false;
    }

    session.status = "logged_out";
    this.stats.sessionsLoggedOut++;

    // Clean up credential from vault
    const vault = getCredentialVault();
    vault.cleanup();

    log.info(`Session logged out: ${sessionId.substring(0, 12)}***`);
    await audit.security("session_logout", "info", {
      sessionId: sessionId.substring(0, 12) + "***",
      lifetimeMinutes: Math.round((Date.now() - session.createdAt) / 60000),
      domain: session.loginDomain,
    });

    return true;
  }

  /**
   * Logout all sessions for a credential
   */
  async logoutCredential(credentialId: string): Promise<number> {
    const sessions = this.getSessionsForCredential(credentialId);
    let count = 0;

    for (const session of sessions) {
      if (await this.logout(session.id)) {
        count++;
      }
    }

    return count;
  }

  /**
   * Get time remaining for a session
   */
  getTimeRemaining(sessionId: string): { lifetime: number; inactivity: number } | null {
    const session = this.getSession(sessionId);
    if (!session) return null;

    const now = Date.now();
    return {
      lifetime: Math.max(0, this.config.maxLifetimeMs - (now - session.createdAt)),
      inactivity: Math.max(0, this.config.inactivityTimeoutMs - (now - session.lastActivity)),
    };
  }

  /**
   * Start the expiration checker interval
   */
  private startExpirationChecker(): void {
    if (this.checkInterval) {
      clearInterval(this.checkInterval);
    }

    this.checkInterval = setInterval(() => {
      this.checkExpiredSessions();
    }, this.config.checkIntervalMs);

    // Don't prevent process from exiting
    this.checkInterval.unref();
  }

  /**
   * Check and expire sessions
   */
  private checkExpiredSessions(): void {
    const now = Date.now();

    for (const session of this.sessions.values()) {
      if (session.status !== "active") continue;

      // Check max lifetime
      if (now - session.createdAt > this.config.maxLifetimeMs) {
        this.expireSession(session.id, "max_lifetime");
        continue;
      }

      // Check inactivity
      if (now - session.lastActivity > this.config.inactivityTimeoutMs) {
        this.expireSession(session.id, "inactivity");
      }
    }
  }

  /**
   * Get session statistics
   */
  getStats(): typeof this.stats & { activeSessions: number } {
    return {
      ...this.stats,
      activeSessions: this.getActiveSessions().length,
    };
  }

  /**
   * Cleanup - stop the checker and expire all sessions
   */
  async cleanup(): Promise<void> {
    if (this.checkInterval) {
      clearInterval(this.checkInterval);
      this.checkInterval = null;
    }

    // Expire all active sessions
    for (const session of this.sessions.values()) {
      if (session.status === "active") {
        await this.expireSession(session.id, "manual");
      }
    }

    this.sessions.clear();
    log.info("Session manager cleaned up");
  }

  /**
   * Get session status info
   */
  getStatus(): {
    enabled: boolean;
    activeSessions: number;
    maxLifetimeMinutes: number;
    inactivityTimeoutMinutes: number;
  } {
    return {
      enabled: this.config.enabled,
      activeSessions: this.getActiveSessions().length,
      maxLifetimeMinutes: Math.round(this.config.maxLifetimeMs / 60000),
      inactivityTimeoutMinutes: Math.round(this.config.inactivityTimeoutMs / 60000),
    };
  }
}

/**
 * Global session manager instance
 */
let globalManager: SessionManager | null = null;

/**
 * Get or create the global session manager
 */
export function getSessionManager(): SessionManager {
  if (!globalManager) {
    globalManager = new SessionManager();
  }
  return globalManager;
}

/**
 * Convenience function to create a session
 */
export async function createLoginSession(credentialId: string, domain?: string): Promise<Session> {
  return getSessionManager().createSession(credentialId, domain);
}

/**
 * Convenience function to update activity
 */
export function updateSessionActivity(sessionId: string): boolean {
  return getSessionManager().updateActivity(sessionId);
}

/**
 * Convenience function to logout
 */
export async function logoutSession(sessionId: string): Promise<boolean> {
  return getSessionManager().logout(sessionId);
}
