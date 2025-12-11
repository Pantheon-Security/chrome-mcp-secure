/**
 * Chrome DevTools Protocol Client
 *
 * Maintains a persistent WebSocket connection to Chrome with:
 * - Automatic reconnection
 * - Connection pooling
 * - Command queuing
 * - Health monitoring
 *
 * Based on lxe/chrome-mcp (https://github.com/lxe/chrome-mcp)
 * Redesigned for reliability by the Claude Code community
 */

import WebSocket from 'ws';
import { EventEmitter } from 'events';

export interface CDPConfig {
  host: string;
  port: number;
  connectionTimeout: number;
  commandTimeout: number;
  maxRetries: number;
  retryDelay: number;
}

export interface ChromeTab {
  id: string;
  title: string;
  url: string;
  webSocketDebuggerUrl: string;
  type: string;
}

interface PendingCommand {
  resolve: (value: any) => void;
  reject: (error: Error) => void;
  timer: NodeJS.Timeout;
}

export class CDPClient extends EventEmitter {
  private config: CDPConfig;
  private ws: WebSocket | null = null;
  private commandId = 0;
  private pendingCommands = new Map<number, PendingCommand>();
  private currentTab: ChromeTab | null = null;
  private isConnecting = false;
  private connectionPromise: Promise<void> | null = null;
  private enabledDomains = new Set<string>();

  constructor(config: Partial<CDPConfig> = {}) {
    super();
    this.config = {
      host: config.host || process.env.CHROME_HOST || 'localhost',
      port: config.port || parseInt(process.env.CHROME_PORT || '9222', 10),
      connectionTimeout: config.connectionTimeout || 10000,
      commandTimeout: config.commandTimeout || 30000,
      maxRetries: config.maxRetries || 3,
      retryDelay: config.retryDelay || 1000,
    };
  }

  get isConnected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN;
  }

  get debugUrl(): string {
    return `http://${this.config.host}:${this.config.port}`;
  }

  /**
   * Check if Chrome is available and get debugging info
   */
  async checkHealth(): Promise<{ ok: boolean; tabs: number; version?: string; error?: string }> {
    try {
      const response = await fetch(`${this.debugUrl}/json/version`, {
        signal: AbortSignal.timeout(5000),
      });

      if (!response.ok) {
        return { ok: false, tabs: 0, error: `HTTP ${response.status}` };
      }

      const version = await response.json() as Record<string, string>;
      const tabsResponse = await fetch(`${this.debugUrl}/json`);
      const tabs = await tabsResponse.json() as unknown[];

      return {
        ok: true,
        tabs: Array.isArray(tabs) ? tabs.length : 0,
        version: version['Browser'] || 'Unknown',
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      return { ok: false, tabs: 0, error: message };
    }
  }

  /**
   * Get all available Chrome tabs
   */
  async getTabs(): Promise<ChromeTab[]> {
    const response = await fetch(`${this.debugUrl}/json`, {
      signal: AbortSignal.timeout(this.config.connectionTimeout),
    });

    if (!response.ok) {
      throw new Error(`Failed to get tabs: HTTP ${response.status}`);
    }

    const tabs = await response.json() as ChromeTab[];
    return tabs.filter((tab) => tab.type === 'page' && tab.webSocketDebuggerUrl);
  }

  /**
   * Connect to a specific tab or the first available one
   */
  async connect(tabId?: string): Promise<void> {
    // Prevent multiple simultaneous connection attempts
    if (this.connectionPromise) {
      return this.connectionPromise;
    }

    if (this.isConnected && this.currentTab) {
      if (!tabId || this.currentTab.id === tabId) {
        return;
      }
      // Different tab requested, disconnect first
      await this.disconnect();
    }

    this.isConnecting = true;
    this.connectionPromise = this._connect(tabId);

    try {
      await this.connectionPromise;
    } finally {
      this.isConnecting = false;
      this.connectionPromise = null;
    }
  }

  private async _connect(tabId?: string): Promise<void> {
    const tabs = await this.getTabs();

    if (tabs.length === 0) {
      throw new Error('No Chrome tabs available. Make sure Chrome is running with --remote-debugging-port=9222');
    }

    const tab = tabId
      ? tabs.find(t => t.id === tabId)
      : tabs[0];

    if (!tab) {
      throw new Error(`Tab ${tabId} not found`);
    }

    this.currentTab = tab;

    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error('Connection timeout'));
        this.ws?.close();
      }, this.config.connectionTimeout);

      this.ws = new WebSocket(tab.webSocketDebuggerUrl);

      this.ws.on('open', () => {
        clearTimeout(timeout);
        this.enabledDomains.clear();
        this.emit('connected', tab);
        resolve();
      });

      this.ws.on('message', (data) => {
        this.handleMessage(data.toString());
      });

      this.ws.on('close', (code, reason) => {
        this.handleDisconnect(code, reason.toString());
      });

      this.ws.on('error', (error) => {
        clearTimeout(timeout);
        this.emit('error', error);
        reject(error);
      });
    });
  }

  /**
   * Disconnect from Chrome
   */
  async disconnect(): Promise<void> {
    if (this.ws) {
      // Clear all pending commands
      for (const [id, cmd] of this.pendingCommands) {
        clearTimeout(cmd.timer);
        cmd.reject(new Error('Connection closed'));
      }
      this.pendingCommands.clear();

      this.ws.close();
      this.ws = null;
    }
    this.currentTab = null;
    this.enabledDomains.clear();
  }

  private handleMessage(data: string): void {
    try {
      const message = JSON.parse(data);

      // Handle command responses
      if (message.id !== undefined) {
        const pending = this.pendingCommands.get(message.id);
        if (pending) {
          clearTimeout(pending.timer);
          this.pendingCommands.delete(message.id);

          if (message.error) {
            pending.reject(new Error(`CDP Error: ${message.error.message}`));
          } else {
            pending.resolve(message.result);
          }
        }
      }

      // Handle events
      if (message.method) {
        this.emit('event', message);
        this.emit(message.method, message.params);
      }
    } catch (error) {
      this.emit('error', new Error(`Failed to parse CDP message: ${data}`));
    }
  }

  private handleDisconnect(code: number, reason: string): void {
    this.ws = null;
    this.currentTab = null;

    // Reject all pending commands
    for (const [id, cmd] of this.pendingCommands) {
      clearTimeout(cmd.timer);
      cmd.reject(new Error(`Connection closed: ${reason}`));
    }
    this.pendingCommands.clear();
    this.enabledDomains.clear();

    this.emit('disconnected', { code, reason });
  }

  /**
   * Send a CDP command with automatic connection and retry
   */
  async send<T = any>(method: string, params: Record<string, any> = {}): Promise<T> {
    let lastError: Error | null = null;

    for (let attempt = 0; attempt < this.config.maxRetries; attempt++) {
      try {
        // Ensure connected
        if (!this.isConnected) {
          await this.connect();
        }

        return await this._send<T>(method, params);
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));

        // If connection error, try to reconnect
        if (!this.isConnected && attempt < this.config.maxRetries - 1) {
          await new Promise(resolve => setTimeout(resolve, this.config.retryDelay));
          continue;
        }

        throw lastError;
      }
    }

    throw lastError || new Error('Max retries exceeded');
  }

  private _send<T>(method: string, params: Record<string, any>): Promise<T> {
    return new Promise((resolve, reject) => {
      if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
        reject(new Error('Not connected to Chrome'));
        return;
      }

      const id = ++this.commandId;

      const timer = setTimeout(() => {
        this.pendingCommands.delete(id);
        reject(new Error(`Command timeout: ${method}`));
      }, this.config.commandTimeout);

      this.pendingCommands.set(id, { resolve, reject, timer });

      const command = JSON.stringify({ id, method, params });
      this.ws.send(command);
    });
  }

  /**
   * Enable a CDP domain (with caching to avoid redundant calls)
   */
  async enableDomain(domain: string): Promise<void> {
    if (this.enabledDomains.has(domain)) {
      return;
    }

    await this.send(`${domain}.enable`);
    this.enabledDomains.add(domain);
  }

  /**
   * Execute JavaScript in the page context
   */
  async evaluate<T = any>(expression: string, options: {
    returnByValue?: boolean;
    awaitPromise?: boolean;
  } = {}): Promise<T> {
    await this.enableDomain('Runtime');

    const result = await this.send('Runtime.evaluate', {
      expression,
      returnByValue: options.returnByValue ?? true,
      awaitPromise: options.awaitPromise ?? false,
    });

    if (result.exceptionDetails) {
      throw new Error(`JavaScript error: ${result.exceptionDetails.text}`);
    }

    return result.result.value;
  }

  /**
   * Get current tab info
   */
  getCurrentTab(): ChromeTab | null {
    return this.currentTab;
  }
}

// Singleton instance for the MCP server
let clientInstance: CDPClient | null = null;

export function getCDPClient(config?: Partial<CDPConfig>): CDPClient {
  if (!clientInstance) {
    clientInstance = new CDPClient(config);
  }
  return clientInstance;
}

export function resetCDPClient(): void {
  if (clientInstance) {
    clientInstance.disconnect();
    clientInstance = null;
  }
}
