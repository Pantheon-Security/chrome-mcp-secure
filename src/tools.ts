/**
 * MCP Tool implementations for Chrome control
 *
 * Based on lxe/chrome-mcp (https://github.com/lxe/chrome-mcp)
 * Enhanced with security validation and error handling
 */

import { z } from 'zod';
import { CDPClient, getCDPClient } from './cdp-client.js';
import {
  validateSelector,
  validateUrl,
  validateText,
  validateCoordinate,
  RateLimiter,
  SecurityError,
} from './security.js';
import { log, audit } from './logger.js';
import { complianceLog, generateCorrelationId, setCorrelationId, clearCorrelationId } from './compliance-logger.js';
import { ElementError, NavigationError, formatError, RateLimitError } from './errors.js';
import {
  credentialToolSchemas,
  handleStoreCredential,
  handleListCredentials,
  handleGetCredential,
  handleDeleteCredential,
  handleUpdateCredential,
  handleSecureLogin,
  handleGetVaultStatus,
} from './credential-tools.js';
import { maskSensitive } from './secure-memory.js';

// Shared rate limiter (100 requests per minute)
const rateLimiter = new RateLimiter(60000, 100);

// Tool result type
export interface ToolResult {
  content: Array<{ type: 'text' | 'image'; text?: string; data?: string; mimeType?: string }>;
  isError?: boolean;
}

// Helper to create text result
function textResult(text: string, isError = false): ToolResult {
  return {
    content: [{ type: 'text', text }],
    isError,
  };
}

// Helper to check rate limit
function checkRateLimit(toolName: string): void {
  const result = rateLimiter.isAllowed(toolName);
  if (!result.allowed) {
    audit.security('rate_limit_exceeded', false, { tool: toolName, resetMs: result.resetMs });
    complianceLog.security('rate_limit_exceeded', 5, { source: toolName, blocked: true });
    throw new RateLimitError(result.resetMs);
  }
}

// Helper to log tool execution to both audit and compliance logs
function logToolExecution(
  toolName: string,
  success: boolean,
  durationMs: number,
  details?: Record<string, unknown>
): void {
  // Log to existing audit system
  audit.tool(toolName, success, durationMs, details);

  // Log to compliance system (CEF/Syslog compatible)
  complianceLog.tool(toolName, success ? 'success' : 'failure', {
    durationMs,
    ...details,
    error: details?.error as string | undefined
  });
}

// Tool definitions
export const toolDefinitions = {
  // Health check
  health: {
    name: 'health',
    description: 'Check Chrome connection health and get debugging info',
    schema: {},
    handler: async (): Promise<ToolResult> => {
      const startTime = Date.now();
      const client = getCDPClient();

      try {
        const health = await client.checkHealth();

        if (!health.ok) {
          logToolExecution('health', false, Date.now() - startTime, { error: health.error });
          return textResult(`Chrome not available: ${health.error}`, true);
        }

        logToolExecution('health', true, Date.now() - startTime, { tabs: health.tabs });
        return textResult(
          `Chrome is running\n` +
          `Version: ${health.version}\n` +
          `Open tabs: ${health.tabs}\n` +
          `Connected: ${client.isConnected}`
        );
      } catch (error) {
        logToolExecution('health', false, Date.now() - startTime, { error: formatError(error) });
        return textResult(`Health check failed: ${formatError(error)}`, true);
      }
    },
  },

  // Navigation
  navigate: {
    name: 'navigate',
    description: 'Navigate Chrome to a URL',
    schema: { url: z.string().describe('URL to navigate to') },
    handler: async (args: { url: string }): Promise<ToolResult> => {
      const startTime = Date.now();
      checkRateLimit('navigate');

      try {
        const url = validateUrl(args.url);
        const client = getCDPClient();

        const result = await client.send('Page.navigate', { url });

        if (result.errorText) {
          throw new NavigationError(result.errorText, url);
        }

        // Wait for page load
        await new Promise(resolve => setTimeout(resolve, 1000));

        logToolExecution('navigate', true, Date.now() - startTime, { url });
        return textResult(`Successfully navigated to ${url}`);
      } catch (error) {
        logToolExecution('navigate', false, Date.now() - startTime, { error: formatError(error) });
        if (error instanceof SecurityError) {
          return textResult(`Security error: ${error.message}`, true);
        }
        return textResult(`Navigation failed: ${formatError(error)}`, true);
      }
    },
  },

  // Get tabs
  get_tabs: {
    name: 'get_tabs',
    description: 'Get list of all Chrome tabs',
    schema: {},
    handler: async (): Promise<ToolResult> => {
      const startTime = Date.now();
      checkRateLimit('get_tabs');

      try {
        const client = getCDPClient();
        const tabs = await client.getTabs();

        const tabList = tabs.map((tab, i) =>
          `${i + 1}. [${tab.id}] ${tab.title}\n   ${tab.url}`
        ).join('\n\n');

        logToolExecution('get_tabs', true, Date.now() - startTime, { count: tabs.length });
        return textResult(`Chrome tabs (${tabs.length}):\n\n${tabList}`);
      } catch (error) {
        logToolExecution('get_tabs', false, Date.now() - startTime, { error: formatError(error) });
        return textResult(`Failed to get tabs: ${formatError(error)}`, true);
      }
    },
  },

  // Click element by selector
  click_element: {
    name: 'click_element',
    description: 'Click on a page element by CSS selector',
    schema: { selector: z.string().describe('CSS selector for the element to click') },
    handler: async (args: { selector: string }): Promise<ToolResult> => {
      const startTime = Date.now();
      checkRateLimit('click_element');

      try {
        const selector = validateSelector(args.selector);
        const client = getCDPClient();

        // Get element position
        const elementInfo = await client.evaluate<{
          found: boolean;
          x?: number;
          y?: number;
          tag?: string;
          text?: string;
        }>(`
          (function() {
            const element = document.querySelector('${selector.replace(/'/g, "\\'")}');
            if (!element) return { found: false };

            const rect = element.getBoundingClientRect();
            return {
              found: true,
              x: rect.left + rect.width / 2 + window.scrollX,
              y: rect.top + rect.height / 2 + window.scrollY,
              tag: element.tagName.toLowerCase(),
              text: (element.textContent || '').trim().substring(0, 50)
            };
          })()
        `);

        if (!elementInfo.found) {
          throw new ElementError('Element not found', selector);
        }

        // Scroll element into view and click
        await client.evaluate(`
          document.querySelector('${selector.replace(/'/g, "\\'")}').scrollIntoView({ block: 'center' });
        `);

        await new Promise(resolve => setTimeout(resolve, 100));

        // Recalculate position after scroll
        const finalPos = await client.evaluate<{ x: number; y: number }>(`
          (function() {
            const element = document.querySelector('${selector.replace(/'/g, "\\'")}');
            const rect = element.getBoundingClientRect();
            return {
              x: rect.left + rect.width / 2,
              y: rect.top + rect.height / 2
            };
          })()
        `);

        // Perform click
        await client.enableDomain('Input');

        await client.send('Input.dispatchMouseEvent', {
          type: 'mousePressed',
          x: finalPos.x,
          y: finalPos.y,
          button: 'left',
          clickCount: 1,
        });

        await client.send('Input.dispatchMouseEvent', {
          type: 'mouseReleased',
          x: finalPos.x,
          y: finalPos.y,
          button: 'left',
          clickCount: 1,
        });

        logToolExecution('click_element', true, Date.now() - startTime, {
          selector,
          element: elementInfo.tag,
        });

        return textResult(
          `Clicked <${elementInfo.tag}> at (${Math.round(finalPos.x)}, ${Math.round(finalPos.y)})` +
          (elementInfo.text ? ` with text: "${elementInfo.text}"` : '')
        );
      } catch (error) {
        logToolExecution('click_element', false, Date.now() - startTime, { error: formatError(error) });
        if (error instanceof SecurityError || error instanceof ElementError) {
          return textResult(error.message, true);
        }
        return textResult(`Click failed: ${formatError(error)}`, true);
      }
    },
  },

  // Click at coordinates
  click: {
    name: 'click',
    description: 'Click at specific screen coordinates',
    schema: {
      x: z.number().describe('X coordinate'),
      y: z.number().describe('Y coordinate'),
    },
    handler: async (args: { x: number; y: number }): Promise<ToolResult> => {
      const startTime = Date.now();
      checkRateLimit('click');

      try {
        const x = validateCoordinate(args.x, 'x');
        const y = validateCoordinate(args.y, 'y');
        const client = getCDPClient();

        await client.enableDomain('Input');

        await client.send('Input.dispatchMouseEvent', {
          type: 'mousePressed',
          x,
          y,
          button: 'left',
          clickCount: 1,
        });

        await client.send('Input.dispatchMouseEvent', {
          type: 'mouseReleased',
          x,
          y,
          button: 'left',
          clickCount: 1,
        });

        logToolExecution('click', true, Date.now() - startTime, { x, y });
        return textResult(`Clicked at coordinates (${x}, ${y})`);
      } catch (error) {
        logToolExecution('click', false, Date.now() - startTime, { error: formatError(error) });
        return textResult(`Click failed: ${formatError(error)}`, true);
      }
    },
  },

  // Type text
  type: {
    name: 'type',
    description: 'Type text at current cursor focus',
    schema: { text: z.string().describe('Text to type') },
    handler: async (args: { text: string }): Promise<ToolResult> => {
      const startTime = Date.now();
      checkRateLimit('type');

      try {
        const text = validateText(args.text);
        const client = getCDPClient();

        await client.enableDomain('Input');
        await client.send('Input.insertText', { text });

        logToolExecution('type', true, Date.now() - startTime, { length: text.length });
        return textResult(`Typed ${text.length} characters`);
      } catch (error) {
        logToolExecution('type', false, Date.now() - startTime, { error: formatError(error) });
        return textResult(`Type failed: ${formatError(error)}`, true);
      }
    },
  },

  // Get text from element
  get_text: {
    name: 'get_text',
    description: 'Extract text content from an element',
    schema: { selector: z.string().describe('CSS selector for the element') },
    handler: async (args: { selector: string }): Promise<ToolResult> => {
      const startTime = Date.now();
      checkRateLimit('get_text');

      try {
        const selector = validateSelector(args.selector);
        const client = getCDPClient();

        const text = await client.evaluate<string | null>(`
          (function() {
            const element = document.querySelector('${selector.replace(/'/g, "\\'")}');
            return element ? element.textContent : null;
          })()
        `);

        if (text === null) {
          throw new ElementError('Element not found', selector);
        }

        logToolExecution('get_text', true, Date.now() - startTime, { selector });
        return textResult(`Text content:\n${text.trim()}`);
      } catch (error) {
        logToolExecution('get_text', false, Date.now() - startTime, { error: formatError(error) });
        return textResult(`Get text failed: ${formatError(error)}`, true);
      }
    },
  },

  // Get page info
  get_page_info: {
    name: 'get_page_info',
    description: 'Get page information including URL, title, and interactive elements',
    schema: {},
    handler: async (): Promise<ToolResult> => {
      const startTime = Date.now();
      checkRateLimit('get_page_info');

      try {
        const client = getCDPClient();

        const pageInfo = await client.evaluate<{
          url: string;
          title: string;
          elements: Array<{
            tag: string;
            type?: string;
            text: string;
            id?: string;
            href?: string;
          }>;
        }>(`
          (function() {
            const elements = Array.from(document.querySelectorAll('a, button, input, select, textarea, [role="button"]'))
              .slice(0, 50)
              .map(el => ({
                tag: el.tagName.toLowerCase(),
                type: el.type || null,
                text: (el.textContent || el.value || el.placeholder || '').trim().substring(0, 100),
                id: el.id || null,
                href: el.href || null
              }));

            return {
              url: window.location.href,
              title: document.title,
              elements
            };
          })()
        `);

        let output = `Page Information\n${'='.repeat(50)}\n`;
        output += `URL: ${pageInfo.url}\n`;
        output += `Title: ${pageInfo.title}\n\n`;
        output += `Interactive Elements (${pageInfo.elements.length}):\n`;

        pageInfo.elements.forEach((el, i) => {
          const id = el.id ? `#${el.id}` : '';
          const type = el.type ? `[${el.type}]` : '';
          const text = el.text ? `: "${el.text.substring(0, 40)}"` : '';
          output += `  ${i + 1}. <${el.tag}${type}>${id}${text}\n`;
        });

        logToolExecution('get_page_info', true, Date.now() - startTime, {
          elements: pageInfo.elements.length,
        });

        return textResult(output);
      } catch (error) {
        logToolExecution('get_page_info', false, Date.now() - startTime, { error: formatError(error) });
        return textResult(`Get page info failed: ${formatError(error)}`, true);
      }
    },
  },

  // Get page state
  get_page_state: {
    name: 'get_page_state',
    description: 'Get current page context including URL, title, scroll position, and viewport',
    schema: {},
    handler: async (): Promise<ToolResult> => {
      const startTime = Date.now();
      checkRateLimit('get_page_state');

      try {
        const client = getCDPClient();

        const state = await client.evaluate<{
          url: string;
          title: string;
          scroll: { x: number; y: number };
          viewport: { width: number; height: number };
          document: { width: number; height: number };
        }>(`
          ({
            url: window.location.href,
            title: document.title,
            scroll: { x: window.scrollX, y: window.scrollY },
            viewport: { width: window.innerWidth, height: window.innerHeight },
            document: {
              width: document.documentElement.scrollWidth,
              height: document.documentElement.scrollHeight
            }
          })
        `);

        const output = [
          'Page State',
          '='.repeat(30),
          `URL: ${state.url}`,
          `Title: ${state.title}`,
          `Scroll: (${state.scroll.x}, ${state.scroll.y})`,
          `Viewport: ${state.viewport.width}x${state.viewport.height}`,
          `Document: ${state.document.width}x${state.document.height}`,
        ].join('\n');

        logToolExecution('get_page_state', true, Date.now() - startTime);
        return textResult(output);
      } catch (error) {
        logToolExecution('get_page_state', false, Date.now() - startTime, { error: formatError(error) });
        return textResult(`Get page state failed: ${formatError(error)}`, true);
      }
    },
  },

  // Scroll page
  scroll: {
    name: 'scroll',
    description: 'Scroll the page to specific coordinates',
    schema: {
      x: z.number().optional().describe('X coordinate to scroll to (default: 0)'),
      y: z.number().optional().describe('Y coordinate to scroll to (default: 0)'),
    },
    handler: async (args: { x?: number; y?: number }): Promise<ToolResult> => {
      const startTime = Date.now();
      checkRateLimit('scroll');

      try {
        const x = validateCoordinate(args.x ?? 0, 'x', 0);
        const y = validateCoordinate(args.y ?? 0, 'y', 0);
        const client = getCDPClient();

        await client.evaluate(`window.scrollTo(${x}, ${y})`);

        logToolExecution('scroll', true, Date.now() - startTime, { x, y });
        return textResult(`Scrolled to (${x}, ${y})`);
      } catch (error) {
        logToolExecution('scroll', false, Date.now() - startTime, { error: formatError(error) });
        return textResult(`Scroll failed: ${formatError(error)}`, true);
      }
    },
  },

  // Screenshot
  screenshot: {
    name: 'screenshot',
    description: 'Take a screenshot of the current page',
    schema: {
      fullPage: z.boolean().optional().describe('Capture full page (default: false)'),
    },
    handler: async (args: { fullPage?: boolean }): Promise<ToolResult> => {
      const startTime = Date.now();
      checkRateLimit('screenshot');

      try {
        const client = getCDPClient();
        await client.enableDomain('Page');

        const params: Record<string, unknown> = {
          format: 'png',
          quality: 80,
        };

        if (args.fullPage) {
          params.captureBeyondViewport = true;
        }

        const result = await client.send<{ data: string }>('Page.captureScreenshot', params);

        logToolExecution('screenshot', true, Date.now() - startTime, { fullPage: args.fullPage });

        return {
          content: [
            {
              type: 'image',
              data: result.data,
              mimeType: 'image/png',
            },
          ],
        };
      } catch (error) {
        logToolExecution('screenshot', false, Date.now() - startTime, { error: formatError(error) });
        return textResult(`Screenshot failed: ${formatError(error)}`, true);
      }
    },
  },

  // Wait for element
  wait_for_element: {
    name: 'wait_for_element',
    description: 'Wait for an element to appear on the page',
    schema: {
      selector: z.string().describe('CSS selector for the element'),
      timeout: z.number().optional().describe('Timeout in milliseconds (default: 10000)'),
    },
    handler: async (args: { selector: string; timeout?: number }): Promise<ToolResult> => {
      const startTime = Date.now();
      checkRateLimit('wait_for_element');

      try {
        const selector = validateSelector(args.selector);
        const timeout = Math.min(args.timeout ?? 10000, 30000);
        const client = getCDPClient();

        const found = await client.evaluate<boolean>(`
          new Promise((resolve) => {
            const timeout = ${timeout};
            const startTime = Date.now();

            const check = () => {
              const element = document.querySelector('${selector.replace(/'/g, "\\'")}');
              if (element) {
                resolve(true);
                return;
              }
              if (Date.now() - startTime > timeout) {
                resolve(false);
                return;
              }
              setTimeout(check, 100);
            };
            check();
          })
        `, { awaitPromise: true });

        if (!found) {
          logToolExecution('wait_for_element', false, Date.now() - startTime, { selector, timeout });
          return textResult(`Element not found within ${timeout}ms: ${selector}`, true);
        }

        logToolExecution('wait_for_element', true, Date.now() - startTime, { selector });
        return textResult(`Element found: ${selector}`);
      } catch (error) {
        logToolExecution('wait_for_element', false, Date.now() - startTime, { error: formatError(error) });
        return textResult(`Wait failed: ${formatError(error)}`, true);
      }
    },
  },

  // Execute JavaScript
  evaluate: {
    name: 'evaluate',
    description: 'Execute JavaScript code in the page context (restricted operations)',
    schema: {
      expression: z.string().describe('JavaScript expression to evaluate'),
    },
    handler: async (args: { expression: string }): Promise<ToolResult> => {
      const startTime = Date.now();
      checkRateLimit('evaluate');

      try {
        // Note: For security, we allow evaluate but log it heavily
        // Consider adding validateJavaScript for stricter control
        const expression = validateText(args.expression, 50000);
        const client = getCDPClient();

        const result = await client.evaluate(expression);

        logToolExecution('evaluate', true, Date.now() - startTime, {
          expressionLength: expression.length,
        });

        const resultStr = result === undefined
          ? 'undefined'
          : typeof result === 'object'
            ? JSON.stringify(result, null, 2)
            : String(result);

        return textResult(`Result:\n${resultStr}`);
      } catch (error) {
        logToolExecution('evaluate', false, Date.now() - startTime, { error: formatError(error) });
        return textResult(`Evaluate failed: ${formatError(error)}`, true);
      }
    },
  },

  // Fill form field
  fill: {
    name: 'fill',
    description: 'Fill a form field with text (clears existing content first)',
    schema: {
      selector: z.string().describe('CSS selector for the input element'),
      value: z.string().describe('Value to fill in'),
    },
    handler: async (args: { selector: string; value: string }): Promise<ToolResult> => {
      const startTime = Date.now();
      checkRateLimit('fill');

      try {
        const selector = validateSelector(args.selector);
        const value = validateText(args.value, 10000);
        const client = getCDPClient();

        // Focus and clear the element
        const success = await client.evaluate<boolean>(`
          (function() {
            const el = document.querySelector('${selector.replace(/'/g, "\\'")}');
            if (!el) return false;

            el.focus();
            el.value = '';
            el.dispatchEvent(new Event('input', { bubbles: true }));
            return true;
          })()
        `);

        if (!success) {
          throw new ElementError('Element not found or not focusable', selector);
        }

        // Type the value
        await client.enableDomain('Input');
        await client.send('Input.insertText', { text: value });

        // Trigger change event
        await client.evaluate(`
          (function() {
            const el = document.querySelector('${selector.replace(/'/g, "\\'")}');
            el.dispatchEvent(new Event('change', { bubbles: true }));
          })()
        `);

        logToolExecution('fill', true, Date.now() - startTime, { selector, valueLength: value.length });
        return textResult(`Filled field ${selector} with ${value.length} characters`);
      } catch (error) {
        logToolExecution('fill', false, Date.now() - startTime, { error: formatError(error) });
        return textResult(`Fill failed: ${formatError(error)}`, true);
      }
    },
  },

  // Bypass certificate warning and navigate
  bypass_cert_and_navigate: {
    name: 'bypass_cert_and_navigate',
    description: 'Navigate to HTTPS URL and automatically bypass certificate warnings',
    schema: { url: z.string().describe('URL to navigate to') },
    handler: async (args: { url: string }): Promise<ToolResult> => {
      const startTime = Date.now();
      checkRateLimit('bypass_cert_and_navigate');

      try {
        const url = validateUrl(args.url);
        const client = getCDPClient();

        // Navigate first
        await client.send('Page.navigate', { url });

        // Wait for potential cert warning
        await new Promise(resolve => setTimeout(resolve, 2000));

        // Try to bypass certificate warning
        const bypassResult = await client.evaluate<string>(`
          (function() {
            try {
              // Look for Chrome certificate warning elements
              const advancedButton = document.querySelector('#details-button') ||
                                   document.querySelector('[id*="advanced"]');

              if (advancedButton) {
                advancedButton.click();

                // Look for proceed link after clicking advanced
                setTimeout(() => {
                  const proceedLink = document.querySelector('#proceed-link') ||
                                    document.querySelector('[id*="proceed"]');
                  if (proceedLink) {
                    proceedLink.click();
                  }
                }, 500);

                return 'Clicked advanced button, attempting to proceed...';
              }

              // Check if we're already past the warning
              if (!document.title.includes('Privacy') && !document.body.innerText.includes('not private')) {
                return 'No certificate warning detected - already on target page';
              }

              return 'Certificate warning page detected but bypass buttons not found';
            } catch (e) {
              return 'Error during bypass: ' + e.message;
            }
          })()
        `);

        logToolExecution('bypass_cert_and_navigate', true, Date.now() - startTime, { url });
        return textResult(`Navigation with cert bypass: ${bypassResult}`);
      } catch (error) {
        logToolExecution('bypass_cert_and_navigate', false, Date.now() - startTime, { error: formatError(error) });
        return textResult(`Navigation failed: ${formatError(error)}`, true);
      }
    },
  },

  // ============================================
  // Secure Credential Tools
  // ============================================

  store_credential: {
    name: 'store_credential',
    description: credentialToolSchemas.store_credential.description,
    schema: {
      name: z.string().describe('Friendly name for this credential'),
      type: z.enum(['google', 'basic', 'oauth', 'api_key', 'custom']).describe('Type of credential'),
      username: z.string().optional().describe('Username or login ID'),
      email: z.string().optional().describe('Email address for login'),
      password: z.string().optional().describe('Password (will be encrypted)'),
      apiKey: z.string().optional().describe('API key (will be encrypted)'),
      domain: z.string().optional().describe('Associated domain'),
      notes: z.string().optional().describe('Additional notes'),
    },
    handler: async (args: {
      name: string;
      type: 'google' | 'basic' | 'oauth' | 'api_key' | 'custom';
      username?: string;
      email?: string;
      password?: string;
      apiKey?: string;
      domain?: string;
      notes?: string;
    }): Promise<ToolResult> => {
      const startTime = Date.now();
      checkRateLimit('store_credential');

      try {
        const result = await handleStoreCredential(args);

        logToolExecution('store_credential', true, Date.now() - startTime, {
          name: args.name,
          type: args.type,
          domain: args.domain,
        });

        return textResult(result.message);
      } catch (error) {
        logToolExecution('store_credential', false, Date.now() - startTime, { error: formatError(error) });
        return textResult(`Store credential failed: ${formatError(error)}`, true);
      }
    },
  },

  list_credentials: {
    name: 'list_credentials',
    description: credentialToolSchemas.list_credentials.description,
    schema: {
      type: z.enum(['google', 'basic', 'oauth', 'api_key', 'custom']).optional().describe('Filter by type'),
      domain: z.string().optional().describe('Filter by domain'),
    },
    handler: async (args: { type?: 'google' | 'basic' | 'oauth' | 'api_key' | 'custom'; domain?: string }): Promise<ToolResult> => {
      const startTime = Date.now();
      checkRateLimit('list_credentials');

      try {
        const credentials = await handleListCredentials(args);

        if (credentials.length === 0) {
          return textResult('No credentials stored');
        }

        let output = `Stored Credentials (${credentials.length}):\n${'='.repeat(40)}\n\n`;

        for (const cred of credentials) {
          output += `ID: ${maskSensitive(cred.id)}\n`;
          output += `Name: ${cred.name}\n`;
          output += `Type: ${cred.type}\n`;
          if (cred.email) output += `Email: ${cred.email}\n`;
          if (cred.username) output += `Username: ${cred.username}\n`;
          if (cred.domain) output += `Domain: ${cred.domain}\n`;
          output += `Created: ${cred.createdAt}\n`;
          if (cred.lastUsed) output += `Last Used: ${cred.lastUsed}\n`;
          output += '\n';
        }

        logToolExecution('list_credentials', true, Date.now() - startTime, { count: credentials.length });
        return textResult(output);
      } catch (error) {
        logToolExecution('list_credentials', false, Date.now() - startTime, { error: formatError(error) });
        return textResult(`List credentials failed: ${formatError(error)}`, true);
      }
    },
  },

  get_credential: {
    name: 'get_credential',
    description: credentialToolSchemas.get_credential.description,
    schema: {
      id: z.string().describe('Credential ID'),
    },
    handler: async (args: { id: string }): Promise<ToolResult> => {
      const startTime = Date.now();
      checkRateLimit('get_credential');

      try {
        const credential = await handleGetCredential(args);

        if (!credential) {
          return textResult(`Credential not found: ${maskSensitive(args.id)}`, true);
        }

        let output = `Credential Details:\n${'='.repeat(30)}\n`;
        output += `ID: ${credential.id}\n`;
        output += `Name: ${credential.name}\n`;
        output += `Type: ${credential.type}\n`;
        if (credential.email) output += `Email: ${credential.email}\n`;
        if (credential.username) output += `Username: ${credential.username}\n`;
        if (credential.domain) output += `Domain: ${credential.domain}\n`;
        if (credential.notes) output += `Notes: ${credential.notes}\n`;
        output += `Created: ${credential.createdAt}\n`;
        output += `Updated: ${credential.updatedAt}\n`;
        if (credential.lastUsed) output += `Last Used: ${credential.lastUsed}\n`;

        logToolExecution('get_credential', true, Date.now() - startTime, { id: maskSensitive(args.id) });
        return textResult(output);
      } catch (error) {
        logToolExecution('get_credential', false, Date.now() - startTime, { error: formatError(error) });
        return textResult(`Get credential failed: ${formatError(error)}`, true);
      }
    },
  },

  delete_credential: {
    name: 'delete_credential',
    description: credentialToolSchemas.delete_credential.description,
    schema: {
      id: z.string().describe('Credential ID to delete'),
    },
    handler: async (args: { id: string }): Promise<ToolResult> => {
      const startTime = Date.now();
      checkRateLimit('delete_credential');

      try {
        const result = await handleDeleteCredential(args);

        logToolExecution('delete_credential', result.success, Date.now() - startTime, {
          id: maskSensitive(args.id),
        });

        return textResult(result.message, !result.success);
      } catch (error) {
        logToolExecution('delete_credential', false, Date.now() - startTime, { error: formatError(error) });
        return textResult(`Delete credential failed: ${formatError(error)}`, true);
      }
    },
  },

  update_credential: {
    name: 'update_credential',
    description: credentialToolSchemas.update_credential.description,
    schema: {
      id: z.string().describe('Credential ID to update'),
      name: z.string().optional().describe('New friendly name'),
      username: z.string().optional().describe('New username'),
      email: z.string().optional().describe('New email'),
      password: z.string().optional().describe('New password'),
      apiKey: z.string().optional().describe('New API key'),
      domain: z.string().optional().describe('New domain'),
      notes: z.string().optional().describe('New notes'),
    },
    handler: async (args: {
      id: string;
      name?: string;
      username?: string;
      email?: string;
      password?: string;
      apiKey?: string;
      domain?: string;
      notes?: string;
    }): Promise<ToolResult> => {
      const startTime = Date.now();
      checkRateLimit('update_credential');

      try {
        const result = await handleUpdateCredential(args);

        logToolExecution('update_credential', result.success, Date.now() - startTime, {
          id: maskSensitive(args.id),
        });

        return textResult(result.message, !result.success);
      } catch (error) {
        logToolExecution('update_credential', false, Date.now() - startTime, { error: formatError(error) });
        return textResult(`Update credential failed: ${formatError(error)}`, true);
      }
    },
  },

  secure_login: {
    name: 'secure_login',
    description: credentialToolSchemas.secure_login.description,
    schema: {
      credentialId: z.string().describe('ID of the stored credential to use'),
      usernameSelector: z.string().optional().describe('CSS selector for username field'),
      passwordSelector: z.string().optional().describe('CSS selector for password field'),
      submitSelector: z.string().optional().describe('CSS selector for submit button'),
      delayMs: z.number().optional().describe('Delay between typing actions'),
      skipSubmit: z.boolean().optional().describe('Skip clicking submit button'),
    },
    handler: async (args: {
      credentialId: string;
      usernameSelector?: string;
      passwordSelector?: string;
      submitSelector?: string;
      delayMs?: number;
      skipSubmit?: boolean;
    }): Promise<ToolResult> => {
      const startTime = Date.now();
      checkRateLimit('secure_login');

      try {
        const client = getCDPClient();
        const result = await handleSecureLogin({
          credentialId: args.credentialId,
          usernameSelector: args.usernameSelector || "input[type='email'], input[name='username'], input[name='email'], #email, #username",
          passwordSelector: args.passwordSelector || "input[type='password'], input[name='password'], #password",
          submitSelector: args.submitSelector || "button[type='submit'], input[type='submit'], button:contains('Sign in'), button:contains('Log in')",
          delayMs: args.delayMs ?? 500,
          skipSubmit: args.skipSubmit ?? false,
        }, client);

        logToolExecution('secure_login', result.success, Date.now() - startTime, {
          credentialId: maskSensitive(args.credentialId),
        });

        return textResult(result.message, !result.success);
      } catch (error) {
        logToolExecution('secure_login', false, Date.now() - startTime, { error: formatError(error) });
        return textResult(`Secure login failed: ${formatError(error)}`, true);
      }
    },
  },

  get_vault_status: {
    name: 'get_vault_status',
    description: credentialToolSchemas.get_vault_status.description,
    schema: {},
    handler: async (): Promise<ToolResult> => {
      const startTime = Date.now();
      checkRateLimit('get_vault_status');

      try {
        const status = await handleGetVaultStatus();

        let output = `Credential Vault Status:\n${'='.repeat(30)}\n`;
        output += `Initialized: ${status.initialized}\n`;
        output += `Active Credentials: ${status.activeCredentials}\n`;
        output += `\nEncryption:\n`;
        output += `  Enabled: ${status.encryption.enabled}\n`;
        output += `  Post-Quantum: ${status.encryption.postQuantumEnabled}\n`;
        output += `  Algorithm: ${status.encryption.algorithm}\n`;
        output += `  PQ Algorithm: ${status.encryption.pqAlgorithm || 'N/A'}\n`;
        output += `  Key Source: ${status.encryption.keySource}\n`;

        logToolExecution('get_vault_status', true, Date.now() - startTime);
        return textResult(output);
      } catch (error) {
        logToolExecution('get_vault_status', false, Date.now() - startTime, { error: formatError(error) });
        return textResult(`Get vault status failed: ${formatError(error)}`, true);
      }
    },
  },
};
