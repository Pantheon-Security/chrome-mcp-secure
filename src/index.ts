#!/usr/bin/env node
/**
 * Chrome MCP Server v2
 *
 * A reliable Model Context Protocol server for Chrome browser automation
 * using the Chrome DevTools Protocol.
 *
 * Based on lxe/chrome-mcp (https://github.com/lxe/chrome-mcp)
 * Security patterns from Pantheon-Security/notebooklm-mcp-secure
 *
 * @author Pantheon Security (https://github.com/Pantheon-Security)
 * @license MIT
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';

import { toolDefinitions, ToolResult } from './tools.js';
import { getCDPClient, resetCDPClient } from './cdp-client.js';
import { log, audit } from './logger.js';
import { checkSecurityContext } from './security.js';

const SERVER_NAME = 'chrome-mcp';
const SERVER_VERSION = '2.0.0';

class ChromeMCPServer {
  private server: Server;
  private shuttingDown = false;

  constructor() {
    this.server = new Server(
      {
        name: SERVER_NAME,
        version: SERVER_VERSION,
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    this.setupHandlers();
    this.setupShutdownHandlers();
  }

  private setupHandlers(): void {
    // List available tools
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      const tools = Object.values(toolDefinitions).map(tool => ({
        name: tool.name,
        description: tool.description,
        inputSchema: {
          type: 'object' as const,
          properties: Object.fromEntries(
            Object.entries(tool.schema).map(([key, zodSchema]) => [
              key,
              this.zodToJsonSchema(zodSchema as z.ZodTypeAny),
            ])
          ),
          required: Object.entries(tool.schema)
            .filter(([_, zodSchema]) => !(zodSchema as z.ZodTypeAny).isOptional?.())
            .map(([key]) => key),
        },
      }));

      return { tools };
    });

    // Handle tool calls
    this.server.setRequestHandler(CallToolRequestSchema, async (request): Promise<{
      content: Array<{ type: string; text?: string; data?: string; mimeType?: string }>;
      isError?: boolean;
    }> => {
      const { name, arguments: args } = request.params;

      log.debug(`Tool call: ${name}`, { args });

      const tool = Object.values(toolDefinitions).find(t => t.name === name);

      if (!tool) {
        return {
          content: [{ type: 'text', text: `Unknown tool: ${name}` }],
          isError: true,
        };
      }

      try {
        // Validate arguments against schema
        const schema = z.object(
          Object.fromEntries(
            Object.entries(tool.schema).map(([key, zodSchema]) => [key, zodSchema])
          ) as Record<string, z.ZodTypeAny>
        );

        const validatedArgs = schema.parse(args || {});
        const result = await tool.handler(validatedArgs as any);

        return result as {
          content: Array<{ type: string; text?: string; data?: string; mimeType?: string }>;
          isError?: boolean;
        };
      } catch (error) {
        if (error instanceof z.ZodError) {
          const messages = error.errors.map(e => `${e.path.join('.')}: ${e.message}`);
          return {
            content: [{ type: 'text', text: `Invalid arguments:\n${messages.join('\n')}` }],
            isError: true,
          };
        }

        const message = error instanceof Error ? error.message : String(error);
        return {
          content: [{ type: 'text', text: `Error: ${message}` }],
          isError: true,
        };
      }
    });
  }

  private zodToJsonSchema(schema: z.ZodTypeAny): Record<string, unknown> {
    // Basic Zod to JSON Schema conversion
    if (schema instanceof z.ZodString) {
      return {
        type: 'string',
        description: schema.description,
      };
    }

    if (schema instanceof z.ZodNumber) {
      return {
        type: 'number',
        description: schema.description,
      };
    }

    if (schema instanceof z.ZodBoolean) {
      return {
        type: 'boolean',
        description: schema.description,
      };
    }

    if (schema instanceof z.ZodOptional) {
      return this.zodToJsonSchema(schema.unwrap());
    }

    return { type: 'string' };
  }

  private setupShutdownHandlers(): void {
    const shutdown = async (signal: string) => {
      if (this.shuttingDown) return;
      this.shuttingDown = true;

      log.info(`Received ${signal}, shutting down gracefully...`);

      try {
        // Close CDP client
        resetCDPClient();

        // Close audit logger
        await audit.close();

        // Close server
        await this.server.close();

        log.success('Shutdown complete');
        process.exit(0);
      } catch (error) {
        log.error(`Error during shutdown: ${error}`);
        process.exit(1);
      }
    };

    process.on('SIGINT', () => shutdown('SIGINT'));
    process.on('SIGTERM', () => shutdown('SIGTERM'));

    process.on('uncaughtException', (error) => {
      log.error(`Uncaught exception: ${error.message}`, { stack: error.stack });
      audit.system('uncaught_exception', false, { error: error.message });
      shutdown('uncaughtException');
    });

    process.on('unhandledRejection', (reason) => {
      log.error(`Unhandled rejection: ${reason}`);
      audit.system('unhandled_rejection', false, { reason: String(reason) });
      shutdown('unhandledRejection');
    });
  }

  async start(): Promise<void> {
    // Check security context
    const warnings = checkSecurityContext();
    for (const warning of warnings) {
      log.warn(warning);
    }

    // Verify Chrome is accessible
    const client = getCDPClient();
    const health = await client.checkHealth();

    if (!health.ok) {
      log.warn(`Chrome not available: ${health.error}`);
      log.info('Server will start, but tools will fail until Chrome is running');
      log.info('Start Chrome with: google-chrome --remote-debugging-port=9222');
    } else {
      log.info(`Chrome detected: ${health.version} with ${health.tabs} tabs`);
    }

    // Log startup
    audit.system('server_start', true, {
      version: SERVER_VERSION,
      chromeAvailable: health.ok,
    });

    // Connect to stdio transport
    const transport = new StdioServerTransport();
    await this.server.connect(transport);

    log.info(`${SERVER_NAME} v${SERVER_VERSION} started`);
  }
}

// Main entry point
async function main(): Promise<void> {
  // Check for CLI arguments
  const args = process.argv.slice(2);

  if (args.includes('--version') || args.includes('-v')) {
    console.log(`${SERVER_NAME} v${SERVER_VERSION}`);
    process.exit(0);
  }

  if (args.includes('--help') || args.includes('-h')) {
    console.log(`
${SERVER_NAME} v${SERVER_VERSION}

A Model Context Protocol server for Chrome browser automation.

Usage:
  chrome-mcp [options]

Options:
  -h, --help     Show this help message
  -v, --version  Show version number
  --health       Check Chrome connection and exit

Environment Variables:
  CHROME_HOST         Chrome debugging host (default: localhost)
  CHROME_PORT         Chrome debugging port (default: 9222)
  LOG_LEVEL           Logging level: debug, info, warn, error (default: info)
  AUDIT_LOGGING       Enable audit logging: true/false (default: true)
  AUDIT_LOG_DIR       Directory for audit logs (default: ./logs)

Chrome Setup:
  Start Chrome with remote debugging enabled:
  google-chrome --remote-debugging-port=9222

For more information, see: https://github.com/Pantheon-Security/chrome-mcp
`);
    process.exit(0);
  }

  if (args.includes('--health')) {
    const client = getCDPClient();
    const health = await client.checkHealth();

    if (health.ok) {
      console.log(`Chrome is running`);
      console.log(`Version: ${health.version}`);
      console.log(`Tabs: ${health.tabs}`);
      process.exit(0);
    } else {
      console.error(`Chrome not available: ${health.error}`);
      process.exit(1);
    }
  }

  // Start server
  const server = new ChromeMCPServer();
  await server.start();
}

main().catch((error) => {
  log.error(`Fatal error: ${error.message}`);
  process.exit(1);
});
