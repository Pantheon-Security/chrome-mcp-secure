/**
 * Custom error types for Chrome MCP server
 *
 * Provides typed errors for better error handling and logging
 */

/**
 * Base error class for Chrome MCP errors
 */
export class ChromeMCPError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ChromeMCPError';
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
  }
}

/**
 * Chrome connection errors
 */
export class ConnectionError extends ChromeMCPError {
  public readonly isRetryable: boolean;

  constructor(message: string, isRetryable = true) {
    super(message);
    this.name = 'ConnectionError';
    this.isRetryable = isRetryable;
  }
}

/**
 * Navigation errors
 */
export class NavigationError extends ChromeMCPError {
  public readonly url: string;

  constructor(message: string, url: string) {
    super(message);
    this.name = 'NavigationError';
    this.url = url;
  }
}

/**
 * Element interaction errors
 */
export class ElementError extends ChromeMCPError {
  public readonly selector: string;

  constructor(message: string, selector: string) {
    super(message);
    this.name = 'ElementError';
    this.selector = selector;
  }
}

/**
 * Command timeout errors
 */
export class TimeoutError extends ChromeMCPError {
  public readonly command: string;
  public readonly timeoutMs: number;

  constructor(command: string, timeoutMs: number) {
    super(`Command '${command}' timed out after ${timeoutMs}ms`);
    this.name = 'TimeoutError';
    this.command = command;
    this.timeoutMs = timeoutMs;
  }
}

/**
 * Rate limit errors
 */
export class RateLimitError extends ChromeMCPError {
  public readonly resetMs: number;

  constructor(resetMs: number) {
    super(`Rate limit exceeded. Try again in ${Math.ceil(resetMs / 1000)} seconds`);
    this.name = 'RateLimitError';
    this.resetMs = resetMs;
  }
}

/**
 * CDP (Chrome DevTools Protocol) errors
 */
export class CDPError extends ChromeMCPError {
  public readonly method: string;
  public readonly code?: number;

  constructor(message: string, method: string, code?: number) {
    super(`CDP error in ${method}: ${message}`);
    this.name = 'CDPError';
    this.method = method;
    this.code = code;
  }
}

/**
 * JavaScript evaluation errors
 */
export class EvaluationError extends ChromeMCPError {
  public readonly expression: string;

  constructor(message: string, expression: string) {
    super(`JavaScript evaluation error: ${message}`);
    this.name = 'EvaluationError';
    this.expression = expression.substring(0, 200);
  }
}

/**
 * Format error for MCP response
 */
export function formatError(error: unknown): string {
  if (error instanceof ChromeMCPError) {
    return `${error.name}: ${error.message}`;
  }

  if (error instanceof Error) {
    return error.message;
  }

  return String(error);
}

/**
 * Check if error is retryable
 */
export function isRetryableError(error: unknown): boolean {
  if (error instanceof ConnectionError) {
    return error.isRetryable;
  }

  if (error instanceof TimeoutError) {
    return true;
  }

  if (error instanceof Error) {
    const message = error.message.toLowerCase();
    return (
      message.includes('connection') ||
      message.includes('timeout') ||
      message.includes('econnrefused') ||
      message.includes('econnreset')
    );
  }

  return false;
}
