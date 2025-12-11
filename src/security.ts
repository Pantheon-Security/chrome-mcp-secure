/**
 * Security utilities for Chrome MCP server
 *
 * Provides input validation, rate limiting, and security checks
 * Based on patterns from notebooklm-mcp-secure
 */

/**
 * Custom security error for validation failures
 */
export class SecurityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SecurityError';
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, SecurityError);
    }
  }
}

/**
 * Validate CSS selector to prevent injection attacks
 */
export function validateSelector(selector: string): string {
  if (!selector || typeof selector !== 'string') {
    throw new SecurityError('Selector is required');
  }

  const trimmed = selector.trim();

  if (trimmed.length === 0) {
    throw new SecurityError('Selector cannot be empty');
  }

  if (trimmed.length > 500) {
    throw new SecurityError('Selector too long (max 500 characters)');
  }

  // Block obvious script injection attempts
  const dangerousPatterns = [
    /javascript:/i,
    /<script/i,
    /on\w+\s*=/i,  // onclick=, onerror=, etc.
    /\beval\s*\(/i,
    /\bFunction\s*\(/i,
    /document\s*\.\s*(write|cookie)/i,
  ];

  for (const pattern of dangerousPatterns) {
    if (pattern.test(trimmed)) {
      throw new SecurityError('Selector contains potentially dangerous content');
    }
  }

  return trimmed;
}

/**
 * Validate URL for navigation
 */
export function validateUrl(url: string): string {
  if (!url || typeof url !== 'string') {
    throw new SecurityError('URL is required');
  }

  const trimmed = url.trim();

  if (trimmed.length === 0) {
    throw new SecurityError('URL cannot be empty');
  }

  if (trimmed.length > 2048) {
    throw new SecurityError('URL too long (max 2048 characters)');
  }

  // Block dangerous protocols
  const dangerousProtocols = ['javascript:', 'data:', 'vbscript:', 'file:'];
  const lowerUrl = trimmed.toLowerCase();

  for (const protocol of dangerousProtocols) {
    if (lowerUrl.startsWith(protocol)) {
      throw new SecurityError(`Dangerous protocol not allowed: ${protocol}`);
    }
  }

  // Block path traversal attempts
  if (trimmed.includes('..') || trimmed.includes('%2e%2e')) {
    throw new SecurityError('Path traversal not allowed');
  }

  return trimmed;
}

/**
 * Validate text input for typing
 */
export function validateText(text: string, maxLength = 10000): string {
  if (typeof text !== 'string') {
    throw new SecurityError('Text must be a string');
  }

  if (text.length > maxLength) {
    throw new SecurityError(`Text too long (max ${maxLength} characters)`);
  }

  return text;
}

/**
 * Validate coordinate values
 */
export function validateCoordinate(value: number, name: string, min = -10000, max = 50000): number {
  if (typeof value !== 'number' || isNaN(value)) {
    throw new SecurityError(`${name} must be a number`);
  }

  if (value < min || value > max) {
    throw new SecurityError(`${name} out of range (${min} to ${max})`);
  }

  return Math.round(value);
}

/**
 * Validate JavaScript code for execution (strict mode)
 */
export function validateJavaScript(code: string, allowedOperations: string[] = []): string {
  if (!code || typeof code !== 'string') {
    throw new SecurityError('JavaScript code is required');
  }

  const trimmed = code.trim();

  if (trimmed.length > 50000) {
    throw new SecurityError('JavaScript code too long (max 50000 characters)');
  }

  // Block dangerous operations
  const dangerousPatterns = [
    /\beval\s*\(/gi,
    /\bFunction\s*\(/gi,
    /document\s*\.\s*write/gi,
    /\.innerHTML\s*=/gi,
    /localStorage/gi,
    /sessionStorage/gi,
    /indexedDB/gi,
    /fetch\s*\(/gi,
    /XMLHttpRequest/gi,
    /WebSocket/gi,
    /Worker\s*\(/gi,
    /import\s*\(/gi,
    /require\s*\(/gi,
  ];

  for (const pattern of dangerousPatterns) {
    const match = pattern.source.replace(/\\[sb]\s*\\\(/g, '(');
    if (!allowedOperations.some(op => pattern.source.toLowerCase().includes(op.toLowerCase()))) {
      if (pattern.test(trimmed)) {
        throw new SecurityError(`Dangerous JavaScript operation detected: ${match}`);
      }
    }
  }

  return trimmed;
}

/**
 * Sanitize values for logging (hide sensitive data)
 */
export function sanitizeForLogging(value: string): string {
  if (!value || typeof value !== 'string') {
    return value;
  }

  let sanitized = value;

  // Mask emails
  sanitized = sanitized.replace(
    /([a-zA-Z0-9._%+-])[a-zA-Z0-9._%+-]*@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g,
    '$1****@$2'
  );

  // Mask potential secrets
  const secretPatterns = [
    /password\s*[=:]\s*\S+/gi,
    /token\s*[=:]\s*\S+/gi,
    /api[_-]?key\s*[=:]\s*\S+/gi,
    /secret\s*[=:]\s*\S+/gi,
    /auth\s*[=:]\s*\S+/gi,
    /bearer\s+\S+/gi,
  ];

  for (const pattern of secretPatterns) {
    sanitized = sanitized.replace(pattern, '[REDACTED]');
  }

  return sanitized;
}

/**
 * Rate limiter for preventing abuse
 */
export class RateLimiter {
  private requests: Map<string, number[]> = new Map();
  private readonly windowMs: number;
  private readonly maxRequests: number;

  constructor(windowMs = 60000, maxRequests = 100) {
    this.windowMs = windowMs;
    this.maxRequests = maxRequests;
  }

  isAllowed(key: string): { allowed: boolean; remaining: number; resetMs: number } {
    const now = Date.now();
    const windowStart = now - this.windowMs;

    // Get existing requests for this key
    let timestamps = this.requests.get(key) || [];

    // Filter to only requests within the window
    timestamps = timestamps.filter(ts => ts > windowStart);

    // Check if allowed
    const allowed = timestamps.length < this.maxRequests;
    const remaining = Math.max(0, this.maxRequests - timestamps.length - (allowed ? 1 : 0));

    // Calculate reset time
    const resetMs = timestamps.length > 0
      ? Math.max(0, timestamps[0] + this.windowMs - now)
      : 0;

    if (allowed) {
      timestamps.push(now);
      this.requests.set(key, timestamps);
    }

    return { allowed, remaining, resetMs };
  }

  reset(key: string): void {
    this.requests.delete(key);
  }

  cleanup(): void {
    const now = Date.now();
    const windowStart = now - this.windowMs;

    for (const [key, timestamps] of this.requests) {
      const valid = timestamps.filter(ts => ts > windowStart);
      if (valid.length === 0) {
        this.requests.delete(key);
      } else {
        this.requests.set(key, valid);
      }
    }
  }
}

/**
 * Check security context and return warnings
 */
export function checkSecurityContext(): string[] {
  const warnings: string[] = [];

  // Check for debug mode
  if (process.env.DEBUG === 'true' || process.env.NODE_ENV === 'development') {
    warnings.push('Running in debug/development mode - additional logging enabled');
  }

  // Check for insecure Chrome flags
  if (process.env.CHROME_DISABLE_SECURITY === 'true') {
    warnings.push('Chrome web security is disabled - use only for testing');
  }

  // Check for visible browser
  if (process.env.HEADLESS === 'false') {
    warnings.push('Browser running in visible mode - screen content may be exposed');
  }

  return warnings;
}
