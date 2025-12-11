# Changelog

All notable changes to Chrome MCP Secure will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.2.1] - 2025-12-11

### Fixed
- **Cross-Platform File Permissions** - All file operations now use centralized `file-permissions.ts` utility
  - Fixed 12 instances of insecure `fs.mkdirSync()` and `fs.writeFileSync()` calls
  - Proper Windows ACL support via `icacls`
  - Consistent 0o700 directory and 0o600 file permissions on Unix

### Changed
- `crypto.ts` - Now uses `mkdirSecure()` and `writeFileSecure()`
- `credential-vault.ts` - Now uses `mkdirSecure()` and `writeFileSecure()`
- `secure-memory.ts` - Deprecated internal functions, delegates to `file-permissions.ts`
- `mcp-auth.ts` - Now uses `mkdirSecure()` and `writeFileSecure()`
- `logger.ts` - Audit log directory now uses `mkdirSecure()`

---

## [2.2.0] - 2025-12-11

### Added

#### Security Modules
- **Secrets Scanner** (`src/secrets-scanner.ts`)
  - Detects 25+ secret patterns including AWS keys, GitHub tokens, API keys
  - Patterns derived from TruffleHog, GitLeaks, and MEDUSA
  - Auto-redaction capability with severity levels
  - Configurable via `CHROME_MCP_SECRETS_*` environment variables

- **Response Validator** (`src/response-validator.ts`)
  - Prompt injection detection (15+ attack patterns)
  - Suspicious URL detection (shorteners, paste services, dangerous protocols)
  - Encoded payload detection (Base64, hex, URL encoding)
  - Content sanitization with redaction

- **Session Manager** (`src/session-manager.ts`)
  - Credential session lifecycle management
  - Maximum session lifetime (default: 8 hours)
  - Inactivity timeout (default: 30 minutes)
  - Automatic session expiration and cleanup

- **MCP Authentication** (`src/mcp-auth.ts`)
  - Token-based authentication for MCP requests
  - Auto-generated tokens on first run
  - Secure token storage (SHA256 hashed)
  - Rate limiting with brute-force lockout (5 attempts = 5 min lockout)

- **Certificate Pinning** (`src/cert-pinning.ts`)
  - SPKI-style certificate pinning
  - Built-in pins for sensitive services (Google, GitHub, Microsoft, etc.)
  - Custom pin configuration via environment
  - Validation caching for performance

- **Screenshot Redaction** (`src/screenshot-redaction.ts`)
  - Automatic redaction of password fields
  - Credit card and CVV field redaction
  - SSN and tax ID field redaction
  - API key and token field redaction
  - Customizable overlay appearance

### Changed
- Version bump to 2.2.0

### Environment Variables (New)

#### Secrets Scanner
- `CHROME_MCP_SECRETS_SCANNING` - Enable/disable (default: true)
- `CHROME_MCP_SECRETS_BLOCK` - Block on detection (default: false)
- `CHROME_MCP_SECRETS_REDACT` - Auto-redact secrets (default: true)
- `CHROME_MCP_SECRETS_MIN_SEVERITY` - Minimum severity to report

#### Response Validator
- `CHROME_MCP_RESPONSE_VALIDATION` - Enable/disable (default: true)
- `CHROME_MCP_BLOCK_PROMPT_INJECTION` - Block injections (default: true)
- `CHROME_MCP_BLOCK_SUSPICIOUS_URLS` - Block suspicious URLs (default: true)

#### Session Manager
- `CHROME_MCP_SESSION_MAX_LIFETIME` - Max session lifetime in ms
- `CHROME_MCP_SESSION_INACTIVITY` - Inactivity timeout in ms
- `CHROME_MCP_SESSION_MANAGEMENT` - Enable/disable (default: true)

#### MCP Authentication
- `CHROME_MCP_AUTH_ENABLED` - Enable authentication (default: false)
- `CHROME_MCP_AUTH_TOKEN` - Authentication token
- `CHROME_MCP_AUTH_TOKEN_FILE` - Token file path
- `CHROME_MCP_AUTH_MAX_FAILED` - Max failed attempts (default: 5)
- `CHROME_MCP_AUTH_LOCKOUT_MS` - Lockout duration (default: 300000)

#### Certificate Pinning
- `CHROME_MCP_CERT_PINNING` - Enable/disable (default: true)
- `CHROME_MCP_CERT_PINS` - Custom pins (format: domain1:pin1,pin2)
- `CHROME_MCP_CERT_CACHE_TTL` - Cache duration in ms
- `CHROME_MCP_CERT_REPORT_ONLY` - Report only mode (default: false)

#### Screenshot Redaction
- `CHROME_MCP_SCREENSHOT_REDACTION` - Enable/disable (default: true)
- `CHROME_MCP_REDACTION_COLOR` - Overlay color (default: #000000)
- `CHROME_MCP_REDACTION_TEXT` - Overlay text (default: [REDACTED])
- `CHROME_MCP_REDACTION_SELECTORS` - Custom selectors

---

## [2.1.0] - 2025-12-10

### Added
- Post-quantum encryption for credential vault (ML-KEM-768 + ChaCha20-Poly1305)
- Secure credential storage with automatic memory wiping
- Credential CRUD operations (store, list, get, update, delete)
- Secure login automation with credential auto-fill
- Vault status tool for health checks
- Comprehensive audit logging
- Security context checks (root user, debug mode warnings)

### Security
- Credentials encrypted at rest in `~/.chrome-mcp/credentials/`
- Auto-wiped from memory after configurable TTL (default: 5 minutes)
- Passwords never logged (automatic masking in audit logs)
- File permissions locked to owner-only (0600)

### Tools Added
- `store_credential` - Store encrypted credentials
- `list_credentials` - List stored credentials (no passwords shown)
- `get_credential` - Get credential metadata
- `delete_credential` - Remove a stored credential
- `update_credential` - Update an existing credential
- `secure_login` - Auto-fill login forms using stored credentials
- `get_vault_status` - Check vault encryption status

---

## [2.0.0] - 2025-12-09

### Added
- Complete rewrite of Chrome MCP server
- Reliable CDP (Chrome DevTools Protocol) client
- Automatic reconnection handling
- Connection pooling and health checks
- Structured logging with configurable levels
- Audit logging for all tool operations

### Changed
- Architecture redesign for reliability
- Modular tool system with Zod validation
- Improved error handling and messages
- TypeScript strict mode enabled

### Tools Available
- `navigate` - Navigate to URL
- `bypass_cert_and_navigate` - Navigate with HTTPS cert bypass
- `get_tabs` - List all Chrome tabs
- `click_element` - Click element by CSS selector
- `click` - Click at coordinates
- `type` - Type text at cursor focus
- `fill` - Fill form field (clears first)
- `get_text` - Get element text content
- `get_page_info` - Get URL, title, interactive elements
- `get_page_state` - Get scroll position, viewport size
- `scroll` - Scroll to coordinates
- `screenshot` - Capture screenshot
- `wait_for_element` - Wait for element
- `evaluate` - Execute JavaScript
- `health` - Check Chrome connection

---

## [1.0.0] - Initial Fork

### Added
- Forked from [lxe/chrome-mcp](https://github.com/lxe/chrome-mcp)
- Basic Chrome DevTools Protocol integration
- MCP server implementation
- Core navigation and interaction tools

### Credits
- Original work by [lxe](https://github.com/lxe)
- Security hardening by [Pantheon Security](https://github.com/Pantheon-Security)
