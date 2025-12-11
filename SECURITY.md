# Security Hardening Documentation

This is a security-hardened fork of [lxe/chrome-mcp](https://github.com/lxe/chrome-mcp), maintained by [Pantheon Security](https://github.com/Pantheon-Security).

**Version**: 2.1.0
**Security Features**: 8 hardening layers

## Security Features Overview

| Feature | Status | Description |
|---------|--------|-------------|
| Post-Quantum Encryption | ✅ | ML-KEM-768 + ChaCha20-Poly1305 |
| Secure Credential Vault | ✅ | Encrypted at rest, auto-wiped |
| Memory Scrubbing | ✅ | Zero sensitive data after use |
| Audit Logging | ✅ | Tamper-evident event logging |
| Profile Isolation | ✅ | Dedicated Chrome profile |
| Log Sanitization | ✅ | Credential masking |
| Rate Limiting | ✅ | Per-operation request throttling |
| Input Validation | ✅ | CSS selector, URL validation |

---

## Post-Quantum Encryption

### Why Post-Quantum?

Recent advances in quantum computing highlight the urgency of preparing for "Q-Day" - when quantum computers can break classical encryption (RSA, ECDH).

This MCP uses **hybrid post-quantum encryption** that combines:
- **ML-KEM-768 (Kyber)** - NIST-standardized post-quantum key encapsulation
- **ChaCha20-Poly1305** - Modern stream cipher (NOT AES-GCM)

### Why ChaCha20-Poly1305 over AES-GCM?

| Property | ChaCha20-Poly1305 | AES-GCM |
|----------|-------------------|---------|
| Timing attacks | Immune (constant-time) | Vulnerable without AES-NI |
| Software speed | Fast everywhere | Slow without hardware |
| Complexity | Simple | Complex (GCM mode) |
| Adoption | Google, Cloudflare TLS | Legacy systems |

This provides **double protection**: even if one algorithm is broken, the other remains secure.

### What's Encrypted

- Login credentials (username, password, API keys)
- Credential vault files on disk
- Post-quantum key pairs (double-encrypted)

### Encrypted File Format

Credential files are saved with `.pqenc` extension:
```json
{
  "version": 3,
  "algorithm": "chacha20-poly1305",
  "pqAlgorithm": "ML-KEM-768",
  "encapsulatedKey": "<base64>",
  "nonce": "<base64>",
  "salt": "<base64>",
  "ciphertext": "<base64 with Poly1305 tag appended>"
}
```

### Configuration

```bash
# Enable/disable post-quantum encryption (default: enabled)
CHROME_MCP_USE_POST_QUANTUM=true

# Provide your own encryption key (optional)
CHROME_MCP_ENCRYPTION_KEY=<base64-32-bytes>

# Use machine-derived key as fallback (default: true)
CHROME_MCP_USE_MACHINE_KEY=true
```

---

## Secure Credential Vault

### Storage Location

Credentials are stored in: `~/.chrome-mcp/credentials/`

Each credential is a separate encrypted file with:
- Unique ID (e.g., `cred_1702345678_abc123.pqenc`)
- Post-quantum encrypted content
- Secure file permissions (0600)

### Credential Types

| Type | Use Case |
|------|----------|
| `google` | Google accounts |
| `basic` | Username/password sites |
| `oauth` | OAuth tokens |
| `api_key` | API key storage |
| `custom` | Custom credential format |

### Credential Lifecycle

1. **Store**: Credentials encrypted immediately, password never stored in plaintext
2. **Retrieve**: Decrypted on-demand, held in SecureCredential object
3. **Use**: Auto-filled into forms via `secure_login`
4. **Wipe**: Automatically wiped from memory after TTL (default: 5 minutes)

### Configuration

```bash
# Credential storage directory
CHROME_MCP_CONFIG_DIR=~/.chrome-mcp

# Time-to-live for decrypted credentials in memory (milliseconds)
CHROME_MCP_CREDENTIAL_TTL=300000  # 5 minutes

# Maximum stored credentials
CHROME_MCP_MAX_CREDENTIALS=50
```

---

## Memory Scrubbing

Sensitive data is securely wiped from memory after use to prevent:
- Memory dump attacks
- Cold boot attacks
- Credential persistence in RAM

### Features

| Feature | Description |
|---------|-------------|
| `zeroBuffer()` | Securely zero-fill Buffer objects |
| `SecureString` | String wrapper with `.wipe()` method |
| `SecureCredential` | Auto-expiring credential with timer |
| `SecureObject` | Object with dispose-and-wipe capability |
| `secureCompare()` | Timing-safe string comparison |

### Auto-cleanup

Using `FinalizationRegistry`, secure buffers are automatically wiped when garbage collected.

### Usage

```typescript
import { SecureCredential, withSecureCredential } from './secure-memory.js';

// Auto-wipe after 5 minutes
const cred = new SecureCredential(password, 300000);

// Or use helper that auto-wipes after function completes
await withSecureCredential(password, async (cred) => {
  await fillPasswordField(cred.getValue());
});
// Credential is now wiped
```

---

## Audit Logging

All security-relevant events are logged with cryptographic integrity.

### Log Location

```
~/.chrome-mcp/logs/
├── audit-2025-12-11.jsonl
└── ...
```

### Log Format (JSONL with hash chain)

```json
{"timestamp":"2025-12-11T10:30:00Z","type":"security","event":"credential_stored","level":"info","details":{"name":"Google Work"},"hash":"a1b2c3..."}
```

Each entry's hash includes the previous entry, making tampering detectable.

### Logged Events

| Event | Description |
|-------|-------------|
| `vault_initialized` | Credential vault started |
| `credential_stored` | New credential saved |
| `credential_retrieved` | Credential decrypted |
| `credential_updated` | Credential modified |
| `credential_deleted` | Credential removed |
| `secure_login` | Login automation performed |

### Configuration

```bash
AUDIT_LOGGING=true
AUDIT_LOG_DIR=~/.chrome-mcp/logs
```

---

## Profile Isolation

Chrome runs with a dedicated profile separate from your default browser:

```bash
~/.chrome-mcp-profile/
```

### Benefits

- **Session isolation**: Login sessions don't affect your main browser
- **Cookie separation**: No cross-contamination with personal browsing
- **Clean state**: Easy to reset by deleting the profile directory
- **Security boundary**: Compromised automation doesn't affect main browser

### Configuration

```bash
CHROME_PROFILE_DIR=~/.chrome-mcp-profile
```

---

## Log Sanitization

Sensitive data is automatically masked in all log output:

| Data Type | Example Input | Logged Output |
|-----------|---------------|---------------|
| Password | `secret123` | `[REDACTED]` |
| API Key | `sk-abc123xyz` | `[REDACTED]` |
| Credential ID | `cred_123456_abc` | `cred****` |
| Email | `john@example.com` | `j***n@example.com` |

### Masked Fields

The following field names are automatically masked:
- `password`, `pass`, `pwd`
- `secret`, `token`, `key`
- `apiKey`, `api_key`
- `credential`, `auth`

---

## Rate Limiting

Built-in rate limiting prevents abuse:

| Operation | Limit |
|-----------|-------|
| All operations | 100 requests per minute |

### Implementation

```typescript
const rateLimiter = new RateLimiter(100, 60000); // 100 req/min

if (!rateLimiter.checkLimit('navigate')) {
  throw new RateLimitError('Rate limit exceeded');
}
```

---

## Input Validation

All user inputs are validated:

### CSS Selectors

- Checked for dangerous characters
- Path traversal attempts blocked
- Maximum length enforced

### URLs

- HTTPS required for sensitive operations
- Domain validation
- No `javascript:` or `data:` URLs
- No `file:` protocol

---

## Chrome DevTools Protocol Security

### WebSocket Connection

- Connects only to localhost by default
- No remote debugging without explicit configuration
- Certificate bypass only when explicitly requested

### Allowed Domains

By default, `bypass_cert_and_navigate` only works for:
- `localhost`
- `127.0.0.1`
- Private IP ranges (192.168.x.x, 10.x.x.x)

---

## Encryption Key Management

### Key Sources (Priority Order)

1. `CHROME_MCP_ENCRYPTION_KEY` - Environment variable (recommended)
2. `CHROME_MCP_ENCRYPTION_KEY_FILE` - File containing key
3. Machine-derived key - Automatic fallback

### Machine-Derived Key

If no explicit key is provided, a key is derived from:
- Machine ID
- Username
- OS-specific identifiers

**Note**: Machine-derived keys are not portable between machines.

### Generating a Strong Key

```bash
# Generate 256-bit key
openssl rand -base64 32

# Set as environment variable
export CHROME_MCP_ENCRYPTION_KEY="your-generated-key"
```

---

## Security API Reference

```typescript
// Post-quantum encryption
import {
  getSecureStorage,
  SecureStorage,
} from './crypto.js';

// Memory security
import {
  SecureString,
  SecureCredential,
  SecureObject,
  zeroBuffer,
  withSecureCredential,
  secureCompare,
  maskSensitive,
} from './secure-memory.js';

// Input validation & rate limiting
import {
  RateLimiter,
  sanitizeSelector,
  validateUrl,
  SecurityError,
  RateLimitError,
} from './security.js';

// Audit logging
import { log, audit } from './logger.js';

// === USAGE EXAMPLES ===

// Secure storage
const storage = getSecureStorage();
await storage.save('/path/to/file', sensitiveData);
const data = await storage.load('/path/to/file');

// Memory-safe credential handling
await withSecureCredential(password, async (cred) => {
  await fillForm(cred.getValue());
}); // Auto-wiped

// Timing-safe comparison
if (secureCompare(userInput, storedValue)) {
  // Match
}

// Audit logging
await audit.security('credential_stored', 'info', {
  name: 'Google Work',
  type: 'google',
});
```

---

## Remaining Considerations

### Browser Automation Risks

This MCP uses Chrome DevTools Protocol which:
- Requires Chrome running with `--remote-debugging-port`
- Has full access to browser state

**Recommendations:**
- Use a dedicated Chrome profile (setup.sh does this)
- Don't store credentials for critical accounts
- Run in an isolated environment for sensitive operations

### Not Encrypted (Chrome Profile)

The Chrome profile directory itself is not encrypted:
- `~/.chrome-mcp-profile/`

The **credentials** are encrypted, but Chrome's own data (history, cookies) use Chrome's built-in protections.

---

## Reporting Vulnerabilities

Found a security issue? **Do not open a public GitHub issue.**

Email: support@pantheonsecurity.io

---

## Credits

- Original implementation: [lxe](https://github.com/lxe) - [chrome-mcp](https://github.com/lxe/chrome-mcp)
- Security hardening: [Pantheon Security](https://github.com/Pantheon-Security)
- Post-quantum crypto: [@noble/post-quantum](https://www.npmjs.com/package/@noble/post-quantum)

## License

MIT License (same as original)
