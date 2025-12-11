<div align="center">

# Chrome MCP Server (Security Hardened)

**Chrome DevTools Protocol automation for AI agents - with enterprise-grade security**

[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue.svg)](https://www.typescriptlang.org/)
[![MCP](https://img.shields.io/badge/MCP-2025-green.svg)](https://modelcontextprotocol.io/)
[![Security](https://img.shields.io/badge/Security-Hardened-red.svg)](./SECURITY.md)
[![Post-Quantum](https://img.shields.io/badge/Encryption-Post--Quantum-purple.svg)](./SECURITY.md#post-quantum-encryption)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

[Security Features](#security-features) • [Installation](#installation) • [Quick Start](#quick-start) • [Tools](#available-tools) • [Documentation](./SECURITY.md)

`#anthropic` `#mcp` `#claude` `#mcp-server` `#ai-agent` `#chrome` `#browser-automation` `#devtools` `#security` `#post-quantum` `#encryption` `#credential-vault` `#pantheon-security`

</div>

> **Security-hardened fork** of [lxe/chrome-mcp](https://github.com/lxe/chrome-mcp)
> Maintained by [Pantheon Security](https://github.com/Pantheon-Security)

---

## Why This Fork?

The original Chrome MCP by [lxe](https://github.com/lxe/chrome-mcp) is excellent for browser automation - but MCP servers handling credentials need protection:
- **Login credentials** stored for automated logins
- **Session cookies** persisted on disk
- **Browsing history** that may contain sensitive URLs

This fork adds **security hardening layers** to protect that data, using the same patterns from our [notebooklm-mcp-secure](https://github.com/Pantheon-Security/notebooklm-mcp-secure).

---

## Security Features

| Feature | Description |
|---------|-------------|
| **Post-Quantum Encryption** | ML-KEM-768 + ChaCha20-Poly1305 hybrid |
| **Secure Credential Vault** | Encrypted at rest, auto-wiped from memory |
| **Memory Scrubbing** | Zeros sensitive data after use |
| **Audit Logging** | Tamper-evident logs with hash chains |
| **Profile Isolation** | Dedicated Chrome profile for secure sessions |
| **Log Sanitization** | Credentials masked in all output |
| **Rate Limiting** | 100 requests per minute per operation |
| **Input Validation** | CSS selector sanitization, URL validation |

### Post-Quantum Ready

Traditional encryption will be broken by quantum computers. This fork uses **hybrid encryption**:

```
ML-KEM-768 (Kyber) + ChaCha20-Poly1305
```

- **ML-KEM-768**: NIST-standardized post-quantum key encapsulation
- **ChaCha20-Poly1305**: Modern stream cipher (immune to timing attacks)

Even if one algorithm is broken, the other remains secure.

---

## Installation

### One-Command Setup (Recommended)

**Linux / macOS:**
```bash
git clone https://github.com/Pantheon-Security/chrome-mcp-secure.git
cd chrome-mcp-secure
./setup.sh
```

**Windows (PowerShell):**
```powershell
git clone https://github.com/Pantheon-Security/chrome-mcp-secure.git
cd chrome-mcp-secure
.\setup.ps1
```

This will:
1. Install dependencies and build the project
2. Register the MCP server with Claude Code
3. Start Chrome with remote debugging
4. Create an isolated Chrome profile

### Manual Setup

```bash
npm install && npm run build
claude mcp add chrome-mcp-secure --scope user -- node /path/to/chrome-mcp-secure/dist/index.js
google-chrome --remote-debugging-port=9222 --user-data-dir=~/.chrome-mcp-profile
```

### Platform-Specific Notes

| Platform | Setup Script | Chrome Profile Location |
|----------|--------------|------------------------|
| Linux | `./setup.sh` | `~/.chrome-mcp-profile` |
| macOS | `./setup.sh` | `~/.chrome-mcp-profile` |
| Windows | `.\setup.ps1` | `%USERPROFILE%\.chrome-mcp-profile` |

---

## Quick Start

### 1. Start Chrome with debugging
```bash
./setup.sh --start-chrome
```

### 2. Use in Claude Code
```
"Check Chrome connection with health tool"
"Navigate to https://example.com"
"Take a screenshot"
```

### 3. Secure Login Flow
```
"Store a credential for my GitHub account"
"Navigate to github.com/login"
"Use secure_login with the stored credential"
```

---

## Available Tools

### Browser Automation (15 tools)

| Tool | Description |
|------|-------------|
| `health` | Check Chrome connection and version |
| `navigate` | Navigate to URL |
| `get_tabs` | List all Chrome tabs |
| `click_element` | Click element by CSS selector |
| `click` | Click at coordinates |
| `type` | Type text at cursor |
| `get_text` | Extract text from element |
| `get_page_info` | Get URL, title, interactive elements |
| `get_page_state` | Get scroll position, viewport size |
| `scroll` | Scroll to coordinates |
| `screenshot` | Capture page screenshot |
| `wait_for_element` | Wait for element to appear |
| `evaluate` | Execute JavaScript |
| `fill` | Fill form field |
| `bypass_cert_and_navigate` | Navigate with HTTPS cert bypass |

### Secure Credential Tools (7 tools)

| Tool | Description |
|------|-------------|
| `store_credential` | Store encrypted login credentials |
| `list_credentials` | List stored credentials (no passwords shown) |
| `get_credential` | Get credential metadata |
| `delete_credential` | Remove a stored credential |
| `update_credential` | Update an existing credential |
| `secure_login` | Auto-fill login forms using stored credentials |
| `get_vault_status` | Check vault encryption status |

---

## Secure Credential Usage

### Storing Credentials

```
Store a credential for my Google account:
- Name: "Google Work"
- Type: google
- Email: me@example.com
- Password: mypassword123
- Domain: google.com
```

### Using Credentials for Login

```
1. Navigate to https://accounts.google.com
2. Use secure_login with the credential ID from list_credentials
```

The `secure_login` tool will:
- Retrieve and decrypt the credential from the vault
- Auto-fill the username/email field
- Auto-fill the password field
- Click the submit button
- Wipe credentials from memory after use

---

## What Gets Protected

| Data | Protection |
|------|------------|
| Login credentials | Post-quantum encrypted at rest |
| Passwords in memory | Auto-wiped after 5 min TTL |
| Log output | Credentials auto-masked |
| Chrome profile | Isolated from default browser |
| Audit trail | Hash-chained for tamper detection |

---

## Configuration

### Environment Variables

```bash
# Chrome connection
CHROME_HOST=localhost
CHROME_PORT=9222
CHROME_PROFILE_DIR=~/.chrome-mcp-profile

# Encryption (recommended for production)
CHROME_MCP_ENCRYPTION_KEY=<base64-32-bytes>
CHROME_MCP_USE_POST_QUANTUM=true

# Credential vault
CHROME_MCP_CONFIG_DIR=~/.chrome-mcp
CHROME_MCP_CREDENTIAL_TTL=300000  # 5 minutes

# Logging
LOG_LEVEL=info
AUDIT_LOGGING=true
```

### Generate Strong Encryption Key

```bash
openssl rand -base64 32
```

See [SECURITY.md](./SECURITY.md) for complete configuration reference.

---

## Security Architecture

### Encryption

```
                    ┌─────────────────────────────────────┐
                    │      ML-KEM-768 Key Pair            │
                    │   (Post-Quantum Key Encapsulation)  │
                    └─────────────────┬───────────────────┘
                                      │
                    ┌─────────────────┴───────────────────┐
                    │      ChaCha20-Poly1305              │
                    │   (Symmetric AEAD Encryption)       │
                    └─────────────────┬───────────────────┘
                                      │
                    ┌─────────────────┴───────────────────┐
                    │      Encrypted Credential Files     │
                    │   ~/.chrome-mcp/credentials/*.pqenc │
                    └─────────────────────────────────────┘
```

### Memory Protection

- **SecureCredential class**: Auto-wipes credentials after TTL (5 min default)
- **Zero-fill buffers**: Random overwrite + zero fill prevents memory dumps
- **No credential logging**: Automatic masking of sensitive field names

### Why ChaCha20-Poly1305 over AES-GCM?

| Property | ChaCha20-Poly1305 | AES-GCM |
|----------|-------------------|---------|
| Timing attacks | Immune (constant-time) | Vulnerable without AES-NI |
| Software speed | Fast everywhere | Slow without hardware |
| Complexity | Simple | Complex (GCM mode) |
| Adoption | Google, Cloudflare TLS | Legacy systems |

---

## Management Commands

```bash
# Full setup
./setup.sh

# Check status
./setup.sh --check

# Uninstall from Claude Code
./setup.sh --uninstall

# Start/stop Chrome
./setup.sh --start-chrome
./setup.sh --stop-chrome
```

---

## Architecture

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────┐
│ Claude/     │────▶│  MCP Server      │────▶│   Chrome    │
│ AI Agent    │     │  (This Fork)     │     │   (CDP)     │
└─────────────┘     └──────────────────┘     └─────────────┘
                           │
                    ┌──────┴──────┐
                    │  Security   │
                    │   Layers    │
                    └─────────────┘
                    • PQ Encryption
                    • Credential Vault
                    • Memory Wipe
                    • Audit Logs
                    • Rate Limits
                    • Input Validation
```

---

## File Structure

```
chrome-mcp-secure/
├── src/
│   ├── index.ts           # MCP server entry point
│   ├── cdp-client.ts      # Persistent CDP WebSocket client
│   ├── tools.ts           # Browser automation tools
│   ├── credential-vault.ts # Encrypted credential storage
│   ├── credential-tools.ts # Credential MCP tools
│   ├── crypto.ts          # Post-quantum encryption
│   ├── secure-memory.ts   # Memory protection utilities
│   ├── security.ts        # Input validation, rate limiting
│   ├── logger.ts          # Logging with auto-masking
│   └── errors.ts          # Typed error classes
├── dist/                  # Compiled JavaScript
├── setup.sh               # Linux/macOS setup
├── setup.ps1              # Windows setup
├── SECURITY.md            # Security documentation
├── CLAUDE.md              # Claude Code integration guide
└── README.md
```

---

## Comparison with Original

| Feature | [lxe/chrome-mcp](https://github.com/lxe/chrome-mcp) | This Fork |
|---------|----------|-----------|
| Chrome automation | ✅ | ✅ |
| Persistent WebSocket | ✅ | ✅ |
| Cross-platform | ✅ | ✅ |
| **Post-quantum encryption** | ❌ | ✅ |
| **Secure credential vault** | ❌ | ✅ |
| **Memory scrubbing** | ❌ | ✅ |
| **Audit logging** | ❌ | ✅ |
| **Auto log masking** | ❌ | ✅ |
| **Profile isolation** | ❌ | ✅ |

---

## Troubleshooting

### Chrome not accessible
```bash
curl http://localhost:9222/json
# If no response, start Chrome:
./setup.sh --start-chrome
```

### Credential decryption fails
1. Check if you changed machines (machine-derived key won't work)
2. Set `CHROME_MCP_ENCRYPTION_KEY` to the same key used to encrypt
3. Credentials may need to be re-stored if key is lost

### Element not found
```
Use get_page_info to see available elements
Use wait_for_element for dynamic content
```

---

## Development

```bash
# Install dependencies
npm install

# Development mode (auto-reload)
npm run dev

# Type checking
npm run typecheck

# Build for production
npm run build

# Run built version
npm start
```

---

## Reporting Vulnerabilities

Found a security issue? **Do not open a public GitHub issue.**

Email: support@pantheonsecurity.io

---

## Credits

- **Original Chrome MCP**: [lxe](https://github.com/lxe) - [chrome-mcp](https://github.com/lxe/chrome-mcp)
- **Security Hardening**: [Pantheon Security](https://github.com/Pantheon-Security)
- **Security Patterns**: Adapted from [notebooklm-mcp-secure](https://github.com/Pantheon-Security/notebooklm-mcp-secure)
- **Post-Quantum Crypto**: [@noble/post-quantum](https://www.npmjs.com/package/@noble/post-quantum)

## License

MIT - Same as original.

---

<div align="center">

**Security hardened by [Pantheon Security](https://github.com/Pantheon-Security)**

[Full Security Documentation](./SECURITY.md) • [Report Vulnerability](mailto:support@pantheonsecurity.io)

</div>
