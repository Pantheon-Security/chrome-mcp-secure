# Chrome MCP Server - Claude Code Integration

**Version**: 2.1.0
**Purpose**: Secure Chrome DevTools Protocol automation with encrypted credential vault

## Quick Start

```bash
# One-command setup (installs, builds, starts Chrome)
./setup.sh

# Verify connection
mcp__chrome-mcp-secure__health()
```

## Available Tools

### Connection & Status
- `health` - Check Chrome connection and version
- `get_vault_status` - Check credential vault encryption status

### Navigation
- `navigate(url)` - Navigate to URL
- `bypass_cert_and_navigate(url)` - Navigate with HTTPS cert bypass
- `get_tabs()` - List all Chrome tabs

### Element Interaction
- `click_element(selector)` - Click element by CSS selector
- `click(x, y)` - Click at coordinates
- `type(text)` - Type text at cursor focus
- `fill(selector, value)` - Fill form field (clears first)

### Data Extraction
- `get_text(selector)` - Get element text content
- `get_page_info()` - Get URL, title, interactive elements
- `get_page_state()` - Get scroll position, viewport size

### Page Actions
- `scroll(x, y)` - Scroll to coordinates
- `screenshot(fullPage?)` - Capture screenshot
- `wait_for_element(selector, timeout?)` - Wait for element

### Advanced
- `evaluate(expression)` - Execute JavaScript

### Secure Credential Tools
- `store_credential(name, type, email, password, domain)` - Store encrypted credentials
- `list_credentials(type?, domain?)` - List stored credentials (no passwords shown)
- `get_credential(id)` - Get credential metadata
- `delete_credential(id)` - Remove a stored credential
- `update_credential(id, ...)` - Update an existing credential
- `secure_login(credentialId, ...)` - Auto-fill login forms using stored credentials

## Usage Examples

### Basic Navigation and Inspection

```javascript
// Check connection first
mcp__chrome-mcp-secure__health()

// Navigate to page
mcp__chrome-mcp-secure__navigate({ url: "https://example.com" })

// Get page info
mcp__chrome-mcp-secure__get_page_info()

// Take screenshot
mcp__chrome-mcp-secure__screenshot()
```

### Secure Login Flow

```javascript
// 1. Store credentials (once, encrypted at rest)
mcp__chrome-mcp-secure__store_credential({
  name: "Google Work",
  type: "google",
  email: "me@company.com",
  password: "mypassword123",
  domain: "google.com"
})

// 2. Navigate to login page
mcp__chrome-mcp-secure__navigate({ url: "https://accounts.google.com" })

// 3. List credentials to get ID
mcp__chrome-mcp-secure__list_credentials()

// 4. Perform secure login
mcp__chrome-mcp-secure__secure_login({
  credentialId: "cred_1234567890_abc123"
})
```

### Form Interaction

```javascript
// Fill a form field
mcp__chrome-mcp-secure__fill({
  selector: "#email",
  value: "test@example.com"
})

// Click submit button
mcp__chrome-mcp-secure__click_element({ selector: "#submit" })

// Wait for result
mcp__chrome-mcp-secure__wait_for_element({
  selector: ".success-message",
  timeout: 5000
})
```

### Dynamic Content

```javascript
// Navigate to page with dynamic content
mcp__chrome-mcp-secure__navigate({ url: "https://app.example.com" })

// Wait for content to load
mcp__chrome-mcp-secure__wait_for_element({ selector: "#main-content" })

// Get the loaded content
mcp__chrome-mcp-secure__get_page_info()
```

## Security Features

### Credential Storage
- Post-quantum encryption (ML-KEM-768 + ChaCha20-Poly1305)
- Credentials encrypted at rest in `~/.chrome-mcp/credentials/`
- Auto-wiped from memory after 5 minutes (configurable)
- Passwords never logged (automatic masking)

### Check Vault Status
```javascript
mcp__chrome-mcp-secure__get_vault_status()
// Returns: encryption enabled, post-quantum status, key source
```

## Error Handling

The server provides clear error messages:

- **Connection errors**: "Chrome not available" - Start Chrome with debugging
- **Element not found**: Includes selector that failed
- **Rate limit**: Shows time until reset
- **Validation errors**: Details about invalid input
- **Credential errors**: "Credential expired" or "not found"

## Troubleshooting

### "Chrome not available"

```bash
# Check if Chrome debugging is enabled
curl http://localhost:9222/json

# Start Chrome with debugging (setup.sh does this automatically)
./setup.sh --start-chrome
```

### "Element not found"

```javascript
// First, see what elements exist
mcp__chrome-mcp-secure__get_page_info()

// For dynamic content, wait first
mcp__chrome-mcp-secure__wait_for_element({ selector: "#target", timeout: 10000 })
```

### "Credential expired"

Credentials are wiped from memory after 5 minutes. Just call `secure_login` again - it will decrypt from the vault.

### Connection Timeouts

1. Verify Chrome is running
2. Check for any Chrome dialogs blocking
3. Restart Chrome: `./setup.sh --stop-chrome && ./setup.sh --start-chrome`

## Environment Variables

```bash
# Chrome connection
CHROME_PORT=9222
CHROME_HOST=localhost

# Encryption (recommended for production)
CHROME_MCP_ENCRYPTION_KEY="base64-key-here"

# Credential TTL (milliseconds)
CHROME_MCP_CREDENTIAL_TTL=300000
```

## Management

```bash
# Full setup
./setup.sh

# Check status
./setup.sh --check

# Uninstall
./setup.sh --uninstall

# Start/stop Chrome
./setup.sh --start-chrome
./setup.sh --stop-chrome
```
