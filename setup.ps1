#Requires -Version 5.1
<#
.SYNOPSIS
    Chrome MCP v2.1.0 - One-Command Setup for Claude Code (Windows)

.DESCRIPTION
    This script:
    1. Installs dependencies and builds the project
    2. Registers the MCP server with Claude Code
    3. Starts Chrome with remote debugging
    4. Creates an isolated Chrome profile

.PARAMETER Uninstall
    Remove from Claude Code

.PARAMETER Check
    Check installation status only

.PARAMETER StartChrome
    Start Chrome with debugging enabled

.PARAMETER StopChrome
    Stop Chrome instance started by this script

.EXAMPLE
    .\setup.ps1              # Full setup
    .\setup.ps1 -Uninstall   # Remove from Claude Code
    .\setup.ps1 -Check       # Check status only
#>

param(
    [switch]$Uninstall,
    [switch]$Check,
    [switch]$StartChrome,
    [switch]$StopChrome,
    [switch]$Help
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$McpName = "chrome-mcp-secure"
$ChromePort = if ($env:CHROME_PORT) { $env:CHROME_PORT } else { "9222" }
$ChromeProfileDir = if ($env:CHROME_PROFILE_DIR) { $env:CHROME_PROFILE_DIR } else { "$env:USERPROFILE\.chrome-mcp-profile" }
$PidFile = Join-Path $ScriptDir ".chrome-mcp.pid"

# Colors for output
function Write-Success { param($Message) Write-Host "[OK] $Message" -ForegroundColor Green }
function Write-Warning { param($Message) Write-Host "[!] $Message" -ForegroundColor Yellow }
function Write-Err { param($Message) Write-Host "[X] $Message" -ForegroundColor Red }
function Write-Step { param($Message) Write-Host "[>] $Message" -ForegroundColor Cyan }

function Show-Banner {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "                                                            " -ForegroundColor Cyan
    Write-Host "     Chrome MCP v2.1.0 - Browser Automation for AI          " -ForegroundColor Cyan
    Write-Host "                                                            " -ForegroundColor Cyan
    Write-Host "     Persistent connections - Post-quantum encryption       " -ForegroundColor Cyan
    Write-Host "     Secure credential vault - Profile isolation            " -ForegroundColor Cyan
    Write-Host "     Based on lxe/chrome-mcp - By Pantheon Security         " -ForegroundColor Cyan
    Write-Host "                                                            " -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Test-ChromeRunning {
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:$ChromePort/json/version" -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue
        if ($response.StatusCode -eq 200) {
            $version = ($response.Content | ConvertFrom-Json).Browser
            Write-Success "Chrome detected: $version"
            return $true
        }
    } catch {
        return $false
    }
    return $false
}

function Find-Chrome {
    $chromePaths = @(
        "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
        "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
        "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe",
        "$env:ProgramFiles\Chromium\Application\chrome.exe"
    )

    foreach ($path in $chromePaths) {
        if (Test-Path $path) {
            return $path
        }
    }

    # Try to find via registry
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe"
    if (Test-Path $regPath) {
        $chromePath = (Get-ItemProperty $regPath).'(Default)'
        if (Test-Path $chromePath) {
            return $chromePath
        }
    }

    return $null
}

function Start-ChromeDebug {
    if (Test-ChromeRunning) {
        return $true
    }

    $chromeBin = Find-Chrome
    if (-not $chromeBin) {
        Write-Err "Chrome not found. Please install Google Chrome."
        Write-Host "Download from: https://www.google.com/chrome/"
        return $false
    }

    Write-Step "Starting Chrome with remote debugging on port $ChromePort..."

    # Create profile directory if needed
    if (-not (Test-Path $ChromeProfileDir)) {
        New-Item -ItemType Directory -Path $ChromeProfileDir -Force | Out-Null
    }

    $chromeArgs = @(
        "--remote-debugging-port=$ChromePort",
        "--user-data-dir=$ChromeProfileDir",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-background-timer-throttling",
        "--disable-backgrounding-occluded-windows",
        "--disable-renderer-backgrounding",
        "about:blank"
    )

    $process = Start-Process -FilePath $chromeBin -ArgumentList $chromeArgs -PassThru -WindowStyle Normal
    $process.Id | Out-File -FilePath $PidFile -Force

    # Wait for Chrome to start
    $count = 0
    while ($count -lt 20) {
        Start-Sleep -Milliseconds 500
        if (Test-ChromeRunning) {
            Write-Success "Chrome started (PID: $($process.Id))"
            return $true
        }
        $count++
    }

    Write-Err "Chrome failed to start within timeout"
    return $false
}

function Stop-ChromeDebug {
    if (Test-Path $PidFile) {
        $pid = Get-Content $PidFile
        try {
            $process = Get-Process -Id $pid -ErrorAction SilentlyContinue
            if ($process) {
                Write-Step "Stopping Chrome (PID: $pid)..."
                Stop-Process -Id $pid -Force
                Write-Success "Chrome stopped"
            }
        } catch {
            Write-Warning "Could not stop Chrome process"
        }
        Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
    } else {
        Write-Warning "No Chrome PID file found"
    }
}

function Test-McpInstalled {
    try {
        $output = & claude mcp list 2>&1
        return $output -match $McpName
    } catch {
        return $false
    }
}

function Build-Project {
    Write-Step "Building Chrome MCP..."
    Push-Location $ScriptDir
    try {
        if (-not (Test-Path "node_modules")) {
            Write-Step "Installing dependencies..."
            & npm install --silent 2>&1 | Out-Null
        }

        $distIndex = Join-Path $ScriptDir "dist\index.js"
        $srcIndex = Join-Path $ScriptDir "src\index.ts"

        if (-not (Test-Path $distIndex) -or ((Get-Item $srcIndex).LastWriteTime -gt (Get-Item $distIndex).LastWriteTime)) {
            & npm run build --silent 2>&1 | Out-Null
        }

        Write-Success "Build complete"
    } finally {
        Pop-Location
    }
}

function Install-Mcp {
    Write-Step "Registering with Claude Code..."

    # Remove if exists
    if (Test-McpInstalled) {
        & claude mcp remove $McpName 2>&1 | Out-Null
    }

    $indexPath = Join-Path $ScriptDir "dist\index.js"
    & claude mcp add $McpName --scope user -- node $indexPath

    Write-Success "MCP server registered: $McpName"
}

function Uninstall-Mcp {
    Write-Step "Removing from Claude Code..."

    if (Test-McpInstalled) {
        & claude mcp remove $McpName
        Write-Success "MCP server removed"
    } else {
        Write-Warning "MCP server not installed"
    }
}

function Show-Status {
    Write-Host ""
    Write-Host "Status:" -ForegroundColor White

    if (Test-McpInstalled) {
        Write-Success "MCP server: Registered"
    } else {
        Write-Err "MCP server: Not registered"
    }

    if (-not (Test-ChromeRunning)) {
        Write-Warning "Chrome: Not running with debugging"
        Write-Host "        Start with: .\setup.ps1 -StartChrome"
    }

    $distIndex = Join-Path $ScriptDir "dist\index.js"
    if (Test-Path $distIndex) {
        Write-Success "Build: Ready"
    } else {
        Write-Warning "Build: Not built (run .\setup.ps1)"
    }
}

function Invoke-Setup {
    Show-Banner

    # Build
    Build-Project

    # Install
    Install-Mcp

    # Start Chrome
    Write-Host ""
    if (-not (Test-ChromeRunning)) {
        Start-ChromeDebug | Out-Null
    }

    # Show tools
    Write-Host ""
    Write-Host "Browser Tools:" -ForegroundColor White
    Write-Host "  health, navigate, get_tabs, click_element, click, type,"
    Write-Host "  get_text, get_page_info, get_page_state, scroll, screenshot,"
    Write-Host "  wait_for_element, evaluate, fill, bypass_cert_and_navigate"
    Write-Host ""
    Write-Host "Secure Credential Tools:" -ForegroundColor White
    Write-Host "  store_credential, list_credentials, get_credential,"
    Write-Host "  delete_credential, update_credential, secure_login,"
    Write-Host "  get_vault_status"
    Write-Host ""
    Write-Host "Security Features:" -ForegroundColor White
    Write-Host "  - Post-quantum encryption (ML-KEM-768 + ChaCha20-Poly1305)"
    Write-Host "  - Credentials encrypted at rest and wiped from memory"
    Write-Host "  - Automatic log masking for sensitive data"
    Write-Host "  - Isolated Chrome profile for secure sessions"
    Write-Host ""
    Write-Host "Quick Test:" -ForegroundColor White
    Write-Host "  In Claude Code, try: " -NoNewline
    Write-Host "Use the health tool to check Chrome connection" -ForegroundColor Cyan
    Write-Host ""

    Write-Success "Setup complete! Chrome MCP is ready to use."
}

function Show-Help {
    Show-Banner
    Write-Host "Usage: .\setup.ps1 [options]"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  (none)        Full setup - build, install, start Chrome"
    Write-Host "  -Uninstall    Remove from Claude Code"
    Write-Host "  -Check        Check installation status"
    Write-Host "  -StartChrome  Start Chrome with debugging enabled"
    Write-Host "  -StopChrome   Stop Chrome instance started by this script"
    Write-Host "  -Help         Show this help"
    Write-Host ""
    Write-Host "Environment Variables:"
    Write-Host "  CHROME_PORT                    Chrome debugging port (default: 9222)"
    Write-Host "  CHROME_PROFILE_DIR             Chrome profile directory"
    Write-Host ""
    Write-Host "Security Environment Variables:"
    Write-Host "  CHROME_MCP_ENCRYPTION_KEY      Base64 encryption key (recommended)"
    Write-Host "  CHROME_MCP_USE_POST_QUANTUM    Enable post-quantum encryption (default: true)"
    Write-Host "  CHROME_MCP_CONFIG_DIR          Config directory"
    Write-Host "  CHROME_MCP_CREDENTIAL_TTL      Credential memory TTL in ms (default: 300000)"
}

# Main
if ($Help) {
    Show-Help
} elseif ($Uninstall) {
    Show-Banner
    Uninstall-Mcp
} elseif ($Check) {
    Show-Banner
    Show-Status
} elseif ($StartChrome) {
    Start-ChromeDebug | Out-Null
} elseif ($StopChrome) {
    Stop-ChromeDebug
} else {
    Invoke-Setup
}
