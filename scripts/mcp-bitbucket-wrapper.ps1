<#!
.SYNOPSIS
  Bitbucket MCP Server Wrapper (Windows PowerShell)
.DESCRIPTION
  Securely launches the Bitbucket MCP server using scoped API token from Windows Credential Manager.
  Email is provided via environment variable or credential manager.

  Create Generic Credential for API token:
    Control Panel > User Accounts > Credential Manager > Windows Credentials > Add a generic credential
      Internet or network address: bitbucket-mcp
      User name: atlassian-api-token
      Password: <your Atlassian scoped API token>

  Create Generic Credential for email (optional):
    Control Panel > User Accounts > Credential Manager > Windows Credentials > Add a generic credential
      Internet or network address: bitbucket-mcp
      User name: email
      Password: <your Atlassian email>

  Or via PowerShell:
    cmd /c "cmdkey /add:bitbucket-mcp /user:atlassian-api-token /pass:<api_token>"
    cmd /c "cmdkey /add:bitbucket-mcp /user:email /pass:<your_email>"

.PARAMETER Args
  Additional arguments passed through to the MCP server process.
#>
Param([Parameter(ValueFromRemainingArguments=$true)] [string[]]$Args)
# Startup order: globally installed npm binary on PATH -> npx (no global install)
# No automatic npm -g installs to avoid interactive prompts in editors (VS Code, Claude Desktop).
# Env overrides: MCP_BITBUCKET_CLI_BIN, MCP_BITBUCKET_NPM_PKG
# Logging note: Diagnostics go to stderr intentionally to keep stdout JSON-only for MCP.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-StoredPassword {
  param([string]$Target)
  
  # Check if credential exists
  $listing = cmd /c "cmdkey /list" 2>$null
  if (-not $listing -or $listing -notmatch $Target) {
    throw "Credential '$Target' not found in Windows Credential Manager."
  }
  
  # Need CredentialManager module to read the credential
  try {
    if (-not (Get-Module -ListAvailable -Name CredentialManager)) { 
      Import-Module CredentialManager -ErrorAction Stop 
    }
    $cred = Get-StoredCredential -Target $Target
    if (-not $cred) { 
      throw "Stored credential not accessible via CredentialManager module" 
    }
    return $cred.Password
  } catch {
    throw "Unable to read credential for '$Target'. Install CredentialManager module: Install-Module CredentialManager -Scope CurrentUser"
  }
}

function Get-StoredEmail {
  try {
    # Check if credential exists
    $listing = cmd /c "cmdkey /list" 2>$null
    if (-not $listing -or $listing -notmatch 'bitbucket-mcp') {
      return $null
    }

    # Need CredentialManager module to read the credential
    if (-not (Get-Module -ListAvailable -Name CredentialManager)) {
      Import-Module CredentialManager -ErrorAction Stop
    }

    $cred = Get-StoredCredential -Target 'bitbucket-mcp'
    if ($cred -and $cred.UserName -eq 'email' -and $cred.Password) {
      return $cred.Password
    }
    return $null
  } catch {
    return $null
  }
}

function Get-StoredWorkspace {
  try {
    # Check if credential exists
    $listing = cmd /c "cmdkey /list" 2>$null
    if (-not $listing -or $listing -notmatch 'bitbucket-mcp') {
      return $null
    }

    # Need CredentialManager module to read the credential
    if (-not (Get-Module -ListAvailable -Name CredentialManager)) {
      Import-Module CredentialManager -ErrorAction Stop
    }

    $cred = Get-StoredCredential -Target 'bitbucket-mcp'
    if ($cred -and $cred.UserName -eq 'workspace' -and $cred.Password) {
      return $cred.Password
    }
    return $null
  } catch {
    return $null
  }
}

# BITBUCKET_DEFAULT_WORKSPACE with fallback hierarchy: env var -> credential manager -> Bitbucket default
if (-not $env:BITBUCKET_DEFAULT_WORKSPACE) {
  # Try credential manager first
  $credentialWorkspace = Get-StoredWorkspace
  if ($credentialWorkspace) {
    $env:BITBUCKET_DEFAULT_WORKSPACE = $credentialWorkspace
    [Console]::Error.WriteLine("Note: BITBUCKET_DEFAULT_WORKSPACE retrieved from credential manager as '$($env:BITBUCKET_DEFAULT_WORKSPACE)'.")
  }
}

# Email derivation with fallback hierarchy: env var -> credential manager -> git email
if (-not $env:ATLASSIAN_USER_EMAIL) {
  # Try credential manager first
  $credentialEmail = Get-StoredEmail
  if ($credentialEmail) {
    $env:ATLASSIAN_USER_EMAIL = $credentialEmail
    [Console]::Error.WriteLine("Note: ATLASSIAN_USER_EMAIL retrieved from credential manager as '$($env:ATLASSIAN_USER_EMAIL)'.")
  } else {
    # If still not set, try git email
    $gitEmail = $null
    if (Get-Command git -ErrorAction SilentlyContinue) {
      try {
        $gitEmail = (git config --get user.email 2>$null).Trim()
      } catch {}
    }
    if ($gitEmail) {
      $env:ATLASSIAN_USER_EMAIL = $gitEmail
      [Console]::Error.WriteLine("Note: Using Atlassian email '$($env:ATLASSIAN_USER_EMAIL)' from git user.email. Set ATLASSIAN_USER_EMAIL to override.")
    } else {
      Write-Error "ATLASSIAN_USER_EMAIL is required for scoped API token authentication. Set it with: `$env:ATLASSIAN_USER_EMAIL='your.email@company.com'"
      exit 1
    }
  }
}

# Get scoped API token from environment or credential manager
if ($env:ATLASSIAN_API_TOKEN) {
  $apiToken = $env:ATLASSIAN_API_TOKEN
} else {
  try {
    $apiToken = Get-StoredPassword -Target 'bitbucket-mcp'
  } catch {
    Write-Error "Could not retrieve Atlassian API token. Either set environment variable ATLASSIAN_API_TOKEN or create credential 'bitbucket-mcp' with user 'atlassian-api-token' in Windows Credential Manager."
    exit 1
  }
}

$env:ATLASSIAN_API_TOKEN = $apiToken

# Prefer npm-installed CLI; fallback to npx
$CLI_BIN = $env:MCP_BITBUCKET_CLI_BIN; if (-not $CLI_BIN) { $CLI_BIN = 'mcp-atlassian-bitbucket' }
$NPM_PKG = $env:MCP_BITBUCKET_NPM_PKG; if (-not $NPM_PKG) { $NPM_PKG = '@aashari/mcp-server-atlassian-bitbucket' }
# Note: @aashari/mcp-server-atlassian-bitbucket only supports Node via npm/npx, no Docker

function Invoke-Exec { param([string]$File,[string[]]$Arguments) & $File @Arguments; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE } }

if (Get-Command $CLI_BIN -ErrorAction SilentlyContinue) {
  [Console]::Error.WriteLine("Using Bitbucket MCP via globally installed npm binary on PATH: $CLI_BIN")
  $env:NO_COLOR = '1'
  & $CLI_BIN @Args | ForEach-Object { if ($_ -match '^\s*$' -or $_ -match '^(?i)\s*Content-(Length|Type):' -or $_ -match '^\s*\{' -or $_ -match '^\s*\[\s*(\"|\{|\[|[0-9-]|t|f|n|\])') { $_ } else { [Console]::Error.WriteLine($_) } }
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

if (Get-Command npx -ErrorAction SilentlyContinue) {
  [Console]::Error.WriteLine("Using Bitbucket MCP via npx package: $NPM_PKG@latest")
  $env:NO_COLOR = '1'
  $env:NPM_CONFIG_LOGLEVEL = 'silent'
  $env:NPM_CONFIG_FUND = 'false'
  $env:NPM_CONFIG_AUDIT = 'false'
  $env:NO_UPDATE_NOTIFIER = '1'
  $env:ADBLOCK = '1'
  $npxArgs = @('-y', "$NPM_PKG@latest")
  & 'npx' @($npxArgs + $Args) | ForEach-Object { if ($_ -match '^\s*$' -or $_ -match '^(?i)\s*Content-(Length|Type):' -or $_ -match '^\s*\{' -or $_ -match '^\s*\[\s*(\"|\{|\[|[0-9-]|t|f|n|\])') { $_ } else { [Console]::Error.WriteLine($_) } }
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

# Docker fallback removed - @aashari/mcp-server-atlassian-bitbucket only supports Node via npm/npx

Write-Error 'Bitbucket MCP npm-installed binary not found and no viable fallback (npx) available.'
exit 1
