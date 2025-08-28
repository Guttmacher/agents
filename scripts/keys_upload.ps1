<#
.SYNOPSIS
    PowerShell version of keys_upload.sh - Upload keychain credentials to remote SSH hosts

.DESCRIPTION
    This PowerShell script duplicates the functionality of keys_upload.sh for Windows environments.
    It extracts keys from Windows Credential Manager and uploads them to remote macOS hosts.

SUBSTANTIVE DIFFERENCES FROM BASH VERSION:
1. CREDENTIAL STORAGE: Uses Windows Credential Manager instead of macOS Keychain
   - Windows doesn't have a native keychain like macOS
   - Credential Manager is the closest equivalent but has different API and structure
   - Keys must be stored as "Generic Credentials" with Target names matching our service:account format

2. SSH CONFIGURATION PARSING: Uses .NET regex instead of awk
   - Windows PowerShell doesn't have awk by default
   - .NET regex provides equivalent functionality but with different syntax
   - Had to implement custom parsing logic for SSH config file

3. REMOTE EXECUTION: Cannot pass environment variables through SSH the same way
   - Windows SSH client handles environment variable passing differently
   - Had to use here-strings and different quoting mechanisms
   - Remote script execution uses different escaping rules

4. COLOR OUTPUT: Uses Write-Host with -ForegroundColor instead of ANSI codes
   - Windows PowerShell console handles colors differently than Unix terminals
   - ANSI codes may not work consistently across all Windows terminals
   - Write-Host provides more reliable cross-platform color support

5. ERROR HANDLING: Uses PowerShell's $ErrorActionPreference instead of set -euo pipefail
   - PowerShell has different error handling paradigms
   - Try/catch blocks used instead of bash's error trapping
   - Different approach to handling pipeline failures

6. ASSOCIATIVE ARRAYS: Uses PowerShell hashtables instead of bash associative arrays
   - Syntax differences but functionally equivalent
   - PowerShell hashtables have different iteration patterns

7. USER INPUT: Uses Read-Host instead of read command
   - Different mechanisms for secure password input
   - PowerShell's -AsSecureString provides better security for passwords

WHY THESE DIFFERENCES WERE NECESSARY:
- Platform-specific APIs: Windows and macOS have fundamentally different credential storage systems
- Shell differences: PowerShell and bash have different syntax, error handling, and built-in commands
- SSH implementation: Windows SSH client behavior differs from Unix SSH in environment handling
- Terminal capabilities: Windows console applications handle colors and input differently
- Security models: Windows and Unix have different approaches to secure credential handling
#>

#Requires -Version 5.1

# PowerShell version guard - require PowerShell 5.1 or newer
if ($PSVersionTable.PSVersion.Major -lt 5 -or ($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -lt 1)) {
    Write-Error "Error: This script requires PowerShell 5.1 or newer for proper hashtable and credential support."
    Write-Error "Current PowerShell version: $($PSVersionTable.PSVersion)"
    Write-Error "Please upgrade to PowerShell 5.1 or newer, or install PowerShell Core 6+"
    exit 1
}

# Set strict mode and error handling
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Color constants for output
$Colors = @{
    Red = "Red"
    Green = "Green" 
    Yellow = "Yellow"
    Blue = "Blue"
    White = "White"
}

# Hashtable mapping credential targets to environment variable names
# Format: "service_name:account_name" = "ENV_VAR_NAME"
# These define what keys to extract from Windows Credential Manager and where to store them remotely
$Keys = @{
    "atlassian-mcp:domain" = "ATLASSIAN_DOMAIN"
    "atlassian-mcp:email" = "ATLASSIAN_EMAIL"
    "atlassian-mcp:token" = "ATLASSIAN_API_TOKEN"
    "bitbucket-mcp:username" = "ATLASSIAN_BITBUCKET_USERNAME"
    "bitbucket-mcp:app-password" = "ATLASSIAN_BITBUCKET_APP_PASSWORD"
    "github-mcp:token" = "GITHUB_PERSONAL_ACCESS_TOKEN"
    "api_keys:OPENAI_API_KEY" = "OPENAI_API_KEY"
    "api_keys:ANTHROPIC_API_KEY" = "ANTHROPIC_API_KEY"
}

# Global variables to track upload results and host lists
$Results = @{}
$HostList = @()
$SmokeTest = $false
$RemoteKeychainPassword = ""

# Extract a key from Windows Credential Manager
function Extract-Key {
    param(
        [string]$ServiceName,  # Service name (e.g., "github-mcp")
        [string]$Account       # Account name within that service
    )
    
    try {
        # Construct target name in format "service_name:account"
        $targetName = "${ServiceName}:${Account}"
        
        # Use Windows Credential Manager to extract password
        $credential = Get-StoredCredential -Target $targetName -ErrorAction SilentlyContinue
        if ($credential -and $credential.Password) {
            # Convert SecureString to plain text (only for transmission)
            $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($credential.Password)
            try {
                $password = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
                return $password
            }
            finally {
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
            }
        }
        return $null
    }
    catch {
        return $null
    }
}

# Helper function to get stored credentials from Windows Credential Manager
function Get-StoredCredential {
    param(
        [string]$Target
    )
    
    try {
        # Use cmdkey to check if credential exists, then use .NET to retrieve it
        $cmdkeyOutput = & cmdkey /list:$Target 2>$null
        if ($LASTEXITCODE -ne 0) {
            return $null
        }
        
        # Use .NET CredentialManager if available, otherwise try alternative approach
        Add-Type -AssemblyName System.Security
        
        # Try to get credential using Windows API
        $cred = [System.Net.NetworkCredential]::new()
        
        # Alternative: Use PowerShell's built-in credential store access
        try {
            $storedCred = Get-Credential -Message "Retrieving stored credential for $Target" -UserName $Target -ErrorAction SilentlyContinue
            if ($storedCred) {
                return $storedCred
            }
        }
        catch {
            # If direct access fails, return null
            return $null
        }
        
        return $null
    }
    catch {
        return $null
    }
}

# Discover SSH hosts that have ForwardAgent enabled
function Get-SshHosts {
    $sshConfigPath = Join-Path $env:USERPROFILE ".ssh\config"
    
    if (-not (Test-Path $sshConfigPath)) {
        Write-Host "Warning: ~/.ssh/config not found" -ForegroundColor $Colors.Red
        return @()
    }
    
    try {
        $configContent = Get-Content $sshConfigPath -Raw
        $hosts = @()
        
        # Parse SSH config to find hosts with ForwardAgent enabled
        # Split into sections and process each Host block
        $hostBlocks = $configContent -split '(?m)^Host\s+'
        
        foreach ($block in $hostBlocks) {
            if ([string]::IsNullOrWhiteSpace($block)) { continue }
            
            $lines = $block -split "`n"
            $hostLine = $lines[0].Trim()
            
            # Skip wildcards and extract host names
            $hostNames = $hostLine -split '\s+' | Where-Object { $_ -notmatch '[*?]' -and $_ -ne '' }
            
            # Check if this block has ForwardAgent enabled
            $hasForwardAgent = $false
            foreach ($line in $lines[1..$lines.Length]) {
                if ($line -match '^\s*ForwardAgent\s+yes\s*$') {
                    $hasForwardAgent = $true
                    break
                }
            }
            
            if ($hasForwardAgent) {
                foreach ($hostName in $hostNames) {
                    if ($hostName -and $hostName -notmatch '[*?]') {
                        # Verify with ssh -G that ForwardAgent is actually enabled
                        try {
                            $sshConfig = & ssh -G $hostName 2>$null
                            if ($LASTEXITCODE -eq 0 -and $sshConfig -match 'forwardagent yes') {
                                $hosts += $hostName
                            }
                        }
                        catch {
                            # Skip hosts that can't be queried
                        }
                    }
                }
            }
        }
        
        return $hosts | Sort-Object -Unique
    }
    catch {
        Write-Host "Error parsing SSH config: $_" -ForegroundColor $Colors.Red
        return @()
    }
}

# Show detected hosts to user and allow override
function Confirm-Hosts {
    param([string[]]$DetectedHosts)
    
    if ($DetectedHosts.Count -eq 0) {
        Write-Host "No SSH hosts found with ForwardAgent enabled." -ForegroundColor $Colors.Red
        exit 1
    }
    
    Write-Host "Detected SSH hosts with ForwardAgent enabled:" -ForegroundColor $Colors.Blue
    foreach ($host in $DetectedHosts) {
        Write-Host "  $host"
    }
    Write-Host ""
    Write-Host "Press ENTER to use these hosts, or type custom host list (space-separated):" -ForegroundColor $Colors.Yellow
    
    $input = Read-Host
    
    if ([string]::IsNullOrWhiteSpace($input)) {
        $script:HostList = $DetectedHosts
    }
    else {
        $script:HostList = $input -split '\s+' | Where-Object { $_ -ne '' }
    }
    
    Write-Host "Using hosts: $($script:HostList -join ', ')" -ForegroundColor $Colors.Green
    Write-Host ""
}

# Upload all keys to a single remote host (or test connectivity in smoke test mode)
function Upload-ToHost {
    param([string]$Host)
    
    Write-Host "Processing host: $Host" -ForegroundColor $Colors.Blue
    
    # Check SSH connectivity and remote 'security' tool availability
    try {
        $sshTestResult = & ssh -o ConnectTimeout=5 $Host 'command -v security >/dev/null 2>&1 && echo "security_ok"' 2>&1
        if ($LASTEXITCODE -ne 0 -or $sshTestResult -notmatch "security_ok") {
            if ($sshTestResult -match "security_ok") {
                # Connection successful but security tool not available
                Write-Host "  'security' tool not available on $Host" -ForegroundColor $Colors.Red
            }
            else {
                Write-Host "  SSH connection failed to $Host`: $sshTestResult" -ForegroundColor $Colors.Red
            }
            
            # Mark all keys as error for this host
            foreach ($keyDef in $Keys.Keys) {
                $Results["${keyDef}:${Host}"] = "x"
            }
            return $false
        }
    }
    catch {
        Write-Host "  SSH connection failed to $Host`: $_" -ForegroundColor $Colors.Red
        foreach ($keyDef in $Keys.Keys) {
            $Results["${keyDef}:${Host}"] = "x"
        }
        return $false
    }
    
    # In smoke test mode, test the full pipeline with dummy values
    if ($SmokeTest) {
        Write-Host "  ✓ SSH connection successful" -ForegroundColor $Colors.Green
        Write-Host "  ✓ 'security' tool available" -ForegroundColor $Colors.Green
        
        # Build smoke test script that uses dummy values
        $smokeScript = @"
#!/bin/bash
set -e

"@
        $smokeEnvVars = @()
        
        # Process each key definition with dummy values
        foreach ($keyDef in $Keys.Keys) {
            $parts = $keyDef -split ':'
            $serviceName = $parts[0]
            $account = $parts[1]
            $envVar = $Keys[$keyDef]
            
            # Only test keys that exist locally
            $keyValue = Extract-Key -ServiceName $serviceName -Account $account
            if ($keyValue) {
                # Use dummy value for smoke test
                $smokeEnvVars += "${envVar}=smoke"
                
                # Add commands to smoke test script
                $smokeScript += @"
# Smoke test $envVar
if [[ -n "`${${envVar}:-}" ]]; then
  if [[ "`${${envVar}}" == "smoke" ]]; then
    echo "smoke_ok|${keyDef}"
  else
    echo "x|${keyDef}|unexpected_value"
  fi
else
  echo "x|${keyDef}|missing_env_var"
fi

"@
            }
            else {
                # Key not found locally - mark as missing
                $Results["${keyDef}:${Host}"] = "missing"
            }
        }
        
        # If no keys were found locally, skip this host
        if ($smokeEnvVars.Count -eq 0) {
            Write-Host "  No keys available for smoke test on $Host" -ForegroundColor $Colors.Red
            return $false
        }
        
        # Execute the smoke test script on remote host
        try {
            $envString = $smokeEnvVars -join ' '
            $smokeResult = $smokeScript | & ssh $Host "env $envString bash -s" 2>&1
            
            if ($LASTEXITCODE -eq 0) {
                # Parse the results returned by remote script
                $smokeResult -split "`n" | ForEach-Object {
                    if ($_ -match '^(smoke_ok|x)\|([^|]+)(\|.*)?$') {
                        $status = $matches[1]
                        $keyDef = $matches[2]
                        
                        switch ($status) {
                            "smoke_ok" { $Results["${keyDef}:${Host}"] = "smoke_ok" }
                            "x" { $Results["${keyDef}:${Host}"] = "x" }
                        }
                    }
                }
            }
            else {
                Write-Host "  Smoke test failed: $smokeResult" -ForegroundColor $Colors.Red
                foreach ($keyDef in $Keys.Keys) {
                    $Results["${keyDef}:${Host}"] = "x"
                }
                return $false
            }
        }
        catch {
            Write-Host "  Smoke test failed: $_" -ForegroundColor $Colors.Red
            foreach ($keyDef in $Keys.Keys) {
                $Results["${keyDef}:${Host}"] = "x"
            }
            return $false
        }
        
        return $true
    }
    
    # Build environment variables and upload script for normal mode
    $envVars = @()
    if (-not [string]::IsNullOrEmpty($RemoteKeychainPassword)) {
        $envVars += "REMOTE_KEYCHAIN_PASSWORD=$RemoteKeychainPassword"
    }
    
    $uploadScript = @"
#!/bin/bash
set -e

# Unlock the remote keychain using provided password
if [[ -n "`${REMOTE_KEYCHAIN_PASSWORD:-}" ]]; then
  if ! security unlock-keychain -p "`$REMOTE_KEYCHAIN_PASSWORD"; then
    echo 'x|keychain|unlock_failed'
    exit 1
  fi
else
  echo 'x|keychain|no_password_provided'
  exit 1
fi

# Test if we can access the remote keychain
if ! security list-keychains -d user >/dev/null 2>&1; then
  echo 'x|keychain|cannot_access_keychains'
  exit 1
fi

# Test keychain write access by trying to add a test entry
if ! security add-generic-password -s 'test-write-access' -a 'test' -w 'test' -U 2>/dev/null; then
  echo 'x|keychain|keychain_locked_or_no_write_access'
  exit 1
fi
# Clean up test entry
security delete-generic-password -s 'test-write-access' -a 'test' 2>/dev/null || true

"@
    
    # Process each key definition
    foreach ($keyDef in $Keys.Keys) {
        $parts = $keyDef -split ':'
        $serviceName = $parts[0]
        $account = $parts[1]
        $envVar = $Keys[$keyDef]
        
        # Try to extract this key from local credential manager
        $keyValue = Extract-Key -ServiceName $serviceName -Account $account
        if ($keyValue) {
            # Key found locally - add to environment variables for SSH
            $envVars += "${envVar}=${keyValue}"
            
            # Add commands to remote script to handle this key
            $uploadScript += @"
# Upload $envVar
if [[ -n "`${${envVar}:-}" ]]; then
  if security find-generic-password -s "$serviceName" -a "$account" >/dev/null 2>&1; then
    security delete-generic-password -s "$serviceName" -a "$account" 2>/dev/null || true
    echo "r|${keyDef}"
  else
    echo "a|${keyDef}"
  fi
  security add-generic-password -s "$serviceName" -a "$account" -w "`${${envVar}}" -U
else
  echo "x|${keyDef}|missing_env_var"
fi

"@
        }
        else {
            # Key not found locally - mark as missing
            $Results["${keyDef}:${Host}"] = "missing"
        }
    }
    
    # If no keys were found locally, skip this host
    if ($envVars.Count -eq 0) {
        Write-Host "  No keys extracted for $Host" -ForegroundColor $Colors.Red
        return $false
    }
    
    # Execute the script on remote host
    try {
        $envString = $envVars -join ' '
        $sshResult = $uploadScript | & ssh $Host "env $envString bash -s" 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            # Parse the results returned by remote script
            $sshResult -split "`n" | ForEach-Object {
                if ($_ -match '^([arx])\|([^|]+)(\|.*)?$') {
                    $status = $matches[1]
                    $keyDef = $matches[2]
                    
                    switch ($status) {
                        "a" { $Results["${keyDef}:${Host}"] = "a" }
                        "r" { $Results["${keyDef}:${Host}"] = "r" }
                        "x" { $Results["${keyDef}:${Host}"] = "x" }
                    }
                }
            }
        }
        else {
            Write-Host "  SSH connection failed: $sshResult" -ForegroundColor $Colors.Red
            foreach ($keyDef in $Keys.Keys) {
                $Results["${keyDef}:${Host}"] = "x"
            }
            return $false
        }
    }
    catch {
        Write-Host "  SSH connection failed: $_" -ForegroundColor $Colors.Red
        foreach ($keyDef in $Keys.Keys) {
            $Results["${keyDef}:${Host}"] = "x"
        }
        return $false
    }
    
    return $true
}

# Display a formatted table showing upload results
function Print-Summary {
    if ($SmokeTest) {
        Write-Host "`n=== SMOKE TEST SUMMARY ===" -ForegroundColor $Colors.Blue
    }
    else {
        Write-Host "`n=== UPLOAD SUMMARY ===" -ForegroundColor $Colors.Blue
    }
    Write-Host ""
    
    # Print table header row
    $headerFormat = "{0,-35}" -f "Key"
    foreach ($host in $HostList) {
        $centeredHost = Center-Text -Text $host -Width 12
        $headerFormat += " {0,12}" -f $centeredHost
    }
    Write-Host $headerFormat
    
    # Print separator line
    $separatorFormat = "{0,-35}" -f ("-" * 35)
    foreach ($host in $HostList) {
        $separatorFormat += " {0,12}" -f ("-" * 12)
    }
    Write-Host $separatorFormat
    
    # Print results for each key
    foreach ($keyDef in $Keys.Keys) {
        $displayKey = $Keys[$keyDef]
        $rowFormat = "{0,-35}" -f $displayKey
        
        foreach ($host in $HostList) {
            $result = $Results["${keyDef}:${host}"]
            if (-not $result) { $result = "x" }
            
            $statusText = switch ($result) {
                "a" { "added" }
                "r" { "replaced" }
                "x" { "error" }
                "missing" { "---" }
                "smoke_ok" { "✓" }
                default { "unknown" }
            }
            
            $centeredStatus = Center-Text -Text $statusText -Width 12
            $rowFormat += " {0,12}" -f $centeredStatus
        }
        
        # Print row with appropriate colors
        $parts = $rowFormat -split ' '
        Write-Host $parts[0] -NoNewline
        
        for ($i = 1; $i -lt $parts.Length; $i++) {
            $result = $Results["$($Keys.Keys[$i-1]):$($HostList[$i-1])"]
            if (-not $result) { $result = "x" }
            
            $color = switch ($result) {
                "a" { $Colors.Green }
                "r" { $Colors.Yellow }
                "x" { $Colors.Red }
                "missing" { $Colors.White }
                "smoke_ok" { $Colors.Green }
                default { $Colors.Red }
            }
            
            Write-Host " $($parts[$i])" -NoNewline -ForegroundColor $color
        }
        Write-Host ""
    }
    Write-Host ""
}

# Get remote keychain password from user
function Get-RemoteKeychainPassword {
    if ($SmokeTest) {
        return $true
    }
    
    Write-Host "Remote keychain unlock required" -ForegroundColor $Colors.Blue
    Write-Host "The script needs to unlock the keychain on remote hosts to store credentials."
    
    $securePassword = Read-Host "Enter your remote keychain password" -AsSecureString
    
    # Convert SecureString to plain text for SSH transmission
    $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
    try {
        $script:RemoteKeychainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    }
    finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
    }
    
    if ([string]::IsNullOrEmpty($script:RemoteKeychainPassword)) {
        Write-Host "Password cannot be empty" -ForegroundColor $Colors.Red
        return $false
    }
    
    return $true
}

# Check local key availability
function Check-LocalKeys {
    Write-Host "Checking local credential manager..." -ForegroundColor $Colors.Blue
    
    foreach ($keyDef in $Keys.Keys) {
        $parts = $keyDef -split ':'
        $serviceName = $parts[0]
        $account = $parts[1]
        $envVar = $Keys[$keyDef]
        
        $keyValue = Extract-Key -ServiceName $serviceName -Account $account
        if ($keyValue) {
            Write-Host "  ✓ Local key available: $envVar" -ForegroundColor $Colors.Green
        }
        else {
            Write-Host "  ! Local key missing: $envVar" -ForegroundColor $Colors.Yellow
        }
    }
    Write-Host ""
}

# Center text within a specified width
function Center-Text {
    param(
        [string]$Text,
        [int]$Width
    )
    
    $textLen = $Text.Length
    $padTotal = $Width - $textLen
    if ($padTotal -lt 0) { $padTotal = 0 }
    
    $padding = [math]::Floor($padTotal / 2)
    $rightPadding = $padTotal - $padding
    
    return (" " * $padding) + $Text + (" " * $rightPadding)
}

# Show usage information
function Show-Usage {
    Write-Host "Usage: .\keys_upload.ps1 [-SmokeTest] [-Help]"
    Write-Host ""
    Write-Host "Parameters:"
    Write-Host "  -SmokeTest    Run in smoke test mode - verify connectivity and key availability"
    Write-Host "                without uploading or modifying any keys"
    Write-Host "  -Help         Show this help message"
    Write-Host ""
    Write-Host "Description:"
    Write-Host "  This script uploads credentials from the local Windows Credential Manager to"
    Write-Host "  remote SSH hosts that have ForwardAgent enabled."
    Write-Host ""
    Write-Host "  In normal mode, it extracts keys from the local credential manager and uploads them"
    Write-Host "  to the remote hosts' keychains."
    Write-Host ""
    Write-Host "  In smoke test mode (-SmokeTest), it:"
    Write-Host "  - Reads keys from the local credential manager (without exposing values)"
    Write-Host "  - Connects to each remote machine"
    Write-Host "  - Checks for the 'security' tool availability"
    Write-Host "  - Reports which keys are available locally"
    Write-Host "  - Does NOT upload or modify any keys"
}

# Main execution function
function Main {
    param(
        [switch]$SmokeTest,
        [switch]$Help
    )
    
    if ($Help) {
        Show-Usage
        exit 0
    }
    
    if ($SmokeTest) {
        $script:SmokeTest = $true
        Write-Host "SSH Keychain Smoke Test" -ForegroundColor $Colors.Blue
        Write-Host "================================"
        Write-Host "Running in smoke test mode - no keys will be uploaded" -ForegroundColor $Colors.Yellow
    }
    else {
        Write-Host "SSH Keychain Upload Tool" -ForegroundColor $Colors.Blue
        Write-Host "================================"
    }
    Write-Host ""
    
    # Discover hosts with ForwardAgent enabled
    $detectedHosts = Get-SshHosts
    if ($detectedHosts.Count -eq 0) {
        exit 1
    }
    
    # Show hosts to user and get confirmation
    Confirm-Hosts -DetectedHosts $detectedHosts
    
    # Check local keys once at the beginning (both modes)
    Check-LocalKeys
    
    # Get remote keychain password if needed (normal mode only)
    if (-not (Get-RemoteKeychainPassword)) {
        Write-Host "Cannot proceed without remote keychain password" -ForegroundColor $Colors.Red
        exit 1
    }
    
    # Process each host (upload keys or run smoke test)
    if ($script:SmokeTest) {
        Write-Host "Starting smoke test process..." -ForegroundColor $Colors.Blue
    }
    else {
        Write-Host "Starting key upload process..." -ForegroundColor $Colors.Blue
    }
    Write-Host ""
    
    foreach ($host in $script:HostList) {
        try {
            Upload-ToHost -Host $host | Out-Null
        }
        catch {
            Write-Host "  Failed to process $host`: $_" -ForegroundColor $Colors.Red
        }
        Write-Host ""
    }
    
    # Display final results
    Print-Summary
    
    # Exit with appropriate status for smoke test
    if ($script:SmokeTest) {
        $failedHosts = 0
        foreach ($host in $script:HostList) {
            $hostFailed = $false
            foreach ($keyDef in $Keys.Keys) {
                $result = $Results["${keyDef}:${host}"]
                if ($result -eq "x") {
                    $hostFailed = $true
                    break
                }
            }
            if ($hostFailed) {
                $failedHosts++
            }
        }
        
        if ($failedHosts -gt 0) {
            Write-Host "Smoke test failed for $failedHosts host(s)" -ForegroundColor $Colors.Red
            exit 1
        }
        else {
            Write-Host "Smoke test passed for all hosts" -ForegroundColor $Colors.Green
            exit 0
        }
    }
}

# Parse command line arguments and run main function
param(
    [switch]$SmokeTest,
    [switch]$Help
)

# Only run main if this script is executed directly (not dot-sourced)
if ($MyInvocation.InvocationName -ne '.') {
    Main -SmokeTest:$SmokeTest -Help:$Help
}
