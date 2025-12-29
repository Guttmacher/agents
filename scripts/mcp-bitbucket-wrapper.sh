#!/usr/bin/env bash
# Bitbucket MCP Server Wrapper (macOS / Linux)
# Securely launches the Bitbucket MCP server with Atlassian API token
# from macOS Keychain (macOS) or environment variables (fallback)
# Startup order: globally installed npm binary on PATH -> npx (no global install)
# No automatic npm -g installs to avoid interactive prompts in editors (VS Code, Claude Desktop).
# Env overrides: MCP_BITBUCKET_CLI_BIN, MCP_BITBUCKET_NPM_PKG
# Logging note: All diagnostics/info are sent to stderr intentionally. MCP clients expect
# stdout to be pure JSON-RPC; human-readable text on stdout can break initialization.

set -euo pipefail

SERVICE_NAME="bitbucket-mcp"
ACCOUNT_NAME="atlassian-api-token"

# Keep stdout clean when npm/npx is used
export NO_COLOR=1
export NPM_CONFIG_LOGLEVEL=silent
export npm_config_loglevel=silent
export NPM_CONFIG_FUND=false
export NPM_CONFIG_AUDIT=false
export NO_UPDATE_NOTIFIER=1
export ADBLOCK=1

get_keychain_token() {
  if [[ "$(uname)" != "Darwin" ]]; then
    return 1
  fi
  security find-generic-password -s "$SERVICE_NAME" -a "atlassian-api-token" -w 2>/dev/null || return 1
}

get_keychain_email() {
  if [[ "$(uname)" != "Darwin" ]]; then
    return 1
  fi
  security find-generic-password -s "$SERVICE_NAME" -a "email" -w 2>/dev/null || return 1
}

get_keychain_workspace() {
  if [[ "$(uname)" != "Darwin" ]]; then
    return 1
  fi
  security find-generic-password -s "$SERVICE_NAME" -a "workspace" -w 2>/dev/null || return 1
}

# Email derivation with fallback hierarchy: env var -> keychain -> git email
if [[ -z "${ATLASSIAN_USER_EMAIL:-}" ]]; then
  # Try keychain first (macOS only) - reuse username field for email
  if [[ "$(uname)" == "Darwin" ]]; then
    if KEYCHAIN_EMAIL=$(get_keychain_email) && [[ -n "$KEYCHAIN_EMAIL" ]]; then
      ATLASSIAN_USER_EMAIL="$KEYCHAIN_EMAIL"
      echo "Note: ATLASSIAN_USER_EMAIL retrieved from keychain as '${ATLASSIAN_USER_EMAIL}'." >&2
    fi
  fi

  # If still not set, try git email
  if [[ -z "${ATLASSIAN_USER_EMAIL:-}" ]]; then
    if command -v git >/dev/null 2>&1; then
      git_email="$(git config --get user.email 2>/dev/null || true)"
    else
      git_email=""
    fi
    if [[ -n "$git_email" ]]; then
      ATLASSIAN_USER_EMAIL="$git_email"
      echo "Note: Using Atlassian email '${ATLASSIAN_USER_EMAIL}' from git user.email. Set ATLASSIAN_USER_EMAIL to override." >&2
    else
      echo "Error: ATLASSIAN_USER_EMAIL is required for scoped API token authentication." >&2
      echo "Set it with: export ATLASSIAN_USER_EMAIL='your.email@company.com'" >&2
      exit 1
    fi
  fi
fi

# Get scoped API token from environment or keychain
if [[ -n "${ATLASSIAN_API_TOKEN:-}" ]]; then
  API_TOKEN="$ATLASSIAN_API_TOKEN"
else
  if [[ "$(uname)" == "Darwin" ]]; then
    if ! API_TOKEN=$(get_keychain_token); then
      echo "Error: Could not retrieve Atlassian API token from macOS login keychain (service '$SERVICE_NAME', account '$ACCOUNT_NAME')." >&2
      echo "Add it with: security add-generic-password -s '$SERVICE_NAME' -a 'atlassian-api-token' -w" >&2
      echo "Or set environment variable: export ATLASSIAN_API_TOKEN='<scoped_api_token>'" >&2
      exit 1
    fi
  else
    echo "Error: ATLASSIAN_API_TOKEN is not set and macOS Keychain is unavailable on this platform." >&2
    exit 1
  fi
fi

export ATLASSIAN_USER_EMAIL
export ATLASSIAN_API_TOKEN="${API_TOKEN}"
# BITBUCKET_DEFAULT_WORKSPACE with fallback hierarchy: env var -> keychain -> Bitbucket default
if [[ -z "${BITBUCKET_DEFAULT_WORKSPACE:-}" ]]; then
  # Try keychain first (macOS only)
  if [[ "$(uname)" == "Darwin" ]]; then
    if KEYCHAIN_WORKSPACE=$(get_keychain_workspace) && [[ -n "$KEYCHAIN_WORKSPACE" ]]; then
      BITBUCKET_DEFAULT_WORKSPACE="$KEYCHAIN_WORKSPACE"
      echo "Note: BITBUCKET_DEFAULT_WORKSPACE retrieved from keychain as '${BITBUCKET_DEFAULT_WORKSPACE}'." >&2
    fi
  fi
fi
if [[ -n "${BITBUCKET_DEFAULT_WORKSPACE:-}" ]]; then
  export BITBUCKET_DEFAULT_WORKSPACE
else
  unset BITBUCKET_DEFAULT_WORKSPACE
fi

# Defaults can be overridden via environment variables
NPM_PKG_NAME=${MCP_BITBUCKET_NPM_PKG:-@aashari/mcp-server-atlassian-bitbucket}
CLI_BIN_NAME=${MCP_BITBUCKET_CLI_BIN:-mcp-atlassian-bitbucket}
# Note: @aashari/mcp-server-atlassian-bitbucket only supports Node via npm/npx, no Docker

run_cli() {
  "${CLI_BIN_NAME}" "$@" 2> >(cat >&2) |
    awk 'BEGIN{IGNORECASE=1}
{
  if ($0 ~ /^[[:space:]]*Content-(Length|Type):/ || $0 ~ /^[[:space:]]*$/ || $0 ~ /^[[:space:]]*\{/ || $0 ~ /^[[:space:]]*\[[[:space:]]*(\"|\{|\[|[0-9-]|t|f|n|\])/) {
    print; fflush();
  } else {
    print $0 > "/dev/stderr"; fflush("/dev/stderr");
  }
}'
  exit ${PIPESTATUS[0]}
}

# 1) If an npm-installed binary is already available on PATH, run it.
if command -v "${CLI_BIN_NAME}" >/dev/null 2>&1; then
  echo "Using Bitbucket MCP via globally installed npm binary on PATH: ${CLI_BIN_NAME}" >&2
  run_cli "$@"
fi

# 2) Try npx as a fallback if available (no global install) as quietly as possible
if command -v npx >/dev/null 2>&1; then
  echo "Using Bitbucket MCP via npx package: ${NPM_PKG_NAME}@latest" >&2
  # Keep flags minimal to avoid incompatibilities across npx versions
  NPX_FLAGS=(-y)
  npx "${NPX_FLAGS[@]}" "${NPM_PKG_NAME}@latest" "$@" 2> >(cat >&2) |
    awk 'BEGIN{IGNORECASE=1; started=0; saw=0}
{
  if (started==0) {
    if ($0 ~ /^[[:space:]]*Content-(Length|Type):/) { print; fflush(); saw=1; next }
    if (saw && $0 ~ /^[[:space:]]*$/) { print; fflush(); started=1; next }
    if ($0 ~ /^[[:space:]]*\{/) { print; fflush(); started=1; next }
    if ($0 ~ /^[[:space:]]*\[[[:space:]]*(\"|\{|\[|[0-9-]|t|f|n|\])/) { print; fflush(); started=1; next }
    print $0 > "/dev/stderr"; fflush("/dev/stderr"); next
  }
  print; fflush();
}'
  exit ${PIPESTATUS[0]}
fi

# Docker fallback removed - @aashari/mcp-server-atlassian-bitbucket only supports Node via npm/npx

echo "Error: Bitbucket MCP npm-installed binary not found and no viable fallback (npx) available." >&2
exit 1
