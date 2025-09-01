#!/usr/bin/env bash
# Atlassian (Local) MCP Server Wrapper (macOS / Linux)
# Securely launches the Sooperset Atlassian MCP server with API token from macOS Keychain or environment variables
# Startup order: container only (Docker-based MCP server)
# The upstream sooperset/mcp-atlassian only provides Docker container deployment
# Env overrides: MCP_ATLASSIAN_IMAGE/DOCKER_COMMAND
# Logging note: All diagnostics/info are sent to stderr on purpose. MCP clients require
# stdout to contain only JSON-RPC (and headers). Any human text on stdout can break init.

set -euo pipefail

SERVICE_NAME="atlassian-mcp"
ACCOUNT_NAME="token"
DOCKER_COMMAND="${DOCKER_COMMAND:-docker}"
export DOCKER_HOST="${DOCKER_HOST:-unix://$HOME/.colima/default/docker.sock}"
MCP_ATLASSIAN_IMAGE="${MCP_ATLASSIAN_IMAGE:-ghcr.io/sooperset/mcp-atlassian:latest}"
AUTH_METHOD="${AUTH_METHOD:-api_token}"
REMOTE_MCP_URL="https://mcp.atlassian.com/v1/sse"
# Note: sooperset/mcp-atlassian supports Docker containers with remote fallback via mcp-remote

# Keep stdout clean when npm/npx is used
export NO_COLOR=1
export NPM_CONFIG_LOGLEVEL=silent
export npm_config_loglevel=silent
export NPM_CONFIG_FUND=false
export NPM_CONFIG_AUDIT=false
export NO_UPDATE_NOTIFIER=1
export ADBLOCK=1

get_keychain_password() {
  if [[ "$(uname)" != "Darwin" ]]; then
    return 1
  fi
  security find-generic-password -s "$SERVICE_NAME" -a "$ACCOUNT_NAME" -w 2>/dev/null || return 1
}

get_keychain_domain() {
  if [[ "$(uname)" != "Darwin" ]]; then
    return 1
  fi
  security find-generic-password -s "$SERVICE_NAME" -a "domain" -w 2>/dev/null || return 1
}

get_keychain_email() {
  if [[ "$(uname)" != "Darwin" ]]; then
    return 1
  fi
  security find-generic-password -s "$SERVICE_NAME" -a "email" -w 2>/dev/null || return 1
}

check_docker_daemon() {
  if ! "$DOCKER_COMMAND" info &> /dev/null; then
    echo "Error: $DOCKER_COMMAND daemon is not running." >&2
    echo "Start it with: 'colima start' (macOS) or start your docker/Podman service before using this wrapper." >&2
    return 1
  fi
  return 0
}

use_remote_server() {
  echo "Falling back to remote Atlassian MCP server: $REMOTE_MCP_URL" >&2
  
  # Check if npx is available for mcp-remote
  if ! command -v npx >/dev/null 2>&1; then
    echo "Error: npx not found. Cannot use mcp-remote for remote server connection." >&2
    echo "Please install Node.js/npm or start Docker/Podman to use Atlassian MCP server." >&2
    exit 1
  fi
  
  # Use mcp-remote to bridge stdio to remote HTTP+SSE server with OAuth
  echo "Using mcp-remote to connect to remote Atlassian MCP server..." >&2
  
  # Set up environment for mcp-remote with authentication
  export ATLASSIAN_API_TOKEN="$API_TOKEN"
  export ATLASSIAN_DOMAIN="$ATLASSIAN_DOMAIN"
  export ATLASSIAN_EMAIL="$ATLASSIAN_EMAIL"
  
  # Use mcp-remote to connect to remote server with OAuth authentication
  # Let mcp-remote handle OAuth instead of passing API token headers
  # The remote server uses OAuth, not API tokens directly
  echo "Note: Remote server uses OAuth authentication, not API tokens." >&2
  echo "You may need to authorize in the browser that opens." >&2
  
  exec npx -y mcp-remote@latest "$REMOTE_MCP_URL" \
    --header "X-Atlassian-Domain:${ATLASSIAN_DOMAIN}" \
    --header "X-Atlassian-Email:${ATLASSIAN_EMAIL}" \
    "$@"
}


# Domain derivation with fallback hierarchy: env var -> keychain -> git email -> error
if [[ -z "${ATLASSIAN_DOMAIN:-}" ]]; then
  # Try keychain first (macOS only)
  if [[ "$(uname)" == "Darwin" ]]; then
    if KEYCHAIN_DOMAIN=$(get_keychain_domain) && [[ -n "$KEYCHAIN_DOMAIN" ]]; then
      ATLASSIAN_DOMAIN="$KEYCHAIN_DOMAIN"
      echo "Note: ATLASSIAN_DOMAIN retrieved from keychain as '${ATLASSIAN_DOMAIN}'." >&2
    fi
  fi
  
  # If still not set, try git email derivation
  if [[ -z "${ATLASSIAN_DOMAIN:-}" ]]; then
    GIT_EMAIL=""
    if command -v git >/dev/null 2>&1; then
      GIT_EMAIL="$(git config --get user.email 2>/dev/null || true)"
    fi
    if [[ -n "$GIT_EMAIL" && "$GIT_EMAIL" =~ @([^.]+)\.([^.]+) ]]; then
      # Extract organization from email (user@organization.domain -> organization.atlassian.net)
      ORG_DOMAIN="${GIT_EMAIL#*@}"
      ORG_NAME="${ORG_DOMAIN%%.*}"
      ATLASSIAN_DOMAIN="${ORG_NAME}.atlassian.net"
      echo "Note: ATLASSIAN_DOMAIN derived from git user.email as '${ATLASSIAN_DOMAIN}'." >&2
    else
      echo "Error: ATLASSIAN_DOMAIN must be set or derivable from git user.email." >&2
      echo "Example: export ATLASSIAN_DOMAIN='yourorg.atlassian.net'" >&2
      echo "Or configure git user.email with your organization email address." >&2
      echo "Or add to keychain: security add-generic-password -s '$SERVICE_NAME' -a 'domain' -w '<domain>'" >&2
      exit 1
    fi
  fi
fi

# Get API token from environment or keychain (for api_token auth method)
if [[ -n "${ATLASSIAN_API_TOKEN:-}" ]]; then
  API_TOKEN="$ATLASSIAN_API_TOKEN"
else
  if [[ "$(uname)" == "Darwin" ]]; then
    if ! API_TOKEN=$(get_keychain_password); then
      echo "Error: Could not retrieve Atlassian API token from Keychain (service '$SERVICE_NAME', account '$ACCOUNT_NAME')." >&2
      echo "Add it with: security add-generic-password -s '$SERVICE_NAME' -a '$ACCOUNT_NAME' -w" >&2
      echo "Or set environment variable: export ATLASSIAN_API_TOKEN='<api_token>'" >&2
      echo "Create API token at: https://id.atlassian.com/manage-profile/security/api-tokens" >&2
      exit 1
    fi
  else
    echo "Error: ATLASSIAN_API_TOKEN is not set and macOS Keychain is unavailable on this platform." >&2
    echo "Set environment variable: export ATLASSIAN_API_TOKEN='<api_token>'" >&2
    echo "Create API token at: https://id.atlassian.com/manage-profile/security/api-tokens" >&2
    exit 1
  fi
fi

# Derive email if not provided (prefer env var -> keychain -> git user.email)
if [[ -z "${ATLASSIAN_EMAIL:-}" ]]; then
  # Try keychain first (macOS only)
  if [[ "$(uname)" == "Darwin" ]]; then
    if KEYCHAIN_EMAIL=$(get_keychain_email) && [[ -n "$KEYCHAIN_EMAIL" ]]; then
      ATLASSIAN_EMAIL="$KEYCHAIN_EMAIL"
      echo "Note: ATLASSIAN_EMAIL retrieved from keychain as '${ATLASSIAN_EMAIL}'." >&2
    fi
  fi
  
  # If still not set, try git user.email
  if [[ -z "${ATLASSIAN_EMAIL:-}" ]]; then
    GIT_EMAIL=""
    if command -v git >/dev/null 2>&1; then
      GIT_EMAIL="$(git config --get user.email 2>/dev/null || true)"
    fi
    if [[ -n "$GIT_EMAIL" ]]; then
      ATLASSIAN_EMAIL="$GIT_EMAIL"
      echo "Note: ATLASSIAN_EMAIL derived from git user.email as '${ATLASSIAN_EMAIL}'." >&2
    fi
  fi
fi

# run_cli function removed - sooperset/mcp-atlassian only supports Docker containers

# Check if Docker is available
if ! command -v "$DOCKER_COMMAND" >/dev/null 2>&1; then
  echo "Error: Docker not found. Please install Docker or set DOCKER_COMMAND to point to your container runtime." >&2
  echo "Attempting to use remote server fallback..." >&2
  use_remote_server
fi

# Check if Docker daemon is running
if ! check_docker_daemon; then
  echo "Attempting to use remote server fallback..." >&2
  use_remote_server
fi

DOCKER_ENV_ARGS=(
  -e "NO_COLOR=1"
  -e "CONFLUENCE_URL=https://$ATLASSIAN_DOMAIN/wiki"
  -e "JIRA_URL=https://$ATLASSIAN_DOMAIN"
  -e "CONFLUENCE_USERNAME=${ATLASSIAN_EMAIL}"
  -e "CONFLUENCE_API_TOKEN=$API_TOKEN"
  -e "JIRA_USERNAME=${ATLASSIAN_EMAIL}"
  -e "JIRA_API_TOKEN=$API_TOKEN"
)

# Ensure image present (auto-pull if missing)
if ! "$DOCKER_COMMAND" image inspect "${MCP_ATLASSIAN_IMAGE}" >/dev/null 2>&1; then
  echo "Pulling Atlassian MCP Docker image: ${MCP_ATLASSIAN_IMAGE}" >&2
  if ! "$DOCKER_COMMAND" pull "${MCP_ATLASSIAN_IMAGE}" >&2; then
    echo "Error: failed to pull image: ${MCP_ATLASSIAN_IMAGE}" >&2
    echo "Attempting to use remote server fallback..." >&2
    use_remote_server
  fi
  echo "Pulled Atlassian MCP Docker image successfully: ${MCP_ATLASSIAN_IMAGE}" >&2
fi

echo "Using Atlassian MCP via container image: ${MCP_ATLASSIAN_IMAGE}" >&2
"$DOCKER_COMMAND" run --rm -i --pull=never \
  "${DOCKER_ENV_ARGS[@]}" \
  "$MCP_ATLASSIAN_IMAGE" \
  "$@" 2> >(cat >&2) | \
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
