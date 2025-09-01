#!/usr/bin/env bash
# GitHub MCP Server wrapper - Docker version
# Uses the official GitHub MCP server Docker image
# Env overrides: MCP_GITHUB_DOCKER_IMAGE, DOCKER_COMMAND
# Logging note: We write diagnostics/info to stderr so stdout remains JSON-only for MCP.
# Any banner/progress on stdout can break the JSON-RPC initialize handshake.
set -euo pipefail

# --- Configurable defaults ---
SERVICE_NAME="github-mcp"
ACCOUNT_NAME="token"
DOCKER_COMMAND="${DOCKER_COMMAND:-docker}"
export DOCKER_HOST="${DOCKER_HOST:-unix://$HOME/.colima/default/docker.sock}"
DOCKER_IMAGE="${MCP_GITHUB_DOCKER_IMAGE:-ghcr.io/github/github-mcp-server:latest}"
REMOTE_MCP_URL="https://api.githubcopilot.com/mcp/"

# --- Helper Functions ---
check_docker_daemon() {
  if ! "$DOCKER_COMMAND" info &> /dev/null; then
    echo "Error: Docker daemon ('$DOCKER_COMMAND') is not running." >&2
    echo "Please start your container runtime (e.g., 'colima start')." >&2
    return 1
  fi
}

use_remote_server() {
  echo "Falling back to remote GitHub MCP server: $REMOTE_MCP_URL" >&2
  
  # Check if npx is available for mcp-remote
  if ! command -v npx >/dev/null 2>&1; then
    echo "Error: npx not found. Cannot use mcp-remote for remote server connection." >&2
    echo "Please install Node.js/npm or start Docker/Podman to use GitHub MCP server." >&2
    exit 1
  fi
  
  # Use mcp-remote to bridge stdio to remote HTTP+SSE server with OAuth
  echo "Using mcp-remote to connect to remote GitHub MCP server..." >&2
  
  # Set up environment for mcp-remote with authentication
  export GITHUB_PERSONAL_ACCESS_TOKEN="$GITHUB_TOKEN"
  
  # Use mcp-remote to connect with proper headers for GitHub authentication
  # The Authorization header will use the GitHub token
  exec npx -y mcp-remote@latest "$REMOTE_MCP_URL" \
    --header "Authorization:Bearer ${GITHUB_TOKEN}" \
    "$@"
}


# --- Main Logic ---

# 1. Obtain GitHub Token (prefer env var, fallback to macOS Keychain)
GITHUB_TOKEN="${GITHUB_PERSONAL_ACCESS_TOKEN:-}"
if [ -z "${GITHUB_TOKEN}" ]; then
  if [[ "$(uname)" == "Darwin" ]]; then
    # Try both common service names: 'github-mcp' (wrapper default) and 'GitHub' (docs/older installs)
    for svc in "$SERVICE_NAME" "GitHub"; do
      GITHUB_TOKEN=$(security find-generic-password -s "$svc" -a "$ACCOUNT_NAME" -w 2>/dev/null || true)
      if [ -n "$GITHUB_TOKEN" ]; then
        break
      fi
    done
  fi
fi
if [ -z "${GITHUB_TOKEN}" ]; then
  echo "Error: GitHub token not found." >&2
  echo "Set GITHUB_PERSONAL_ACCESS_TOKEN, or add a macOS Keychain item: service 'github-mcp' (or 'GitHub'), account 'token'." >&2
  echo "macOS (secure prompt):" >&2
  echo "  security add-generic-password -s github-mcp -a token -w" >&2
  exit 1
fi

# 2. Set environment for Docker
export GITHUB_PERSONAL_ACCESS_TOKEN="$GITHUB_TOKEN"

# 3. Ensure stdio transport unless explicitly provided
NEEDS_STDIO=1
for a in "$@"; do
  case "$a" in
    stdio|--stdio|--sse|--transport=*|--http*|--sse*|--port|--host)
      NEEDS_STDIO=0
      ;;
  esac
done
if [ $NEEDS_STDIO -eq 1 ]; then
  set -- stdio "$@"
fi

# --- Startup ---

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

# Ensure image present (auto-pull if missing)
if ! "$DOCKER_COMMAND" image inspect "${DOCKER_IMAGE}" >/dev/null 2>&1; then
  echo "Pulling GitHub MCP Docker image: ${DOCKER_IMAGE}" >&2
  if ! "$DOCKER_COMMAND" pull "${DOCKER_IMAGE}" >&2; then
    echo "Error: failed to pull image: ${DOCKER_IMAGE}" >&2
    echo "Attempting to use remote server fallback..." >&2
    use_remote_server
  fi
  echo "Pulled GitHub MCP Docker image successfully: ${DOCKER_IMAGE}" >&2
fi

echo "Using GitHub MCP via Docker image: ${DOCKER_IMAGE}" >&2

# Run the Docker container
"$DOCKER_COMMAND" run -i --rm \
  -e GITHUB_PERSONAL_ACCESS_TOKEN \
  "${DOCKER_IMAGE}" "$@" 2> >(cat >&2)

exit $?
