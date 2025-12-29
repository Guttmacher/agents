#!/usr/bin/env zsh
# Setup Bitbucket MCP credentials in macOS Keychain

set -euo pipefail

SERVICE_NAME="bitbucket-mcp"
DRY_RUN=false

# Parse arguments
if [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN=true
  echo "DRY RUN MODE - No changes will be made to keychain"
  echo
fi

echo "Setting up Bitbucket MCP credentials in macOS Keychain..."
echo

# Get API token
echo "Create a scoped API token at: https://id.atlassian.com/manage-profile/security/api-tokens"
echo "Required scopes:"
echo "  • read:me"
echo "  • read:pullrequest:bitbucket"
echo "  • read:repository:bitbucket"
echo "  • read:user:bitbucket"
echo "  • read:workspace:bitbucket"
echo "Optional (for write operations):"
echo "  • write:pullrequest:bitbucket"
echo "  • write:repository:bitbucket"
echo
echo -n "Enter your Atlassian scoped API token: "
read -s API_TOKEN
echo
if [[ -z "$API_TOKEN" ]]; then
  echo "Error: API token cannot be empty"
  exit 1
fi

# Get email
GIT_EMAIL=""
if command -v git >/dev/null 2>&1; then
  GIT_EMAIL=$(git config --get user.email 2>/dev/null || true)
fi

if [[ -n "$GIT_EMAIL" ]]; then
  echo -n "Enter your Atlassian email [$GIT_EMAIL]: "
else
  echo -n "Enter your Atlassian email: "
fi
read EMAIL
if [[ -z "$EMAIL" ]]; then
  if [[ -n "$GIT_EMAIL" ]]; then
    EMAIL="$GIT_EMAIL"
  else
    echo "Error: Email cannot be empty"
    exit 1
  fi
fi

# Get workspace (optional)
echo -n "Enter your default Bitbucket workspace [guttmacher]: "
read WORKSPACE
if [[ -z "$WORKSPACE" ]]; then
  WORKSPACE="guttmacher"
fi

echo
if [[ "$DRY_RUN" == "true" ]]; then
  echo "DRY RUN - Would save these credentials to keychain:"
  echo "  Service: $SERVICE_NAME"
  echo "  API Token: $SERVICE_NAME/atlassian-api-token = [HIDDEN]"
  echo "  Email: $SERVICE_NAME/email = $EMAIL"
  echo "  Workspace: $SERVICE_NAME/workspace = $WORKSPACE"
else
  echo "Saving credentials to keychain..."
  
  # Save API token
  security add-generic-password -s "$SERVICE_NAME" -a "atlassian-api-token" -w "$API_TOKEN" -U
  
  # Save email
  security add-generic-password -s "$SERVICE_NAME" -a "email" -w "$EMAIL" -U
  
  # Save workspace if provided
  if [[ -n "$WORKSPACE" ]]; then
    security add-generic-password -s "$SERVICE_NAME" -a "workspace" -w "$WORKSPACE" -U
  fi
  echo "✓ Saved API token, email, and workspace ($WORKSPACE) to keychain"
fi

echo
if [[ "$DRY_RUN" == "true" ]]; then
  echo "DRY RUN completed - no changes made to keychain"
else
  echo "Credentials saved successfully!"
fi
echo "You can now use the Bitbucket MCP wrapper."
