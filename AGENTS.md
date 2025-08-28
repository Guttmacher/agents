# Claude Instructions for This Repository

These notes help Claude (and you) run and debug local MCP servers consistently.

Key wrappers
- GitHub: ~/bin/mcp-github-wrapper.sh (Docker with remote fallback via mcp-remote)
- Atlassian: ~/bin/mcp-atlassian-wrapper.sh (Docker with remote fallback via mcp-remote)
- Bitbucket: ~/bin/mcp-bitbucket-wrapper.sh (npm-installed binary on PATH → npx @latest; no Docker fallback)
- Context7: ~/bin/mcp-context7-wrapper.sh (npm package or npx; no auth required)

Important: stdout must be JSON-only
- MCP clients parse JSON-RPC on stdout. Any banners or human text on stdout can break initialization.
- Our wrappers send diagnostics to stderr on purpose. Seeing messages labeled as “warnings” in UIs is expected and safe.

Quick smoke test for wrappers
- We provide tests that verify wrapper stdout is clean (JSON-only) and safe for MCP clients.
- Run from repo root or anywhere:
  - Python: python3 tests/smoke_mcp_wrappers.py --timeout 6.0
- Options:
  - --include-bin to also test the copies in ~/bin
  - Provide specific paths to test particular wrappers

Examples
- Test installed copies in ~/bin: tests/smoke_mcp_wrappers.py --include-bin
- Test only the GitHub wrapper: tests/smoke_mcp_wrappers.py scripts/mcp-github-wrapper.sh

Credentials
- GitHub
  - Prefer macOS Keychain item: Service “github-mcp”, Account “token”; or set GITHUB_PERSONAL_ACCESS_TOKEN in the environment used by the editor.
- Atlassian
  - macOS Keychain:
    - service “atlassian-mcp”, account “token” = your API token
    - optional: service "atlassian-mcp", account "atlassian-domain" = your Atlassian domain (e.g., yourorg.atlassian.net)
  - Windows Credential Manager equivalents:
    - Generic Credential target "atlassian-mcp", user name "token" = your API token
    - optional: Generic Credential target "mcp-atlassian", user name "atlassian-domain" = your Atlassian domain (e.g., yourorg.atlassian.net)
  - Set ATLASSIAN_DOMAIN and ATLASSIAN_EMAIL in the agent configs (domain derived from git user.email if unset; email from env var → keychain → git user.email if unset).
  - Remote fallback uses mcp-remote (OAuth flow).
- Bitbucket
  - Keychain items (macOS):
    - service "bitbucket-mcp", account "app-password" = your app password
    - service "bitbucket-mcp", account "bitbucket-username" = your Bitbucket username
    - service "bitbucket-mcp", account "bitbucket-workspace" = your default workspace (optional)
  - Windows Credential Manager (optional):
    - Generic Credential target "bitbucket-mcp", user name "app-password" = your app password
    - Generic Credential target "bitbucket-mcp", user name "bitbucket-username" = your Bitbucket username
    - Generic Credential target "bitbucket-mcp", user name "bitbucket-workspace" = your default workspace (optional)
  - Or set environment variables:
    - ATLASSIAN_BITBUCKET_APP_PASSWORD
    - ATLASSIAN_BITBUCKET_USERNAME (env var → keychain → git user.email → OS username if unset)
    - BITBUCKET_DEFAULT_WORKSPACE (optional; uses your Bitbucket account's default workspace if unset)

Troubleshooting symptom → action
- “Failed to parse message: '\n'” or similar in clients:
  - The server printed banners on stdout. Use the GitHub Docker image (preferred) or ensure wrappers filter stdout to JSON only.
- Immediate exit before initialize:
  - Missing credentials or docker daemon not running. Check stderr for “Using … via …” line and error details.

Style
- Keep stdout machine-readable. Log to stderr or a file when in doubt.

