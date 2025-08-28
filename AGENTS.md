# AI Agent Instructions for This Repository

These instructions help AI agents (Claude, GitHub Copilot, Q, etc.) work effectively with this documentation repository for AI assistant setup and configuration.

## Repository Overview

This is a documentation repository for GitHub Copilot modes and tools. All "building" and "testing" consists of validating documentation structure and markdown formatting.

**Bootstrap and validate the repository:**
- `cd <repo-root>` (if needed)
- **Lint markdown files:** Run `markdownlint "*.md" "**/*.md"` — takes < 1 second. NEVER CANCEL.
- **Verify git status:** `git --no-pager status && git --no-pager log --oneline -5` — takes < 0.1 seconds. NEVER CANCEL.

## Validation

**CRITICAL VALIDATION SCENARIOS:** After making any changes to this repository, you MUST test the following complete end-to-end scenarios:

1. **Documentation Navigation Test:** Verify an agent can navigate the repository structure by reading README.md and understanding the mode hierarchy. Test with: `head -50 README.md | grep -E "(##|###)"` — takes < 0.1 seconds.

2. **Mode File Structure Test:** Validate that all mode files follow correct format (YAML frontmatter with tools list and contract section). Check manually by viewing each file.

3. **Cross-Reference Validation:** Check that the tool matrix in README.md matches the tools lists in the individual mode files.

4. **Markdown Quality Check:** Run full markdown linting to ensure documentation quality. The linting will show many existing issues — this is expected and not blocking.

5. **Tools Lists Validation:** Ensure the tools list in README.md accurately reflects the tools lists in the chatmode.md files. Verify with: `Rscript tests/smoke_rules.R`.

**NEVER CANCEL any validation command.** All validation operations complete in under 1 second.

## Repository Structure
```
./
├── README.md                         # Main documentation
├── TOOLS_GLOSSARY.md                 # Glossary of all available tools
├── copilot/
│   └── modes/
│       ├── QnA.chatmode.md                # Strict read-only Q&A / analysis (no mutations)
│       ├── Plan.chatmode.md               # Remote planning & artifact curation + PR create/edit/review (no merge/branch)
│       ├── Code-Sonnet4.chatmode.md       # Full coding, execution, PR + branch ops (Claude Sonnet 4 model)
│       ├── Code-GPT5.chatmode.md          # Full coding, execution, PR + branch ops (GPT-5 model)
│       ├── Review.chatmode.md             # PR & issue review feedback (comments only)
├── scripts/
│   ├── mcp-github-wrapper.sh        # macOS/Linux GitHub MCP wrapper script
│   ├── mcp-github-wrapper.ps1       # Windows GitHub MCP wrapper script
│   ├── mcp-atlassian-wrapper.sh     # macOS/Linux Atlassian MCP wrapper script
│   ├── mcp-atlassian-wrapper.ps1    # Windows Atlassian MCP wrapper script
│   ├── mcp-bitbucket-wrapper.sh     # macOS/Linux Bitbucket MCP wrapper script
│   ├── mcp-bitbucket-wrapper.ps1    # Windows Bitbucket MCP wrapper script
│   ├── mcp-context7-wrapper.sh      # macOS/Linux Context7 MCP wrapper script
│   └── mcp-context7-wrapper.ps1     # Windows Context7 MCP wrapper script
├── templates/
│   ├── llm_code_style_guidelines.txt      # General coding style guidelines (for copy/paste to other tools)
│   ├── mcp_mac.json                       # MCP configuration for macOS (VS Code and Claude Desktop)
│   ├── mcp_win.json                       # MCP configuration for Windows (VS Code and Claude Desktop)
│   └── vscode-settings.jsonc              # VS Code user settings template (optional)
└── tests/
    ├── smoke_mcp_wrappers.py        # Smoke test runner for wrapper stdout (filters/validates stdout)
    ├── smoke_auth.sh                # Tests for authentication setup
    └── smoke_rules.R                # R script for validating tool lists/matrix consistency
```

## Mode Capabilities

**Mode File Format:**
Standard YAML frontmatter:
   ```markdown
   ---
   description: 'Mode Name'
   tools: [...]
   ---
   Contract: ...
   ```

**Mode Privilege Levels:**
- **QnA Mode:** Read-only analysis, no mutations anywhere
- **Review Mode:** PR review comments + issue comments only
- **Plan Mode:** Planning artifacts + PR create/edit (no merge/branch ops)
- **Code-GPT5 Mode:** Full implementation including merge & branch operations (GPT-5 model)
- **Code-Sonnet4 Mode:** Full implementation including merge & branch operations (Claude Sonnet 4 model)

**Tool Availability Matrix:** The README.md contains a comprehensive table showing which tools are available in which modes. Reference this instead of guessing tool availability.

**Key Relationships:**
- [`templates/llm_code_style_guidelines.txt`](templates/llm_code_style_guidelines.txt) (referenced in README) is the canonical source for coding guidelines. Copy/paste into other tools as needed.
- Mode files define different privilege levels: QnA < Review < Plan < Code

## Build/Test Commands

This repository has no traditional build process. The validation workflow is:
1. Markdown linting: `markdownlint *.md **/*.md`  
2. Git status check: `git --no-pager status`

**Timing Expectations:**
- All validation operations: < 1 second
- Git operations: < 0.1 seconds  
- File reading/analysis: < 0.1 seconds
- Complete workflow validation: < 1 second total

## Navigation Points

**For understanding the repository:**
- Start with README.md lines 1-50 for overview and structure
- Check copilot/modes/ directory for mode definitions
- Reference Tool Availability Matrix in README.md for tool capabilities

**For making changes:**
- Always validate mode file format if editing .chatmode.md files
- Run markdown linting before committing
- Test documentation navigation scenarios
- Verify cross-references remain intact

**For debugging issues:**
- Check mode file YAML frontmatter syntax
- Verify tool lists in mode files match README.md matrix
- Validate contract sections exist in all mode files
- Ensure proper file permissions and structure

## Critical Warnings

**NEVER CANCEL any validation command** - all operations complete in under 1 second.

**ALWAYS test documentation navigation scenarios** after making changes to ensure agents can effectively use the repository.

**MAINTAIN cross-reference integrity** between README.md tool matrix and individual mode files.

**PRESERVE existing mode file formats** - some use standard YAML frontmatter, others use code-block wrappers. Do not change format without understanding implications.

## MCP Server Configuration

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
    - optional: service "atlassian-mcp", account "domain" = your Atlassian domain (e.g., yourorg.atlassian.net)
  - Windows Credential Manager equivalents:
    - Generic Credential target "atlassian-mcp", user name "token" = your API token
    - optional: Generic Credential target "mcp-atlassian", user name "domain" = your Atlassian domain (e.g., yourorg.atlassian.net)
  - Set ATLASSIAN_DOMAIN and ATLASSIAN_EMAIL in the agent configs (domain derived from git user.email if unset; email from env var → keychain → git user.email if unset).
  - Remote fallback uses mcp-remote (OAuth flow).
- Bitbucket
  - Keychain items (macOS):
    - service "bitbucket-mcp", account "app-password" = your app password
    - service "bitbucket-mcp", account "username" = your Bitbucket username
    - service "bitbucket-mcp", account "workspace" = your default workspace (optional)
  - Windows Credential Manager (optional):
    - Generic Credential target "bitbucket-mcp", user name "app-password" = your app password
    - Generic Credential target "bitbucket-mcp", user name "username" = your Bitbucket username
    - Generic Credential target "bitbucket-mcp", user name "workspace" = your default workspace (optional)
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

