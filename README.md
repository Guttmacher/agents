# AI Assistant Setup & Configuration

This repository provides installation guides, configuration files, scripts, and documentation for setting up GitHub Copilot, Claude Desktop, Q, and other AI coding assistants with custom modes and MCP servers.

## Repository Structure

```
./
├── README.md                         # This document
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
│   └── mcp-bitbucket-wrapper.ps1    # Windows Bitbucket MCP wrapper script
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

## Modes

### Modes Overview

We define **four categories** of modes for different use cases, that follow a **privilege gradient:** **QnA < Review** (adds review + issue comments) **< Plan** (adds planning artifact + PR creation/edit) **< Code** (full lifecycle incl. merge & branch ops).

From these four categories, we create **five modes**. **Code-GPT5** and **Code-Sonnet4** modes provide the same toolsets with different prompts. We do this because these models respond differently to prompts and possess different strengths. For reference, see OpenAI's [GPT-5 prompting guide](https://cookbook.openai.com/examples/gpt-5/gpt-5_prompting_guide) and Anthropic's [Claude 4 prompt engineering best practices](https://docs.anthropic.com/en/docs/build-with-claude/prompt-engineering/claude-4-best-practices).

<table>
  <thead>
    <tr>
      <th>Mode</th>
      <th>Default Model</th>
      <th>Purpose</th>
      <th>Contract Summary</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><a href="copilot/modes/QnA.chatmode.md">📚 QnA</a></td>
      <td>GPT-4.1</td>
      <td>Q&amp;A, exploration, explain code, gather context</td>
      <td>Strict read-only (no mutations anywhere)</td>
    </tr>
    <tr>
      <td><a href="copilot/modes/Plan.chatmode.md">🔭 Plan</a></td>
      <td>Sonnet 4</td>
      <td>Plan work, refine scope, shape issues/pages, organize PR scaffolding</td>
      <td>Mutate planning artifacts + create/edit/review PRs (no merge/branch ops)</td>
    </tr>
    <tr>
      <td><a href="copilot/modes/Review.chatmode.md">🔬 Review</a></td>
      <td>GPT-5</td>
      <td>Provide review feedback on PRs / issues</td>
      <td>PR review + issue comments only; no other mutations</td>
    </tr>
    <tr>
      <td><a href="copilot/modes/Code-GPT5.chatmode.md">🚀 Code-GPT5</a></td>
      <td>GPT-5</td>
      <td rowspan="2">Implement changes, run tests/commands</td>
      <td rowspan="2">Full implementation, execution, &amp; PR lifecycle</td>
    </tr>
    <tr>
      <td><a href="copilot/modes/Code-Sonnet4.chatmode.md">☄️ Code-Sonnet4</a></td>
      <td>Sonnet 4</td>
    </tr>
  </tbody>
</table>

**Note:** One can use any model with any mode. For example, one might use Review mode with Sonnet or Gemini.

### Why custom modes?

- The built-in **Agent mode does not remember which tools you turned on and off.**
  - When you reopen VS Code, it turns every tool back on.
- The built-in **Ask** mode cannot call _any_ tools.
  - This means you cannot use it to fetch information, such as documentation from Context7 or issue details from Jira.
- Custom modes **enforce their behavioral boundaries** by defining which tools agents can call.
- In VS Code, selecting a built-in modes does not set a model.
  - This means it takes eight clicks from Ask/GPT-4.1 to Agent/Sonnet and back.
- You can **type less** because each mode contains prompts tailored to its specific use case.
  - This reduces the need for repetitive instructions.
  - We created two variants of Code Mode, with instructions tailored to GPT-5 (terse) and Sonnet 4 (verbose).
- **You can still use the built-in modes.**
  - Switch to **Agent** mode when you do not want to use tailored instructions.


### Add Modes to VS Code

**Save the files from [copilot/modes/](copilot/modes) to:**

| OS        | Folder                                                 |
|-----------|--------------------------------------------------------|
| Windows   | C:\Users\<your-os-username>\AppData\Roaming\Code\User\prompts\ |
| Macintosh | ~/Library/Application Support/Code/User/prompts/       |


**Alternatively,** you can create create these files using the VS Code menus:

1. Choose "Configure Modes..." from the Mode menu in the Chat pane
2. From the "Select the chat mode file to open" menu, press "Create new custom mode chat file..."
3. From the "Select a location to create the mode file in..." menu, press "User Data Folder"
4. From the "Enter the name of the custom chat mode file..." menu, type the mode name as you want it to appear in your modes menu
5. Paste the file contents into the new file (repeating steps 1 to 5 for each mode)



## Models

### Models by Agent

| Agent             | Sonnet 4 | Opus 4.1 | GPT-5 | GPT-5 mini | GPT 4.1 | Gemini 2.5 Pro | Gemini 2.5 Flash |
|-------------------|----------|----------|-------|------------|---------|----------------|------------------|
| Claude.ai/Desktop | ✅      | ✅        | ❌     | ❌         | ❌      | ❌              | ❌              |
| Claude Code       | ✅      | ✅        | ❌     | ❌         | ❌      | ❌              | ❌              |
| GitHub Copilot    | ✅      | ❌        | ✅     | ✅         | ✅      | ✅              | ❌              |
| Q                 | ✅      | ❌        | ❌     | ❌         | ❌      | ❌              | ❌              |
| Warp              | ✅      | ✅        | ✅     | ❌         | ✅      | ✅              | ✅              |

**Note:** None of these agents except Warp specify whether GPT-5 refers to the model with minimal, low, medium, or high reasoning. (Warp offers low, medium, and high.)


### Simulated Reasoning

| Agent             | SR Options   | Notes |
|-------------------|--------------|------------------------------------------------------------|
| Claude.ai/Desktop | ✅           | Toggle "Extended thinking" in the "Search and tools" menu  |
| Claude Code       | ✅           | Use [keywords](https://www.anthropic.com/engineering/claude-code-best-practices): _think_ < _think hard_ < _think harder_ < _ultrathink_                                         |
| GitHub Copilot    | —            | Has Sonnet 3.7 Thinking and o4 mini                        |
| Q                 | ❌           |                                                            |
| Warp              | —            | Has o3 and o4 mini, and can specify GPT-5 reasoning level  |


**Note:** [GPT-5 adds _reasoning_effort_ and _verbosity_ parameters ranging from minimal/low to high](https://openai.com/index/introducing-gpt-5-for-developers/), but providers do not transparently communicate how they configure it. One can access high/high settings for planning tasks via the OpenAI API.

### Context Windows

| Agent             | Claude Sonnet | GPT-5     | GPT 4.1   | Gemini    |
|-------------------|---------------|-----------|-----------|-----------|
| GitHub Copilot    | 111,836       | 108,637   | 111,452	  | 108,637   |
| Claude.ai/Desktop | 200,000       | —         | —         | —         |
| Claude Code       | 200,000       | —         | —         | —         |
| Q                 | 200,000       | —         |           | —         |
| Warp              | 200,000       | ?         | ?         | ?         |
| **API:**          | 200,000       | 400,000   | 1,000,000 | 1,000,000 |
| (in beta in API)  | (1,000,000)   | —         | —         | —         |

- Context windows are measured in tokens.
- A token is roughly 4 characters long.
- For example, _unbreakable_ consists of _un_ - _break_ - _able_.

**Note:** Agents will generally compress and prune prompts to fit within their context windows in multi-turn chats. However, Claude.ai/Desktop will not; if after several turns you exceed the context window, you cannot continue the chat.


## MCP Servers

Model Context Provider (MCP) Servers provide a bridge between agents and APIs: Agent <-> MCP Server <-> API. MCP Servers provide agents tool lists and (ideally) include usage examples for each tool.

Local MCP servers run on your computer whereas remote MCP servers run in the cloud. 
 - Microsoft provides both kinds for GitHub. However, they describe their remote server as "[in preview](https://github.blog/changelog/2025-06-12-remote-github-mcp-server-is-now-available-in-public-preview/)".
 - Atlassian provides a remote server for Jira and Confluence. However, they describe it as "[in public beta](https://github.com/atlassian/atlassian-mcp-server)".
 - Atlassian subjects their beta to [usage limits](https://github.com/atlassian/atlassian-mcp-server?tab=readme-ov-file#beta-access-and-limits): 1,000 requests per hour per organization, plus unspecified per-user limits.
 - Occasionally, I have found Atlassian's server not to respond to requests.

This repository contains wrapper scripts for each MCP server that try to launch the appropriate local server, and, should that fail, try to launch the remote server. Since the local servers run in docker containers, this provides a graceful fallback mechanism in case the daemon is not running. 

A separate MCP server handles Bitbucket. A remote version does not exist.

Atlassian does not make a local MCP server, and does not provide one of either kind for Bitbucket. For this reason, we use open-source alternatives.

You must download each of the wrapper scripts and store login information in your credential manager (on Windows) or login keychain (on macOS). Follow the steps provided below for each MCP server, and then follow the instructions in [Add MCP Servers to Agents](#add-mcp-servers-to-agents).

### Prerequisites

Before you begin, ensure you have the necessary tools installed.

#### Container Runtime

**You need a docker-compatible container runtime:**

##### Windows:
```powershell
winget install RedHat.Podman
podman machine init --cpus 2 --memory 4096 --disk-size 20
podman machine start
```

##### macOS: 

```zsh
brew install colima docker
echo "export DOCKER_HOST=\"unix://$HOME/.colima/default/docker.sock\"" >> ~/.zprofile
brew services start colima
```

#### Node.js

**You need node.js:**

##### Windows:
```powershell
winget install nodejs
```

##### macOS:
```zsh
brew install nodejs
```

### GitHub MCP Server

#### Obtain GitHub Personal Access Token

Follow these steps to obtain a necessary GitHub access token:

1. Go to [GitHub Settings](https://github.com/settings/tokens).
2. Click on "Generate new token" > "Generate new token (classic)".
3. Select the scopes/permissions you want to grant this token, including:
- repo
- read:org
- read:user
- user:email
- project
4. Click "Generate token".
5. Copy your new personal access token. You won’t be able to see it again!

#### Configure GitHub MCP Server on Windows

1. Store token securely:
   - Control Panel → User Accounts → Credential Manager → Windows Credentials → Add a generic credential.
   - Internet or network address: `github-mcp`
   - Username: `token` (placeholder)
   - Password: (your PAT)
2. (Optional) Inspect via PowerShell:
   ```powershell
   Install-Module -Name CredentialManager -Scope CurrentUser -Force
   Import-Module CredentialManager
   Get-StoredCredential -Target github-mcp
   ```
3. Use the provided wrapper script: copy [`scripts/mcp-github-wrapper.ps1`](scripts/mcp-github-wrapper.ps1) to `C:\Users\<your-os-username>\bin\mcp-github-wrapper.ps1`
4. Ensure script dir: `New-Item -ItemType Directory -Force "$Env:UserProfile\bin" | Out-Null`
5. Set execution policy (user scope):
   ```powershell
   Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -Force
   ```
7. Verify wrapper:
   ```powershell
   & $Env:UserProfile\bin\mcp-github-wrapper.ps1 --help | Select-Object -First 10
   ```
   If it errors about credentials, re-create the Generic Credential `GitHub`

#### Configure GitHub MCP Server on macOS

1. Create a keychain item:
   - GUI: Keychain Access → File → New Password Item…
     - Name (Service): `github-mcp`
     - Account: `token`
     - Password: (your GitHub Personal Access Token)
   - Or CLI:
     ```bash
     security add-generic-password -s github-mcp -a token -w
     ```
2. Use the provided wrapper script: copy [`scripts/mcp-github-wrapper.sh`](scripts/mcp-github-wrapper.sh) to `~/bin/mcp-github-wrapper.sh`
3. Make it executable: `chmod +x ~/bin/mcp-github-wrapper.sh`
4. Test retrieval (optional): `security find-generic-password -s github-mcp -a token -w`
5. Verify wrapper: `~/bin/mcp-github-wrapper.sh --help | head -5`

**Note:** If `~/bin` is not already on your PATH, add the following line to your `~/.zshrc` (macOS default shell) and then `source ~/.zshrc`:

```
export PATH="$HOME/bin:$PATH"
```


### Atlassian MCP Server

#### Obtain Atlassian API Token

**You need an Atlassian API Token. To create one, follow these steps:**

1. Go to [Atlassian API Tokens](https://id.atlassian.com/manage-profile/security/api-tokens)
2. Click "Create API token"
3. Enter a label (e.g., "MCP Server Access")
4. Copy the generated token immediately (you won't be able to see it again!)

#### Configure Atlassian MCP Server on macOS

1. Create a keychain item for the API token:
   - GUI: Keychain Access → File → New Password Item…
     - Name (Service): `atlassian-mcp`
     - Account: `token`
     - Password: (your Atlassian API token)
   - Or CLI:
     ```bash
     security add-generic-password -s atlassian-mcp -a token -w
     ```

2. Copy `scripts/mcp-atlassian-wrapper.sh` to `~/bin/`:
   ```bash
   cp scripts/mcp-atlassian-wrapper.sh ~/bin/
   ```

3. Make it executable:
   ```bash
   chmod +x ~/bin/mcp-atlassian-wrapper.sh
   ```
  **Note:** If `~/bin` is not already on your PATH, add the following line to your `~/.zshrc` and then `source ~/.zshrc`:
  ```
  export PATH="$HOME/bin:$PATH"
  ```

4. Test
   ```bash
   ~/bin/mcp-atlassian-wrapper.sh --help | head -5
   ```

**Note:** If Docker/Podman is unavailable, the wrapper may fall back to the Atlassian remote MCP server and authenticate via OAuth. This will open your default browser to complete sign-in.

#### Configure Atlassian MCP Server on Windows

1. If you have not already done so, install the CredentialManager module:
   ```powershell
   Install-Module CredentialManager -Scope CurrentUser -Force
   ```

  **Note:** If this fails with a permissions or execution policy error and you are not in an elevated session, start PowerShell by right‑clicking and choosing "Run as administrator", then retry (you can still use `-Scope CurrentUser`).

2. Create a _generic credential_ in Windows Credential Manager for the API token:
   - GUI: Control Panel → User Accounts → Credential Manager → Windows Credentials → Add a generic credential.
     - Internet or network address: `atlassian-mcp`
     - User name: `token`
     - Password: (your Atlassian API token)
   - Or CLI:
   > ⚠️ **Security Warning:** Running `cmd /c "cmdkey /add:atlassian-mcp /user:token /pass:<your-api-token>"` directly will write your secret in cleartext to your shell history. Use this secure command instead:
   ```powershell
   $secure = Read-Host -AsSecureString "Enter Atlassian API token"
   $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
   try {
     $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
     # Use Start-Process so the literal token isn't echoed back; it's still passed in memory only.
     Start-Process -FilePath cmd.exe -ArgumentList "/c","cmdkey","/add:atlassian-mcp","/user:token","/pass:$plain" -WindowStyle Hidden -NoNewWindow -Wait
     Write-Host "Credential 'atlassian-mcp' created." -ForegroundColor Green
   } finally {
     if ($bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
   }
   ```

3. Copy `scripts/mcp-atlassian-wrapper.ps1` to `%USERPROFILE%\bin\`:
   ```powershell
   # Create a user bin folder and copy the script there
   New-Item -ItemType Directory -Force "$Env:UserProfile\bin"
   Copy-Item -Path scripts\mcp-atlassian-wrapper.ps1 -Destination "$Env:UserProfile\bin\mcp-atlassian-wrapper.ps1" -Force

   # Optionally add the folder to your user PATH
   [Environment]::SetEnvironmentVariable('PATH', $Env:PATH + ';' + "$Env:UserProfile\bin", 'User')
   ```

4. Ensure PowerShell can run local scripts:
   ```powershell
   Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -Force
   ```

5. Test
   ```powershell
   # Set your organization domain: $env:ATLASSIAN_DOMAIN="yourorg.atlassian.net"
   & $Env:UserProfile\bin\mcp-atlassian-wrapper.ps1 --help | Select-Object -First 5
   ```

**Note:** If Docker/Podman is unavailable, the wrapper may fall back to the Atlassian remote MCP server and authenticate via OAuth. This will open your default browser to complete sign-in.



### Bitbucket MCP Server

#### Obtain Bitbucket App Password

**You need a Bitbucket App Password with the required scopes. To create one, follow these steps:**

1. Go to Personal Bitbucket Settings → App Passwords → Create app password (https://bitbucket.org/account/settings/app-passwords/)
2. Permissions needed (tick these):
   - **Account**
     - email
     - read
   - **Workspace membership:**
     - read
   - **Projects:**
     - read
   - **Repositories:**
     - read
     - write
   - **Pull requests:**
     - read
     - write
   - **Pipelines:**
     - read
   - **Runners:**
     - read

#### Configure Bitbucket MCP Server on macOS

1. Create a Keychain item for the app password:
   - GUI: Keychain Access → File → New Password Item…
     - Name (Service): `bitbucket-mcp`
     - Account: `app-password`
     - Password: (your Bitbucket app password)
   - Or CLI:
     ```bash
     security add-generic-password -s bitbucket-mcp -a app-password -w
     ```

2. Create a keychain item for your Bitbucket username:
   - GUI: Keychain Access → File → New Password Item…
     - Name (Service): `bitbucket-mcp`
     - Account: `bitbucket-username`
     - Password: (your Bitbucket username)
   - Or CLI:
  ```bash
  security add-generic-password -s bitbucket-mcp -a username -w "<your-bitbucket-username>"
  ```

You can skip step 2 if your Bitbucket username is the same as the first part of your email address--the one set in your global git config.
- *If* my Bitbucket username was _jbearak_, I could skip step 2, _but_ my Bitbucket username is _jonathan-b_, so I need to set it in the keychain.
- As an alternative to storing your Bitbucket username in your system keychain, could specify your Bitbucket username in an environment variable (in the json file, place `"ATLASSIAN_BITBUCKET_USERNAME": "`<your-bitbucket-username>`" in the `env` section). I like using the keychain for convenience, so I do not have to set it--this lets me use the configuration file templates without editing them.

3. Copy `scripts/mcp-bitbucket-wrapper.sh` to `~/bin/`:
   ```bash
  cp scripts/mcp-bitbucket-wrapper.sh ~/bin/
   ```

4. Make it executable:
   ```bash
   chmod +x ~/bin/mcp-bitbucket-wrapper.sh
   ```

5. Test:
   ```bash
   ~/bin/mcp-bitbucket-wrapper.sh --help | head -5
   ```

#### Configure Bitbucket MCP Server on Windows

1. If you have not already done so, install the CredentialManager module:
```powershell
Install-Module CredentialManager -Scope CurrentUser -Force
```
  **Note:** If this fails with a permissions or execution policy error and you are not in an elevated session, start PowerShell by right‑clicking and choosing "Run as administrator", then retry (you can still use `-Scope CurrentUser`).

2. Create a _generic credential_ in Windows Credential Manager for the app password:
   - GUI: Control Panel → User Accounts → Credential Manager → Windows Credentials → Add a generic credential.
     - Internet or network address: `bitbucket-mcp`
     - User name: `app-password`
     - Password: (your Bitbucket app password)
   - Or CLI:
     > ⚠️ **Security Warning:** Running `cmd /c "cmdkey /add:bitbucket-mcp /user:app-password /pass:<app_password>` directly will write your secret in cleartext to your shell history. Use this secure command instead:
   ```powershell
    $secure = Read-Host -AsSecureString "Enter Bitbucket app password"
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
      $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
      # Use Start-Process so the literal password isn't echoed back; it's still passed in memory only.
      Start-Process -FilePath cmd.exe -ArgumentList "/c","cmdkey","/add:bitbucket-mcp","/user:app-password","/pass:$plain" -WindowStyle Hidden -NoNewWindow -Wait
      Write-Host "Credential 'bitbucket-mcp' created." -ForegroundColor Green
    } finally {
      if ($bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    }
    ```

3. Create a _general credential_ in Windows Credential Manager for your Bitbucket username:
   - GUI: Control Panel → User Accounts → Credential Manager → Windows Credentials → Add a generic credential.
     - Internet or network address: `bitbucket-mcp`
     - User name: `username`
     - Password: (your Bitbucket username)
   - Or CLI:
   ```powershell
   cmdkey /add:bitbucket-mcp /user:username /pass:<your-bitbucket-username>
   ```

4. Copy `scripts/mcp-bitbucket-wrapper.ps1` to `%USERPROFILE%\bin\`:
```powershell
# create a user bin folder and copy the script there
New-Item -ItemType Directory -Force "$Env:UserProfile\bin"
Copy-Item -Path scripts\mcp-bitbucket-wrapper.ps1 -Destination "$Env:UserProfile\bin\mcp-bitbucket-wrapper.ps1" -Force

# optionally add the folder to your user PATH (persists for the current user)
[Environment]::SetEnvironmentVariable('PATH', $Env:PATH + ';' + "$Env:UserProfile\bin", 'User')

# run the script (example)
& "$Env:UserProfile\bin\mcp-bitbucket-wrapper.ps1" --help | Select-Object -First 5
```

6. Ensure PowerShell can run local scripts (set execution policy for the current user):
```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -Force
```

7. Test:
```powershell
# Set your workspace if needed: $env:BITBUCKET_DEFAULT_WORKSPACE = 'YourWorkspace'
$env:ATLASSIAN_BITBUCKET_USERNAME="your-username"; & $Env:UserProfile\bin\mcp-bitbucket-wrapper.ps1 --help | Select-Object -First 5
```


### Context7 MCP Server

Context7 provides up-to-date, version-specific documentation and code examples for libraries and frameworks. It requires no authentication.

**Configuration:**

1. Copy the wrapper script to your bin directory:
   - macOS: `cp scripts/mcp-context7-wrapper.sh ~/bin/ && chmod +x ~/bin/mcp-context7-wrapper.sh`
   - Windows: Copy `scripts/mcp-context7-wrapper.ps1` to `%USERPROFILE%\bin\`

2. Test the wrapper:
   - macOS: `~/bin/mcp-context7-wrapper.sh --help`
   - Windows: `& "$Env:UserProfile\bin\mcp-context7-wrapper.ps1" --help`

The wrapper automatically uses the globally installed package if available, falling back to npx if not.

**Usage:** Ask for documentation like "show me dplyr mutate examples" or "get ggplot2 plotting docs", or instruct the agent to use it in the course of planning, coding, or reviewing.

### Add MCP Servers to Agents

#### Add MCP Servers to Claude Desktop

1. Open Settings -> Developer > Edit Config
- Note: This will open a File Explorer (Windows) or Finder (macOS) window
2. Double-click the config file
3. Use the provided configuration: copy [`templates/mcp_win.json`](templates/mcp_win.json) (Windows) or [`templates/mcp_mac.json`](templates/mcp_mac.json) (macOS)
4. On the first line of the template file, replace "servers" with "mcpServers"
5. Restart Claude Desktop

#### Add MCP Servers to VS Code

1. Restart VS Code
2. Command Palette -> List Servers
3. If VS Code lists the MCP servers from Claude Desktop, you're all set!
- If not:

1. From the Command Palette, choose **MCP: Open User Configuration**
2. Use the provided configuration: copy [`templates/mcp_mac.json`](templates/mcp_mac.json) (macOS) or [`templates/mcp_win.json`](templates/mcp_win.json) (Windows)
3. Restart VS Code

**Note:** On my Mac, VS Code detects and reads in the configuration from Claude Desktop. I could not figure out how to override this. On the one hand, not having to save and edit to configuration files saves time. On the other hand, I would like to know how to override this behavior because so I could configure them differently.

⚠️ If VS Code picks up the config from Claude Desktop, _and_ you _also_ add the same MCP servers to the VS Code's MCP config file, you will end up with duplicate MCP servers in the list. This could confuse the agents.

## LLM Coding Style Guidelines

We maintain concise coding style guidelines for LLMs in [`templates/llm_code_style_guidelines.txt`](templates/llm_code_style_guidelines.txt). We can copy/paste this file into other tools that support custom instructions, such as GitHub Copilot, Warp, Q, and Claude Code.

### GitHub Copilot (Repository-Level)
1. Create or edit `.github/copilot-instructions.md`
2. Paste [`templates/llm_code_style_guidelines.txt`](templates/llm_code_style_guidelines.txt).
3. Edit as/if needed/desired.

Reference: [Adding repository custom instructions for GitHub Copilot](https://docs.github.com/en/enterprise-cloud@latest/copilot/how-tos/configure-custom-instructions/add-repository-instructions)

### GitHub Copilot (GitHub.com Chats)

#### Organization-Level Instructions
**Note:** Organization custom instructions are currently only supported for GitHub Copilot Chat in GitHub.com and do not affect VS Code or other editors. For editor support, see [GitHub Copilot (Repository-Level)](#github-copilot-repository-level) above.

1. Org admin navigates to GitHub: Settings > (Organization) > Copilot > Policies / Custom Instructions.
2. Open Custom Instructions editor and paste the full contents of [`templates/llm_code_style_guidelines.txt`](templates/llm_code_style_guidelines.txt).
3. Save; changes propagate to organization members (may require editor reload).
4. Version control: treat this repository file as the single source of truth; update here first, then re-paste.

Reference: [Adding organization custom instructions for GitHub Copilot](https://docs.github.com/en/enterprise-cloud@latest/copilot/how-tos/configure-custom-instructions/add-organization-instructions)

#### Personal Instructions
**Note:** Personal custom instructions are currently only supported for GitHub Copilot Chat in GitHub.com and do not affect VS Code or other editors.

Since the organization-level instructions equal [`templates/llm_code_style_guidelines.txt`](templates/llm_code_style_guidelines.txt), do not re-paste it here. However, you may wish to customize Copilot Chat behavior further.

1. Navigate to GitHub: Settings > (Personal) > Copilot > Custom Instructions.
2. Open Custom Instructions editor and paste your personal instructions.
3. Save; changes apply to your personal GitHub.com chats.

Reference: [Adding personal custom instructions for GitHub Copilot](https://docs.github.com/en/copilot/how-tos/configure-custom-instructions/add-personal-instructions)

### Warp (Repository-Level)
1. Create `WARP.md`
2. Paste [templates/llm_code_style_guidelines.txt](templates/llm_code_style_guidelines.txt) content.
3. Edit as/if needed/desired.

### Warp (User-Level)
1. Open `Warp Drive` (the left sidebar) > `Rules` > `+ Add`
2. Paste your personal instructions.
3. Edit as/if needed/desired.


### Q (Repository-Level)
1. Create `.amazonq/rules/llm_coding_style_guidelines.txt` in the repository root
2. Paste [templates/llm_code_style_guidelines.txt](templates/llm_code_style_guidelines.txt) content.
3. Edit as/if needed/desired.

## Claude Code (Repository-Level)
1. Create or edit `CLAUDE.md` in the repository root
2. Paste [templates/llm_code_style_guidelines.txt](templates/llm_code_style_guidelines.txt) content.
3. Edit as/if needed/desired.


## VS Code Copilot Settings

We provide a template for reasonable default settings for GitHub Copilot in VS Code. The template includes:
- Safe terminal commands that can be auto-approved
- Disabled telemetry for privacy
- Extended chat agent limits (100 turns instead of default 25)
- [Enabled thinking tool for better agent performance](https://github.com/microsoft/vscode-copilot-chat/blob/549d817809926490f97ea449697ad6bc01a391c6/CHANGELOG.md#thinking-tool)

### Installation

1. Copy the template file: [`templates/vscode-settings.jsonc`](templates/vscode-settings.jsonc)
2. Add it to your VS Code user settings:
   - On Windows: `%APPDATA%\Code\User\settings.json`
   - On macOS: `~/Library/Application Support/Code/User/settings.json`
   - On Linux: `~/.config/Code/User/settings.json`

3. Merge the settings with your existing configuration or use as-is.



## Tool Availability Matrix

This table summarizes the tools available in each mode. For a more concise overview, see [Modes](#modes).

- Modes organized left-to-right from least to most privileges
- Review mode adds PR review + issue commenting over QnA, without broader planning artifact mutation.
- Plan mode extends Review with planning artifact creation/edit and PR creation/edit (no merge / branch ops).
- Code modes include full repository mutation (branches, merges, execution).
- See [Modes](#modes)

Note: "Code" shows toolsets for "Code - GPT-5" and "Code - Sonnet-4" modes.

📚 **For detailed tool descriptions, see the [Tools Glossary](TOOLS_GLOSSARY.md).**

Legend: ✅ available, ❌ unavailable in that mode.

<table>
<thead>
<tr>
<th>Tool</th>
<th>QnA</th>
<th>Review</th>
<th>Plan</th>
<th>Code</th>
</tr>
</thead>
<tbody>
<tr style="background-color: #f8f9fa;">
<td><strong>Built-In (VS Code / Core)</strong></td>
<td></td>
<td></td>
<td></td>
<td></td>
</tr>
<tr style="background-color: #ffffff;">
<td><em>Code &amp; Project Navigation</em></td>
<td></td>
<td></td>
<td></td>
<td></td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#codebase">codebase</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#findtestfiles">findTestFiles</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#search">search</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#searchresults">searchResults</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#usages">usages</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><em>Quality &amp; Diagnostics</em></td>
<td></td>
<td></td>
<td></td>
<td></td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#problems">problems</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#testfailure">testFailure</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><em>Version Control &amp; Changes</em></td>
<td></td>
<td></td>
<td></td>
<td></td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#changes">changes</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><em>Environment &amp; Execution</em></td>
<td></td>
<td></td>
<td></td>
<td></td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#terminallastcommand">terminalLastCommand</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#terminalselection">terminalSelection</a></td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#think">think</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#todos">todos</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><em>Web &amp; External Content</em></td>
<td></td>
<td></td>
<td></td>
<td></td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#fetch">fetch</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#githubrepo">githubRepo</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><em>Editor &amp; Extensions</em></td>
<td></td>
<td></td>
<td></td>
<td></td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#extensions">extensions</a></td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#vscodeapi">vscodeAPI</a></td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
</tr>
<tr style="background-color: #ffffff;">
<td><em>Editing &amp; Automation</em></td>
<td></td>
<td></td>
<td></td>
<td></td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#editfiles">editFiles</a></td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#runcommands">runCommands</a></td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
<td>✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#runtasks">runTasks</a></td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><strong>GitHub Pull Requests Extension (VS Code)</strong></td>
<td></td>
<td></td>
<td></td>
<td></td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#activepullrequest">activePullRequest</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#copilotcodingagent">copilotCodingAgent</a></td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
<td>✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><strong>Context7</strong></td>
<td></td>
<td></td>
<td></td>
<td></td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#resolve-library-id">resolve-library-id</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#get-library-docs">get-library-docs</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><strong>Atlassian</strong></td>
<td></td>
<td></td>
<td></td>
<td></td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><em>Atlassian Common</em></td>
<td></td>
<td></td>
<td></td>
<td></td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#getaccessibleatlassianresources">getAccessibleAtlassianResources</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><em>Jira Issues &amp; Operations</em></td>
<td></td>
<td></td>
<td></td>
<td></td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#jira_add_comment">jira_add_comment</a></td>
<td rowspan="2">❌</td>
<td rowspan="2">✅</td>
<td rowspan="2">✅</td>
<td rowspan="2">✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#addcommenttojiraissue">addCommentToJiraIssue</a></td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#jira_create_issue">jira_create_issue</a></td>
<td rowspan="2">❌</td>
<td rowspan="2">❌</td>
<td rowspan="2">✅</td>
<td rowspan="2">✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#createjiraissue">createJiraIssue</a></td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#jira_update_issue">jira_update_issue</a></td>
<td rowspan="2">❌</td>
<td rowspan="2">❌</td>
<td rowspan="2">✅</td>
<td rowspan="2">✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#editjiraissue">editJiraIssue</a></td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#jira_get_issue">jira_get_issue</a></td>
<td rowspan="2">✅</td>
<td rowspan="2">✅</td>
<td rowspan="2">✅</td>
<td rowspan="2">✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#getjiraissue">getJiraIssue</a></td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#jira_search">jira_search</a></td>
<td rowspan="2">✅</td>
<td rowspan="2">✅</td>
<td rowspan="2">✅</td>
<td rowspan="2">✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#searchjiraissuesusingjql">searchJiraIssuesUsingJql</a></td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#jira_transition_issue">jira_transition_issue</a></td>
<td rowspan="2">❌</td>
<td rowspan="2">❌</td>
<td rowspan="2">✅</td>
<td rowspan="2">✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#transitionjiraissue">transitionJiraIssue</a></td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#jira_get_transitions">jira_get_transitions</a></td>
<td rowspan="2">✅</td>
<td rowspan="2">✅</td>
<td rowspan="2">✅</td>
<td rowspan="2">✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#gettransitionsforjiraissue">getTransitionsForJiraIssue</a></td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#jira_get_link_types">jira_get_link_types</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#jira_get_project_versions">jira_get_project_versions</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#jira_get_worklog">jira_get_worklog</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#jira_download_attachments">jira_download_attachments</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#jira_add_worklog">jira_add_worklog</a></td>
<td>❌</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#jira_link_to_epic">jira_link_to_epic</a></td>
<td>❌</td>
<td>❌</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#jira_create_issue_link">jira_create_issue_link</a></td>
<td>❌</td>
<td>❌</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#jira_create_remote_issue_link">jira_create_remote_issue_link</a></td>
<td>❌</td>
<td>❌</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#getJiraIssueRemoteIssueLinks">getJiraIssueRemoteIssueLinks</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#getJiraProjectIssueTypesMetadata">getJiraProjectIssueTypesMetadata</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#jira_delete_issue">jira_delete_issue</a></td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
</tr>
<tr style="background-color: #ffffff;">
<td><em>Jira Project &amp; Board Operations</em></td>
<td></td>
<td></td>
<td></td>
<td></td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#jira_get_all_projects">jira_get_all_projects</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr><tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#getVisibleJiraProjects">getVisibleJiraProjects</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#jira_get_project_issues">jira_get_project_issues</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#jira_get_agile_boards">jira_get_agile_boards</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#jira_get_board_issues">jira_get_board_issues</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#jira_get_sprints_from_board">jira_get_sprints_from_board</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#jira_get_sprint_issues">jira_get_sprint_issues</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#jira_search_fields">jira_search_fields</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#jira_get_user_profile">jira_get_user_profile</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#lookupJiraAccountId">lookupJiraAccountId</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#atlassianuserinfo">atlassianUserInfo</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><em>Confluence Pages &amp; Content</em></td>
<td></td>
<td></td>
<td></td>
<td></td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#confluence_create_page">confluence_create_page</a></td>
<td rowspan="2">❌</td>
<td rowspan="2">❌</td>
<td rowspan="2">✅</td>
<td rowspan="2">✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#createconfluencepage">createConfluencePage</a></td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#confluence_get_page">confluence_get_page</a></td>
<td rowspan="2">✅</td>
<td rowspan="2">✅</td>
<td rowspan="2">✅</td>
<td rowspan="2">✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#getconfluencepage">getConfluencePage</a></td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#getconfluencepageancestors">getConfluencePageAncestors</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#confluence_update_page">confluence_update_page</a></td>
<td rowspan="2">❌</td>
<td rowspan="2">❌</td>
<td rowspan="2">✅</td>
<td rowspan="2">✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#updateconfluencepage">updateConfluencePage</a></td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#confluence_delete_page">confluence_delete_page</a></td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#confluence_get_page_children">confluence_get_page_children</a></td>
<td rowspan="2">✅</td>
<td rowspan="2">✅</td>
<td rowspan="2">✅</td>
<td rowspan="2">✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#getconfluencepagedescendants">getConfluencePageDescendants</a></td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#getconfluencepagefootercomments">getConfluencePageFooterComments</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#getconfluencepageinlinecomments">getConfluencePageInlineComments</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#confluence_search">confluence_search</a></td>
<td rowspan="2">✅</td>
<td rowspan="2">✅</td>
<td rowspan="2">✅</td>
<td rowspan="2">✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#searchconfluenceusingcql">searchConfluenceUsingCql</a></td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#confluence_get_comments">confluence_get_comments</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#confluence_add_comment">confluence_add_comment</a></td>
<td>❌</td>
<td>❌</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#createconfluencefootercomment">createConfluenceFooterComment</a></td>
<td>❌</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#createconfluenceinlinecomment">createConfluenceInlineComment</a></td>
<td>❌</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#confluence_get_labels">confluence_get_labels</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#confluence_add_label">confluence_add_label</a></td>
<td>❌</td>
<td>❌</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#getconfluencespaces">getConfluenceSpaces</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#getpagesinconfluencespace">getPagesInConfluenceSpace</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#confluence_search_user">confluence_search_user</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><strong>GitHub</strong></td>
<td></td>
<td></td>
<td></td>
<td></td>
</tr>
<tr style="background-color: #ffffff;">
<td><em>Commits &amp; Repository</em></td>
<td></td>
<td></td>
<td></td>
<td></td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#create_branch">create_branch</a></td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#create_repository">create_repository</a></td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
<td>✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#get_commit">get_commit</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#get_file_contents">get_file_contents</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#get_tag">get_tag</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#list_branches">list_branches</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#list_commits">list_commits</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#list_tags">list_tags</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#push_files">push_files</a></td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><em>Pull Requests  Retrieval</em></td>
<td></td>
<td></td>
<td></td>
<td></td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#get_pull_request">get_pull_request</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#get_pull_request_comments">get_pull_request_comments</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#get_pull_request_diff">get_pull_request_diff</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#get_pull_request_files">get_pull_request_files</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#get_pull_request_reviews">get_pull_request_reviews</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#get_pull_request_status">get_pull_request_status</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#list_pull_requests">list_pull_requests</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><em>Pull Requests  Actions</em></td>
<td></td>
<td></td>
<td></td>
<td></td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#add_comment_to_pending_review">add_comment_to_pending_review</a></td>
<td>❌</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#create_pending_pull_request_review">create_pending_pull_request_review</a></td>
<td>❌</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#create_pull_request">create_pull_request</a></td>
<td>❌</td>
<td>❌</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#create_pull_request_with_copilot">create_pull_request_with_copilot</a></td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
<td>✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#merge_pull_request">merge_pull_request</a></td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#request_copilot_review">request_copilot_review</a></td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#submit_pending_pull_request_review">submit_pending_pull_request_review</a></td>
<td>❌</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#update_pull_request">update_pull_request</a></td>
<td>❌</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#update_pull_request_branch">update_pull_request_branch</a></td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><em>Issues</em></td>
<td></td>
<td></td>
<td></td>
<td></td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#add_issue_comment">add_issue_comment</a></td>
<td>❌</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#create_issue">create_issue</a></td>
<td>❌</td>
<td>❌</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#get_issue">get_issue</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#get_issue_comments">get_issue_comments</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#list_issues">list_issues</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#search_issues">search_issues</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#update_issue">update_issue</a></td>
<td>❌</td>
<td>❌</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><em>Sub-Issues</em></td>
<td></td>
<td></td>
<td></td>
<td></td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#list_sub_issues">list_sub_issues</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#reprioritize_sub_issue">reprioritize_sub_issue</a></td>
<td>❌</td>
<td>❌</td>
<td>✅</td>
<td>❌</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><em>Gists</em></td>
<td></td>
<td></td>
<td></td>
<td></td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#list_gists">list_gists</a></td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#update_gist">update_gist</a></td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
</tr>
<tr style="background-color: #ffffff;">
<td><em>Notifications</em></td>
<td></td>
<td></td>
<td></td>
<td></td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#list_notifications">list_notifications</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><em>Code Scanning &amp; Security</em></td>
<td></td>
<td></td>
<td></td>
<td></td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#list_code_scanning_alerts">list_code_scanning_alerts</a></td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
</tr>
<tr style="background-color: #ffffff;">
<td><em>Workflows (GitHub Actions)</em></td>
<td></td>
<td></td>
<td></td>
<td></td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#get_workflow_run">get_workflow_run</a></td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#get_workflow_run_logs">get_workflow_run_logs</a></td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#get_workflow_run_usage">get_workflow_run_usage</a></td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#list_workflow_jobs">list_workflow_jobs</a></td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#list_workflow_run_artifacts">list_workflow_run_artifacts</a></td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#list_workflow_runs">list_workflow_runs</a></td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#list_workflows">list_workflows</a></td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#rerun_failed_jobs">rerun_failed_jobs</a></td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#rerun_workflow_run">rerun_workflow_run</a></td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
</tr>
<tr style="background-color: #ffffff;">
<td><em>Search &amp; Discovery</em></td>
<td></td>
<td></td>
<td></td>
<td></td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#search_code">search_code</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#search_orgs">search_orgs</a></td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#search_pull_requests">search_pull_requests</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#search_repositories">search_repositories</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#search_users">search_users</a></td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
</tr>
<tr style="background-color: #ffffff;">
<td><em>User &amp; Account</em></td>
<td></td>
<td></td>
<td></td>
<td></td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#get_me">get_me</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><em>Organization &amp; Teams</em></td>
<td></td>
<td></td>
<td></td>
<td></td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#get_teams">get_teams</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#get_team_members">get_team_members</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#list_issue_types">list_issue_types</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><em>File Operations</em></td>
<td></td>
<td></td>
<td></td>
<td></td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#create_or_update_file">create_or_update_file</a></td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><strong>Bitbucket</strong></td>
<td></td>
<td></td>
<td></td>
<td></td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><em>Workspaces</em></td>
<td></td>
<td></td>
<td></td>
<td></td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#bb_ls_workspaces">bb_ls_workspaces</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#bb_get_workspace">bb_get_workspace</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><em>Repositories</em></td>
<td></td>
<td></td>
<td></td>
<td></td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#bb_ls_repos">bb_ls_repos</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#bb_get_repo">bb_get_repo</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#bb_get_commit_history">bb_get_commit_history</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#bb_get_file">bb_get_file</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#bb_list_branches">bb_list_branches</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#bb_add_branch">bb_add_branch</a></td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
<td>✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#bb_clone_repo">bb_clone_repo</a></td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><em>Pull Requests</em></td>
<td></td>
<td></td>
<td></td>
<td></td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#bb_ls_prs">bb_ls_prs</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#bb_get_pr">bb_get_pr</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#bb_ls_pr_comments">bb_ls_pr_comments</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#bb_add_pr_comment">bb_add_pr_comment</a></td>
<td>❌</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#bb_add_pr">bb_add_pr</a></td>
<td>❌</td>
<td>❌</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#bb_update_pr">bb_update_pr</a></td>
<td>❌</td>
<td>❌</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#bb_approve_pr">bb_approve_pr</a></td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#bb_reject_pr">bb_reject_pr</a></td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
<td>❌</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><em>Search</em></td>
<td></td>
<td></td>
<td></td>
<td></td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#bb_search">bb_search</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><em>Diff</em></td>
<td></td>
<td></td>
<td></td>
<td></td>
</tr>
<tr style="background-color: #ffffff;">
<td><a href="TOOLS_GLOSSARY.md#bb_diff_branches">bb_diff_branches</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
<tr style="background-color: #f8f9fa;">
<td><a href="TOOLS_GLOSSARY.md#bb_diff_commits">bb_diff_commits</a></td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
<td>✅</td>
</tr>
</tbody>
</table>
