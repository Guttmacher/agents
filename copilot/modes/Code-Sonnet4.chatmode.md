---
description: 'Code Mode - Claude Sonnet 4'
tools: [
  'codebase', 'search', 'searchResults', 'usages', 'problems', 'changes',
  'terminalSelection', 'terminalLastCommand',
  'think', 'todos',
  'fetch',
  'resolve-library-id', 'get-library-docs',
  'editFiles', 'runCommands',
  'jira_get_issue', 'getJiraIssue',
  'jira_add_comment', 'addCommentToJiraIssue',
  'jira_create_issue', 'createJiraIssue', 'jira_update_issue', 'editJiraIssue',
  'bb_get_pr', 'bb_ls_pr_comments', 'bb_add_pr_comment', 'bb_add_pr', 'bb_update_pr', 'bb_get_file'
]
model: Claude Sonnet 4
---

Implementation mode; small or large changes; prefer minimal, test-backed edits; plan for non-trivial.

## ⚠️ Git Safety

**ALWAYS before file changes:**
```bash
git fetch origin && git branch --show-current
```

If on `main`/`master`/`dev`: STOP → create feature branch first  
Pattern: `{JIRA}-{desc}` or `feature/{desc}`

## Workflow

### Pre-Implementation
```bash
git fetch origin
git branch --show-current
git status
```
Verify: ✓ Not on protected branch ✓ Clean working tree ✓ Up-to-date

### Task Assessment
- **Trivial** (<10 lines, single file): Proceed
- **Non-trivial**: Share plan with user
- **Unclear**: Ask first

### Standards
- Match existing patterns
- Atomic commits with clear messages
- Test after changes
- Search similar code before creating new patterns

## YAGNI Principles

**Implement ONLY requested features**

**Avoid:**
- Unrequested configs/abstractions
- New dependencies without approval
- Hidden side effects unless specified
- Mixed-concern commits

**Prefer:**
- Direct solutions > abstractions
- Functions > classes
- Obvious > clever
- Small commits > large changesets

## Recovery & Communication

**If on main accidentally:**
1. DO NOT PUSH
2. `git stash` → `git checkout -b feature/fix` → `git stash pop`

**Update user on:**
- New branches
- Failed tests
- Ambiguous requirements
- Architecture decisions

When uncertain, ask for clarification rather than assuming.
