# repo-security-audit

[![skills.sh](https://skills.sh/b/hashtafak/repo-security-audit)](https://skills.sh/hashtafak/repo-security-audit)

A skill for AI coding agents that performs a **read-only, comprehensive security audit of an untrusted repository** before you run or install it — local path or GitHub URL.

It answers one question: **"Is this repo safe to run locally?"** — with `file:line` evidence, not guesses.

## What it detects

- **Malware & hostile code** — obfuscated payloads, encoded blobs, anti-analysis tricks, credential harvesting, C2-style network endpoints
- **Supply-chain attacks** — suspicious install scripts, deps resolved outside the registry, missing lockfile integrity, typosquats, committed binaries
- **Persistence & system tampering** — registry writes, scheduled tasks, startup entries, `fs.rmSync`/`Remove-Item` on attacker-controlled paths
- **RCE & injection surfaces** — unsafe `exec`/shell-string usage, `eval`/`new Function`, path traversal in archives
- **Desktop-app attack surface** — Electron `webPreferences`, IPC handlers trusting renderer input, `shell.openExternal` scheme abuse
- **Download-time integrity** — self-updaters fetching binaries without SHA-256/signature verification, third-party mirrors
- **Secrets** — credentials in working tree _and_ git history
- **Known vulnerabilities** — `npm audit` plus optional Semgrep/Trivy deep scans

## How it works

8 steps: inventory → dangerous-pattern grep groups → Electron/desktop deep dive → dependency & lockfile audit → secrets (code + git history) → optional SAST → download/install-time behavior → structured report.

Strict rules: read-only (never executes repo code), every finding needs a concrete exploit case, and the report ends with a `Not checked:` section listing unaudited scope.

## Install

```bash
npx skills add hashtafak/repo-security-audit@repo-security-audit
```

## Usage

Trigger it with prompts like:

- "security audit this repo"
- "is https://github.com/user/repo safe to run?"
- "scan this project for malware before I install it"

Works with any agent that supports the open Agent Skills format (`SKILL.md`), including Claude Code, Cursor, Codex, OpenCode, Windsurf, and others.

## License

MIT
