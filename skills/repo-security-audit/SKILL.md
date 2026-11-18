---
name: repo-security-audit
description: Comprehensive security audit of a repository (local path or GitHub URL) before running/installing it — detects malware, supply-chain attacks, dependency compromise, persistence, RCE, and real security vulnerabilities. Use when the user asks to "scan this repo", "security check", "audit security", "is it safe to run", or shares a GitHub link for review.
---

# repo-security-audit — Repository Security Audit

Standard audit workflow distilled from real scans. Goal: answer "is this repo safe to run locally?" with concrete evidence, not guesses.

## Principles

- **Read-only.** Never edit/delete files, never install packages, never execute repo binaries. Only read code, grep, `node --check`, `npm audit`.
- **Separate clearly:** (a) intentionally malicious code, (b) real security vulnerabilities, (c) risky-but-by-design behavior. Do not mix the three in the conclusion.
- Every conclusion must cite `file:line` evidence.

## Step 1 — Inventory

```bash
ls -la
cat package.json 2>/dev/null || cat Cargo.toml pyproject.toml go.mod 2>/dev/null
find . -type f \( -name "*.js" -o -name "*.ts" -o -name "*.py" -o -name "*.ps1" -o -name "*.sh" -o -name "*.bat" -o -name "*.exe" -o -name "*.dll" \) -not -path "./node_modules/*" -not -path "./.git/*" | head -100
```

Note: language, entry point, install/build scripts, bundled binaries, suspicious `.lnk`/shortcut files.

## Step 2 — Grep dangerous patterns

Run per group, one `rg` command each:

```bash
# Process execution / shell
rg -n "child_process|execSync|execFile|spawn\(|exec\(|os\.system|subprocess|shell=True|powershell|cmd\.exe /c" --glob '!node_modules'

# Dynamic code execution
rg -n "eval\(|new Function|Function\(|vm\.runIn|import\(.*\+|require\(.*\+" --glob '!node_modules'

# Persistence / registry / system write
rg -n "reg add|reg delete|HKLM|HKCU|schtasks|startup|Run\\\\|launchd|crontab|systemctl|rm -rf|fs\.rmSync|Remove-Item" --glob '!node_modules'

# Network endpoints
rg -no "https?://[^\"'\` )]+" --glob '!node_modules' | sort -u

# Obfuscation / encoded payloads
rg -n "FromBase64String|atob\(|\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|charCodeAt|payload" --glob '!node_modules'

# Credential / secret access
rg -n "password|passwd|secret|token|api[_-]?key|credential|\.ssh|id_rsa|cookie|wallet" --glob '!node_modules' -i

# Anti-analysis
rg -n "debugger|anti.?vm|sandbox|vmware|virtualbox|wireshark|procmon|IsDebuggerPresent" --glob '!node_modules' -i
```

For each match: read surrounding context, classify benign/malicious.

## Step 3 — Electron/desktop app deep dive (if applicable)

```bash
rg -n "webPreferences|nodeIntegration|contextIsolation|sandbox|webSecurity|loadURL|loadFile|openExternal|ipcMain\.(handle|on)|will-navigate|setWindowOpenHandler" src/
```

Checklist:
- `nodeIntegration: false` + `contextIsolation: true` + local files only = good.
- Every `ipcMain.handle` taking renderer input → check validation (especially handlers leading to `fs.rm`, `reg delete`, `spawn`, `openExternal`).
- `shell.openExternal(url)` must whitelist http(s) schemes.
- `sandbox: false` = record as a hardening weakness.
- Bundled `.ps1`/`.bat` files: read fully, look for download/exec/registry/persistence.

## Step 4 — Dependencies / supply chain

```bash
cat package.json | node -e "const p=require('./package.json');console.log(JSON.stringify({deps:p.dependencies,dev:p.devDependencies,scripts:p.scripts},null,2))"
# Lockfile: resolved URLs + integrity
node -e "const l=require('./package-lock.json');const pk=Object.entries(l.packages||{});const bad=pk.filter(([k,v])=>v.resolved&&!/registry\.npmjs\.org/.test(v.resolved));const noint=pk.filter(([k,v])=>v.resolved&&!v.integrity);const inst=pk.filter(([k,v])=>v.hasInstallScript);console.log({total:pk.length,nonNpm:bad,noint,inst})"
npm audit 2>&1 | tail -30
```

- Flag: deps resolving from odd git/http URLs, missing `integrity`, suspicious install scripts, typosquat names, outdated versions with known CVEs.
- Distinguish **runtime** vulns vs **build-time only** (devDependencies not shipped to users).
- Also check: committed `.exe/.dll` binaries (hash/inspect if needed), postinstall chains.

## Step 5 — Secrets in code and git history

```bash
# If gitleaks is installed (preferred — scans full history)
gitleaks detect --source . --no-banner 2>&1 | tail -30
# Fallback without gitleaks: scan history diffs for secret-shaped strings
git log -p --all 2>/dev/null | rg -n "(api[_-]?key|secret|token|password|BEGIN [A-Z ]*PRIVATE KEY)" | head -30
rg -n "(api[_-]?key|secret|token|password)\s*[:=]\s*['\"][^'\"]{8,}" --glob '!node_modules' --glob '!package-lock.json'
```

Flag: live-looking credentials committed to the repo (history counts — a "deleted" secret is still leaked). Distinguish real secrets from placeholders (`your-key-here`, `xxx`, env var names).

## Step 6 — Optional deep SAST (only if user wants more than triage)

Lightweight, read-only scanners — skip if not installed, do not install without asking:

```bash
# Semgrep — pattern-based SAST, best signal for injection/traversal
npx -y semgrep --config auto --metrics off <target-dir> 2>&1 | tail -40
# Trivy — vuln + misconfig + secret scan in one pass
trivy fs --severity HIGH,CRITICAL --scanners vuln,secret,misconfig <target-dir> 2>&1 | tail -40
```

Treat scanner output as leads, not verdicts: verify each finding by reading the code path before reporting. SAST noise is high on minified/bundled code — exclude `dist/`, `node_modules/`, vendored dirs.

## Step 7 — Download/install-time behavior

If the app self-downloads or self-updates, check:
- Download source URLs (third-party mirrors = risk).
- **Is there SHA-256/signature verification?** — `expectSha256`, `sha256File`, checksum manifest.
- Binary replacement mechanism (PowerShell encoded commands, silent install `/S`) — by-design but needs integrity.

## Step 8 — Report

Answer in the user's language, format:

```
## Quick verdict
| Category | Result |

## Strengths (with evidence)
## Risks/vulnerabilities (file:line + why dangerous + exploit scenario)
## Recommended actions
## Not checked
```

Reporting rules (borrowed from ponytail-audit):
- Every finding needs a concrete case: "this input or situation leads to this bad outcome". No case, no finding.
- Number findings so the user can reference them ("fix 2 and 5"). Cap at ~20; say how many smaller ones were left out.
- Before calling something dead/unused/unsafe, check the whole tree including tests, fixtures, config, and dynamic/string references.
- `Not checked:` lists parts you did not read or could not run — never silently skip scope.
- No style taste, no "consider", no vague worries.

## Environment workarounds (context-mode hook)

If the context-mode hook is active and output gets compressed:
- Files >~20KB: use `read` with `offset`+`limit` ~120 lines at a time, or `sed -n 'X,Yp'` via exec in <~5KB chunks.
- Exec output >~5-6KB gets trimmed to "best matching parts" — split commands into smaller ones.
- `mcp_call_tool` may drop arguments — prefer `exec`/`read`/`grep` directly.
- `node --check <file>` to syntax-verify after edits; run related test suites if present.

## Anti-patterns

- Do not conclude "safe" just because grep found nothing — read the main spawn/network/fs files.
- Do not flag every `exec`/`spawn` as malicious — an emulator manager naturally spawns processes; what matters is arg array vs shell string, and where the spawned binary comes from.
- Do not skip test/CI files and build scripts — they run on dev machines/CI with secrets.
