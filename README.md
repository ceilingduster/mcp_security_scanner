# Orcorus Repository Scanner

A repository security scanner for GitHub repositories, available as both an MCP server and a CLI tool. Orcorus clones a repo, runs static analysis, detects hardcoded secrets, verifies the build, and performs an AI-powered OWASP-aligned security code review — producing a scored `SECURITY.md` report.

## Features

- **Static analysis** — Runs [Bandit](https://bandit.readthedocs.io/) on Python code to detect common vulnerabilities
- **Secrets detection** — Pattern-based scanning for API keys, tokens, private keys, and credentials
- **Build verification** — Attempts to build/install the project (supports Python, Node, Go, Rust)
- **Test detection** — Identifies test frameworks (pytest, jest, mocha, vitest, unittest)
- **AI security review** — Agentic, multi-turn code review that explores the codebase with tools (read files, search code, list directories) and produces an OWASP Top 10-aligned report. Two backends: any OpenAI-compatible LLM, or the [Claude Code](https://docs.anthropic.com/en/docs/claude-code) CLI driven in print mode
- **Scoring & tiering** — Assigns a 0–100 security score and classifies repos as Gold / Silver / Bronze / Reject
- **MCP server** — Exposes `scan_repo`, `get_report`, and `list_reports` tools via [FastMCP](https://github.com/jlowin/fastmcp)

## Project Structure

```
src/                   # Core library
  __init__.py          # Public API: Scanner, ScanConfig, ScanResult
  models.py            # Data models (ScanConfig, ScanResult)
  scanner.py           # Main scanning pipeline
  analyzers.py         # Bandit, secrets, build, test, and quality checks
  ai_review.py         # Agentic AI security review loop
  report.py            # SECURITY.md report generation
server.py              # MCP server (FastMCP)
scan_repo.py           # CLI client
```

## Quick Start

### CLI

```bash
# With AI review (GitHub repo)
python scan_repo.py https://github.com/owner/repo --api-key sk-...

# Without AI review
python scan_repo.py https://github.com/owner/repo --skip-ai

# Scan a local directory in-place (absolute --subdir path)
python scan_repo.py --name SSH-Command \
  --subdir /srv/docker/orcorus-integrations/ssh-command \
  --api-key sk-... --model gpt-5.4 --base-url https://api.cometapi.com/v1

# Scan current directory
python scan_repo.py .

# Custom model / provider
python scan_repo.py https://github.com/owner/repo \
  --model gpt-5.2 \
  --base-url https://api.openai.com/v1 \
  --api-key sk-...
```

### Claude Code CLI backend

If the `claude` CLI is installed and logged in, the scanner can hand the review to it instead of calling an API directly. Claude explores the checkout with its own read-only tools (Read, Grep, Glob, LS); no API key is needed.

```bash
python scan_repo.py https://github.com/owner/repo --ai-backend claude-cli            # model: sonnet
python scan_repo.py https://github.com/owner/repo --ai-backend claude-cli --model opus
python scan_repo.py https://github.com/owner/repo --ai-backend claude-cli \
  --ai-timeout 900 --max-budget-usd 2 --json-out result.json
```

How the CLI is invoked, and why:

- `claude -p --output-format json` with the prompt on stdin; the JSON result carries the report plus cost and turn counts, which land in `ScanResult.ai_cost_usd` / `ai_turns`.
- Tools are restricted to `Read,Grep,Glob,LS` via `--tools` / `--allowedTools`, and `Bash`, `Edit`, `Write`, web and agent tools are disallowed, so the reviewer can only look.
- `--setting-sources user` and `--strict-mcp-config` stop a scanned repository's own `.claude/settings.json`, hooks or MCP config from being honoured. The system prompt also tells the model to treat `CLAUDE.md`, `AGENTS.md` and READMEs in the repo as untrusted evidence.
- `--ai-timeout` bounds the whole review for this backend (default 900s). `--max-turns` and `--max-budget-usd` are passed through when the installed CLI supports them.
- Nested-session environment variables (`CLAUDECODE`, `CLAUDE_CODE_*`) are stripped so a scan can be launched from inside a Claude Code session.

Set `ORCORUS_AI_BACKEND=claude-cli` (and optionally `ORCORUS_CLAUDE_BIN`, `ORCORUS_MODEL`, `ORCORUS_MAX_BUDGET_USD`) to use the same backend from the MCP server. The Docker image does not ship the Claude CLI; this backend is meant for host runs.

### MCP Server

```bash
python server.py
# or
fastmcp run server.py
```

The server exposes three tools:

| Tool | Description |
|------|-------------|
| `scan_repo` | Scan a GitHub repo (runs as a background task) |
| `get_report` | Retrieve a completed SECURITY.md report by name |
| `list_reports` | List all available scan reports with scores |

## MCP Client Setup

### VS Code / Claude Code (`settings.json`)

Add the following to your MCP `settings.json` to run Orcorus as a Docker container:

```json
{
  "mcpServers": {
    "scanner": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-e", "OPENAI_API_KEY=sk-your-api-key-here",
        "-e", "ORCORUS_MODEL=gpt-5.2",
        "-e", "OPENAI_BASE_URL=https://api.openai.com/v1",
        "-e", "ORCORUS_REPORTS_DIR=/app/reports",
        "-e", "ORCORUS_WORK_DIR=/app/repos",
        "-e", "ORCORUS_AI_TIMEOUT=300",
        "-e", "ORCORUS_MAX_TURNS=40",
        "orcorus/security_scanner:latest"
      ]
    }
  }
}
```

To persist reports between runs, mount a volume:

```json
{
  "mcpServers": {
    "scanner": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-e", "OPENAI_API_KEY=sk-your-api-key-here",
        "-e", "ORCORUS_MODEL=gpt-5.2",
        "-e", "OPENAI_BASE_URL=https://api.openai.com/v1",
        "-v", "/path/to/local/reports:/app/reports",
        "orcorus/security_scanner:latest"
      ]
    }
  }
}
```

To skip AI review (static analysis only), add `-e`, `"ORCORUS_SKIP_AI=true"` to the args.

## Configuration

### CLI Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `repo_url` | `.` | GitHub repository URL or local path (ignored when `--subdir` is absolute) |
| `--name` | auto-detected | Display name for the report |
| `--commit` | HEAD | Specific commit to checkout |
| `--subdir` | *(none)* | Subdirectory scope, **or an absolute path** to scan a directory in-place without cloning |
| `--ai-backend` | `$ORCORUS_AI_BACKEND` or `openai` | `openai` (API with tool calling) or `claude-cli` (Claude Code CLI in print mode) |
| `--claude-bin` | `claude` | Claude CLI executable name for `claude-cli` |
| `--max-budget-usd` | `0` | Spend cap per review for `claude-cli` (0 = none) |
| `--api-key` | `$OPENAI_API_KEY` | API key for the LLM provider (`openai` backend) |
| `--model` | `gpt-5.2` / `sonnet` | Model to use for AI review (default depends on backend) |
| `--base-url` | `https://api.openai.com/v1` | OpenAI-compatible API base URL |
| `--reports-dir` | `./reports` | Directory to save reports |
| `--work-dir` | `./repos` | Where repositories are cloned |
| `--json-out` | *(none)* | Also write the ScanResult as JSON to this path |
| `--ai-timeout` | `300` / `900` | Timeout per AI call (`openai`) or for the whole review (`claude-cli`) |
| `--max-turns` | `40` | Max agentic review turns |
| `--skip-ai` | `false` | Skip the AI review step |
| `--keep-repo` | `false` | Keep the cloned repo after scanning |

### Environment Variables (MCP Server)

| Variable | Default | Description |
|----------|---------|-------------|
| `ORCORUS_AI_BACKEND` | `openai` | `openai` or `claude-cli` |
| `ORCORUS_CLAUDE_BIN` | `claude` | Claude CLI executable for `claude-cli` |
| `ORCORUS_MAX_BUDGET_USD` | `0` | Spend cap per review for `claude-cli` |
| `OPENAI_API_KEY` | *(none)* | API key for AI review (`openai` backend) |
| `ORCORUS_MODEL` | `gpt-5.2` / `sonnet` | LLM model name |
| `OPENAI_BASE_URL` | `https://api.openai.com/v1` | API base URL |
| `ORCORUS_REPORTS_DIR` | `./reports` | Reports output directory |
| `ORCORUS_WORK_DIR` | `./repos` | Temporary clone directory |
| `ORCORUS_AI_TIMEOUT` | `300` | Timeout per AI call (seconds) |
| `ORCORUS_MAX_TURNS` | `40` | Max agentic review turns |
| `ORCORUS_SKIP_AI` | `false` | Set to `1` or `true` to skip AI review |
| `ORCORUS_ALLOW_LOCAL_PATHS` | `false` | Set to `1` or `true` to allow scanning local filesystem paths via MCP |

## Scoring

| Score | Tier |
|-------|------|
| 90–100 | Gold |
| 75–89 | Silver |
| 60–74 | Bronze |
| 0–59 | Reject |

Deductions are applied for high/medium/low Bandit findings, hardcoded secrets, build failures, missing tests, missing README, missing dependency files, and critical/high severity issues found during AI review.

## Dependencies

- Python 3.10+
- [openai](https://pypi.org/project/openai/) — LLM client (only for the `openai` backend; imported lazily)
- [Claude Code CLI](https://docs.anthropic.com/en/docs/claude-code) — only for the `claude-cli` backend
- [fastmcp](https://github.com/jlowin/fastmcp) — MCP server framework
- [bandit](https://pypi.org/project/bandit/) — Python static analysis (optional, for security scanning)
- git — for cloning repositories
