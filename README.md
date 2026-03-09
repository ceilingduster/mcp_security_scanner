# Orcorus Repository Scanner

A repository security scanner for GitHub repositories, available as both an MCP server and a CLI tool. Orcorus clones a repo, runs static analysis, detects hardcoded secrets, verifies the build, and performs an AI-powered OWASP-aligned security code review — producing a scored `SECURITY.md` report.

## Features

- **Static analysis** — Runs [Bandit](https://bandit.readthedocs.io/) on Python code to detect common vulnerabilities
- **Secrets detection** — Pattern-based scanning for API keys, tokens, private keys, and credentials
- **Build verification** — Attempts to build/install the project (supports Python, Node, Go, Rust)
- **Test detection** — Identifies test frameworks (pytest, jest, mocha, vitest, unittest)
- **AI security review** — Agentic, multi-turn code review using an OpenAI-compatible LLM that explores the codebase with tools (read files, search code, list directories) and produces an OWASP Top 10-aligned report
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
| `--api-key` | `$OPENAI_API_KEY` | API key for the LLM provider |
| `--model` | `gpt-5.2` | Model to use for AI review |
| `--base-url` | `https://api.openai.com/v1` | OpenAI-compatible API base URL |
| `--reports-dir` | `./reports` | Directory to save reports |
| `--ai-timeout` | `300` | Timeout per AI call (seconds) |
| `--max-turns` | `40` | Max agentic review turns |
| `--skip-ai` | `false` | Skip the AI review step |
| `--keep-repo` | `false` | Keep the cloned repo after scanning |

### Environment Variables (MCP Server)

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENAI_API_KEY` | *(none)* | API key for AI review |
| `ORCORUS_MODEL` | `gpt-5.2` | LLM model name |
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
- [openai](https://pypi.org/project/openai/) — LLM client
- [fastmcp](https://github.com/jlowin/fastmcp) — MCP server framework
- [bandit](https://pypi.org/project/bandit/) — Python static analysis (optional, for security scanning)
- git — for cloning repositories
