"""Data models for scan results and configuration."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

AI_BACKENDS = ("openai", "claude-cli")


@dataclass
class ScanConfig:
    """Configuration for the scanner."""
    api_key: str = ""
    model: str = "gpt-5.2"
    base_url: str = "https://api.openai.com/v1"
    reports_dir: str = "./reports"
    work_dir: str = "./repos"
    ai_timeout: int = 300
    max_agent_turns: int = 40
    skip_ai: bool = False
    cleanup_repos: bool = True
    allow_dangerous_builds: bool = False
    include_build_logs: bool = False
    allow_local_paths: bool = True
    # AI backend: "openai" (OpenAI-compatible chat completions with tool calling)
    # or "claude-cli" (drive the Claude Code CLI in print mode; it explores the
    # checkout with its own read-only tools). The CLI backend needs no API key,
    # it uses whatever login the `claude` binary already has.
    ai_backend: str = "openai"
    claude_bin: str = "claude"
    # Optional hard spend cap per review for the claude-cli backend (0 = none).
    max_budget_usd: float = 0.0


@dataclass
class ScanResult:
    """Result of scanning a single repository."""
    name: str
    repo_url: str
    commit: str = ""
    subdir: str = ""
    clone_success: bool = False
    build_attempted: bool = False
    build_success: bool = False
    build_skipped_reason: str = ""
    bandit_issues: dict = field(default_factory=lambda: {"high": 0, "medium": 0, "low": 0})
    hardcoded_secrets: int = 0
    has_tests: bool = False
    has_readme: bool = False
    has_dependency_file: bool = False
    security_findings: list = field(default_factory=list)
    ai_review: str = ""
    ai_backend: str = ""
    ai_model: str = ""
    ai_cost_usd: float = 0.0
    ai_turns: int = 0
    security_score: int = 0
    tier: str = "Reject"
    build_log: str = ""
    test_framework: str = ""
    report_path: Optional[Path] = None
    readme_path: Optional[Path] = None
    error: str = ""
