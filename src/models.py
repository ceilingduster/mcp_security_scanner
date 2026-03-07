"""Data models for scan results and configuration."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class ScanConfig:
    """Configuration for the scanner."""
    api_key: str = ""
    model: str = "gpt-5.2"
    base_url: str = "https://api.openai.com/v1"
    reports_dir: str = "./reports"
    work_dir: str = "./repos"
    ai_timeout: int = 300
    max_agent_turns: int = 20
    skip_ai: bool = False
    cleanup_repos: bool = True


@dataclass
class ScanResult:
    """Result of scanning a single repository."""
    name: str
    repo_url: str
    commit: str = ""
    subdir: str = ""
    clone_success: bool = False
    build_success: bool = False
    bandit_issues: dict = field(default_factory=lambda: {"high": 0, "medium": 0, "low": 0})
    hardcoded_secrets: int = 0
    has_tests: bool = False
    has_readme: bool = False
    has_dependency_file: bool = False
    security_findings: list = field(default_factory=list)
    ai_review: str = ""
    security_score: int = 0
    tier: str = "Reject"
    build_log: str = ""
    test_framework: str = ""
    report_path: Optional[Path] = None
    readme_path: Optional[Path] = None
    error: str = ""
