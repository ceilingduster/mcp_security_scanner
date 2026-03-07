"""Scanner -- the main public API for Orcorus repository scanner."""

import logging
import re
import shutil
import subprocess
from pathlib import Path
from typing import Optional

from openai import OpenAI

from src.models import ScanConfig, ScanResult
from src.analyzers import (
    run_bandit, detect_secrets, try_build, detect_tests,
    check_readme, check_dependency_file,
)
from src.ai_review import run_ai_review
from src.report import generate_security_md

log = logging.getLogger("orcorus_scanner")


class Scanner:
    """Orcorus Repository Scanner.

    Usage:
        scanner = Scanner(ScanConfig(api_key="sk-...", model="gpt-5.2"))
        result = scanner.scan("https://github.com/owner/repo")
        print(result.security_score, result.tier)
    """

    def __init__(self, config: Optional[ScanConfig] = None, **kwargs):
        if config is None:
            config = ScanConfig(**kwargs)
        self.config = config

        self.reports_dir = Path(config.reports_dir).resolve()
        self.work_dir = Path(config.work_dir).resolve()
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.work_dir.mkdir(parents=True, exist_ok=True)

        self._client: Optional[OpenAI] = None
        if config.api_key and not config.skip_ai:
            self._client = OpenAI(api_key=config.api_key, base_url=config.base_url)
            log.info(f"AI client initialized (model: {config.model}, base: {config.base_url})")

    def scan(
        self,
        repo_url: str,
        name: str = "",
        commit: str = "",
        subdir: str = "",
    ) -> ScanResult:
        """Scan a GitHub repository and return a security report.

        Args:
            repo_url: GitHub URL. Supports:
                - https://github.com/owner/repo
                - https://github.com/owner/repo/tree/commit/subdir
            name: Display name. Defaults to owner/repo from URL.
            commit: Commit hash. Auto-detected from URL.
            subdir: Subdirectory scope. Auto-detected from URL.

        Returns:
            ScanResult with findings, score, tier, and report path.
        """
        parsed_url, parsed_commit, parsed_subdir = _parse_github_url(repo_url)
        repo_url = parsed_url or repo_url
        commit = commit or parsed_commit
        subdir = subdir or parsed_subdir

        if not name:
            name = _repo_name_from_url(repo_url)

        result = ScanResult(name=name, repo_url=repo_url, commit=commit, subdir=subdir)
        safe_name = re.sub(r'[^\w\-.]', '_', name)
        repo_path = self.work_dir / safe_name
        report_dir = self.reports_dir / safe_name

        # 1. Clone
        log.info(f"[{name}] Cloning {repo_url} (commit: {commit or 'HEAD'})...")
        result.clone_success = _clone_repo(repo_url, commit, repo_path)
        if not result.clone_success:
            result.error = "Clone failed"
            return result

        scan_path = repo_path / subdir if subdir and (repo_path / subdir).exists() else repo_path

        # 2. Copy README
        readme_name = check_readme(scan_path) or check_readme(repo_path)
        result.has_readme = bool(readme_name)
        if readme_name:
            report_dir.mkdir(parents=True, exist_ok=True)
            src = (scan_path / readme_name) if (scan_path / readme_name).exists() else (repo_path / readme_name)
            dst = report_dir / readme_name
            shutil.copy2(src, dst)
            result.readme_path = dst
            log.info(f"[{name}] README saved to {dst}")

        # 3. Quality checks
        result.has_dependency_file = check_dependency_file(scan_path) or check_dependency_file(repo_path)
        result.has_tests, result.test_framework = detect_tests(scan_path)
        if not result.has_tests:
            result.has_tests, result.test_framework = detect_tests(repo_path)

        # 4. Static analysis
        log.info(f"[{name}] Running static analysis...")
        bandit_result = run_bandit(scan_path)
        result.bandit_issues = {
            "high": bandit_result["high"],
            "medium": bandit_result["medium"],
            "low": bandit_result["low"],
        }
        result.security_findings = bandit_result.get("findings", [])

        # 5. Secrets
        log.info(f"[{name}] Scanning for hardcoded secrets...")
        result.hardcoded_secrets = len(detect_secrets(scan_path))

        # 6. Build
        log.info(f"[{name}] Attempting build verification...")
        result.build_success, result.build_log = try_build(repo_path, subdir)

        # 7. AI review
        if self._client:
            log.info(f"[{name}] Starting AI security review...")
            result.ai_review = run_ai_review(
                client=self._client,
                model=self.config.model,
                repo_path=repo_path,
                check_path=scan_path,
                name=name,
                bandit_findings=result.security_findings,
                ai_timeout=self.config.ai_timeout,
                max_turns=self.config.max_agent_turns,
            )

        # 8. Score
        result.security_score = _calculate_score(result)
        result.tier = _classify_tier(result.security_score)

        # 9. Write report
        report_dir.mkdir(parents=True, exist_ok=True)
        security_md = generate_security_md(result)
        report_file = report_dir / "SECURITY.md"
        report_file.write_text(security_md)
        result.report_path = report_file
        log.info(f"[{name}] Score: {result.security_score}/100 -> {result.tier}")
        log.info(f"[{name}] Report: {report_file}")

        # 10. Cleanup
        if self.config.cleanup_repos and repo_path.exists():
            shutil.rmtree(repo_path)

        return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_github_url(url: str) -> tuple[str, str, str]:
    if not url:
        return ("", "", "")
    m = re.match(r'(https://github\.com/[^/]+/[^/]+)/tree/([^/]+)(?:/(.+))?', url)
    if m:
        return (m.group(1), m.group(2), m.group(3) or "")
    m2 = re.match(r'(https://github\.com/[^/]+/[^/]+)/?$', url)
    if m2:
        return (m2.group(1), "", "")
    return (url, "", "")


def _repo_name_from_url(url: str) -> str:
    m = re.match(r'https://github\.com/([^/]+)/([^/]+)', url)
    if m:
        return f"{m.group(1)}/{m.group(2)}"
    return url.rstrip("/").split("/")[-1] or "unknown"


def _clone_repo(repo_url: str, commit: str, dest: Path, timeout: int = 120) -> bool:
    if dest.exists():
        shutil.rmtree(dest)
    try:
        if not commit:
            subprocess.run(
                ["git", "clone", "--depth", "1", repo_url, str(dest)],
                capture_output=True, text=True, timeout=timeout, check=True,
            )
        else:
            subprocess.run(
                ["git", "clone", repo_url, str(dest)],
                capture_output=True, text=True, timeout=timeout, check=True,
            )
            subprocess.run(
                ["git", "checkout", commit],
                capture_output=True, text=True, timeout=30, check=True,
                cwd=str(dest),
            )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        log.warning(f"Clone failed for {repo_url}: {e}")
        return False


def _calculate_score(result: ScanResult) -> int:
    score = 100
    vuln_penalty = (
        result.bandit_issues.get("high", 0) * 15
        + result.bandit_issues.get("medium", 0) * 5
        + result.bandit_issues.get("low", 0) * 1
    )
    score -= min(vuln_penalty, 30)
    score -= min(result.hardcoded_secrets * 20, 20)
    if not result.build_success:
        score -= 10
    if not result.has_tests:
        score -= 5
    if not result.has_readme:
        score -= 5
    if not result.has_dependency_file:
        score -= 5

    ai_text = result.ai_review.lower()
    critical_mentions = len(re.findall(r'\bcritical\b.*?(?:vulnerabilit|injection|rce|deserializ)', ai_text))
    high_mentions = len(re.findall(r'\bhigh\b.*?(?:severity|risk)', ai_text))
    ai_penalty = critical_mentions * 25 + high_mentions * 10
    score -= min(ai_penalty, 15)

    return max(0, min(100, score))


def _classify_tier(score: int) -> str:
    if score >= 90:
        return "Gold"
    if score >= 75:
        return "Silver"
    if score >= 60:
        return "Bronze"
    return "Reject"
