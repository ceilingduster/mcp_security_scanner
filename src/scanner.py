"""Scanner -- the main public API for Orcorus repository scanner."""

import logging
import re
import shutil
import subprocess
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from openai import OpenAI

from src.models import ScanConfig, ScanResult
from src.analyzers import (
    run_bandit, detect_secrets, try_build, detect_tests,
    check_readme, check_dependency_file,
)
from src.ai_review import run_ai_review
from src.report import generate_security_md
from src.subprocess_utils import run_safe

log = logging.getLogger("orcorus_scanner")
LOCAL_COPY_IGNORE_NAMES = {
    ".git", ".venv", "venv", "__pycache__", ".tox", "node_modules", "dist", "build"
}


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
        """Scan a GitHub repository or local directory and return a security report.

        Args:
            repo_url: GitHub URL or local path. Supports:
                - https://github.com/owner/repo
                - https://github.com/owner/repo/tree/commit/subdir
                - A local filesystem path (e.g. "." or "/path/to/project")
            name: Display name. Defaults to owner/repo from URL or directory name.
            commit: Commit hash. Auto-detected from URL.
            subdir: Subdirectory scope, or an absolute path to scan directly.
                When an absolute path is given the scanner reads from that
                directory in-place — no clone or copy is performed.

        Returns:
            ScanResult with findings, score, tier, and report path.
        """
        # --- Direct subdir scan (absolute path) ---
        is_direct_subdir = subdir and Path(subdir).is_absolute()
        if is_direct_subdir:
            direct_path = Path(subdir).resolve()
            if not direct_path.exists() or not direct_path.is_dir():
                auto_named = not name
                if auto_named:
                    name = direct_path.name or "unknown"
                result = ScanResult(name=name, repo_url=str(direct_path), subdir=subdir)
                result.error = f"Subdir path does not exist or is not a directory: {direct_path}"
                log.warning(f"[{result.name}] {result.error}")
                return result

            auto_named = not name
            if auto_named:
                name = direct_path.name or "local-project"
            result = ScanResult(name=name, repo_url=str(direct_path), commit="local", subdir=subdir)

            safe_paths = _derive_scan_paths(name, self.work_dir, self.reports_dir)
            if not safe_paths:
                result.error = "Invalid repository name. Use letters, numbers, dots, dashes, and underscores."
                log.warning(f"[{result.name}] Rejected invalid name: {name!r}")
                return result
            _, _, report_dir = safe_paths

            log.info(f"[{result.name}] Scanning directory in-place: {direct_path}")
            result.clone_success = True
            repo_path = direct_path
            scan_path = direct_path
            effective_subdir = ""
            result.subdir = subdir
            owns_repo_path = False
        else:
            # --- Normal flow (clone / stage) ---
            owns_repo_path = True
            parsed_url, parsed_commit, parsed_subdir = _parse_github_url(repo_url)
            repo_url = parsed_url or repo_url
            commit = commit or parsed_commit
            subdir = subdir or parsed_subdir

            auto_named = not name
            if auto_named:
                name = _repo_name_from_url(repo_url)

            result = ScanResult(name=name, repo_url=repo_url, commit=commit, subdir=subdir)
            safe_paths = _derive_scan_paths(name, self.work_dir, self.reports_dir)
            if not safe_paths:
                result.error = "Invalid repository name. Use letters, numbers, dots, dashes, and underscores."
                log.warning(f"[{result.name}] Rejected invalid repository name: {name!r}")
                return result
            _, repo_path, report_dir = safe_paths

            local_source = Path(repo_url).expanduser()
            is_local_path = local_source.exists() and local_source.is_dir()

            # 1. Stage source
            if is_local_path:
                if not self.config.allow_local_paths:
                    result.error = "Local repository paths are disabled for this scanner."
                    log.warning(f"[{result.name}] Rejected local path scan: {repo_url}")
                    return result
                source_path = local_source.resolve()
                if auto_named:
                    result.name = source_path.name or "local-project"
                    safe_paths = _derive_scan_paths(result.name, self.work_dir, self.reports_dir)
                    if not safe_paths:
                        result.error = "Invalid repository name derived from local path."
                        log.warning(f"[{result.name}] Rejected derived repository name: {result.name!r}")
                        return result
                    _, repo_path, report_dir = safe_paths
                log.info(f"[{result.name}] Staging local project from {source_path}...")
                result.repo_url = str(source_path)
                result.clone_success = _stage_local_repo(source_path, repo_path)
                result.commit = "local"
            else:
                if not _is_allowed_remote_repo_url(repo_url):
                    result.error = "Disallowed repository URL. Only HTTPS GitHub owner/repo URLs are allowed."
                    log.warning(f"[{result.name}] Rejected disallowed repository URL: {repo_url}")
                    return result
                log.info(f"[{result.name}] Cloning {repo_url} (commit: {commit or 'HEAD'})...")
                result.clone_success = _clone_repo(repo_url, commit, repo_path)

            if not result.clone_success:
                result.error = "Clone failed" if not is_local_path else f"Local path staging failed: {repo_url}"
                return result

            scan_path = _resolve_scan_path(repo_path, subdir)
            if scan_path is None:
                result.error = "Invalid subdir. Subdir must stay within the repository."
                log.warning(f"[{result.name}] Rejected unsafe subdir: {subdir!r}")
                if self.config.cleanup_repos and repo_path.exists():
                    shutil.rmtree(repo_path)
                result.clone_success = False
                return result
            effective_subdir = "" if scan_path == repo_path else str(scan_path.relative_to(repo_path))
            result.subdir = effective_subdir

        # 2. Copy README
        readme_name = check_readme(scan_path) or check_readme(repo_path)
        result.has_readme = bool(readme_name)
        if readme_name:
            report_dir.mkdir(parents=True, exist_ok=True)
            src = (scan_path / readme_name) if (scan_path / readme_name).exists() else (repo_path / readme_name)
            dst = report_dir / readme_name
            shutil.copy2(src, dst)
            result.readme_path = dst
            log.info(f"[{result.name}] README saved to {dst}")

        # 3. Quality checks
        result.has_dependency_file = check_dependency_file(scan_path) or check_dependency_file(repo_path)
        result.has_tests, result.test_framework = detect_tests(scan_path)
        if not result.has_tests:
            result.has_tests, result.test_framework = detect_tests(repo_path)

        # 4. Static analysis
        log.info(f"[{result.name}] Running static analysis...")
        bandit_result = run_bandit(scan_path)
        result.bandit_issues = {
            "high": bandit_result["high"],
            "medium": bandit_result["medium"],
            "low": bandit_result["low"],
        }
        result.security_findings = bandit_result.get("findings", [])

        # 5. Secrets
        log.info(f"[{result.name}] Scanning for hardcoded secrets...")
        result.hardcoded_secrets = len(detect_secrets(scan_path))

        # 6. Build
        if self.config.allow_dangerous_builds:
            log.info(f"[{result.name}] Attempting build verification...")
            result.build_attempted = True
            result.build_success, build_log = try_build(repo_path, effective_subdir)
            result.build_log = build_log if self.config.include_build_logs else ""
        else:
            result.build_attempted = False
            result.build_success = False
            result.build_skipped_reason = (
                "Build step skipped by default for safety. "
                "Enable allow_dangerous_builds to run untrusted build commands."
            )
            result.build_log = ""

        # 7. AI review
        if self._client:
            log.info(f"[{result.name}] Starting AI security review...")
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
        log.info(f"[{result.name}] Score: {result.security_score}/100 -> {result.tier}")
        log.info(f"[{result.name}] Report: {report_file}")

        # 10. Cleanup (never remove a direct --subdir path we don't own)
        if owns_repo_path and self.config.cleanup_repos and repo_path.exists():
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


def _is_allowed_remote_repo_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
    except ValueError:
        return False

    if parsed.scheme != "https":
        return False
    if parsed.hostname not in {"github.com", "www.github.com"}:
        return False
    if parsed.username or parsed.password:
        return False
    if parsed.query or parsed.fragment:
        return False

    path = (parsed.path or "").rstrip("/")
    return bool(re.fullmatch(r"/[^/]+/[^/]+(?:\.git)?", path))


def _repo_name_from_url(url: str) -> str:
    m = re.match(r'https://github\.com/([^/]+)/([^/]+)', url)
    if m:
        return f"{m.group(1)}/{m.group(2)}"
    return url.rstrip("/").split("/")[-1] or "unknown"


def _derive_scan_paths(name: str, work_dir: Path, reports_dir: Path) -> tuple[str, Path, Path] | None:
    safe_name = _sanitize_scan_name(name)
    if not safe_name:
        return None
    repo_path = _resolve_within_base(work_dir, safe_name)
    report_dir = _resolve_within_base(reports_dir, safe_name)
    if not repo_path or not report_dir:
        return None
    return safe_name, repo_path, report_dir


def _sanitize_scan_name(name: str) -> str:
    safe_name = re.sub(r"[^\w\-.]", "_", name).strip("._")
    if not safe_name or safe_name in {".", ".."}:
        return ""
    return safe_name


def _resolve_within_base(base_dir: Path, rel_path: str) -> Path | None:
    candidate = (base_dir / rel_path).resolve()
    try:
        candidate.relative_to(base_dir.resolve())
    except ValueError:
        return None
    return candidate


def _resolve_scan_path(repo_path: Path, subdir: str) -> Path | None:
    if not subdir:
        return repo_path
    rel_subdir = Path(subdir)
    if rel_subdir.is_absolute():
        return None
    candidate = (repo_path / rel_subdir).resolve()
    try:
        candidate.relative_to(repo_path.resolve())
    except ValueError:
        return None
    if candidate.exists() and candidate.is_dir():
        return candidate
    return repo_path


def _clone_repo(repo_url: str, commit: str, dest: Path, timeout: int = 120) -> bool:
    if dest.exists():
        shutil.rmtree(dest)
    try:
        if not commit:
            run_safe(
                ["git", "clone", "--depth", "1", repo_url, str(dest)],
                capture_output=True, text=True, timeout=timeout, check=True,
            )
        else:
            run_safe(
                ["git", "clone", repo_url, str(dest)],
                capture_output=True, text=True, timeout=timeout, check=True,
            )
            run_safe(
                ["git", "checkout", commit],
                capture_output=True, text=True, timeout=30, check=True,
                cwd=str(dest),
            )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError, ValueError) as e:
        log.warning(f"Clone failed for {repo_url}: {e}")
        return False


def _stage_local_repo(source: Path, dest: Path) -> bool:
    if not source.exists() or not source.is_dir():
        log.warning(f"Local source path does not exist or is not a directory: {source}")
        return False
    if dest.exists():
        shutil.rmtree(dest)
    try:
        ignored_names = set(LOCAL_COPY_IGNORE_NAMES)
        try:
            rel_dest = dest.resolve().relative_to(source.resolve())
            if rel_dest.parts:
                ignored_names.add(rel_dest.parts[0])
        except ValueError:
            pass

        def _ignore(_dir: str, names: list[str]) -> set[str]:
            return {name for name in names if name in ignored_names}

        shutil.copytree(source, dest, ignore=_ignore)
        return True
    except OSError as e:
        log.warning(f"Failed staging local path {source}: {e}")
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
    if result.build_attempted and not result.build_success:
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
