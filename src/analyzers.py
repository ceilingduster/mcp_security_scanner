"""Static analysis, secrets detection, build verification, and code quality checks."""

import json
import logging
import os
import re
import subprocess
from pathlib import Path

from src.subprocess_utils import run_safe

log = logging.getLogger("orcorus")

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", "dist", "build"}
SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".java", ".rb",
    ".yaml", ".yml", ".json", ".toml", ".cfg", ".ini", ".env", ".sh",
}

SECRET_PATTERNS = [
    re.compile(r'(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|password|passwd)\s*[=:]\s*["\'][A-Za-z0-9+/=_\-]{16,}["\']', re.IGNORECASE),
    re.compile(r'(?:sk-[a-zA-Z0-9]{20,})', re.IGNORECASE),
    re.compile(r'(?:ghp_[a-zA-Z0-9]{36,})'),
    re.compile(r'(?:glpat-[a-zA-Z0-9\-_]{20,})'),
    re.compile(r'(?:AKIA[0-9A-Z]{16})'),
    re.compile(r'(?:-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----)'),
]
BUILD_LOG_REDACTIONS = [
    re.compile(r"(sk-[a-zA-Z0-9]{20,})", re.IGNORECASE),
    re.compile(r"(ghp_[a-zA-Z0-9]{36,})"),
    re.compile(r"(glpat-[a-zA-Z0-9\-_]{20,})"),
    re.compile(r"(AKIA[0-9A-Z]{16})"),
    re.compile(r"((?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|password|passwd)\s*[=:]\s*['\"][^'\"]+['\"])", re.IGNORECASE),
]
MAX_BUILD_LOG_CHARS = 1200


# ---------------------------------------------------------------------------
# Bandit
# ---------------------------------------------------------------------------

def run_bandit(scan_path: Path) -> dict:
    """Run bandit on Python files and return issue counts + findings."""
    result = {"high": 0, "medium": 0, "low": 0, "findings": []}

    py_files = list(scan_path.rglob("*.py"))
    if not py_files:
        return result

    try:
        proc = run_safe(
            ["bandit", "-r", str(scan_path), "-f", "json", "-q",
             "--exclude", ".venv,venv,node_modules,.git,__pycache__"],
            capture_output=True, text=True, timeout=120,
        )
        if proc.stdout:
            data = json.loads(proc.stdout)
            for issue in data.get("results", []):
                severity = issue.get("issue_severity", "LOW").lower()
                if severity in result:
                    result[severity] += 1
                result["findings"].append({
                    "severity": severity,
                    "issue": issue.get("issue_text", ""),
                    "file": os.path.relpath(issue.get("filename", ""), scan_path),
                    "line": issue.get("line_number", 0),
                    "confidence": issue.get("issue_confidence", ""),
                })
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError, ValueError) as e:
        log.warning(f"Bandit failed on {scan_path}: {e}")

    return result


# ---------------------------------------------------------------------------
# Secrets detection
# ---------------------------------------------------------------------------

def detect_secrets(scan_path: Path) -> list[dict]:
    """Pattern-based secrets detection."""
    findings = []
    for root, dirs, files in os.walk(scan_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in files:
            fpath = Path(root) / fname
            if fpath.suffix not in SCAN_EXTENSIONS:
                continue
            try:
                content = fpath.read_text(errors="ignore")
                for i, line in enumerate(content.splitlines(), 1):
                    for pat in SECRET_PATTERNS:
                        if pat.search(line):
                            rel = os.path.relpath(fpath, scan_path)
                            if any(x in rel.lower() for x in ["test", "example", "mock", "fixture", "sample"]):
                                continue
                            findings.append({
                                "file": rel,
                                "line": i,
                                "pattern": pat.pattern[:50],
                            })
            except (OSError, UnicodeDecodeError):
                continue
    return findings


# ---------------------------------------------------------------------------
# Build verification
# ---------------------------------------------------------------------------

def detect_project_type(repo_path: Path, subdir: str = "") -> str:
    check_path = repo_path / subdir if subdir else repo_path

    if (check_path / "package.json").exists():
        return "node"
    if (check_path / "pyproject.toml").exists():
        return "python-pyproject"
    if (check_path / "setup.py").exists():
        return "python-setup"
    if (check_path / "requirements.txt").exists():
        return "python-requirements"
    if (check_path / "Cargo.toml").exists():
        return "rust"
    if (check_path / "go.mod").exists():
        return "go"

    if subdir:
        return detect_project_type(repo_path, "")

    return "unknown"


def try_build(repo_path: Path, subdir: str = "") -> tuple[bool, str]:
    """Attempt to build/install the project. Returns (success, log)."""
    work_dir = repo_path / subdir if subdir else repo_path
    if not work_dir.exists():
        work_dir = repo_path

    project_type = detect_project_type(repo_path, subdir)
    log_output = f"Project type: {project_type}\n"

    try:
        if project_type == "node":
            lock = "yarn.lock" if (work_dir / "yarn.lock").exists() else None
            if lock:
                proc = run_safe(
                    ["yarn", "install", "--frozen-lockfile"],
                    capture_output=True, text=True, timeout=180, cwd=str(work_dir),
                )
            else:
                proc = run_safe(
                    ["npm", "install", "--ignore-scripts"],
                    capture_output=True, text=True, timeout=180, cwd=str(work_dir),
                )
            log_output += proc.stdout[-500:] + proc.stderr[-500:]
            if proc.returncode == 0:
                pkg = json.loads((work_dir / "package.json").read_text())
                if "build" in pkg.get("scripts", {}):
                    proc2 = run_safe(
                        ["npm", "run", "build"],
                        capture_output=True, text=True, timeout=180, cwd=str(work_dir),
                    )
                    log_output += proc2.stdout[-500:] + proc2.stderr[-500:]
                    return proc2.returncode == 0, _sanitize_build_log(log_output)
            return proc.returncode == 0, _sanitize_build_log(log_output)

        elif project_type.startswith("python"):
            if project_type == "python-requirements":
                proc = run_safe(
                    ["pip3", "install", "--break-system-packages", "--dry-run",
                     "-r", "requirements.txt"],
                    capture_output=True, text=True, timeout=120, cwd=str(work_dir),
                )
            else:
                proc = run_safe(
                    ["pip3", "install", "--break-system-packages", "--dry-run", "."],
                    capture_output=True, text=True, timeout=120, cwd=str(work_dir),
                )
            log_output += proc.stdout[-500:] + proc.stderr[-500:]
            return proc.returncode == 0, _sanitize_build_log(log_output)

        elif project_type == "go":
            proc = run_safe(
                ["go", "build", "./..."],
                capture_output=True, text=True, timeout=180, cwd=str(work_dir),
            )
            log_output += proc.stdout[-500:] + proc.stderr[-500:]
            return proc.returncode == 0, _sanitize_build_log(log_output)

        elif project_type == "rust":
            proc = run_safe(
                ["cargo", "check"],
                capture_output=True, text=True, timeout=300, cwd=str(work_dir),
            )
            log_output += proc.stdout[-500:] + proc.stderr[-500:]
            return proc.returncode == 0, _sanitize_build_log(log_output)

        else:
            log_output += "Unknown project type, skipping build.\n"
            return False, _sanitize_build_log(log_output)

    except (subprocess.TimeoutExpired, FileNotFoundError, ValueError) as e:
        log_output += f"Build error: {e}\n"
        return False, _sanitize_build_log(log_output)


def _sanitize_build_log(log_output: str) -> str:
    cleaned = log_output
    for pattern in BUILD_LOG_REDACTIONS:
        cleaned = pattern.sub("[REDACTED]", cleaned)
    if len(cleaned) > MAX_BUILD_LOG_CHARS:
        return cleaned[:MAX_BUILD_LOG_CHARS] + "\n...[truncated]..."
    return cleaned


# ---------------------------------------------------------------------------
# Code quality checks
# ---------------------------------------------------------------------------

def detect_tests(repo_path: Path) -> tuple[bool, str]:
    indicators = {
        "pytest": ["pytest.ini", "conftest.py", "pyproject.toml"],
        "jest": ["jest.config.js", "jest.config.ts", "jest.config.mjs"],
        "mocha": [".mocharc.yml", ".mocharc.json"],
        "unittest": [],
        "vitest": ["vitest.config.ts", "vitest.config.js"],
    }

    for framework, configs in indicators.items():
        for cfg in configs:
            if list(repo_path.rglob(cfg)):
                return True, framework

    test_patterns = ["**/test_*.py", "**/*_test.py", "**/*.test.js", "**/*.test.ts",
                     "**/*.spec.js", "**/*.spec.ts", "**/tests/**", "**/__tests__/**"]
    for pat in test_patterns:
        if list(repo_path.glob(pat))[:1]:
            framework = "pytest" if pat.endswith(".py") else "jest/mocha"
            return True, framework

    pyproject = repo_path / "pyproject.toml"
    if pyproject.exists():
        content = pyproject.read_text(errors="ignore")
        if "pytest" in content:
            return True, "pytest"

    return False, ""


def check_readme(repo_path: Path) -> str:
    """Return the path to the README if found, else empty string."""
    for name in ["README.md", "README.rst", "README.txt", "README", "readme.md"]:
        if (repo_path / name).exists():
            return name
    return ""


def check_dependency_file(repo_path: Path) -> bool:
    dep_files = ["requirements.txt", "pyproject.toml", "setup.py", "setup.cfg",
                 "package.json", "Cargo.toml", "go.mod", "Gemfile", "pom.xml",
                 "build.gradle"]
    return any((repo_path / f).exists() for f in dep_files)
