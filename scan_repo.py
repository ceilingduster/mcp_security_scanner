#!/usr/bin/env python3
"""
Example client -- scan a repository or local directory from the command line.

Usage:
    # Scan a GitHub repo
    python scan_repo.py https://github.com/owner/repo --api-key sk-...
    python scan_repo.py https://github.com/owner/repo --skip-ai

    # Scan a local directory in-place (absolute --subdir path)
    python scan_repo.py --name MyProject --subdir /path/to/project --api-key sk-...

    # Scan the current directory
    python scan_repo.py .

    # Custom model / provider
    python scan_repo.py --name SSH-Command --subdir /srv/docker/ssh-command \
        --model gpt-5.4 --base-url https://api.cometapi.com/v1 --api-key sk-...
"""

import argparse
import logging
import os
import sys

from src import Scanner, ScanConfig

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Scan a GitHub repository, local project path, or a specific directory "
            "for security issues. Use --subdir with an absolute path to scan a "
            "directory in-place without cloning or copying."
        ),
    )
    parser.add_argument(
        "repo_url",
        nargs="?",
        default=".",
        help=(
            "GitHub repository URL or local path to scan. Ignored when "
            "--subdir is an absolute path. (default: current directory)"
        ),
    )
    parser.add_argument(
        "--name", default="",
        help="Display name for the report (default: auto-detected from URL or directory)",
    )
    parser.add_argument("--commit", default="", help="Specific commit to checkout")
    parser.add_argument(
        "--subdir", default="",
        help=(
            "Subdirectory to scope analysis to. When given an absolute path "
            "(e.g. /srv/docker/my-app), the scanner reads that directory "
            "in-place — no clone or copy is performed."
        ),
    )
    parser.add_argument("--api-key", default=os.environ.get("OPENAI_API_KEY", ""))
    parser.add_argument("--model", default="gpt-5.2")
    parser.add_argument("--base-url", default="https://api.openai.com/v1")
    parser.add_argument("--reports-dir", default="./reports")
    parser.add_argument("--ai-timeout", type=int, default=300)
    parser.add_argument("--max-turns", type=int, default=40)
    parser.add_argument("--skip-ai", action="store_true")
    parser.add_argument("--keep-repo", action="store_true")
    parser.add_argument(
        "--allow-dangerous-builds",
        action="store_true",
        help="Run repository build commands (disabled by default for security)",
    )
    parser.add_argument(
        "--include-build-logs",
        action="store_true",
        help="Include sanitized build output in ScanResult (raw logs stay out of SECURITY.md)",
    )
    args = parser.parse_args()

    scanner = Scanner(ScanConfig(
        api_key=args.api_key,
        model=args.model,
        base_url=args.base_url,
        reports_dir=args.reports_dir,
        ai_timeout=args.ai_timeout,
        max_agent_turns=args.max_turns,
        skip_ai=args.skip_ai,
        cleanup_repos=not args.keep_repo,
        allow_dangerous_builds=args.allow_dangerous_builds,
        include_build_logs=args.include_build_logs,
    ))

    result = scanner.scan(
        repo_url=args.repo_url,
        name=args.name,
        commit=args.commit,
        subdir=args.subdir,
    )

    print()
    print("=" * 60)
    print(f"  Repository:  {result.repo_url}")
    print(f"  Name:        {result.name}")
    print(f"  Commit:      {result.commit or 'HEAD'}")
    if result.subdir:
        print(f"  Subdir:      {result.subdir}")
    print(f"  Score:       {result.security_score} / 100")
    print(f"  Tier:        {result.tier}")
    build_status = "SKIPPED"
    if result.build_attempted:
        build_status = "PASS" if result.build_success else "FAIL"
    print(f"  Build:       {build_status}")
    print(f"  Tests:       {result.test_framework or 'not detected'}")
    print(f"  README:      {'yes' if result.has_readme else 'no'}")
    print(f"  Bandit:      {result.bandit_issues.get('high', 0)}H / {result.bandit_issues.get('medium', 0)}M / {result.bandit_issues.get('low', 0)}L")
    print(f"  Secrets:     {result.hardcoded_secrets} detected")
    if result.report_path:
        print(f"  Report:      {result.report_path}")
    if result.readme_path:
        print(f"  README copy: {result.readme_path}")
    if result.error:
        print(f"  Error:       {result.error}")
    print("=" * 60)

    sys.exit(0 if result.clone_success else 1)


if __name__ == "__main__":
    main()
