#!/usr/bin/env python3
"""
Orcorus Repository Scanner -- MCP Server

An MCP server that scans GitHub repositories for security vulnerabilities
and produces executive security summaries.

Tools:
  - scan_repo: Scan a GitHub repo (runs as background task)
  - get_report: Retrieve a completed SECURITY.md report

Run:
  python server.py
  # or
  fastmcp run server.py
"""

import asyncio
import json
import logging
import os
from dataclasses import asdict
from pathlib import Path

from fastmcp import FastMCP, Context

from src import Scanner, ScanConfig, ScanResult

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("orcorus")

REPORTS_DIR = Path(os.environ.get("ORCORUS_REPORTS_DIR", "./reports")).resolve()
WORK_DIR = Path(os.environ.get("ORCORUS_WORK_DIR", "./repos")).resolve()

mcp = FastMCP(
    "Orcorus Repository Scanner",
    instructions=(
        "Security scanner for GitHub repositories. "
        "Use scan_repo to analyze a repository -- it runs as a background task. "
        "Use get_report to retrieve the SECURITY.md once the scan completes."
    ),
)


def _build_scanner() -> Scanner:
    """Build a Scanner from environment variables."""
    return Scanner(ScanConfig(
        api_key=os.environ.get("OPENAI_API_KEY", ""),
        model=os.environ.get("ORCORUS_MODEL", "gpt-5.2"),
        base_url=os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1"),
        reports_dir=str(REPORTS_DIR),
        work_dir=str(WORK_DIR),
        ai_timeout=int(os.environ.get("ORCORUS_AI_TIMEOUT", "300")),
        max_agent_turns=int(os.environ.get("ORCORUS_MAX_TURNS", "20")),
        skip_ai=os.environ.get("ORCORUS_SKIP_AI", "").lower() in ("1", "true", "yes"),
        cleanup_repos=True,
    ))


def _result_to_summary(result: ScanResult) -> str:
    """Format a ScanResult as a concise executive summary string."""
    lines = [
        f"# Security Scan: {result.name}",
        "",
        f"**Repository:** {result.repo_url}",
        f"**Commit:** {result.commit or 'HEAD'}",
    ]
    if result.subdir:
        lines.append(f"**Subdir:** {result.subdir}")

    lines += [
        "",
        f"## Score: {result.security_score} / 100  --  Tier: {result.tier}",
        "",
        "| Check | Result |",
        "|-------|--------|",
        f"| Build | {'PASS' if result.build_success else 'FAIL'} |",
        f"| Tests | {result.test_framework or 'not detected'} |",
        f"| README | {'present' if result.has_readme else 'missing'} |",
        f"| Dependencies | {'present' if result.has_dependency_file else 'missing'} |",
        f"| Bandit (H/M/L) | {result.bandit_issues.get('high', 0)} / {result.bandit_issues.get('medium', 0)} / {result.bandit_issues.get('low', 0)} |",
        f"| Hardcoded secrets | {result.hardcoded_secrets} |",
        "",
    ]

    if result.ai_review and "failed" not in result.ai_review.lower()[:20]:
        lines += ["## AI Security Review", "", result.ai_review, ""]

    if result.report_path:
        lines.append(f"Full report saved to: `{result.report_path}`")
    if result.readme_path:
        lines.append(f"README saved to: `{result.readme_path}`")

    if result.error:
        lines += ["", f"**Error:** {result.error}"]

    return "\n".join(lines)


@mcp.tool(task=True)
async def scan_repo(
    repo_url: str,
    ctx: Context,
    name: str = "",
    commit: str = "",
    subdir: str = "",
) -> str:
    """Scan a GitHub repository for security vulnerabilities.

    Clones the repo, runs static analysis (bandit), checks for hardcoded
    secrets, verifies the build, and performs an AI-powered OWASP-aligned
    security code review. Produces a SECURITY.md report and executive summary.

    This runs as a background task -- it may take several minutes for large
    repos with AI review enabled.

    Args:
        repo_url: GitHub repository URL (e.g. https://github.com/owner/repo).
                  Supports /tree/commit/subdir URLs for monorepos.
        name: Optional display name. Defaults to owner/repo.
        commit: Optional commit hash to checkout.
        subdir: Optional subdirectory to scope analysis to.
    """
    await ctx.info(f"Starting security scan of {repo_url}")
    await ctx.report_progress(0, 100)

    scanner = _build_scanner()

    await ctx.info("Cloning repository...")
    await ctx.report_progress(5, 100)

    # Run the blocking scan in a thread
    result = await asyncio.to_thread(
        scanner.scan,
        repo_url=repo_url,
        name=name,
        commit=commit,
        subdir=subdir,
    )

    if not result.clone_success:
        await ctx.error(f"Scan failed: {result.error}")
        return f"Scan failed: {result.error}"

    await ctx.report_progress(100, 100)
    await ctx.info(f"Scan complete: {result.security_score}/100 -> {result.tier}")

    return _result_to_summary(result)


@mcp.tool()
def get_report(name: str) -> str:
    """Retrieve a previously generated SECURITY.md report.

    Args:
        name: The repository name (e.g. 'brave/brave-search-mcp-server' or
              the safe directory name like 'brave_brave-search-mcp-server').
    """
    import re
    safe_name = re.sub(r'[^\w\-.]', '_', name)

    report_file = REPORTS_DIR / safe_name / "SECURITY.md"
    if report_file.exists():
        return report_file.read_text()

    # Try exact name match
    report_file2 = REPORTS_DIR / name / "SECURITY.md"
    if report_file2.exists():
        return report_file2.read_text()

    # List available reports
    available = []
    if REPORTS_DIR.exists():
        for d in sorted(REPORTS_DIR.iterdir()):
            if (d / "SECURITY.md").exists():
                available.append(d.name)

    if available:
        return f"Report not found for '{name}'. Available reports:\n" + "\n".join(f"  - {a}" for a in available)
    return f"No reports found. Run scan_repo first."


@mcp.tool()
def list_reports() -> str:
    """List all available security scan reports."""
    if not REPORTS_DIR.exists():
        return "No reports directory found."

    reports = []
    for d in sorted(REPORTS_DIR.iterdir()):
        if not d.is_dir():
            continue
        security_md = d / "SECURITY.md"
        if security_md.exists():
            # Extract score from first few lines
            content = security_md.read_text()
            score = "?"
            tier = "?"
            for line in content.splitlines()[:20]:
                if "/ 100" in line:
                    score = line.strip().split("/")[0].strip()
                if line.strip() in ("Gold", "Silver", "Bronze", "Reject"):
                    tier = line.strip()
            reports.append(f"  {d.name}: {score}/100 ({tier})")

    if not reports:
        return "No scan reports found."
    return f"Available reports ({len(reports)}):\n" + "\n".join(reports)


if __name__ == "__main__":
    mcp.run()
