"""SECURITY.md report generation."""

import re
from datetime import datetime, timezone

from src.models import ScanResult

OWASP_TOP10_CATEGORIES = [
    ("A01", "Broken Access Control"),
    ("A02", "Cryptographic Failures"),
    ("A03", "Injection"),
    ("A04", "Insecure Design"),
    ("A05", "Security Misconfiguration"),
    ("A06", "Vulnerable and Outdated Components"),
    ("A07", "Identification and Authentication Failures"),
    ("A08", "Software and Data Integrity Failures"),
    ("A09", "Security Logging and Monitoring Failures"),
    ("A10", "Server-Side Request Forgery"),
]

OWASP_CATEGORY_KEYWORDS = {
    "A01": ("auth bypass", "authorization", "access control", "privilege", "idor", "permission"),
    "A02": ("crypto", "cryptographic", "tls", "ssl", "cipher", "hash", "encryption", "secret"),
    "A03": ("injection", "sql", "command", "shell", "xpath", "deserializ", "unsafe eval"),
    "A04": ("insecure design", "missing validation", "trust boundary", "threat model", "design flaw"),
    "A05": ("misconfiguration", "default credentials", "debug", "cors", "permission bits"),
    "A06": ("dependency", "outdated", "vulnerable package", "cve", "version"),
    "A07": ("authentication", "session", "token", "credential", "password"),
    "A08": ("integrity", "supply chain", "untrusted update", "signature", "artifact"),
    "A09": ("logging", "audit", "monitoring", "alerting", "traceability"),
    "A10": ("ssrf", "server-side request forgery", "open redirect", "internal url"),
}


def _map_findings_to_owasp(findings: list[dict]) -> dict[str, list[dict]]:
    categorized: dict[str, list[dict]] = {code: [] for code, _ in OWASP_TOP10_CATEGORIES}
    for finding in findings:
        text = f"{finding.get('issue', '')} {finding.get('file', '')}".lower()
        for code, keywords in OWASP_CATEGORY_KEYWORDS.items():
            if any(keyword in text for keyword in keywords):
                categorized[code].append(finding)
                break
    return categorized


def generate_security_md(result: ScanResult) -> str:
    findings_high = [f for f in result.security_findings if f.get("severity") == "high"]
    findings_medium = [f for f in result.security_findings if f.get("severity") == "medium"]
    findings_low = [f for f in result.security_findings if f.get("severity") == "low"]
    all_findings = findings_high + findings_medium + findings_low
    owasp_mapped = _map_findings_to_owasp(all_findings)

    def format_findings(findings: list) -> str:
        if not findings:
            return "None\n"
        lines = []
        for f in findings[:20]:
            lines.append(f"- {f.get('issue', 'Unknown')} in {f.get('file', '?')}:{f.get('line', '?')} (confidence: {f.get('confidence', 'N/A')})")
        return "\n".join(lines) + "\n"

    secrets_section = ""
    if result.hardcoded_secrets > 0:
        secrets_section = f"\n## Hardcoded Secrets\n\n**{result.hardcoded_secrets} potential hardcoded secret(s) detected.**\n"

    dep_section = ""

    ai_section = ""
    if result.ai_review and "failed" not in result.ai_review.lower()[:20]:
        ai_section = f"\n## AI Security Review\n\n{result.ai_review}\n"

    owasp_lines = []
    for code, name in OWASP_TOP10_CATEGORIES:
        count = len(owasp_mapped.get(code, []))
        status = f"{count} finding(s)" if count else "none"
        owasp_lines.append(f"- {code} {name}: {status}")
    owasp_section = "\n".join(owasp_lines)

    build_status = "PASS" if result.build_success else "FAIL"
    test_status = f"Detected ({result.test_framework})" if result.has_tests else "Not detected"
    build_output_section = ""
    if not result.build_success:
        build_log = (result.build_log or "").strip() or "(No build output captured.)"
        build_log = build_log.replace("```", "``\\`")
        build_output_section = f"\n## Build Attempt Output\n```text\n{build_log}\n```\n"

    md = f"""# Security Review

Integration: {result.name}
Repository: {result.repo_url}
Commit: {result.commit or 'latest'}
Scan Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}

## Security Score

{result.security_score} / 100

## Tier Classification

{result.tier}

## OWASP Alignment

### OWASP Rubric
- Standard: OWASP Top 10 (2021) aligned review
- Core methodology: architecture context, trust boundaries, data-flow tracing, threat modeling, control verification, and evidence-backed validation
- Key characteristics considered: exploitability, impact, likelihood, attacker preconditions, and business context

### OWASP Security Category Mapping
{owasp_section}

## Static Analysis Findings (Bandit)

### High Severity
{format_findings(findings_high)}
### Medium Severity
{format_findings(findings_medium)}
### Low Severity
{format_findings(findings_low)}
{secrets_section}
## Build Status
{build_status}
{build_output_section}

## Tests
{test_status}

## Documentation
README: {'Present' if result.has_readme else 'Missing'}
Dependency file: {'Present' if result.has_dependency_file else 'Missing'}
{ai_section}
## Summary

Security Score: {result.security_score}/100 ({result.tier})
Static analysis found {result.bandit_issues.get('high', 0)} high, {result.bandit_issues.get('medium', 0)} medium, and {result.bandit_issues.get('low', 0)} low severity issues.
{'Build verified successfully.' if result.build_success else 'Build verification failed.'}
{'Tests detected.' if result.has_tests else 'No automated tests detected.'}
"""
    return md
