"""Agentic AI security review — the model explores the codebase iteratively.

Instead of dumping the entire codebase into one prompt, the AI gets tools to
explore the repo like a human reviewer:
  - read_file: examine specific files on demand
  - search_code: grep for patterns across the codebase
  - list_directory: explore project structure
  - submit_review: deliver the final report
"""

import json
import logging
import os
import re
import time
from pathlib import Path

from openai import OpenAI

from src.analyzers import SKIP_DIRS

log = logging.getLogger("orcorus")

SOURCE_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".java", ".rb"}

REVIEW_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read the contents of a file in the repository. Use this to examine source code, configs, and other files. You can read any file — start with entry points and files flagged by static analysis, then follow imports and data flows.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Relative path to the file from the repo root (e.g. 'src/server.py', 'package.json')"
                    }
                },
                "required": ["path"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "search_code",
            "description": "Search for a pattern across all source files in the repository. Use this to trace function calls, find usage of dangerous APIs (eval, exec, subprocess, SQL queries), locate secret handling, or follow data flows across files. Returns matching lines with file paths and line numbers.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Text or regex pattern to search for (e.g. 'subprocess', 'eval(', 'password', 'os.path.join')"
                    },
                    "file_glob": {
                        "type": "string",
                        "description": "Optional glob to restrict search (e.g. '*.py', '*.ts'). Default: all source files."
                    }
                },
                "required": ["pattern"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "list_directory",
            "description": "List files and subdirectories in a directory. Use this to explore the project structure beyond the initial file tree.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Relative path to the directory (e.g. 'src', 'lib/auth'). Use '.' for the root."
                    }
                },
                "required": ["path"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "submit_review",
            "description": "Submit your final security review report. Call this ONLY when you have thoroughly investigated the codebase and are ready to deliver your findings. Do not call this prematurely — make sure you have read all security-relevant files first.",
            "parameters": {
                "type": "object",
                "properties": {
                    "report": {
                        "type": "string",
                        "description": "The complete security review report in markdown format."
                    }
                },
                "required": ["report"]
            }
        }
    },
]


# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------

def build_file_tree(repo_path: Path, check_path: Path) -> str:
    lines = []
    for root, dirs, files in os.walk(check_path):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        level = len(Path(root).relative_to(check_path).parts)
        indent = "  " * level
        dirname = os.path.basename(root)
        if level == 0:
            dirname = os.path.relpath(check_path, repo_path) if check_path != repo_path else "."
        lines.append(f"{indent}{dirname}/")
        for f in sorted(files)[:30]:
            lines.append(f"{indent}  {f}")
        if len(files) > 30:
            lines.append(f"{indent}  ... ({len(files) - 30} more files)")
    return "\n".join(lines[:200])


def _handle_read_file(repo_path: Path, check_path: Path, rel_path: str) -> str:
    for base in [check_path, repo_path]:
        fpath = base / rel_path
        try:
            fpath.resolve().relative_to(repo_path.resolve())
        except ValueError:
            return f"Error: path '{rel_path}' is outside the repository."
        if fpath.is_file():
            try:
                content = fpath.read_text(errors="ignore")
                if len(content) > 30000:
                    content = content[:30000] + f"\n\n... (truncated, {len(content) - 30000} chars omitted)"
                return content
            except OSError as e:
                return f"Error reading file: {e}"
    return f"File not found: '{rel_path}'. Use list_directory to see available files."


def _handle_search_code(check_path: Path, pattern: str, file_glob: str = "") -> str:
    try:
        pat = re.compile(pattern, re.IGNORECASE)
    except re.error:
        pat = re.compile(re.escape(pattern), re.IGNORECASE)

    glob_suffixes = None
    if file_glob and file_glob.startswith("*."):
        glob_suffixes = {"." + file_glob[2:]}

    matches = []
    for root, dirs, files in os.walk(check_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in sorted(files):
            fpath = Path(root) / fname
            if glob_suffixes:
                if fpath.suffix not in glob_suffixes:
                    continue
            elif fpath.suffix not in SOURCE_EXTENSIONS and fname not in {
                "package.json", "pyproject.toml", "Dockerfile", "docker-compose.yml",
                ".env.example", "Cargo.toml", "go.mod",
            }:
                continue
            try:
                content = fpath.read_text(errors="ignore")
            except (OSError, UnicodeDecodeError):
                continue
            rel = os.path.relpath(fpath, check_path)
            for i, line in enumerate(content.splitlines(), 1):
                if pat.search(line):
                    matches.append(f"  {rel}:{i}: {line.strip()[:150]}")
                    if len(matches) >= 50:
                        matches.append("  ... (truncated, more matches exist)")
                        return f"Found {len(matches)} matches for '{pattern}':\n" + "\n".join(matches)

    if not matches:
        return f"No matches found for '{pattern}'."
    return f"Found {len(matches)} matches for '{pattern}':\n" + "\n".join(matches)


def _handle_list_directory(repo_path: Path, check_path: Path, rel_path: str) -> str:
    for base in [check_path, repo_path]:
        dpath = base / rel_path if rel_path and rel_path != "." else base
        try:
            dpath.resolve().relative_to(repo_path.resolve())
        except ValueError:
            return f"Error: path '{rel_path}' is outside the repository."
        if dpath.is_dir():
            entries = []
            for item in sorted(dpath.iterdir()):
                if item.name in SKIP_DIRS:
                    continue
                suffix = "/" if item.is_dir() else f" ({item.stat().st_size:,} bytes)"
                entries.append(f"  {item.name}{suffix}")
            if not entries:
                return f"Directory '{rel_path}' is empty."
            return f"Contents of '{rel_path}':\n" + "\n".join(entries[:100])
    return f"Directory not found: '{rel_path}'."


def _assistant_message_to_dict(message) -> dict:
    """Convert SDK message objects to plain dicts for provider compatibility."""
    content = message.content if message.content is not None else ""
    payload = {"role": "assistant", "content": content}
    if message.tool_calls:
        payload["tool_calls"] = []
        for tc in message.tool_calls:
            fn = tc.function
            payload["tool_calls"].append({
                "id": tc.id,
                "type": tc.type or "function",
                "function": {"name": fn.name, "arguments": fn.arguments},
            })
    return payload


# ---------------------------------------------------------------------------
# Main agentic review loop
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are an expert security code reviewer performing a thorough review of an MCP (Model Context Protocol) integration.

Use an OWASP-aligned rubric and methodology for this review:
- OWASP core methodology: establish architecture/context, identify trust boundaries and entry points, trace data flows, model threats, verify controls, and validate findings with concrete code evidence.
- OWASP key characteristics: exploitability, impact, likelihood, attacker preconditions, and business/security context.
- OWASP security categories: map findings to OWASP Top 10 2021 categories where applicable (A01 Broken Access Control, A02 Cryptographic Failures, A03 Injection, A04 Insecure Design, A05 Security Misconfiguration, A06 Vulnerable and Outdated Components, A07 Identification and Authentication Failures, A08 Software and Data Integrity Failures, A09 Security Logging and Monitoring Failures, A10 Server-Side Request Forgery).

You have tools to explore the codebase. Work methodically like a senior security engineer:

1. ORIENT: Study the file tree and static analysis results to understand the project.
2. ENTRY POINTS: Read main entry points (server.py, index.ts, main.go, etc.) to understand what's exposed.
3. DATA FLOWS: Trace how user/external input flows through the code. Use search_code to follow function calls across files.
4. ATTACK SURFACE: Identify where the integration handles untrusted input, makes network requests, executes commands, or accesses the filesystem.
5. DEEP DIVE: Read files that handle auth, secrets, file operations, subprocess calls, and serialization.
6. DEPENDENCIES: Check dependency configs for known issues (OWASP A06).
7. REPORT: Once you have sufficient evidence, submit your review.

Focus on real, exploitable vulnerabilities. Do NOT flag:
- Assert statements in test files
- Stylistic issues or code quality nits
- Hypothetical issues without evidence in the actual code
- Known false positives (e.g., temp file usage in tests)

Be thorough — read every security-relevant file before submitting. But be efficient — don't read every test file or documentation file unless you suspect something."""


def run_ai_review(
    client: OpenAI,
    model: str,
    repo_path: Path,
    check_path: Path,
    name: str,
    bandit_findings: list,
    ai_timeout: int = 300,
    max_turns: int = 20,
) -> str:
    """Run an agentic, multi-turn AI security review.

    The model explores the codebase iteratively using tool calls,
    then submits a structured security report.
    """
    file_tree = build_file_tree(repo_path, check_path)

    bandit_summary = "No static analysis findings."
    if bandit_findings:
        severity_counts = {}
        for f in bandit_findings:
            sev = f.get("severity", "unknown")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        bandit_lines = [f"Static analysis (bandit) found {len(bandit_findings)} issues:"]
        for sev, count in sorted(severity_counts.items()):
            bandit_lines.append(f"  {sev}: {count}")
        for finding in bandit_findings[:20]:
            bandit_lines.append(
                f"  - [{finding.get('severity', '?').upper()}] {finding.get('issue', '?')} "
                f"in {finding.get('file', '?')}:{finding.get('line', '?')}"
            )
        if len(bandit_findings) > 20:
            bandit_lines.append(f"  ... and {len(bandit_findings) - 20} more")
        bandit_summary = "\n".join(bandit_lines)

    user_prompt = f"""Please perform a security code review of the repository "{name}" using an OWASP-aligned rubric.

## Project Structure
```
{file_tree}
```

## Static Analysis Results
{bandit_summary}

Begin by reading the main entry points, then trace data flows and investigate any suspicious areas. Use search_code to find usage of dangerous APIs and follow function calls. When you have reviewed all security-relevant code, call submit_review with your complete report.

Your report must include:
1. **OWASP Review Methodology Applied** — brief summary of how you applied the OWASP process.
2. **OWASP Top 10 Category Mapping** — map each finding to relevant OWASP Top 10 2021 category IDs.
3. **Critical Vulnerabilities** (if any) — RCE, injection, auth bypass, unsafe deserialization.
4. **High Severity Issues** (if any) — SSRF, privilege escalation, credential exposure.
5. **Medium Severity Issues** (if any) — Missing input validation, insecure defaults.
6. **Low Severity Issues** (if any) — Minor best-practice gaps.
7. **Key Risk Characteristics** — exploitability, impact, likelihood, required attacker preconditions.
8. **Positive Security Practices** — What the code does well.
9. **Recommendations** — Specific fixes with file:line references and OWASP category context.
10. **Next Tier Upgrade Plan** — State the integration's likely current tier (Bronze/Silver/Gold/Reject), the next target tier, and a prioritized set of concrete actions needed to reach that next tier.

For each finding: specify file, line number, severity, and concrete remediation."""

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ]

    log.info(f"  [AI] Starting agentic review (up to {max_turns} turns, {ai_timeout}s timeout per call)")
    log.info(f"  [AI] File tree: {len(file_tree)} chars, bandit findings: {len(bandit_findings)}")

    total_start = time.monotonic()
    total_prompt_tokens = 0
    total_completion_tokens = 0
    files_read = []
    searches_done = []

    for turn in range(1, max_turns + 1):
        elapsed_total = time.monotonic() - total_start
        log.info(f"  [AI Turn {turn}/{max_turns}] Calling {model} ({elapsed_total:.0f}s elapsed)...")

        try:
            start_time = time.monotonic()
            response = client.chat.completions.create(
                model=model,
                messages=messages,
                tools=REVIEW_TOOLS,
                tool_choice="auto",
                temperature=0.1,
                timeout=ai_timeout,
            )
            call_elapsed = time.monotonic() - start_time

            if response.usage:
                total_prompt_tokens += response.usage.prompt_tokens
                total_completion_tokens += response.usage.completion_tokens

            message = response.choices[0].message

            if message.tool_calls:
                messages.append(_assistant_message_to_dict(message))

                for tool_call in message.tool_calls:
                    fn_name = tool_call.function.name
                    try:
                        fn_args = json.loads(tool_call.function.arguments)
                    except json.JSONDecodeError:
                        fn_args = {}

                    if fn_name == "read_file":
                        path = fn_args.get("path", "")
                        log.info(f"  [AI Turn {turn}] read_file('{path}') [{call_elapsed:.1f}s]")
                        files_read.append(path)
                        tool_result = _handle_read_file(repo_path, check_path, path)

                    elif fn_name == "search_code":
                        pattern = fn_args.get("pattern", "")
                        file_glob = fn_args.get("file_glob", "")
                        glob_info = f", glob='{file_glob}'" if file_glob else ""
                        log.info(f"  [AI Turn {turn}] search_code('{pattern}'{glob_info}) [{call_elapsed:.1f}s]")
                        searches_done.append(pattern)
                        tool_result = _handle_search_code(check_path, pattern, file_glob)

                    elif fn_name == "list_directory":
                        path = fn_args.get("path", ".")
                        log.info(f"  [AI Turn {turn}] list_directory('{path}') [{call_elapsed:.1f}s]")
                        tool_result = _handle_list_directory(repo_path, check_path, path)

                    elif fn_name == "submit_review":
                        report = fn_args.get("report", "")
                        total_elapsed = time.monotonic() - total_start
                        log.info(f"  [AI Turn {turn}] submit_review ({len(report)} chars) [{call_elapsed:.1f}s]")
                        _log_summary(total_elapsed, turn, files_read, searches_done, total_prompt_tokens, total_completion_tokens)
                        return report

                    else:
                        tool_result = f"Unknown tool: {fn_name}"

                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": tool_result[:50000],
                    })

            else:
                text = message.content or ""
                if text:
                    total_elapsed = time.monotonic() - total_start
                    log.info(f"  [AI Turn {turn}] Model returned text response ({len(text)} chars) [{call_elapsed:.1f}s]")
                    _log_summary(total_elapsed, turn, files_read, searches_done, total_prompt_tokens, total_completion_tokens)
                    return text

                messages.append(_assistant_message_to_dict(message))
                messages.append({"role": "user", "content": "Continue your review. Read more files or call submit_review when done."})

        except Exception as e:
            elapsed = time.monotonic() - total_start
            log.error(f"  [AI Turn {turn}] Error after {elapsed:.1f}s: {e}")
            if turn > 1 and files_read:
                messages.append({"role": "user", "content": "There was an error. Please call submit_review now with your findings so far."})
                continue
            return f"AI review failed after {turn} turns: {e}"

    # Exhausted turns
    total_elapsed = time.monotonic() - total_start
    log.warning(f"  [AI] Hit turn limit ({max_turns}). Forcing final report...")
    _log_summary(total_elapsed, max_turns, files_read, searches_done, total_prompt_tokens, total_completion_tokens)

    messages.append({
        "role": "user",
        "content": "You have reached the maximum number of exploration turns. Please call submit_review NOW with your complete findings based on what you've reviewed so far."
    })

    try:
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            tools=REVIEW_TOOLS,
            tool_choice={"type": "function", "function": {"name": "submit_review"}},
            temperature=0.1,
            timeout=ai_timeout,
        )
        message = response.choices[0].message
        if message.tool_calls:
            for tc in message.tool_calls:
                if tc.function.name == "submit_review":
                    args = json.loads(tc.function.arguments)
                    return args.get("report", "Review could not be completed.")
        if message.content:
            return message.content
    except Exception as e:
        log.error(f"  [AI] Final report extraction failed: {e}")

    return "AI review could not be completed within turn limit."


def _log_summary(elapsed, turns, files_read, searches_done, prompt_tok, completion_tok):
    log.info(f"  [AI] Review complete in {elapsed:.1f}s over {turns} turns")
    log.info(f"  [AI] Files read: {len(files_read)} -- {', '.join(files_read[:10])}")
    log.info(f"  [AI] Searches: {len(searches_done)} -- {', '.join(searches_done[:10])}")
    log.info(f"  [AI] Tokens: {prompt_tok:,} prompt + {completion_tok:,} completion = {prompt_tok + completion_tok:,} total")
