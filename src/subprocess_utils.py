"""Hardened subprocess execution helpers."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

SAFE_EXECUTABLES = frozenset({
    "bandit",
    "git",
    "npm",
    "yarn",
    "pip3",
    "go",
    "cargo",
})


def run_safe(
    args: list[str],
    *,
    cwd: Path | str | None = None,
    capture_output: bool = True,
    text: bool = True,
    timeout: int | None = None,
    check: bool = False,
) -> subprocess.CompletedProcess:
    if not args or not args[0]:
        raise ValueError("Command must include an executable name.")
    executable = args[0]
    if "/" in executable or "\\" in executable:
        raise ValueError("Executable must be a bare command name.")
    if executable not in SAFE_EXECUTABLES:
        raise ValueError(f"Executable '{executable}' is not in the allowlist.")

    executable_path = shutil.which(executable)
    if not executable_path:
        raise FileNotFoundError(f"Executable not found: {executable}")

    safe_args = [executable_path, *args[1:]]
    return subprocess.run(  # nosec B603
        safe_args,
        cwd=str(cwd) if cwd is not None else None,
        shell=False,
        capture_output=capture_output,
        text=text,
        timeout=timeout,
        check=check,
    )
