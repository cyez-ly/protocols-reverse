from __future__ import annotations

import shlex
import subprocess
import time
from pathlib import Path
from typing import List, Optional

from testcrewai.models import ShellCommandResult


class ShellRunner:
    """Unified subprocess runner with timeout and structured output."""

    def run(
        self,
        command: str | List[str],
        timeout_sec: int = 60,
        cwd: str | Path | None = None,
        env: Optional[dict[str, str]] = None,
        stdin_text: str | None = None,
    ) -> ShellCommandResult:
        # 指明command
        cmd_list = command if isinstance(command, list) else shlex.split(command)
        start = time.perf_counter()

        try:
            completed = subprocess.run(
                cmd_list,
                cwd=str(cwd) if cwd else None,
                env=env,
                capture_output=True,
                text=True,
                input=stdin_text,
                timeout=timeout_sec,
                check=False,
            )
            duration = time.perf_counter() - start
            return ShellCommandResult(
                command=cmd_list,
                return_code=completed.returncode,
                stdout=completed.stdout,
                stderr=completed.stderr,
                timed_out=False,
                duration_sec=round(duration, 4),
            )
        except subprocess.TimeoutExpired as exc:
            duration = time.perf_counter() - start
            return ShellCommandResult(
                command=cmd_list,
                return_code=124,
                stdout=exc.stdout.decode("utf-8", errors="ignore") if isinstance(exc.stdout, bytes) else (exc.stdout or ""),
                stderr=exc.stderr.decode("utf-8", errors="ignore") if isinstance(exc.stderr, bytes) else (exc.stderr or ""),
                timed_out=True,
                duration_sec=round(duration, 4),
            )
        except Exception as exc:  # pragma: no cover - defensive branch
            duration = time.perf_counter() - start
            return ShellCommandResult(
                command=cmd_list,
                return_code=1,
                stdout="",
                stderr=f"Shell execution failed: {exc}",
                timed_out=False,
                duration_sec=round(duration, 4),
            )
