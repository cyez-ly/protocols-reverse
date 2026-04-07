from __future__ import annotations

import shlex
import subprocess
import time
from pathlib import Path
from typing import List, Optional

from testcrewai.models import ShellCommandResult

"""
    统一子进程执行器
    负责调用 subprocess.run(...)，并统一返回结构化结果
    所有外部工具（tshark、netzob、netplier、binaryinferno 等）最终都通过它执行

"""


class ShellRunner:
    """统一的子进程执行器，支持超时与结构化输出。"""

    def run(
        self,
        command: str | List[str],
        timeout_sec: int = 60,
        cwd: str | Path | None = None,
        env: Optional[dict[str, str]] = None,
        stdin_text: str | None = None,
    ) -> ShellCommandResult:
        # 统一把命令规范成列表：字符串按 shell 规则拆分，列表则直接使用。
        cmd_list = command if isinstance(command, list) else shlex.split(command)
        start = time.perf_counter()

        try:
            # 采用非 shell 模式执行，完整捕获 stdout/stderr 供上游记录与诊断。
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
            # 超时统一映射为 124，并尽量保留子进程已产生的输出。
            duration = time.perf_counter() - start
            return ShellCommandResult(
                command=cmd_list,
                return_code=124,
                stdout=exc.stdout.decode("utf-8", errors="ignore") if isinstance(exc.stdout, bytes) else (exc.stdout or ""),
                stderr=exc.stderr.decode("utf-8", errors="ignore") if isinstance(exc.stderr, bytes) else (exc.stderr or ""),
                timed_out=True,
                duration_sec=round(duration, 4),
            )
        except Exception as exc:  # pragma: no cover - 防御性分支
            duration = time.perf_counter() - start
            return ShellCommandResult(
                command=cmd_list,
                return_code=1,
                stdout="",
                stderr=f"Shell 执行失败: {exc}",
                timed_out=False,
                duration_sec=round(duration, 4),
            )
