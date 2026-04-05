#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict

from testcrewai.workflows.protocol_reverse_flow import ProtocolReverseFlow

# 加载环境变量
def _load_project_env() -> None:
    """加载项目根目录/.env,供 CLI 默认参数读取。"""
    project_root = Path(__file__).resolve().parents[2]
    env_path = project_root / ".env"
    if not env_path.exists():
        return

    try:
        from dotenv import load_dotenv

        load_dotenv(dotenv_path=env_path, override=False)
    except Exception:
        # Optional dependency fallback: keep startup robust even if dotenv is unavailable.
        for raw_line in env_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            os.environ.setdefault(key, value)

# 提前加载环境变量：下面 parser 的默认值会依赖这些配置。
_load_project_env()

# 命令行参数定义
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="testcrewai",
        description="基于 CrewAI Flow + Agents + Tools 的未知协议结构逆向原型系统。",
    )
    parser.add_argument("--pcap", required=True, help="输入抓包文件路径（优先 .pcap/.pcapng）")
    parser.add_argument("--output", required=True, help="输出目录路径")
    parser.add_argument(
        "--python-bin",
        default=os.getenv("PYTHON_BIN", sys.executable),
        help="子进程适配器的全局兜底 Python 解释器路径",
    )
    parser.add_argument(
        "--netzob-python-bin",
        default=os.getenv("NETZOB_PYTHON_BIN"),
        help="仅用于 Netzob 适配器的 Python 解释器",
    )
    parser.add_argument(
        "--nemesys-python-bin",
        default=os.getenv("NEMESYS_PYTHON_BIN"),
        help="仅用于 NEMESYS 适配器的 Python 解释器",
    )
    parser.add_argument(
        "--netplier-python-bin",
        default=os.getenv("NETPLIER_PYTHON_BIN"),
        help="仅用于 NetPlier 适配器的 Python 解释器",
    )
    parser.add_argument(
        "--binaryinferno-python-bin",
        default=os.getenv("BINARYINFERNO_PYTHON_BIN"),
        help="仅用于 BinaryInferno 适配器的 Python 解释器",
    )
    parser.add_argument("--timeout", type=int, default=90, help="子进程超时时间（秒）")
    parser.add_argument(
        "--use-llm",
        action="store_true",
        help="启用各阶段可选 LLM 注释（需要可用 API Key）",
    )
    parser.add_argument(
        "--print-json",
        action="store_true",
        help="以 JSON 格式打印最终摘要",
    )
    return parser

# 执行
def execute(args: argparse.Namespace) -> Dict[str, Any]:
    # 将 CLI 参数映射为 Flow 输入，并触发完整流程，flow=protocol_reverse_flow.py中的类ProtocolReverseFlow。
    flow = ProtocolReverseFlow()
    result = flow.kickoff(
        inputs={
            "pcap_path": str(Path(args.pcap).resolve()),
            "output_dir": str(Path(args.output).resolve()),
            "python_bin": args.python_bin,
            "netzob_python_bin": getattr(args, "netzob_python_bin", None) or "",
            "nemesys_python_bin": getattr(args, "nemesys_python_bin", None) or "",
            "netplier_python_bin": getattr(args, "netplier_python_bin", None) or "",
            "binaryinferno_python_bin": getattr(args, "binaryinferno_python_bin", None) or "",
            "timeout_sec": args.timeout,
            "use_llm": bool(args.use_llm),
        }
    )
    return result


def run(argv: list[str] | None = None) -> Dict[str, Any]:
    # 标准命令行入口。（命令行参数定义）
    parser = build_parser()
    args = parser.parse_args(argv) # 读取命令行参数
    result = execute(args)

    if args.print_json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"运行完成。输出目录: {result.get('output_dir', args.output)}")
        print("产物文件:")
        for key, value in result.get("artifacts", {}).items():
            print(f"- {key}: {value}")
        if result.get("warnings"):
            print(f"警告数: {len(result['warnings'])}")
        if result.get("errors"):
            print(f"错误数: {len(result['errors'])}")

    return result


# 供其他程序调用的接口，例如：python main.py '{"pcap":"a.pcap", "output":"out"}'
def run_with_trigger() -> Dict[str, Any]:
    # 触发器入口：从 argv[1] 读取 JSON 负载。
    if len(sys.argv) < 2:
        raise ValueError("未提供 trigger 负载")

    payload = json.loads(sys.argv[1])
    pcap = payload.get("pcap")
    output = payload.get("output")
    if not pcap or not output:
        raise ValueError("trigger 负载必须包含 'pcap' 和 'output'")

    namespace = argparse.Namespace(
        pcap=pcap,
        output=output,
        python_bin=payload.get("python_bin", sys.executable),
        netzob_python_bin=payload.get("netzob_python_bin"),
        nemesys_python_bin=payload.get("nemesys_python_bin"),
        netplier_python_bin=payload.get("netplier_python_bin"),
        binaryinferno_python_bin=payload.get("binaryinferno_python_bin"),
        timeout=int(payload.get("timeout", 90)),
        use_llm=bool(payload.get("use_llm", False)),
        print_json=True,
    )
    return execute(namespace)


def train() -> None:
    raise NotImplementedError("暂未实现 train 命令。")


def replay() -> None:
    raise NotImplementedError("当前原型暂未实现 replay。")


def test() -> None:
    raise NotImplementedError("请使用 `python -m unittest` 运行本地测试。")


if __name__ == "__main__":
    run()
