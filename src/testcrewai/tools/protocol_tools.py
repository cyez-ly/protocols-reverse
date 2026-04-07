from __future__ import annotations

import json
import os
import re
import shutil
from pathlib import Path
from typing import Any, Dict, Optional

from testcrewai.models import ToolRunResult
from testcrewai.tools.shell_runner import ShellRunner
from testcrewai.utils.io import read_json

"""
    工具适配层
    把 tshark / netzob / nemesys / netplier / binaryinferno 
    这些工具封装成统一接口 run(input_path, output_dir, extra_args)
---------------------------------------------------------------------
    预处理阶段调用 TsharkTool
    分段阶段调用 NetzobTool/NemesysTool
    语义阶段调用 NetPlierAdapter/BinaryInfernoAdapter

"""


def _normalize_python_bin(value: str) -> str:
    # 兼容两种写法：既支持 /path/to/venv，也支持 /path/to/venv/bin/python。
    candidate = value.strip()
    if not candidate:
        return "python3"

    expanded = Path(candidate).expanduser()
    if expanded.is_dir():
        interpreter = expanded / "bin" / "python"
        if interpreter.exists():
            return str(interpreter)
    if expanded.exists():
        return str(expanded)
    return candidate


def _validate_python_bin(python_bin: str) -> str | None:
    # 像 "python3" 这种命令名由 subprocess 通过 PATH 解析即可。
    if "/" not in python_bin and not python_bin.startswith("."):
        return None

    path = Path(python_bin).expanduser()
    if path.is_dir():
        suggestion = path / "bin" / "python"
        return f"Python 路径指向的是目录: {path}。请改为解释器文件: {suggestion}"
    if not path.exists():
        return f"未找到 Python 解释器: {path}"
    if not os.access(path, os.X_OK):
        return f"Python 解释器不可执行: {path}"
    return None


def _resolve_python_bin(
    extra_args: Dict[str, str],
    direct_key: str,
    env_keys: list[str],
) -> str:
    # 解释器优先级：函数参数 > 环境变量 > 全局 python_bin。
    value = extra_args.get(direct_key, "")
    if value:
        return _normalize_python_bin(value)

    for env_key in env_keys:
        env_value = os.getenv(env_key)
        if env_value:
            return _normalize_python_bin(env_value)

    return _normalize_python_bin(extra_args.get("python_bin", "python3"))


def _build_tool_env(extra_python_paths: Optional[list[str]] = None) -> Dict[str, str]:
    # 为子进程构建 PYTHONPATH，确保工具脚本能导入项目与外部仓库模块。
    env = os.environ.copy()
    project_src = Path(__file__).resolve().parents[2]  # 项目的 src 目录
    path_items: list[str] = [str(project_src)]
    for item in extra_python_paths or []:
        candidate = str(Path(item).expanduser())
        if candidate:
            path_items.append(candidate)

    existing = env.get("PYTHONPATH", "")
    if existing:
        path_items.extend(existing.split(":"))

    deduped: list[str] = []
    for item in path_items:
        if item and item not in deduped:
            deduped.append(item)
    env["PYTHONPATH"] = ":".join(deduped)
    return env


def _project_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _resolve_optional_path(extra_args: Dict[str, str], direct_key: str, env_keys: list[str]) -> str:
    value = extra_args.get(direct_key, "").strip()
    if value:
        return str(Path(value).expanduser())
    for env_key in env_keys:
        env_value = os.getenv(env_key, "").strip()
        if env_value:
            return str(Path(env_value).expanduser())
    return ""


def _resolve_positive_int(
    extra_args: Dict[str, str],
    direct_key: str,
    env_keys: list[str],
    default: int,
    allow_zero: bool = False,
) -> int:
    values: list[str] = []
    value = str(extra_args.get(direct_key, "")).strip()
    if value:
        values.append(value)
    for env_key in env_keys:
        env_value = str(os.getenv(env_key, "")).strip()
        if env_value:
            values.append(env_value)

    for item in values:
        try:
            parsed = int(item)
        except ValueError:
            continue
        if allow_zero and parsed == 0:
            return 0
        if parsed > 0:
            return parsed
    return default


def _resolve_bool(
    extra_args: Dict[str, str],
    direct_key: str,
    env_keys: list[str],
    default: bool,
) -> bool:
    values: list[str] = []
    value = str(extra_args.get(direct_key, "")).strip()
    if value:
        values.append(value)
    for env_key in env_keys:
        env_value = str(os.getenv(env_key, "")).strip()
        if env_value:
            values.append(env_value)

    for item in values:
        lowered = item.lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
    return default


def _detect_netplier_protocol_type(profile_payload: Dict[str, Any]) -> str:
    raw_protocols = profile_payload.get("protocols_observed", [])
    if not isinstance(raw_protocols, list):
        return ""
    normalized = {str(item).strip().lower() for item in raw_protocols if str(item).strip()}
    # 该工具仅支持少数协议类型，这里做保守推断，避免误判。
    if "dhcp" in normalized or ("udp" in normalized and "dhcp" in normalized):
        return "dhcp"
    if "icmp" in normalized:
        return "icmp"
    return ""


def _compact_error_text(text: str, max_len: int = 1200) -> str:
    value = text.strip()
    if not value:
        return ""
    if len(value) <= max_len:
        return value
    return value[:max_len] + "...(truncated)"


def _normalize_capture_for_official(
    profile_path: str,
    output_dir: str,
    runner: ShellRunner,
    timeout_sec: int,
    prefix: str,
) -> tuple[str, list[str]]:
    # 官方工具通常更偏好标准 pcap，这里先做一次归一化。
    notes: list[str] = []
    profile_file = Path(profile_path)
    if not profile_file.exists():
        return profile_path, notes

    try:
        profile_payload = read_json(profile_file)
    except Exception as exc:
        notes.append(f"官方抓包归一化已跳过：无法读取 profile（{exc}）")
        return profile_path, notes

    source_capture = str(profile_payload.get("input_file", "")).strip()
    if not source_capture:
        return profile_path, notes

    source_path = Path(source_capture)
    if not source_path.exists():
        notes.append(f"官方抓包归一化已跳过：未找到输入抓包（{source_path}）")
        return profile_path, notes

    target_capture = Path(output_dir) / f"{prefix}_official_input_normalized.pcap"
    converted = False

    # 优先用 editcap 转为标准 pcap；若不可用或失败，再尝试 tshark 重写。
    if shutil.which("editcap"):
        convert_cmd = ["editcap", "-F", "pcap", str(source_path), str(target_capture)]
        convert_res = runner.run(convert_cmd, timeout_sec=max(20, min(timeout_sec, 120)))
        if convert_res.return_code == 0 and target_capture.exists():
            converted = True
            notes.append("官方抓包归一化成功：editcap -F pcap")
        else:
            notes.append(
                "官方抓包归一化失败（editcap）: "
                + _compact_error_text(convert_res.stderr or convert_res.stdout)
            )

    if not converted and shutil.which("tshark"):
        convert_cmd = ["tshark", "-r", str(source_path), "-w", str(target_capture)]
        convert_res = runner.run(convert_cmd, timeout_sec=max(20, min(timeout_sec, 120)))
        if convert_res.return_code == 0 and target_capture.exists():
            converted = True
            notes.append("官方抓包归一化成功：tshark 重写")
        else:
            notes.append(
                "官方抓包归一化失败（tshark）: "
                + _compact_error_text(convert_res.stderr or convert_res.stdout)
            )

    if not converted:
        return profile_path, notes

    patched_profile = dict(profile_payload)
    patched_profile["input_file"] = str(target_capture)
    patched_profile_path = Path(output_dir) / f"{prefix}_official_profile.json"
    patched_profile_path.write_text(
        json.dumps(patched_profile, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    notes.append(f"官方 profile 已写入归一化输入路径: {target_capture}")
    return str(patched_profile_path), notes


def _discover_netplier_main(extra_args: Dict[str, str]) -> str:
    explicit = _resolve_optional_path(
        extra_args,
        direct_key="netplier_main_path",
        env_keys=["NETPLIER_MAIN_PATH"],
    )
    if explicit and Path(explicit).is_file():
        return explicit

    home = Path.home()
    candidates: list[Path] = []

    netplier_home = _resolve_optional_path(
        extra_args,
        direct_key="netplier_home",
        env_keys=["NETPLIER_HOME"],
    )
    if netplier_home:
        base = Path(netplier_home)
        if base.is_file() and base.name == "main.py":
            candidates.append(base)
        else:
            candidates.extend(
                [
                    base / "main.py",
                    base / "netplier" / "main.py",
                    base / "NetPlier" / "netplier" / "main.py",
                ]
            )

    candidates.extend(
        [
            home / "NetPlier" / "NetPlier" / "netplier" / "main.py",
            home / "NetPlier" / "netplier" / "main.py",
            _project_root() / "NetPlier" / "netplier" / "main.py",
        ]
    )

    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)

    return ""


def _parse_netplier_field_rows(fields_info_path: Path) -> list[tuple[int, str]]:
    rows: list[tuple[int, str]] = []
    for raw_line in fields_info_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line:
            continue

        parts = line.split()
        if len(parts) < 4:
            continue
        try:
            bits = int(parts[2])
        except ValueError:
            continue
        if bits <= 0:
            continue
        field_type = parts[3].strip() or "?"
        rows.append((bits, field_type))
    return rows


def _parse_netplier_fields_info_with_meta(
    fields_info_path: Path,
) -> tuple[list[tuple[int, int, str]], dict[str, Any]]:
    if not fields_info_path.exists():
        return [], {"mode": "missing", "line_count": 0, "selected_count": 0}

    rows = _parse_netplier_field_rows(fields_info_path)
    if not rows:
        return [], {"mode": "empty", "line_count": 0, "selected_count": 0}

    end_mode_fields: list[tuple[int, int, str]] = []
    previous_end = 0
    for bits, field_type in rows:
        end = max(1, bits // 8)
        if end <= previous_end:
            continue
        end_mode_fields.append((previous_end, end, field_type))
        previous_end = end

    width_mode_fields: list[tuple[int, int, str]] = []
    cursor = 0
    for bits, field_type in rows:
        width = max(1, bits // 8)
        start = cursor
        end = start + width
        width_mode_fields.append((start, end, field_type))
        cursor = end

    line_count = len(rows)
    end_count = len(end_mode_fields)
    width_count = len(width_mode_fields)

    # 该工具的 msa_fields_info.txt 在不同版本中含义可能不同：
    # 有些版本存“累计结束位”，有些版本存“每字段位宽”。
    # 这里自动判别，避免把大量字段错误压缩成少数字段。
    if end_count >= max(8, int(line_count * 0.75)):
        selected = end_mode_fields
        mode = "end_bits"
    else:
        selected = width_mode_fields
        mode = "width_bits"

    metadata: dict[str, Any] = {
        "mode": mode,
        "line_count": line_count,
        "selected_count": len(selected),
        "end_mode_count": end_count,
        "width_mode_count": width_count,
    }
    return selected, metadata


def _parse_netplier_fields_info(fields_info_path: Path) -> list[tuple[int, int, str]]:
    parsed, _ = _parse_netplier_fields_info_with_meta(fields_info_path)
    return parsed


def _semantic_from_netplier_field_type(
    field_type: str,
    field_span: int = 0,
    field_start: int = 0,
) -> tuple[str, float, str]:
    upper = field_type.upper()
    if upper == "D":
        return "type", 0.78, "官方 NetPlier 判定字段（D）"
    if upper == "V":
        return "payload", 0.68, "官方 NetPlier 可变字段（V）"
    if upper == "S":
        if field_span <= 2 or field_start <= 8:
            return "type", 0.56, "官方 NetPlier 静态/分隔字段（S），短字段或头部位置"
        if field_span <= 8:
            return "session_id", 0.54, "官方 NetPlier 静态/分隔字段（S），短控制标记"
        return "unknown", 0.48, "官方 NetPlier 静态/分隔字段（S），跨度较大"
    return "unknown", 0.4, f"官方 NetPlier 字段类型={field_type}"


def _map_official_fields_to_segments(
    segment_candidates: list[dict[str, Any]],
    official_fields: list[tuple[int, int, str]],
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    max_official_end = max((end for _, end, _ in official_fields), default=0)
    for item in segment_candidates:
        try:
            start = int(item.get("start", 0))
            end = int(item.get("end", 0))
        except Exception:
            continue

        if end <= start:
            continue

        segment_len = max(1, end - start)
        # 核心思路：按“重叠长度 × 语义基础置信度”进行投票，再选最高分语义。
        total_overlap = 0
        semantic_votes: dict[str, float] = {}
        semantic_reasons: dict[str, list[str]] = {}
        semantic_raw_overlap: dict[str, int] = {}

        for off_start, off_end, field_type in official_fields:
            overlap = max(0, min(end, off_end) - max(start, off_start))
            if overlap <= 0:
                continue
            total_overlap += overlap
            field_span = max(1, off_end - off_start)
            semantic_type, base_confidence, base_reason = _semantic_from_netplier_field_type(
                field_type,
                field_span=field_span,
                field_start=off_start,
            )
            weighted_vote = overlap * base_confidence
            semantic_votes[semantic_type] = semantic_votes.get(semantic_type, 0.0) + weighted_vote
            semantic_raw_overlap[semantic_type] = semantic_raw_overlap.get(semantic_type, 0) + overlap
            semantic_reasons.setdefault(semantic_type, []).append(
                f"{field_type}@{off_start}:{off_end} overlap={overlap}"
            )

        if total_overlap > 0 and semantic_votes:
            ranked = sorted(semantic_votes.items(), key=lambda entry: entry[1], reverse=True)
            chosen_semantic, chosen_score = ranked[0]

            # 如果 unknown 仅略高于其他语义，则优先选择更具体的语义类型。
            if chosen_semantic == "unknown" and len(ranked) > 1:
                for challenger_semantic, challenger_score in ranked[1:]:
                    if challenger_semantic == "unknown":
                        continue
                    if challenger_score >= chosen_score * 0.88:
                        chosen_semantic = challenger_semantic
                        chosen_score = challenger_score
                        break

            coverage = min(1.0, total_overlap / segment_len)
            dominance = chosen_score / max(1e-6, sum(semantic_votes.values()))
            confidence = 0.35 + 0.45 * dominance + 0.15 * coverage

            top_reason_items = semantic_reasons.get(chosen_semantic, [])[:3]
            overlap_sem = semantic_raw_overlap.get(chosen_semantic, 0)
            reason = (
                f"官方 NetPlier overlap-vote -> {chosen_semantic}; "
                f"coverage={coverage:.2f}; semantic_overlap={overlap_sem}; "
                f"evidence={'; '.join(top_reason_items)}"
            )
        else:
            if start >= max_official_end and segment_len >= 4:
                semantic_type = "payload"
                confidence = 0.46
                reason = (
                    "官方 NetPlier 字段在该区间前已耗尽；"
                    "尾部区间按 payload-like 处理"
                )
            else:
                semantic_type = "unknown"
                confidence = 0.33
                reason = "与官方 NetPlier 字段无重叠"
            results.append(
                {
                    "message_cluster": item.get("message_cluster", "cluster_1"),
                    "field_range": f"{start}:{end}",
                    "semantic_type": semantic_type,
                    "confidence": round(max(0.3, min(0.95, confidence)), 3),
                    "source_tool": "netplier_adapter",
                    "reason": reason,
                }
            )
            continue

        results.append(
            {
                "message_cluster": item.get("message_cluster", "cluster_1"),
                "field_range": f"{start}:{end}",
                "semantic_type": chosen_semantic,
                "confidence": round(max(0.3, min(0.95, confidence)), 3),
                "source_tool": "netplier_adapter",
                "reason": reason,
            }
        )

    return results


def _sample_pcap(
    source_pcap: Path,
    sampled_pcap: Path,
    max_packets: int,
) -> tuple[str, str]:
    if max_packets <= 0:
        return str(source_pcap), ""
    try:
        from scapy.all import Dot1Q, Ether, IPv6, IP, rdpcap, wrpcap  # type: ignore
    except Exception as exc:
        return str(source_pcap), f"netplier 采样已跳过：scapy 不可用（{exc}）"

    try:
        packets = rdpcap(str(source_pcap), count=max_packets)
    except Exception as exc:
        return str(source_pcap), f"netplier 采样已跳过：读取 pcap 失败（{exc}）"

    if not packets:
        return str(source_pcap), "netplier 采样已跳过：pcap 未读取到数据包"

    sanitized_packets = []
    stripped_vlan = 0
    dropped_non_ip = 0
    for pkt in packets:
        current = pkt
        try:
            if pkt.haslayer(Dot1Q):
                stripped_vlan += 1
                if pkt.haslayer(IP):
                    ip_payload = pkt[IP].copy()
                    if pkt.haslayer(Ether):
                        current = Ether(src=pkt[Ether].src, dst=pkt[Ether].dst, type=0x0800) / ip_payload
                    else:
                        current = Ether(type=0x0800) / ip_payload
                elif pkt.haslayer(IPv6):
                    ip6_payload = pkt[IPv6].copy()
                    if pkt.haslayer(Ether):
                        current = Ether(src=pkt[Ether].src, dst=pkt[Ether].dst, type=0x86DD) / ip6_payload
                    else:
                        current = Ether(type=0x86DD) / ip6_payload

            if not current.haslayer(IP) and not current.haslayer(IPv6):
                dropped_non_ip += 1
                continue
            sanitized_packets.append(current)
        except Exception:
            sanitized_packets.append(current)

    if dropped_non_ip >= len(packets):
        return (
            str(source_pcap),
            (
                "netplier 采样已跳过：scapy 无法在采样包中保留 IP 层；"
                "将直接使用归一化后的源抓包"
            ),
        )

    if sanitized_packets:
        packets = sanitized_packets
    if not packets:
        return str(source_pcap), "netplier 采样已跳过：VLAN/IP 清洗后数据包为空"

    try:
        wrpcap(str(sampled_pcap), packets)
    except Exception as exc:
        return str(source_pcap), f"netplier 采样已跳过：写入采样 pcap 失败（{exc}）"

    return (
        str(sampled_pcap),
        (
            f"netplier 官方输入已采样为前 {len(packets)} 个数据包，以提升运行稳定性"
            f"（stripped_vlan={stripped_vlan}, dropped_non_ip={dropped_non_ip}）"
        ),
    )


def _discover_binaryinferno_main(extra_args: Dict[str, str]) -> str:
    explicit = _resolve_optional_path(
        extra_args,
        direct_key="binaryinferno_main_path",
        env_keys=["BINARYINFERNO_MAIN_PATH"],
    )
    if explicit and Path(explicit).is_file():
        return explicit

    candidates: list[Path] = []
    home = Path.home()
    inferno_home = _resolve_optional_path(
        extra_args,
        direct_key="binaryinferno_home",
        env_keys=["BINARYINFERNO_HOME"],
    )
    if inferno_home:
        base = Path(inferno_home)
        if base.is_file() and base.name == "blackboard.py":
            candidates.append(base)
        else:
            candidates.extend(
                [
                    base / "blackboard.py",
                    base / "binaryinferno" / "blackboard.py",
                    base / "binaryinferno" / "binaryinferno" / "blackboard.py",
                ]
            )

    candidates.extend(
        [
            home / "BinaryInferno" / "binaryinferno" / "binaryinferno" / "blackboard.py",
            _project_root() / "BinaryInferno" / "binaryinferno" / "binaryinferno" / "blackboard.py",
        ]
    )

    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return ""


def _discover_nemesys_home(extra_args: Dict[str, str]) -> str:
    explicit = _resolve_optional_path(
        extra_args,
        direct_key="nemesys_home",
        env_keys=["NEMESYS_HOME"],
    )
    if explicit:
        explicit_path = Path(explicit)
        if explicit_path.name == "src" and (explicit_path / "nemere").exists():
            return str(explicit_path.parent)
        if (explicit_path / "src" / "nemere").exists():
            return str(explicit_path)

    candidates: list[Path] = []
    home = Path.home()
    candidates.extend(
        [
            home / "tools" / "nemesys",
            home / "nemesys",
            Path("/root/tools/nemesys"),
            _project_root() / "tools" / "nemesys",
        ]
    )

    for candidate in candidates:
        if (candidate / "src" / "nemere").exists():
            return str(candidate)
    return ""


def _extract_binaryinferno_field_hints(stdout: str) -> list[tuple[str, str]]:
    hints: list[tuple[str, str]] = []
    in_section = False
    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if line == "INFERRED DESCRIPTION":
            in_section = True
            continue
        if not in_section:
            continue
        if line.startswith("QTY SAMPLES"):
            break
        match = re.match(r"^\d+\s+([A-Za-z\?])\s+(.+)$", line)
        if not match:
            continue
        symbol = match.group(1).upper()
        detail = match.group(2).strip()
        if detail:
            hints.append((symbol, detail))
    return hints


def _semantic_from_binaryinferno_hint(symbol: str, detail: str) -> tuple[str, float, str]:
    lower = detail.lower()
    width_match = re.search(r"(\d+)\s*byte", lower)
    width_bytes = int(width_match.group(1)) if width_match else 0
    if "unknown type variable length" in lower:
        return "payload", 0.56, f"官方 BinaryInferno 可变长 unknown 提示，按 payload-like 处理: {detail}"
    if "unknown type" in lower and "byte(s)" in lower:
        if width_bytes and width_bytes <= 2:
            return "type", 0.54, f"官方 BinaryInferno 定长 unknown 提示，按 type-like 处理: {detail}"
        if width_bytes and width_bytes <= 4:
            return "id", 0.5, f"官方 BinaryInferno 定长 unknown 提示，按 id-like 处理: {detail}"
        return "id", 0.46, f"官方 BinaryInferno 定长 unknown 提示，按 id-like 处理: {detail}"
    if "checksum" in lower:
        return "checksum", 0.74, f"官方 BinaryInferno 提示: {detail}"
    if "timestamp" in lower or "span seconds" in lower:
        return "timestamp", 0.72, f"官方 BinaryInferno 提示: {detail}"
    if symbol == "L" or "length" in lower:
        return "length", 0.78, f"官方 BinaryInferno 提示: {detail}"
    if symbol == "R" or "variable length" in lower:
        return "payload", 0.68, f"官方 BinaryInferno 提示: {detail}"
    if "sequence" in lower or "counter" in lower:
        return "id", 0.66, f"官方 BinaryInferno 提示: {detail}"
    if symbol in {"I"}:
        return "id", 0.62, f"官方 BinaryInferno 提示: {detail}"
    if symbol in {"C"}:
        return "checksum", 0.7, f"官方 BinaryInferno 提示: {detail}"
    return "unknown", 0.38, f"官方 BinaryInferno 提示: {detail}"


def _binaryinferno_hints_useful(hints: list[tuple[str, str]]) -> bool:
    if not hints:
        return False

    for symbol, detail in hints:
        semantic_type, _, _ = _semantic_from_binaryinferno_hint(symbol, detail)
        if semantic_type != "unknown":
            return True

    structural_hints = 0
    for _, detail in hints:
        lower = detail.lower()
        if "byte" in lower or "length" in lower or "variable" in lower:
            structural_hints += 1
    if structural_hints >= 2:
        return True
    return False


def _map_binaryinferno_hints_to_segments(
    segment_candidates: list[dict[str, Any]],
    hints: list[tuple[str, str]],
) -> list[dict[str, Any]]:
    if not segment_candidates or not hints:
        return []

    grouped: dict[str, list[dict[str, Any]]] = {}
    for item in segment_candidates:
        cluster_id = str(item.get("message_cluster", "cluster_1"))
        grouped.setdefault(cluster_id, []).append(item)

    mapped: list[dict[str, Any]] = []
    for cluster_id, items in grouped.items():
        ordered = sorted(
            items,
            key=lambda entry: (
                int(entry.get("start", 0)),
                int(entry.get("end", 0)),
            ),
        )
        total_segments = len(ordered)
        hint_count = len(hints)
        for index, item in enumerate(ordered):
            start = int(item.get("start", 0))
            end = int(item.get("end", 0))
            if end <= start:
                continue

            if hint_count <= 1:
                hint_index = 0
            elif total_segments <= hint_count:
                hint_index = min(index, hint_count - 1)
            else:
                # 当提示数少于分段数时，按比例把提示均匀映射到各分段。
                hint_index = min(hint_count - 1, int(index * hint_count / max(1, total_segments)))
            symbol, detail = hints[hint_index]
            semantic_type, confidence, reason = _semantic_from_binaryinferno_hint(symbol, detail)
            if total_segments > hint_count:
                confidence = max(0.3, confidence * 0.94)
                reason = f"{reason}; mapped_from_hint_index={hint_index + 1}/{hint_count}"

            mapped.append(
                {
                    "message_cluster": cluster_id,
                    "field_range": f"{start}:{end}",
                    "semantic_type": semantic_type,
                    "confidence": round(max(0.3, min(0.95, confidence)), 3),
                    "source_tool": "binaryinferno_adapter",
                    "reason": reason,
                }
            )
    return mapped


class CliToolBase:
    def __init__(self, shell_runner: Optional[ShellRunner] = None) -> None:
        self.runner = shell_runner or ShellRunner()

    @property
    def name(self) -> str:
        return self.__class__.__name__

    def run(self, input_path: str, output_dir: str, extra_args: Optional[Dict[str, str]] = None) -> ToolRunResult:
        raise NotImplementedError


class TsharkTool(CliToolBase):
    def run(self, input_path: str, output_dir: str, extra_args: Optional[Dict[str, str]] = None) -> ToolRunResult:
        extra_args = extra_args or {}
        timeout_sec = int(extra_args.get("timeout_sec", 90))
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        output_path = Path(output_dir) / "tshark_summary.txt"

        if shutil.which("tshark") is None:
            return ToolRunResult(
                tool_name="tshark",
                success=False,
                input_path=input_path,
                output_path=str(output_path),
                error="PATH 中未找到 tshark",
            )

        # 拼装command
        command = ["tshark", "-r", input_path, "-q", "-z", "io,phs"]
        
        # 调用shellrunner的run
        result = self.runner.run(command, timeout_sec=timeout_sec)

        if result.return_code == 0:
            output_path.write_text(result.stdout, encoding="utf-8")
            return ToolRunResult(
                tool_name="tshark",
                success=True,
                input_path=input_path,
                output_path=str(output_path),
                command_result=result,
                data={"summary": result.stdout[:2000]},
            )

        return ToolRunResult(
            tool_name="tshark",
            success=False,
            input_path=input_path,
            output_path=str(output_path),
            command_result=result,
            error=result.stderr or "tshark 命令执行失败",
        )


class NetzobTool(CliToolBase):
    def run(self, input_path: str, output_dir: str, extra_args: Optional[Dict[str, str]] = None) -> ToolRunResult:
        # 通过独立适配脚本执行：内部采用“官方优先，失败降级”策略。
        extra_args = extra_args or {}
        timeout_sec = int(extra_args.get("timeout_sec", 90))
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        python_bin = _resolve_python_bin(
            extra_args,
            direct_key="netzob_python_bin",
            env_keys=["NETZOB_PYTHON_BIN", "NETZOB_PYTHON"],
        )
        netzob_mode = str(extra_args.get("netzob_mode") or os.getenv("NETZOB_MODE", "auto"))
        netzob_import_layer = str(extra_args.get("netzob_import_layer") or os.getenv("NETZOB_IMPORT_LAYER", "5"))
        netzob_import_layer_candidates = str(
            extra_args.get("netzob_import_layer_candidates")
            or os.getenv("NETZOB_IMPORT_LAYER_CANDIDATES", "5,4,3,2,1")
        )
        python_error = _validate_python_bin(python_bin)
        if python_error:
            return ToolRunResult(
                tool_name="netzob_adapter",
                success=False,
                input_path=input_path,
                output_path=str(Path(output_dir) / "netzob_segments_raw.json"),
                error=python_error,
            )

        script_path = Path(__file__).resolve().parents[1] / "adapters" / "netzob_cli.py"
        output_path = Path(output_dir) / "netzob_segments_raw.json"
        normalize_capture = _resolve_bool(
            extra_args,
            direct_key="normalize_capture_for_official",
            env_keys=["OFFICIAL_CAPTURE_NORMALIZE", "NETZOB_NORMALIZE_CAPTURE"],
            default=True,
        )
        effective_input = input_path
        normalization_notes: list[str] = []
        if normalize_capture and netzob_mode in {"auto", "official"}:
            effective_input, normalization_notes = _normalize_capture_for_official(
                profile_path=input_path,
                output_dir=output_dir,
                runner=self.runner,
                timeout_sec=timeout_sec,
                prefix="netzob",
            )

        # 拼装command
        command = [
            python_bin,
            str(script_path),
            "--input",
            effective_input,
            "--output",
            str(output_path),
            "--mode",
            netzob_mode,
            "--import-layer",
            netzob_import_layer,
            "--import-layer-candidates",
            netzob_import_layer_candidates,
        ]

        # 调用shellrunner的run方法
        result = self.runner.run(
            command,
            timeout_sec=timeout_sec,
            cwd=_project_root(),
            env=_build_tool_env(),
        )

        if result.return_code == 0 and output_path.exists():
            payload = read_json(output_path)
            if normalization_notes:
                notes = payload.get("notes", [])
                if not isinstance(notes, list):
                    notes = []
                notes.extend(normalization_notes)
                payload["notes"] = notes
                output_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
            return ToolRunResult(
                tool_name="netzob_adapter",
                success=True,
                input_path=input_path,
                output_path=str(output_path),
                command_result=result,
                data={**payload, "python_bin": python_bin},
            )

        return ToolRunResult(
            tool_name="netzob_adapter",
            success=False,
            input_path=input_path,
            output_path=str(output_path),
            command_result=result,
            error=result.stderr or "netzob 适配器执行失败",
        )


class NemesysTool(CliToolBase):
    def run(self, input_path: str, output_dir: str, extra_args: Optional[Dict[str, str]] = None) -> ToolRunResult:
        # 通过独立适配脚本执行：支持官方、启发式、自动三种模式（official/heuristic/auto）。
        extra_args = extra_args or {}
        timeout_sec = int(extra_args.get("timeout_sec", 90))
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        python_bin = _resolve_python_bin(
            extra_args,
            direct_key="nemesys_python_bin",
            env_keys=["NEMESYS_PYTHON_BIN", "NEMESYS_PYTHON"],
        )
        python_error = _validate_python_bin(python_bin)
        if python_error:
            return ToolRunResult(
                tool_name="nemesys_adapter",
                success=False,
                input_path=input_path,
                output_path=str(Path(output_dir) / "nemesys_segments_raw.json"),
                error=python_error,
            )

        script_path = Path(__file__).resolve().parents[1] / "adapters" / "nemesys_cli.py"
        output_path = Path(output_dir) / "nemesys_segments_raw.json"
        nemesys_mode = str(
            extra_args.get("nemesys_mode")
            or os.getenv("NEMESYS_MODE", "auto")
        ).strip() or "auto"
        if nemesys_mode not in {"auto", "official", "heuristic"}:
            nemesys_mode = "auto"
        nemesys_home = _discover_nemesys_home(extra_args)
        sigma = str(extra_args.get("nemesys_sigma") or os.getenv("NEMESYS_SIGMA", "0.6")).strip() or "0.6"
        layer = str(extra_args.get("nemesys_layer") or os.getenv("NEMESYS_LAYER", "2")).strip() or "2"
        layer_candidates = str(
            extra_args.get("nemesys_layer_candidates")
            or os.getenv("NEMESYS_LAYER_CANDIDATES", "2,3,4")
        ).strip()
        consensus_min_support = (
            str(
                extra_args.get("nemesys_consensus_min_support")
                or os.getenv("NEMESYS_CONSENSUS_MIN_SUPPORT", "0.60")
            ).strip()
            or "0.60"
        )
        consensus_max_fields = str(
            _resolve_positive_int(
                extra_args,
                direct_key="nemesys_consensus_max_fields",
                env_keys=["NEMESYS_CONSENSUS_MAX_FIELDS"],
                default=64,
            )
        )
        relative_to_ip = _resolve_bool(
            extra_args,
            direct_key="nemesys_relative_to_ip",
            env_keys=["NEMESYS_RELATIVE_TO_IP"],
            default=False,
        )
        disable_refinement = _resolve_bool(
            extra_args,
            direct_key="nemesys_disable_refinement",
            env_keys=["NEMESYS_DISABLE_REFINEMENT"],
            default=False,
        )
        disable_consensus = _resolve_bool(
            extra_args,
            direct_key="nemesys_disable_consensus",
            env_keys=["NEMESYS_DISABLE_CONSENSUS"],
            default=False,
        )
        relative_mode = str(
            extra_args.get("nemesys_relative_to_ip_mode")
            or os.getenv("NEMESYS_RELATIVE_TO_IP_MODE", "auto")
        ).strip().lower()
        if relative_mode not in {"auto", "fixed"}:
            relative_mode = "auto"

        if nemesys_mode == "official" and not nemesys_home:
            return ToolRunResult(
                tool_name="nemesys_adapter",
                success=False,
                input_path=input_path,
                output_path=str(output_path),
                error=(
                    "已请求 NEMESYS official 模式，但 NEMESYS_HOME 不可用。"
                    "请将 NEMESYS_HOME 设置为包含 src/nemere 的仓库根目录。"
                ),
            )

        # 拼装command
        command = [
            python_bin,
            str(script_path),
            "--input",
            input_path,
            "--output",
            str(output_path),
            "--mode",
            nemesys_mode,
            "--sigma",
            sigma,
            "--layer",
            layer,
            "--layer-candidates",
            layer_candidates,
            "--relative-to-ip-mode",
            relative_mode,
            "--consensus-min-support",
            consensus_min_support,
            "--consensus-max-fields",
            consensus_max_fields,
        ]
        if nemesys_home:
            command.extend(["--nemesys-home", nemesys_home])
        if relative_to_ip:
            command.append("--relative-to-ip")
        if disable_refinement:
            command.append("--no-refinement")
        if disable_consensus:
            command.append("--disable-consensus")

        normalize_capture = _resolve_bool(
            extra_args,
            direct_key="normalize_capture_for_official",
            env_keys=["OFFICIAL_CAPTURE_NORMALIZE", "NEMESYS_NORMALIZE_CAPTURE"],
            default=True,
        )
        normalization_notes: list[str] = []
        if normalize_capture and nemesys_mode in {"auto", "official"}:
            effective_input, normalization_notes = _normalize_capture_for_official(
                profile_path=input_path,
                output_dir=output_dir,
                runner=self.runner,
                timeout_sec=timeout_sec,
                prefix="nemesys",
            )
            command[command.index("--input") + 1] = effective_input

        extra_python_paths: list[str] = []
        if nemesys_home:
            extra_python_paths.append(str(Path(nemesys_home) / "src"))
        
        # 调用shellrunner的run方法
        result = self.runner.run(
            command,
            timeout_sec=timeout_sec,
            cwd=_project_root(),
            env=_build_tool_env(extra_python_paths=extra_python_paths),
        )

        if result.return_code == 0 and output_path.exists():
            payload = read_json(output_path)
            if normalization_notes:
                notes = payload.get("notes", [])
                if not isinstance(notes, list):
                    notes = []
                notes.extend(normalization_notes)
                payload["notes"] = notes
                output_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
            return ToolRunResult(
                tool_name="nemesys_adapter",
                success=True,
                input_path=input_path,
                output_path=str(output_path),
                command_result=result,
                data={
                    **payload,
                    "python_bin": python_bin,
                    "nemesys_home": nemesys_home,
                },
            )

        return ToolRunResult(
            tool_name="nemesys_adapter",
            success=False,
            input_path=input_path,
            output_path=str(output_path),
            command_result=result,
            error=result.stderr or "nemesys 适配器执行失败",
        )


class NetPlierAdapter(CliToolBase):
    def run(self, input_path: str, output_dir: str, extra_args: Optional[Dict[str, str]] = None) -> ToolRunResult:
        # 优先尝试 NetPlier 官方入口；失败后回退到本地语义适配脚本。
        extra_args = extra_args or {}
        timeout_sec = int(extra_args.get("timeout_sec", 90))
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        python_bin = _resolve_python_bin(
            extra_args,
            direct_key="netplier_python_bin",
            env_keys=["NETPLIER_PYTHON_BIN", "NETPLIER_PYTHON"],
        )
        python_error = _validate_python_bin(python_bin)
        if python_error:
            return ToolRunResult(
                tool_name="netplier_adapter",
                success=False,
                input_path=input_path,
                output_path=str(Path(output_dir) / "netplier_semantic_raw.json"),
                error=python_error,
            )

        profile_path = extra_args.get("traffic_profile_path")

        if not profile_path:
            return ToolRunResult(
                tool_name="netplier_adapter",
                success=False,
                input_path=input_path,
                error="必须提供 traffic_profile_path",
            )

        output_path = Path(output_dir) / "netplier_semantic_raw.json"
        profile_payload = read_json(profile_path)
        pcap_path = str(profile_payload.get("input_file", "")).strip()

        official_main = _discover_netplier_main(extra_args)
        official_error = ""
        official_timeout_sec = _resolve_positive_int(
            extra_args,
            direct_key="netplier_timeout_sec",
            env_keys=["NETPLIER_TIMEOUT_SEC"],
            default=timeout_sec,
        )
        max_packets = _resolve_positive_int(
            extra_args,
            direct_key="netplier_max_packets",
            env_keys=["NETPLIER_MAX_PACKETS"],
            default=0,
            allow_zero=True,
        )
        sample_note = ""

        if official_main and pcap_path and Path(pcap_path).exists():
            official_output_dir = Path(output_dir) / "netplier_official"
            official_output_dir.mkdir(parents=True, exist_ok=True)
            normalize_capture = _resolve_bool(
                extra_args,
                direct_key="normalize_capture_for_official",
                env_keys=["OFFICIAL_CAPTURE_NORMALIZE", "NETPLIER_NORMALIZE_CAPTURE"],
                default=True,
            )
            normalization_notes: list[str] = []
            official_source_path = Path(pcap_path)
            if normalize_capture:
                normalized_profile_path, normalization_notes = _normalize_capture_for_official(
                    profile_path=profile_path,
                    output_dir=output_dir,
                    runner=self.runner,
                    timeout_sec=timeout_sec,
                    prefix="netplier",
                )
                try:
                    normalized_profile = read_json(normalized_profile_path)
                    normalized_input = str(normalized_profile.get("input_file", "")).strip()
                    if normalized_input and Path(normalized_input).exists():
                        official_source_path = Path(normalized_input)
                except Exception:
                    pass
            sampled_input = Path(output_dir) / "netplier_official_input_sampled.pcap"
            official_input_path, sample_note = _sample_pcap(
                official_source_path,
                sampled_input,
                max_packets=max_packets,
            )
            runner_script = Path(__file__).resolve().parents[1] / "adapters" / "netplier_official_runner.py"
            protocol_type = str(extra_args.get("netplier_protocol_type") or os.getenv("NETPLIER_PROTOCOL_TYPE", "")).strip()
            if not protocol_type:
                protocol_type = _detect_netplier_protocol_type(profile_payload)
            mafft_mode = str(extra_args.get("netplier_mafft_mode") or os.getenv("NETPLIER_MAFFT_MODE", "")).strip()
            multithread = str(extra_args.get("netplier_multithread") or os.getenv("NETPLIER_MULTITHREAD", "")).strip().lower()
            layer = str(extra_args.get("netplier_layer") or os.getenv("NETPLIER_LAYER", "")).strip()
            layer_candidates_raw = str(
                extra_args.get("netplier_layer_candidates")
                or os.getenv("NETPLIER_LAYER_CANDIDATES", "5,4,3,2,1")
            ).strip()
            layer_attempts: list[str] = []
            if layer:
                layer_attempts.append(layer)
            for token in layer_candidates_raw.replace(";", ",").split(","):
                token = token.strip()
                if token and token not in layer_attempts:
                    layer_attempts.append(token)
            if not layer_attempts:
                layer_attempts = [""]

            official_attempt_notes: list[str] = []
            segment_payload = read_json(input_path)
            official_result = None
            for attempt_index, layer_attempt in enumerate(layer_attempts, start=1):
                official_args: list[str] = ["-i", official_input_path, "-o", str(official_output_dir)]
                if protocol_type:
                    official_args.extend(["-t", protocol_type])
                if mafft_mode:
                    official_args.extend(["-m", mafft_mode])
                if layer_attempt:
                    official_args.extend(["-l", layer_attempt])
                if multithread in {"1", "true", "yes", "on"}:
                    official_args.append("-mt")

                official_command = [
                    python_bin,
                    str(runner_script),
                    "--main",
                    official_main,
                    "--",
                    *official_args,
                ]
                official_result = self.runner.run(
                    official_command,
                    timeout_sec=official_timeout_sec,
                    cwd=_project_root(),
                    env=_build_tool_env(extra_python_paths=[str(Path(official_main).resolve().parent)]),
                )

                fields_info_path = official_output_dir / "msa_fields_info.txt"
                official_fields, parse_meta = _parse_netplier_fields_info_with_meta(fields_info_path)
                if official_fields:
                    mapped_candidates = _map_official_fields_to_segments(
                        segment_payload.get("candidates", []),
                        official_fields,
                    )
                    if mapped_candidates:
                        notes: list[str] = [
                            f"官方 NetPlier 命令已执行: {official_main}",
                            f"官方字段解析数量: {len(official_fields)}",
                            (
                                "官方字段解析模式: "
                                f"{parse_meta.get('mode', 'unknown')} "
                                f"(line_count={parse_meta.get('line_count', 0)}, "
                                f"end_mode_count={parse_meta.get('end_mode_count', 0)}, "
                                f"width_mode_count={parse_meta.get('width_mode_count', 0)})"
                            ),
                            f"官方超时设置: {official_timeout_sec}s",
                            f"官方 protocol_type: {protocol_type or 'auto-none'}",
                            f"官方 layer: {layer_attempt or 'default'}（attempt {attempt_index}/{len(layer_attempts)}）",
                        ]
                        if official_attempt_notes:
                            notes.extend(official_attempt_notes)
                        if sample_note:
                            notes.append(sample_note)
                        if normalization_notes:
                            notes.extend(normalization_notes)
                        if official_result.return_code != 0:
                            notes.append(
                                f"官方 NetPlier 返回码 {official_result.return_code}，但部分输出仍可用"
                            )
                        payload = {
                            "tool_name": "netplier_adapter",
                            "success": True,
                            "backend": "official_netplier",
                            "candidates": mapped_candidates,
                            "notes": notes,
                        }
                        output_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
                        return ToolRunResult(
                            tool_name="netplier_adapter",
                            success=True,
                            input_path=input_path,
                            output_path=str(output_path),
                            command_result=official_result,
                            data={**payload, "python_bin": python_bin},
                        )

                if official_result.return_code == 0:
                    official_attempt_notes.append(
                        f"attempt#{attempt_index} layer={layer_attempt or 'default'}: 已执行但字段信息缺失/无效"
                    )
                else:
                    error_text = _compact_error_text(official_result.stderr) or (
                        f"返回码 {official_result.return_code}"
                    )
                    official_attempt_notes.append(
                        f"attempt#{attempt_index} layer={layer_attempt or 'default'} 失败: {error_text}"
                    )

            official_error = "官方 NetPlier 未产出可用字段；" + " | ".join(official_attempt_notes)
            if sample_note:
                official_error = f"{official_error}; {sample_note}"
            if normalization_notes:
                official_error = f"{official_error}; {' | '.join(normalization_notes)}"
        elif official_main and pcap_path and not Path(pcap_path).exists():
            official_error = f"官方 NetPlier 输入 pcap 不存在: {pcap_path}"
        elif not official_main:
            official_error = "未找到官方 NetPlier 入口脚本"

        script_path = Path(__file__).resolve().parents[1] / "adapters" / "netplier_cli.py"
        
        # 拼装command
        command = [
            python_bin,
            str(script_path),
            "--segments",
            input_path,
            "--profile",
            profile_path,
            "--output",
            str(output_path),
        ]
        result = self.runner.run(
            command,
            timeout_sec=timeout_sec,
            cwd=_project_root(),
            env=_build_tool_env(),
        )

        if result.return_code == 0 and output_path.exists():
            payload = read_json(output_path)
            notes = payload.get("notes", [])
            if not isinstance(notes, list):
                notes = []
            if official_error:
                notes.append(f"官方 NetPlier 不可用: {official_error}")
                payload["notes"] = notes
                output_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
            return ToolRunResult(
                tool_name="netplier_adapter",
                success=True,
                input_path=input_path,
                output_path=str(output_path),
                command_result=result,
                data={**payload, "python_bin": python_bin, "official_main": official_main},
            )

        merged_error = result.stderr or "netplier 适配器执行失败"
        if official_error:
            merged_error = f"{merged_error}; 官方 NetPlier 详情: {official_error}"
        return ToolRunResult(
            tool_name="netplier_adapter",
            success=False,
            input_path=input_path,
            output_path=str(output_path),
            command_result=result,
            error=merged_error,
        )


class BinaryInfernoAdapter(CliToolBase):
    def run(self, input_path: str, output_dir: str, extra_args: Optional[Dict[str, str]] = None) -> ToolRunResult:
        # 优先尝试 BinaryInferno 官方 blackboard；失败后回退到本地规则语义。
        extra_args = extra_args or {}
        timeout_sec = int(extra_args.get("timeout_sec", 90))
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        python_bin = _resolve_python_bin(
            extra_args,
            direct_key="binaryinferno_python_bin",
            env_keys=["BINARYINFERNO_PYTHON_BIN", "BINARYINFERNO_PYTHON"],
        )
        python_error = _validate_python_bin(python_bin)
        if python_error:
            return ToolRunResult(
                tool_name="binaryinferno_adapter",
                success=False,
                input_path=input_path,
                output_path=str(Path(output_dir) / "binaryinferno_semantic_raw.json"),
                error=python_error,
            )
        profile_path = extra_args.get("traffic_profile_path")

        if not profile_path:
            return ToolRunResult(
                tool_name="binaryinferno_adapter",
                success=False,
                input_path=input_path,
                error="必须提供 traffic_profile_path",
            )

        output_path = Path(output_dir) / "binaryinferno_semantic_raw.json"
        profile_payload = read_json(profile_path)
        sample_messages = [
            item.strip()
            for item in profile_payload.get("sample_messages_hex", [])
            if isinstance(item, str) and item.strip()
        ]

        official_main = _discover_binaryinferno_main(extra_args)
        official_timeout_sec = _resolve_positive_int(
            extra_args,
            direct_key="binaryinferno_timeout_sec",
            env_keys=["BINARYINFERNO_TIMEOUT_SEC"],
            default=timeout_sec,
        )
        max_messages = _resolve_positive_int(
            extra_args,
            direct_key="binaryinferno_max_messages",
            env_keys=["BINARYINFERNO_MAX_MESSAGES"],
            default=40,
        )
        detectors_raw = str(
            extra_args.get("binaryinferno_detectors")
            or os.getenv("BINARYINFERNO_DETECTORS", "boundBE")
        ).strip()
        detectors = [item for item in re.split(r"[,\s]+", detectors_raw) if item]
        if not detectors:
            detectors = ["boundBE"]
        max_attempts = _resolve_positive_int(
            extra_args,
            direct_key="binaryinferno_max_attempts",
            env_keys=["BINARYINFERNO_MAX_ATTEMPTS"],
            default=3,
        )
        accept_low_signal = _resolve_bool(
            extra_args,
            direct_key="binaryinferno_accept_low_signal",
            env_keys=["BINARYINFERNO_ACCEPT_LOW_SIGNAL"],
            default=True,
        )
        official_error = ""

        if official_main and Path(official_main).exists() and sample_messages:
            bounded_messages = sample_messages[:max_messages]
            stdin_payload = "\n".join(bounded_messages).strip()
            if stdin_payload:
                detector_attempts: list[list[str]] = [detectors]
                default_fallbacks = [
                    ["boundBE", "boundLE"],
                    ["length2BE", "length2LE", "length4BE", "length4LE"],
                    ["seq16BE", "seq16LE", "seq32BE", "seq32LE"],
                    ["BE"],
                    ["LE"],
                ]
                for fallback in default_fallbacks:
                    if fallback not in detector_attempts:
                        detector_attempts.append(fallback)
                detector_attempts = detector_attempts[: max(1, max_attempts)]

                main_dir = Path(official_main).resolve().parent
                floatfinder_dir = main_dir / "floatfinder"
                attempts_notes: list[str] = []
                segment_payload = read_json(input_path)
                per_attempt_timeout = max(15, official_timeout_sec // max(1, len(detector_attempts)))
                if per_attempt_timeout > official_timeout_sec:
                    per_attempt_timeout = official_timeout_sec

                for attempt_index, detector_set in enumerate(detector_attempts, start=1):
                    official_command = [
                        python_bin,
                        official_main,
                        "--detectors",
                        *detector_set,
                        "--n",
                        str(max_messages),
                    ]
                    official_result = self.runner.run(
                        official_command,
                        timeout_sec=per_attempt_timeout,
                        cwd=str(main_dir),
                        env=_build_tool_env(
                            extra_python_paths=[
                                str(main_dir),
                                str(floatfinder_dir),
                            ]
                        ),
                        stdin_text=stdin_payload + "\n",
                    )
                    combined_output = "\n".join(
                        [official_result.stdout or "", official_result.stderr or ""]
                    )
                    hints = _extract_binaryinferno_field_hints(combined_output)
                    useful = _binaryinferno_hints_useful(hints)
                    acceptable = useful or (accept_low_signal and len(hints) >= 2)
                    attempts_notes.append(
                        (
                            f"attempt#{attempt_index} detectors={','.join(detector_set)} "
                            f"rc={official_result.return_code} hints={len(hints)} useful={useful} acceptable={acceptable}"
                        )
                    )

                    if hints and acceptable:
                        mapped_candidates = _map_binaryinferno_hints_to_segments(
                            segment_payload.get("candidates", []),
                            hints,
                        )
                        if mapped_candidates:
                            notes: list[str] = [
                                f"官方 BinaryInferno 命令已执行: {official_main}",
                                f"官方 detectors: {', '.join(detector_set)}",
                                f"官方 attempt 序号: {attempt_index}/{len(detector_attempts)}",
                                f"官方使用消息数: {len(bounded_messages)}",
                                f"官方超时设置: 每次 {per_attempt_timeout}s（总预算 {official_timeout_sec}s）",
                                *attempts_notes,
                            ]
                            if not useful and accept_low_signal:
                                notes.append(
                                    "官方提示信号较弱，但为保留官方链路输出仍予以接受"
                                )
                            if official_result.return_code != 0:
                                notes.append(
                                    f"官方 BinaryInferno 返回码 {official_result.return_code}，但解析出的提示可用"
                                )
                            payload = {
                                "tool_name": "binaryinferno_adapter",
                                "success": True,
                                "backend": "official_binaryinferno",
                                "candidates": mapped_candidates,
                                "notes": notes,
                            }
                            output_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
                            return ToolRunResult(
                                tool_name="binaryinferno_adapter",
                                success=True,
                                input_path=input_path,
                                output_path=str(output_path),
                                command_result=official_result,
                                data={**payload, "python_bin": python_bin},
                            )

                official_error = (
                    "官方 BinaryInferno 未产出可用语义映射；"
                    + " | ".join(attempts_notes)
                    + (
                        f"; command={official_main}; messages={len(bounded_messages)}; timeout={official_timeout_sec}s"
                    )
                )
            else:
                official_error = "官方 BinaryInferno 已跳过：没有有效十六进制消息"
        elif official_main and not Path(official_main).exists():
            official_error = f"未找到官方 BinaryInferno 入口脚本: {official_main}"
        elif not official_main:
            official_error = "未找到官方 BinaryInferno 入口脚本"
        elif not sample_messages:
            official_error = "官方 BinaryInferno 已跳过：traffic profile 中无样本消息"

        script_path = Path(__file__).resolve().parents[1] / "adapters" / "binaryinferno_cli.py"

        # 拼装command
        command = [
            python_bin,
            str(script_path),
            "--segments",
            input_path,
            "--profile",
            profile_path,
            "--output",
            str(output_path),
        ]
        result = self.runner.run(
            command,
            timeout_sec=timeout_sec,
            cwd=_project_root(),
            env=_build_tool_env(),
        )

        if result.return_code == 0 and output_path.exists():
            payload = read_json(output_path)
            notes = payload.get("notes", [])
            if not isinstance(notes, list):
                notes = []
            if official_error:
                notes.append(f"官方 BinaryInferno 不可用: {official_error}")
                payload["notes"] = notes
                output_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
            return ToolRunResult(
                tool_name="binaryinferno_adapter",
                success=True,
                input_path=input_path,
                output_path=str(output_path),
                command_result=result,
                data={**payload, "python_bin": python_bin, "official_main": official_main},
            )

        merged_error = result.stderr or "binaryinferno 适配器执行失败"
        if official_error:
            merged_error = f"{merged_error}; 官方 BinaryInferno 详情: {official_error}"
        return ToolRunResult(
            tool_name="binaryinferno_adapter",
            success=False,
            input_path=input_path,
            output_path=str(output_path),
            command_result=result,
            error=merged_error,
        )
