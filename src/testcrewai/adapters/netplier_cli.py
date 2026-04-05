from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
import sys
from typing import Any, Dict, List, Tuple

"""

    语义推断降级适配器（非官方 main.py）。对已有边界打分推断 length/type/payload/unknown；
    输出 netplier_semantic_raw.json。

"""


PROJECT_SRC = Path(__file__).resolve().parents[2]
if str(PROJECT_SRC) not in sys.path:
    sys.path.insert(0, str(PROJECT_SRC))

from testcrewai.adapters.common import cluster_messages_by_length, printable_ratio, range_to_str


def score_length_field(messages: List[bytes], start: int, end: int) -> Tuple[float, str]:
    # 长度字段打分：检查字段值是否与报文总长/剩余长度一致。
    if not messages or end - start > 4:
        return 0.0, "field too wide for length inference"
    checked = 0
    matches = 0
    for message in messages:
        if len(message) < end:
            continue
        value = int.from_bytes(message[start:end], byteorder="big", signed=False)
        checked += 1
        if value in {len(message), len(message) - start, len(message) - end}:
            matches += 1
    if checked == 0:
        return 0.0, "insufficient samples"
    ratio = matches / checked
    return ratio, f"{matches}/{checked} values match packet length patterns"


def score_type_field(messages: List[bytes], start: int, end: int) -> Tuple[float, str]:
    # 类型字段打分：候选值越稳定（离散度低），越像 type。
    if not messages or end - start > 2:
        return 0.0, "field too wide for type inference"
    values = []
    for message in messages:
        if len(message) >= end:
            values.append(int.from_bytes(message[start:end], "big"))
    if not values:
        return 0.0, "no aligned samples"
    distinct = len(set(values))
    ratio = distinct / len(values)
    score = max(0.0, min(1.0, 1.0 - ratio))
    return score, f"distinct={distinct}, samples={len(values)}"


def score_payload_field(messages: List[bytes], start: int, end: int) -> Tuple[float, str]:
    # 载荷字段打分：字段占比更大且可打印比例合理时，更偏向 payload。
    if not messages:
        return 0.0, "no samples"
    lengths = [len(msg) for msg in messages]
    avg_len = sum(lengths) / len(lengths)
    field_len = end - start
    if field_len <= 0:
        return 0.0, "invalid range"
    ratio = field_len / max(1.0, avg_len)
    if ratio < 0.35:
        return 0.0, f"field ratio {ratio:.2f} too small"

    ratios = []
    for message in messages:
        if len(message) >= end:
            ratios.append(printable_ratio(message[start:end]))
    mean_ratio = sum(ratios) / max(1, len(ratios))
    score = min(1.0, 0.5 + ratio * 0.3 + mean_ratio * 0.2)
    return score, f"size ratio={ratio:.2f}, printable={mean_ratio:.2f}"


def main() -> None:
    # 该脚本是 NetPlier 的本地降级语义路径（非官方 main.py）。
    parser = argparse.ArgumentParser(description="NetPlier-style semantic inference adapter")
    parser.add_argument("--segments", required=True, help="segment_candidates.json path")
    parser.add_argument("--profile", required=True, help="traffic_profile.json path")
    parser.add_argument("--output", required=True, help="output json path")
    args = parser.parse_args()

    profile = json.loads(Path(args.profile).read_text(encoding="utf-8"))
    segments = json.loads(Path(args.segments).read_text(encoding="utf-8"))

    messages = []
    for raw_hex in profile.get("sample_messages_hex", []):
        try:
            messages.append(bytes.fromhex(raw_hex))
        except ValueError:
            continue
    cluster_messages = cluster_messages_by_length(messages)

    by_cluster: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for candidate in segments.get("candidates", []):
        by_cluster[candidate.get("message_cluster", "cluster_1")].append(candidate)

    semantic_results: List[Dict[str, Any]] = []

    for cluster_id, cluster_candidates in by_cluster.items():
        # 逐 cluster 推断语义，避免不同长度消息相互污染。
        candidates_messages = cluster_messages.get(cluster_id, messages)
        for candidate in cluster_candidates:
            start = int(candidate["start"])
            end = int(candidate["end"])

            length_score, length_reason = score_length_field(candidates_messages, start, end)
            type_score, type_reason = score_type_field(candidates_messages, start, end)
            payload_score, payload_reason = score_payload_field(candidates_messages, start, end)

            options = [
                ("length", length_score, length_reason),
                ("type", type_score, type_reason),
                ("payload", payload_score, payload_reason),
            ]
            # 选择得分最高的语义；低分统一降为 unknown。
            semantic_type, confidence, reason = max(options, key=lambda item: item[1])

            if confidence < 0.45:
                semantic_type = "unknown"

            semantic_results.append(
                {
                    "message_cluster": cluster_id,
                    "field_range": range_to_str(start, end),
                    "semantic_type": semantic_type,
                    "confidence": round(max(0.3, min(0.95, confidence)), 3),
                    "source_tool": "netplier_adapter",
                    "reason": reason,
                }
            )

    payload = {
        "tool_name": "netplier_adapter",
        "success": True,
        "candidates": semantic_results,
    }
    Path(args.output).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
