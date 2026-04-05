from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
import sys
from typing import Any, Dict, List, Tuple

"""
    
    语义推断降级适配器（非官方 blackboard 直连）。对已有边界打分推断 timestamp/id/checksum/unknown；
    输出 binaryinferno_semantic_raw.json。

"""


PROJECT_SRC = Path(__file__).resolve().parents[2]
if str(PROJECT_SRC) not in sys.path:
    sys.path.insert(0, str(PROJECT_SRC))

from testcrewai.adapters.common import (
    cluster_messages_by_length,
    printable_ratio,
    range_to_str,
)


def score_timestamp_field(messages: List[bytes], start: int, end: int) -> Tuple[float, str]:
    # 时间戳字段打分：检查 4/8 字节字段是否落在合理 Unix 时间范围。
    if end - start not in (4, 8):
        return 0.0, "timestamp usually 4 or 8 bytes"
    values = []
    for message in messages:
        if len(message) >= end:
            values.append(int.from_bytes(message[start:end], "big"))
    if not values:
        return 0.0, "no values"

    valid = [946684800 <= value <= 4102444800 for value in values]
    ratio = sum(1 for flag in valid if flag) / len(valid)
    return ratio, f"{sum(valid)}/{len(valid)} values in [2000, 2100] unix-ts range"


def score_id_field(messages: List[bytes], start: int, end: int) -> Tuple[float, str]:
    # ID 字段打分：唯一值比例越高，越像标识符字段。
    if end - start < 2:
        return 0.0, "id field generally at least 2 bytes"
    values = []
    for message in messages:
        if len(message) >= end:
            values.append(message[start:end])
    if not values:
        return 0.0, "no aligned values"
    unique_ratio = len(set(values)) / len(values)
    return unique_ratio, f"unique ratio={unique_ratio:.2f}"


def score_checksum_field(messages: List[bytes], start: int, end: int) -> Tuple[float, str]:
    # 校验字段打分：偏尾部、非可打印字节比例高通常更像 checksum。
    field_len = end - start
    if field_len not in (1, 2, 4):
        return 0.0, "checksum usually 1/2/4 bytes"
    if not messages:
        return 0.0, "no samples"

    near_tail_votes = 0
    low_printable_votes = 0
    evaluated = 0
    for message in messages:
        if len(message) < end:
            continue
        evaluated += 1
        if start >= len(message) - 6:
            near_tail_votes += 1
        if printable_ratio(message[start:end]) < 0.2:
            low_printable_votes += 1

    if evaluated == 0:
        return 0.0, "insufficient samples"
    score = 0.5 * (near_tail_votes / evaluated) + 0.5 * (low_printable_votes / evaluated)
    return score, f"tail={near_tail_votes}/{evaluated}, nonprintable={low_printable_votes}/{evaluated}"


def main() -> None:
    # 该脚本是 BinaryInferno 的本地降级语义路径（非官方 blackboard.py）。
    parser = argparse.ArgumentParser(description="BinaryInferno-style semantic inference adapter")
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
        # 逐 cluster 推断语义，减少跨消息类型干扰。
        cluster_payloads = cluster_messages.get(cluster_id, messages)

        for boundary in cluster_candidates:
            start = int(boundary["start"])
            end = int(boundary["end"])

            timestamp_score, timestamp_reason = score_timestamp_field(cluster_payloads, start, end)
            id_score, id_reason = score_id_field(cluster_payloads, start, end)
            checksum_score, checksum_reason = score_checksum_field(cluster_payloads, start, end)

            options = [
                ("timestamp", timestamp_score, timestamp_reason),
                ("id", id_score, id_reason),
                ("checksum", checksum_score, checksum_reason),
            ]
            # 选择最高分语义；低分降级为 unknown。
            semantic_type, confidence, reason = max(options, key=lambda item: item[1])

            if confidence < 0.45:
                semantic_type = "unknown"

            semantic_results.append(
                {
                    "message_cluster": cluster_id,
                    "field_range": range_to_str(start, end),
                    "semantic_type": semantic_type,
                    "confidence": round(max(0.3, min(0.95, confidence)), 3),
                    "source_tool": "binaryinferno_adapter",
                    "reason": reason,
                }
            )

    payload = {
        "tool_name": "binaryinferno_adapter",
        "success": True,
        "candidates": semantic_results,
    }
    Path(args.output).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
