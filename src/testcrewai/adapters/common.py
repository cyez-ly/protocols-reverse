from __future__ import annotations

import math
from collections import defaultdict
from typing import Dict, Iterable, List, Sequence, Tuple


def shannon_entropy(values: Sequence[int]) -> float:
    # 计算离散序列的信息熵。
    if not values:
        return 0.0
    counts: Dict[int, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    total = len(values)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def printable_ratio(payload: bytes) -> float:
    # 统计可打印字符比例，用于区分文本/二进制倾向。
    if not payload:
        return 0.0
    printable = 0
    for value in payload:
        if 32 <= value <= 126 or value in (9, 10, 13):
            printable += 1
    return printable / len(payload)


def range_to_str(start: int, end: int) -> str:
    return f"{start}:{end}"


def parse_range(field_range: str) -> Tuple[int, int]:
    start_str, end_str = field_range.split(":", maxsplit=1)
    return int(start_str), int(end_str)


def cluster_messages_by_length(messages: List[bytes], min_cluster_size: int = 2) -> Dict[str, List[bytes]]:
    # 以消息长度聚类（原型阶段的轻量分群方式）。
    buckets: Dict[int, List[bytes]] = defaultdict(list)
    for message in messages:
        buckets[len(message)].append(message)

    clusters: Dict[str, List[bytes]] = {}
    cluster_idx = 1
    for length, members in sorted(buckets.items(), key=lambda item: (-len(item[1]), item[0])):
        if len(members) >= min_cluster_size:
            clusters[f"cluster_{cluster_idx}"] = members
            cluster_idx += 1

    if not clusters and messages:
        clusters["cluster_1"] = messages
    return clusters


def non_overlapping_ranges(ranges: Iterable[Tuple[int, int, float]]) -> List[Tuple[int, int, float]]:
    # 按分数贪心选择互不重叠区间，用于融合阶段边界裁决。
    ordered = sorted(ranges, key=lambda item: (-item[2], item[1] - item[0]))
    selected: List[Tuple[int, int, float]] = []

    def overlaps(start: int, end: int) -> bool:
        for s, e, _ in selected:
            if not (end <= s or start >= e):
                return True
        return False

    for start, end, score in ordered:
        if start >= end:
            continue
        if overlaps(start, end):
            continue
        selected.append((start, end, score))

    return sorted(selected, key=lambda item: item[0])
