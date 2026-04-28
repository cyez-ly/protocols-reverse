from __future__ import annotations

import os
from pathlib import Path
import re
from typing import Dict, List, Optional, Tuple

from testcrewai.models import ExecutionPlan, FieldBoundaryCandidate, TrafficProfile
from testcrewai.pipeline.preprocess import _cluster_key_for_payload, _normalize_protocol_name
from testcrewai.tools.protocol_tools import NemesysTool, NetzobTool
from testcrewai.utils.io import write_json


def _deduplicate(candidates: List[FieldBoundaryCandidate]) -> List[FieldBoundaryCandidate]:
    best: Dict[Tuple[str, int, int], FieldBoundaryCandidate] = {}
    for candidate in candidates:
        key = (candidate.message_cluster, candidate.start, candidate.end)
        cached = best.get(key)
        if not cached or candidate.confidence > cached.confidence:
            best[key] = candidate
    return sorted(best.values(), key=lambda item: (item.message_cluster, item.start, item.end))


def _profile_protocols(profile: TrafficProfile) -> set[str]:
    return {item.strip().lower() for item in profile.protocols_observed if item.strip()}


def _is_text_profile(profile: TrafficProfile) -> bool:
    text_protocols = {"http", "smtp", "ftp", "imap", "pop", "sip"}
    protos = _profile_protocols(profile)
    if protos & text_protocols:
        return True
    return profile.protocol_style == "text" and profile.mean_printable_ratio >= 0.60


def _decode_sample_messages(profile: TrafficProfile) -> List[bytes]:
    payloads: List[bytes] = []
    for item in profile.sample_messages_hex:
        try:
            payload = bytes.fromhex(item)
        except ValueError:
            continue
        if payload:
            payloads.append(payload)
    return payloads


def _payloads_by_cluster(profile: TrafficProfile) -> Dict[str, List[bytes]]:
    payloads = _decode_sample_messages(profile)
    grouped: Dict[str, List[bytes]] = {cluster.cluster_id: [] for cluster in profile.message_clusters}
    if not payloads or not profile.message_clusters:
        return grouped

    protocols = {_normalize_protocol_name(item) for item in profile.protocols_observed}
    basis_to_cluster: Dict[str, str] = {}
    for cluster in profile.message_clusters:
        if cluster.basis.startswith("content:key="):
            basis_to_cluster[cluster.basis.split("content:key=", maxsplit=1)[1]] = cluster.cluster_id

    length_to_cluster: Dict[int, str] = {}
    for cluster in profile.message_clusters:
        for length in cluster.representative_lengths:
            length_to_cluster[int(length)] = cluster.cluster_id

    length_map = _cluster_length_map(profile)
    for payload in payloads:
        cluster_id = None
        if basis_to_cluster:
            cluster_id = basis_to_cluster.get(
                _cluster_key_for_payload(payload, profile.protocol_style, protocols)
            )
        if cluster_id is None:
            cluster_id = length_to_cluster.get(len(payload))
        if cluster_id is None and length_map:
            cluster_id = min(
                length_map,
                key=lambda item: abs(length_map[item] - len(payload)),
            )
        if cluster_id is not None:
            grouped.setdefault(cluster_id, []).append(payload)
    return grouped


def _text_boundary_points(payload: bytes, max_fields: int = 36) -> List[int]:
    points = {0, len(payload)}
    if not payload:
        return [0]

    header_end = payload.find(b"\r\n\r\n")
    if header_end < 0:
        header_end = payload.find(b"\n\n")
    scan_limit = header_end + 4 if header_end >= 0 else min(len(payload), 1024)

    for delimiter in [b"\r\n", b"\n"]:
        start = 0
        while start < scan_limit:
            idx = payload.find(delimiter, start, scan_limit)
            if idx < 0:
                break
            points.add(min(len(payload), idx + len(delimiter)))
            start = idx + len(delimiter)
            if len(points) >= max_fields:
                break
        if len(points) >= max_fields:
            break

    first_line_end = min(
        [idx for idx in [payload.find(b"\r\n"), payload.find(b"\n"), scan_limit] if idx >= 0],
        default=scan_limit,
    )
    for delimiter in [b" ", b"\t"]:
        start = 0
        while start < first_line_end:
            idx = payload.find(delimiter, start, first_line_end)
            if idx < 0:
                break
            points.add(min(len(payload), idx + 1))
            start = idx + 1

    colon_limit = min(scan_limit, 768)
    start = 0
    while start < colon_limit:
        idx = payload.find(b":", start, colon_limit)
        if idx < 0:
            break
        points.add(min(len(payload), idx + 1))
        start = idx + 1
        if len(points) >= max_fields:
            break

    if len(points) <= 3 and len(payload) > 64:
        for point in [min(64, len(payload)), min(256, len(payload)), len(payload)]:
            points.add(point)

    ordered = sorted(point for point in points if 0 <= point <= len(payload))
    if len(ordered) > max_fields + 1:
        ordered = ordered[:max_fields] + [len(payload)]
        ordered = sorted(set(ordered))
    return ordered


def _text_protocol_candidates(profile: TrafficProfile) -> List[FieldBoundaryCandidate]:
    if not _is_text_profile(profile):
        return []

    grouped_payloads = _payloads_by_cluster(profile)
    candidates: List[FieldBoundaryCandidate] = []
    for cluster in profile.message_clusters:
        payloads = grouped_payloads.get(cluster.cluster_id, [])
        payload = payloads[0] if payloads else b""
        if not payload and cluster.representative_lengths:
            payload = b" " * int(cluster.representative_lengths[0])
        if not payload:
            continue

        points = _text_boundary_points(payload)
        for start, end in zip(points[:-1], points[1:]):
            if end <= start:
                continue
            candidates.append(
                FieldBoundaryCandidate(
                    message_cluster=cluster.cluster_id,
                    start=start,
                    end=end,
                    confidence=0.68,
                    source_tool="text_segmenter",
                    reason="基于文本协议分隔符/行结构的轻量切分",
                )
            )
    return candidates


def _fallback_candidates(profile: TrafficProfile) -> List[FieldBoundaryCandidate]:
    fallback: List[FieldBoundaryCandidate] = []
    if not profile.message_clusters:
        return fallback

    for cluster in profile.message_clusters:
        if not cluster.representative_lengths:
            continue
        message_len = int(cluster.representative_lengths[0])
        if message_len <= 0:
            continue

        boundary_points = [0]
        if message_len > 1:
            boundary_points.append(1)
        if message_len > 3:
            boundary_points.append(3)
        if message_len > 8:
            boundary_points.append(8)
        boundary_points.append(message_len)

        boundary_points = sorted(set(point for point in boundary_points if 0 <= point <= message_len))
        for start, end in zip(boundary_points[:-1], boundary_points[1:]):
            if end <= start:
                continue
            fallback.append(
                FieldBoundaryCandidate(
                    message_cluster=cluster.cluster_id,
                    start=start,
                    end=end,
                    confidence=0.45,
                    source_tool="fallback_segmenter",
                    reason="基于长度的 fallback 切分",
                )
            )

    return fallback


def _ordered_segmentation_tools(execution_plan: ExecutionPlan) -> List[str]:
    segmentation_tools = {"netzob_adapter", "nemesys_adapter"}
    primary = [
        item.tool_name
        for item in execution_plan.decisions
        if item.tool_name in segmentation_tools and item.selected
    ]
    backup = [
        item.tool_name
        for item in execution_plan.decisions
        if item.tool_name in segmentation_tools and not item.selected
    ]
    ordered = primary + backup

    if not ordered:
        ordered = [item for item in execution_plan.selected_tools if item in segmentation_tools]
    if not ordered:
        ordered = ["netzob_adapter", "nemesys_adapter"]

    deduped: List[str] = []
    for item in ordered:
        if item not in deduped:
            deduped.append(item)
    return deduped


def _cluster_length_map(profile: TrafficProfile) -> Dict[str, int]:
    result: Dict[str, int] = {}
    for cluster in profile.message_clusters:
        if cluster.representative_lengths:
            result[cluster.cluster_id] = max(int(length) for length in cluster.representative_lengths)
            continue
        if cluster.mean_length > 0:
            result[cluster.cluster_id] = int(round(cluster.mean_length))
    return result


def _clamp_candidates_to_cluster_lengths(
    candidates: List[FieldBoundaryCandidate],
    profile: TrafficProfile,
) -> tuple[List[FieldBoundaryCandidate], int]:
    length_map = _cluster_length_map(profile)
    if not length_map:
        return candidates, 0

    clamped: List[FieldBoundaryCandidate] = []
    adjusted_count = 0
    for item in candidates:
        cluster_len = length_map.get(item.message_cluster)
        if cluster_len is None or cluster_len <= 0:
            clamped.append(item)
            continue

        start = max(0, min(item.start, cluster_len))
        end = max(start, min(item.end, cluster_len))
        if end <= start:
            adjusted_count += 1
            continue

        if start != item.start or end != item.end:
            adjusted_count += 1
            clamped.append(
                FieldBoundaryCandidate(
                    message_cluster=item.message_cluster,
                    start=start,
                    end=end,
                    confidence=round(max(0.25, item.confidence * 0.92), 3),
                    source_tool=item.source_tool,
                    reason=(
                        f"{item.reason}; clipped_to_cluster_length={cluster_len} "
                        f"from={item.start}:{item.end}"
                    ),
                )
            )
            continue
        clamped.append(item)

    return clamped, adjusted_count


def _merge_overfragmented_candidates(
    candidates: List[FieldBoundaryCandidate],
    profile: TrafficProfile,
) -> tuple[List[FieldBoundaryCandidate], int]:
    if str(os.getenv("SEGMENT_ENABLE_SMALL_FIELD_MERGE", "true")).strip().lower() in {"0", "false", "no", "off"}:
        return candidates, 0
    if not candidates:
        return candidates, 0

    try:
        max_small_width = int(os.getenv("SEGMENT_MERGE_SMALL_WIDTH", "2"))
        max_merged_width = int(os.getenv("SEGMENT_MERGE_MAX_WIDTH", "8"))
        min_cluster_fields = int(os.getenv("SEGMENT_MERGE_MIN_CLUSTER_FIELDS", "16"))
        min_small_ratio = float(os.getenv("SEGMENT_MERGE_MIN_SMALL_RATIO", "0.25"))
    except ValueError:
        max_small_width = 2
        max_merged_width = 8
        min_cluster_fields = 16
        min_small_ratio = 0.25

    grouped: Dict[str, List[FieldBoundaryCandidate]] = {}
    for item in candidates:
        grouped.setdefault(item.message_cluster, []).append(item)

    merged_count = 0
    output: List[FieldBoundaryCandidate] = []
    for cluster_id, items in grouped.items():
        ordered = sorted(items, key=lambda item: (item.start, item.end))
        small_count = sum(1 for item in ordered if item.end - item.start <= max_small_width)
        small_ratio = small_count / max(1, len(ordered))
        if len(ordered) < min_cluster_fields or small_ratio < min_small_ratio:
            output.extend(ordered)
            continue

        idx = 0
        while idx < len(ordered):
            current = ordered[idx]
            width = current.end - current.start
            if width > max_small_width:
                output.append(current)
                idx += 1
                continue

            run = [current]
            run_end = current.end
            cursor = idx + 1
            while cursor < len(ordered):
                nxt = ordered[cursor]
                next_width = nxt.end - nxt.start
                if nxt.start != run_end or next_width > max_small_width:
                    break
                if nxt.end - run[0].start > max_merged_width:
                    break
                run.append(nxt)
                run_end = nxt.end
                cursor += 1

            if len(run) >= 2:
                avg_conf = sum(item.confidence for item in run) / len(run)
                output.append(
                    FieldBoundaryCandidate(
                        message_cluster=cluster_id,
                        start=run[0].start,
                        end=run[-1].end,
                        confidence=round(max(0.3, min(0.9, avg_conf * 0.98)), 3),
                        source_tool=run[0].source_tool,
                        reason=(
                            f"小字段连续片段合并，count={len(run)}; "
                            f"sources={','.join(sorted({item.source_tool for item in run}))}"
                        ),
                    )
                )
                merged_count += len(run) - 1
                idx = cursor
                continue

            output.append(current)
            idx += 1

    return sorted(output, key=lambda item: (item.message_cluster, item.start, item.end)), merged_count


def _normalize_candidate_clusters(
    candidates: List[FieldBoundaryCandidate],
    profile: TrafficProfile,
) -> List[FieldBoundaryCandidate]:
    if not candidates or not profile.message_clusters:
        return candidates

    valid_ids = {cluster.cluster_id for cluster in profile.message_clusters}
    if not valid_ids:
        return candidates

    length_map = _cluster_length_map(profile)
    if len(valid_ids) == 1:
        only_cluster = next(iter(valid_ids))
        for item in candidates:
            item.message_cluster = only_cluster
        return candidates

    normalized: List[FieldBoundaryCandidate] = []
    for item in candidates:
        if item.message_cluster in valid_ids:
            normalized.append(item)
            continue

        guessed_len = 0
        if item.message_cluster.startswith("len_"):
            try:
                guessed_len = int(item.message_cluster.split("_", maxsplit=1)[1])
            except Exception:
                guessed_len = 0

        if guessed_len <= 0:
            guessed_len = max(1, item.end - item.start)

        nearest_cluster = min(
            valid_ids,
            key=lambda cluster_id: abs(length_map.get(cluster_id, guessed_len) - guessed_len),
        )
        normalized.append(
            FieldBoundaryCandidate(
                message_cluster=nearest_cluster,
                start=item.start,
                end=item.end,
                confidence=item.confidence,
                source_tool=item.source_tool,
                reason=f"{item.reason}; cluster_normalized_from={item.message_cluster}",
            )
        )

    return normalized


def _segmentation_quality_issue(
    candidates: List[FieldBoundaryCandidate],
    profile: TrafficProfile,
    min_fields_per_cluster: int,
    max_fields_per_cluster: int,
    max_span_ratio: float,
    max_single_byte_ratio: float,
    min_boundary_stability: float,
    min_coverage_ratio: float,
) -> tuple[bool, str]:
    # 质量门控：用于判断是否需要启用备份分段工具。
    if not candidates:
        return True, "主分段工具未产出候选字段"

    grouped: Dict[str, List[FieldBoundaryCandidate]] = {}
    for item in candidates:
        grouped.setdefault(item.message_cluster, []).append(item)

    cluster_lengths = _cluster_length_map(profile)
    if not grouped:
        return True, "主分段工具未产出可分组候选字段"

    for cluster_id, items in grouped.items():
        if len(items) < max(1, min_fields_per_cluster):
            return True, f"{cluster_id}: field_count={len(items)} < min_required={min_fields_per_cluster}"
        if len(items) > max(1, max_fields_per_cluster):
            return True, f"{cluster_id}: field_count={len(items)} > max_allowed={max_fields_per_cluster}"

        one_byte_count = sum(1 for item in items if max(0, item.end - item.start) <= 1)
        one_byte_ratio = one_byte_count / max(1, len(items))
        if one_byte_ratio > max_single_byte_ratio:
            return True, (
                f"{cluster_id}: one_byte_ratio={one_byte_ratio:.3f} > "
                f"max_allowed={max_single_byte_ratio:.3f}"
            )

        support_ratios: List[float] = []
        for item in items:
            match = re.search(r"support\s*=\s*(\d+)\s*/\s*(\d+)", item.reason)
            if match:
                numer = int(match.group(1))
                denom = int(match.group(2))
                if denom > 0:
                    support_ratios.append(numer / denom)
                continue

            approx_match = re.search(r"support\s*[~:=]\s*(0(?:\.\d+)?|1(?:\.0+)?)", item.reason)
            if approx_match:
                support_ratios.append(float(approx_match.group(1)))
        if support_ratios:
            avg_support = sum(support_ratios) / len(support_ratios)
            if avg_support < min_boundary_stability:
                return True, (
                    f"{cluster_id}: boundary_stability={avg_support:.3f} < "
                    f"min_required={min_boundary_stability:.3f}"
                )

        cluster_len = cluster_lengths.get(cluster_id, 0)
        if cluster_len <= 0:
            continue
        ordered = sorted(items, key=lambda item: (item.start, item.end))
        merged: List[Tuple[int, int]] = []
        for item in ordered:
            start = max(0, item.start)
            end = max(start, item.end)
            if not merged or start > merged[-1][1]:
                merged.append((start, end))
            else:
                prev_start, prev_end = merged[-1]
                merged[-1] = (prev_start, max(prev_end, end))
        covered = sum(max(0, end - start) for start, end in merged)
        coverage_ratio = covered / max(1, cluster_len)
        if coverage_ratio < min_coverage_ratio:
            return True, (
                f"{cluster_id}: coverage_ratio={coverage_ratio:.3f} < "
                f"min_required={min_coverage_ratio:.3f}"
            )

        max_span = max(max(0, item.end - item.start) for item in items)
        span_ratio = max_span / max(1, cluster_len)
        if span_ratio > max_span_ratio:
            # 若其他质量指标都健康，允许出现一个相对较大的尾段，避免过度惩罚。
            relaxed_upper = min(0.99, max_span_ratio + 0.12)
            if not (
                len(items) >= max(1, min_fields_per_cluster)
                and one_byte_ratio <= max_single_byte_ratio
                and coverage_ratio >= min_coverage_ratio
                and span_ratio <= relaxed_upper
            ):
                return True, f"{cluster_id}: max_span_ratio={span_ratio:.3f} > {max_span_ratio:.3f}"

    return False, "primary segmentation quality acceptable"


class SegmentationAgentStage:
    # 分段阶段：执行主分段工具，必要时回退到备份工具或内置兜底策略。
    def __init__(
        self,
        netzob_tool: Optional[NetzobTool] = None,
        nemesys_tool: Optional[NemesysTool] = None,
    ) -> None:
        self.netzob_tool = netzob_tool or NetzobTool()
        self.nemesys_tool = nemesys_tool or NemesysTool()

    def run(
        self,
        profile: TrafficProfile,
        execution_plan: ExecutionPlan,
        traffic_profile_path: str,
        output_dir: str,
        timeout_sec: int,
        python_bin: str,
        netzob_python_bin: str,
        nemesys_python_bin: str,
        logger,
    ) -> List[FieldBoundaryCandidate]:
        # 输出统一结构：字段切分候选结果文件。
        candidates: List[FieldBoundaryCandidate] = []
        tool_errors: List[str] = []
        runtime_info: Dict[str, str] = {}

        if not execution_plan.selected_tools and not profile.message_clusters:
            payload = {
                "candidates": [],
                "tool_errors": [
                    "未执行字段切分：当前没有可解析流量。",
                ],
                "runtime_info": runtime_info,
            }
            output_path = Path(output_dir) / "segment_candidates.json"
            write_json(output_path, payload)
            logger.info("Segmentation completed -> %s", output_path)
            return candidates

        ordered_tools = _ordered_segmentation_tools(execution_plan)
        runtime_info["segmentation_primary_tool"] = ordered_tools[0]
        if len(ordered_tools) > 1:
            runtime_info["segmentation_backup_tool"] = ordered_tools[1]

        min_fields_per_cluster = int(os.getenv("SEGMENT_MIN_FIELDS_PER_CLUSTER", "4"))
        max_fields_per_cluster = int(os.getenv("SEGMENT_MAX_FIELDS_PER_CLUSTER", "64"))
        try:
            max_span_ratio = float(os.getenv("SEGMENT_MAX_SPAN_RATIO", "0.85"))
        except ValueError:
            max_span_ratio = 0.85
        try:
            max_single_byte_ratio = float(os.getenv("SEGMENT_MAX_SINGLE_BYTE_RATIO", "0.60"))
        except ValueError:
            max_single_byte_ratio = 0.60
        try:
            min_boundary_stability = float(os.getenv("SEGMENT_MIN_BOUNDARY_STABILITY", "0.30"))
        except ValueError:
            min_boundary_stability = 0.30
        try:
            min_coverage_ratio = float(os.getenv("SEGMENT_MIN_COVERAGE_RATIO", "0.55"))
        except ValueError:
            min_coverage_ratio = 0.55

        text_candidates = _text_protocol_candidates(profile)
        if text_candidates:
            text_issue, text_reason = _segmentation_quality_issue(
                text_candidates,
                profile=profile,
                min_fields_per_cluster=1,
                max_fields_per_cluster=max_fields_per_cluster,
                max_span_ratio=1.01,
                max_single_byte_ratio=max_single_byte_ratio,
                min_boundary_stability=0.0,
                min_coverage_ratio=min_coverage_ratio,
            )
            runtime_info["text_segmenter_candidates"] = str(len(text_candidates))
            runtime_info["text_segmenter_quality_reason"] = text_reason
            if not text_issue:
                candidates = _normalize_candidate_clusters(text_candidates, profile)
                candidates, clipped_count = _clamp_candidates_to_cluster_lengths(candidates, profile)
                candidates = _deduplicate(candidates)
                candidates, merged_count = _merge_overfragmented_candidates(candidates, profile)
                runtime_info["segmentation_attempted_tools"] = "text_segmenter"
                runtime_info["text_segmenter_used"] = "true"
                runtime_info["segment_boundary_clipped_count"] = str(clipped_count)
                runtime_info["small_field_merge_count"] = str(merged_count)
                payload = {
                    "candidates": [item.model_dump(mode="json") for item in candidates],
                    "tool_errors": tool_errors,
                    "runtime_info": runtime_info,
                }
                output_path = Path(output_dir) / "segment_candidates.json"
                write_json(output_path, payload)
                logger.info("Segmentation completed -> %s", output_path)
                return candidates
            runtime_info["text_segmenter_used"] = "false"

        attempted: List[str] = []
        quality_triggered = False
        quality_reason = ""
        for idx, tool_name in enumerate(ordered_tools):
            # 单工具优先 + 质量门控：
            # 仅当主工具失败/为空/质量不达标时，才启用备份工具。
            if idx > 0 and candidates and not quality_triggered:
                break
            attempted.append(tool_name)

            parsed_candidates: List[FieldBoundaryCandidate] = []
            if tool_name == "netzob_adapter":
                tool_result = self.netzob_tool.run(
                    input_path=traffic_profile_path,
                    output_dir=output_dir,
                    extra_args={
                        "timeout_sec": str(timeout_sec),
                        "python_bin": python_bin,
                        "netzob_python_bin": netzob_python_bin,
                    },
                )
                if tool_result.success:
                    runtime_info["netzob_python_bin"] = str(tool_result.data.get("python_bin", ""))
                    raw_candidates = tool_result.data.get("candidates", [])
                    parsed_count = 0
                    for raw_candidate in raw_candidates:
                        try:
                            parsed_candidates.append(FieldBoundaryCandidate(**raw_candidate))
                            parsed_count += 1
                        except Exception:
                            continue
                    candidates.extend(parsed_candidates)
                else:
                    tool_errors.append(tool_result.error or f"{tool_name} 执行失败")
                    continue

            elif tool_name == "nemesys_adapter":
                tool_result = self.nemesys_tool.run(
                    input_path=traffic_profile_path,
                    output_dir=output_dir,
                    extra_args={
                        "timeout_sec": str(timeout_sec),
                        "python_bin": python_bin,
                        "nemesys_python_bin": nemesys_python_bin,
                    },
                )
                if tool_result.success:
                    runtime_info["nemesys_python_bin"] = str(tool_result.data.get("python_bin", ""))
                    runtime_info["nemesys_home"] = str(tool_result.data.get("nemesys_home", ""))
                    raw_candidates = tool_result.data.get("candidates", [])
                    parsed_count = 0
                    for raw_candidate in raw_candidates:
                        try:
                            parsed_candidates.append(FieldBoundaryCandidate(**raw_candidate))
                            parsed_count += 1
                        except Exception:
                            continue
                    candidates.extend(parsed_candidates)
                else:
                    tool_errors.append(tool_result.error or f"{tool_name} 执行失败")
                    continue

            else:
                tool_errors.append(f"未知分段工具: {tool_name}")
                continue

            if idx == 0:
                quality_triggered, quality_reason = _segmentation_quality_issue(
                    parsed_candidates,
                    profile=profile,
                    min_fields_per_cluster=min_fields_per_cluster,
                    max_fields_per_cluster=max_fields_per_cluster,
                    max_span_ratio=max_span_ratio,
                    max_single_byte_ratio=max_single_byte_ratio,
                    min_boundary_stability=min_boundary_stability,
                    min_coverage_ratio=min_coverage_ratio,
                )
                runtime_info["segmentation_quality_triggered"] = str(quality_triggered).lower()
                runtime_info["segmentation_quality_reason"] = quality_reason
                runtime_info["segment_min_fields_per_cluster"] = str(min_fields_per_cluster)
                runtime_info["segment_max_fields_per_cluster"] = str(max_fields_per_cluster)
                runtime_info["segment_max_span_ratio"] = f"{max_span_ratio:.3f}"
                runtime_info["segment_max_single_byte_ratio"] = f"{max_single_byte_ratio:.3f}"
                runtime_info["segment_min_boundary_stability"] = f"{min_boundary_stability:.3f}"
                runtime_info["segment_min_coverage_ratio"] = f"{min_coverage_ratio:.3f}"
            elif parsed_candidates and quality_triggered:
                # 若主工具质量不达标，则以备份工具结果作为最终分段结果。
                candidates.clear()
                candidates.extend(parsed_candidates)
                tool_errors.append(
                    f"Segmentation backup tool triggered（分段备份已触发）({tool_name}): {quality_reason}; "
                    f"backup_candidates={len(parsed_candidates)}"
                )

        runtime_info["segmentation_attempted_tools"] = ",".join(attempted)

        if not candidates:
            candidates.extend(_fallback_candidates(profile))
            tool_errors.append("分段 fallback 已触发：工具输出为空。")

        candidates = _normalize_candidate_clusters(candidates, profile)
        candidates, clipped_count = _clamp_candidates_to_cluster_lengths(candidates, profile)
        candidates = _deduplicate(candidates)
        candidates, merged_count = _merge_overfragmented_candidates(candidates, profile)
        runtime_info["segment_boundary_clipped_count"] = str(clipped_count)
        runtime_info["small_field_merge_count"] = str(merged_count)
        payload = {
            "candidates": [item.model_dump(mode="json") for item in candidates],
            "tool_errors": tool_errors,
            "runtime_info": runtime_info,
        }
        output_path = Path(output_dir) / "segment_candidates.json"
        write_json(output_path, payload)
        logger.info("Segmentation completed -> %s", output_path)
        return candidates
