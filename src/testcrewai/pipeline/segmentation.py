from __future__ import annotations

import os
from pathlib import Path
import re
from typing import Dict, List, Optional, Tuple

from testcrewai.models import ExecutionPlan, FieldBoundaryCandidate, TrafficProfile
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
                    reason="Length-based fallback segmentation",
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
            result[cluster.cluster_id] = int(cluster.representative_lengths[0])
            continue
        if cluster.mean_length > 0:
            result[cluster.cluster_id] = int(round(cluster.mean_length))
    return result


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
        return True, "primary segmentation produced no candidates"

    grouped: Dict[str, List[FieldBoundaryCandidate]] = {}
    for item in candidates:
        grouped.setdefault(item.message_cluster, []).append(item)

    cluster_lengths = _cluster_length_map(profile)
    if not grouped:
        return True, "primary segmentation produced no grouped candidates"

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
            # Allow one relatively-large tail span when other quality signals are healthy.
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
    # 分段阶段：执行主分段工具，必要时回退到备份工具或内置 fallback。
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
        # 输出统一结构：segment_candidates.json
        candidates: List[FieldBoundaryCandidate] = []
        tool_errors: List[str] = []
        runtime_info: Dict[str, str] = {}

        if not execution_plan.selected_tools and not profile.message_clusters:
            payload = {
                "candidates": [],
                "tool_errors": [
                    "No segmentation executed because no parseable traffic was available.",
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

        attempted: List[str] = []
        quality_triggered = False
        quality_reason = ""
        for idx, tool_name in enumerate(ordered_tools):
            # Single-tool-first with quality gate:
            # run backup only when primary is empty/failed or quality gate is not satisfied.
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
                    tool_errors.append(tool_result.error or f"{tool_name} failed")
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
                    tool_errors.append(tool_result.error or f"{tool_name} failed")
                    continue

            else:
                tool_errors.append(f"unknown segmentation tool: {tool_name}")
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
                # When quality gate says primary segmentation is poor, use backup output as authoritative.
                candidates.clear()
                candidates.extend(parsed_candidates)
                tool_errors.append(
                    f"Segmentation backup tool triggered ({tool_name}): {quality_reason}; "
                    f"backup_candidates={len(parsed_candidates)}"
                )

        runtime_info["segmentation_attempted_tools"] = ",".join(attempted)

        if not candidates:
            candidates.extend(_fallback_candidates(profile))
            tool_errors.append("Segmentation fallback triggered because tool output was empty.")

        candidates = _normalize_candidate_clusters(candidates, profile)
        candidates = _deduplicate(candidates)
        payload = {
            "candidates": [item.model_dump(mode="json") for item in candidates],
            "tool_errors": tool_errors,
            "runtime_info": runtime_info,
        }
        output_path = Path(output_dir) / "segment_candidates.json"
        write_json(output_path, payload)
        logger.info("Segmentation completed -> %s", output_path)
        return candidates
