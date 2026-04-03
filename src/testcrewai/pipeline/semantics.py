from __future__ import annotations

import os
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional

from testcrewai.adapters.common import parse_range, range_to_str
from testcrewai.models import ExecutionPlan, FieldBoundaryCandidate, FieldSemanticCandidate
from testcrewai.tools.protocol_tools import BinaryInfernoAdapter, NetPlierAdapter
from testcrewai.utils.io import write_json


def _fallback_semantics(boundaries: List[FieldBoundaryCandidate]) -> List[FieldSemanticCandidate]:
    grouped: Dict[str, List[FieldBoundaryCandidate]] = {}
    for boundary in boundaries:
        grouped.setdefault(boundary.message_cluster, []).append(boundary)

    results: List[FieldSemanticCandidate] = []
    for cluster_id, candidates in grouped.items():
        ordered = sorted(candidates, key=lambda item: item.start)
        for idx, candidate in enumerate(ordered):
            semantic_type = "unknown"
            confidence = 0.38
            reason = "fallback 语义规则"

            if idx == 0 and candidate.end - candidate.start <= 2:
                semantic_type = "type"
                confidence = 0.55
                reason = "首个短字段通常更像消息类型"
            elif idx == 1 and candidate.end - candidate.start <= 4:
                semantic_type = "length"
                confidence = 0.52
                reason = "第二个短字段可能是长度字段"
            elif idx == len(ordered) - 1:
                semantic_type = "payload"
                confidence = 0.58
                reason = "在 fallback 策略中，尾字段通常视为 payload"

            results.append(
                FieldSemanticCandidate(
                    message_cluster=cluster_id,
                    field_range=range_to_str(candidate.start, candidate.end),
                    semantic_type=semantic_type,
                    confidence=confidence,
                    source_tool="fallback_semantic",
                    reason=reason,
                )
            )

    return results


def _ordered_semantic_tools(execution_plan: ExecutionPlan) -> List[str]:
    semantic_tools = {"netplier_adapter", "binaryinferno_adapter"}
    primary = [
        item.tool_name
        for item in execution_plan.decisions
        if item.tool_name in semantic_tools and item.selected
    ]
    backup = [
        item.tool_name
        for item in execution_plan.decisions
        if item.tool_name in semantic_tools and not item.selected
    ]
    ordered = primary + backup

    if not ordered:
        ordered = [item for item in execution_plan.selected_tools if item in semantic_tools]
    if not ordered:
        ordered = ["netplier_adapter", "binaryinferno_adapter"]

    deduped: List[str] = []
    for item in ordered:
        if item not in deduped:
            deduped.append(item)
    return deduped


def _unknown_ratio(candidates: List[FieldSemanticCandidate]) -> float:
    if not candidates:
        return 1.0
    unknown_count = sum(1 for item in candidates if item.semantic_type == "unknown")
    return unknown_count / max(1, len(candidates))


def _dominant_semantic_ratio(candidates: List[FieldSemanticCandidate]) -> tuple[str, float]:
    if not candidates:
        return "unknown", 1.0
    counter = Counter(item.semantic_type for item in candidates)
    semantic_type, count = counter.most_common(1)[0]
    return semantic_type, count / max(1, len(candidates))


def _align_semantics_to_boundaries(
    semantic_candidates: List[FieldSemanticCandidate],
    boundaries: List[FieldBoundaryCandidate],
) -> tuple[List[FieldSemanticCandidate], int]:
    # 语义边界对齐：减少“分段工具”和“语义工具”边界不一致带来的损耗。
    if not semantic_candidates or not boundaries:
        return semantic_candidates, 0

    boundary_map: Dict[str, List[tuple[int, int]]] = {}
    for boundary in boundaries:
        boundary_map.setdefault(boundary.message_cluster, []).append((boundary.start, boundary.end))

    for cluster_id in list(boundary_map.keys()):
        boundary_map[cluster_id] = sorted(set(boundary_map[cluster_id]), key=lambda item: (item[0], item[1]))

    aligned_count = 0
    aligned: List[FieldSemanticCandidate] = []
    for candidate in semantic_candidates:
        ranges = boundary_map.get(candidate.message_cluster, [])
        if not ranges:
            aligned.append(candidate)
            continue

        try:
            start, end = parse_range(candidate.field_range)
        except Exception:
            aligned.append(candidate)
            continue

        if (start, end) in ranges:
            aligned.append(candidate)
            continue

        best_overlap = 0.0
        best_range: tuple[int, int] | None = None
        for b_start, b_end in ranges:
            inter = max(0, min(end, b_end) - max(start, b_start))
            if inter <= 0:
                continue
            union = max(end, b_end) - min(start, b_start)
            ratio = inter / max(1, union)
            if ratio > best_overlap:
                best_overlap = ratio
                best_range = (b_start, b_end)

        chosen = best_range
        align_mode = "overlap"
        if chosen is None:
            # No overlap: use nearest boundary to reduce cross-tool boundary mismatch.
            best_distance: int | None = None
            for b_start, b_end in ranges:
                distance = abs(start - b_start) + abs(end - b_end)
                if best_distance is None or distance < best_distance:
                    best_distance = distance
                    chosen = (b_start, b_end)
            if best_distance is None or best_distance > 8:
                aligned.append(candidate)
                continue
            align_mode = "nearest"

        assert chosen is not None
        new_start, new_end = chosen
        conf = candidate.confidence
        if align_mode == "overlap":
            conf *= max(0.8, min(1.0, 0.88 + best_overlap * 0.12))
            note = f"aligned_to_boundary {start}:{end}->{new_start}:{new_end} overlap={best_overlap:.2f}"
        else:
            conf *= 0.82
            note = f"aligned_to_boundary {start}:{end}->{new_start}:{new_end} nearest-gap"

        aligned.append(
            FieldSemanticCandidate(
                message_cluster=candidate.message_cluster,
                field_range=f"{new_start}:{new_end}",
                semantic_type=candidate.semantic_type,
                confidence=round(max(0.3, min(0.95, conf)), 3),
                source_tool=candidate.source_tool,
                reason=f"{candidate.reason}; {note}",
            )
        )
        aligned_count += 1

    return aligned, aligned_count


class SemanticInferenceAgentStage:
    # 语义阶段：先跑主语义工具；unknown 过高或过于单一时触发备份工具。
    def __init__(
        self,
        netplier_adapter: Optional[NetPlierAdapter] = None,
        binaryinferno_adapter: Optional[BinaryInfernoAdapter] = None,
    ) -> None:
        self.netplier_adapter = netplier_adapter or NetPlierAdapter()
        self.binaryinferno_adapter = binaryinferno_adapter or BinaryInfernoAdapter()

    def run(
        self,
        execution_plan: ExecutionPlan,
        segment_candidates_path: str,
        traffic_profile_path: str,
        boundaries: List[FieldBoundaryCandidate],
        output_dir: str,
        timeout_sec: int,
        python_bin: str,
        netplier_python_bin: str,
        binaryinferno_python_bin: str,
        logger,
    ) -> List[FieldSemanticCandidate]:
        # 输出统一结构：semantic_candidates.json
        semantic_candidates: List[FieldSemanticCandidate] = []
        tool_errors: List[str] = []
        runtime_info: Dict[str, str] = {}
        try:
            unknown_ratio_trigger = float(os.getenv("SEMANTIC_UNKNOWN_RATIO_TRIGGER", "0.70"))
        except ValueError:
            unknown_ratio_trigger = 0.70
        try:
            dominant_ratio_trigger = float(os.getenv("SEMANTIC_DOMINANT_RATIO_TRIGGER", "0.85"))
        except ValueError:
            dominant_ratio_trigger = 0.85
        try:
            dominant_min_candidates = int(os.getenv("SEMANTIC_DOMINANT_MIN_CANDIDATES", "5"))
        except ValueError:
            dominant_min_candidates = 5

        if not execution_plan.selected_tools and not boundaries:
            output_path = Path(output_dir) / "semantic_candidates.json"
            payload = {
                "candidates": [],
                "tool_errors": [
                    "未执行语义推断：当前没有可用字段切分候选。",
                ],
                "runtime_info": runtime_info,
            }
            write_json(output_path, payload)
            logger.info("Semantic inference completed -> %s", output_path)
            return semantic_candidates

        ordered_tools = _ordered_semantic_tools(execution_plan)
        runtime_info["semantic_primary_tool"] = ordered_tools[0]
        if len(ordered_tools) > 1:
            runtime_info["semantic_backup_tool"] = ordered_tools[1]

        def _run_semantic_tool(tool_name: str) -> List[FieldSemanticCandidate]:
            parsed: List[FieldSemanticCandidate] = []
            if tool_name == "netplier_adapter":
                netplier_result = self.netplier_adapter.run(
                    input_path=segment_candidates_path,
                    output_dir=output_dir,
                    extra_args={
                        "timeout_sec": str(timeout_sec),
                        "python_bin": python_bin,
                        "netplier_python_bin": netplier_python_bin,
                        "traffic_profile_path": traffic_profile_path,
                    },
                )
                if not netplier_result.success:
                    tool_errors.append(netplier_result.error or "netplier 适配器执行失败")
                    return parsed
                runtime_info["netplier_python_bin"] = str(netplier_result.data.get("python_bin", ""))
                backend = str(netplier_result.data.get("backend", "")).strip()
                for item in netplier_result.data.get("candidates", []):
                    try:
                        candidate = FieldSemanticCandidate(**item)
                        if backend and f"backend={backend}" not in candidate.reason:
                            candidate.reason = f"{candidate.reason}; backend={backend}"
                        parsed.append(candidate)
                    except Exception:
                        continue
                parsed, aligned_count = _align_semantics_to_boundaries(parsed, boundaries)
                runtime_info[f"{tool_name}_aligned_count"] = str(aligned_count)
                return parsed

            if tool_name == "binaryinferno_adapter":
                inferno_result = self.binaryinferno_adapter.run(
                    input_path=segment_candidates_path,
                    output_dir=output_dir,
                    extra_args={
                        "timeout_sec": str(timeout_sec),
                        "python_bin": python_bin,
                        "binaryinferno_python_bin": binaryinferno_python_bin,
                        "traffic_profile_path": traffic_profile_path,
                    },
                )
                if not inferno_result.success:
                    tool_errors.append(inferno_result.error or "binaryinferno 适配器执行失败")
                    return parsed
                runtime_info["binaryinferno_python_bin"] = str(inferno_result.data.get("python_bin", ""))
                backend = str(inferno_result.data.get("backend", "")).strip()
                for item in inferno_result.data.get("candidates", []):
                    try:
                        candidate = FieldSemanticCandidate(**item)
                        if backend and f"backend={backend}" not in candidate.reason:
                            candidate.reason = f"{candidate.reason}; backend={backend}"
                        parsed.append(candidate)
                    except Exception:
                        continue
                parsed, aligned_count = _align_semantics_to_boundaries(parsed, boundaries)
                runtime_info[f"{tool_name}_aligned_count"] = str(aligned_count)
                return parsed

            tool_errors.append(f"未知语义工具: {tool_name}")
            return parsed

        primary_tool = ordered_tools[0]
        primary_candidates = _run_semantic_tool(primary_tool)
        semantic_candidates.extend(primary_candidates)

        need_backup = False
        backup_reason = ""
        if not primary_candidates:
            need_backup = True
            backup_reason = f"主语义工具 `{primary_tool}` 未产出可用候选。"
        else:
            primary_unknown_ratio = _unknown_ratio(primary_candidates)
            runtime_info["semantic_primary_unknown_ratio"] = f"{primary_unknown_ratio:.3f}"
            dominant_type, dominant_ratio = _dominant_semantic_ratio(primary_candidates)
            runtime_info["semantic_primary_dominant_type"] = dominant_type
            runtime_info["semantic_primary_dominant_ratio"] = f"{dominant_ratio:.3f}"
            runtime_info["semantic_unknown_ratio_trigger"] = f"{unknown_ratio_trigger:.2f}"
            runtime_info["semantic_dominant_ratio_trigger"] = f"{dominant_ratio_trigger:.2f}"
            runtime_info["semantic_dominant_min_candidates"] = str(dominant_min_candidates)
            if primary_unknown_ratio >= unknown_ratio_trigger:
                need_backup = True
                backup_reason = (
                    f"主语义 unknown 占比 {primary_unknown_ratio:.3f} >= {unknown_ratio_trigger:.2f}"
                )
            elif len(primary_candidates) >= dominant_min_candidates and dominant_ratio >= dominant_ratio_trigger:
                need_backup = True
                backup_reason = (
                    f"主语义类型过于单一: type={dominant_type}, "
                    f"ratio={dominant_ratio:.3f} >= {dominant_ratio_trigger:.2f}"
                )

        if need_backup and len(ordered_tools) > 1:
            backup_tool = ordered_tools[1]
            backup_candidates = _run_semantic_tool(backup_tool)
            if backup_candidates:
                semantic_candidates.extend(backup_candidates)
                tool_errors.append(
                    f"Semantic backup tool triggered（语义备份已触发）({backup_tool}): {backup_reason} "
                    f"backup_candidates={len(backup_candidates)}"
                )
            else:
                tool_errors.append(
                    f"Semantic backup tool triggered（语义备份已触发）({backup_tool})，但未产出候选: {backup_reason}"
                )

        if not semantic_candidates:
            semantic_candidates.extend(_fallback_semantics(boundaries))
            tool_errors.append("语义 fallback 已触发：工具输出为空。")

        output_path = Path(output_dir) / "semantic_candidates.json"
        payload = {
            "candidates": [item.model_dump(mode="json") for item in semantic_candidates],
            "tool_errors": tool_errors,
            "runtime_info": runtime_info,
        }
        write_json(output_path, payload)
        logger.info("Semantic inference completed -> %s", output_path)
        return semantic_candidates
