from __future__ import annotations

from collections import defaultdict
import os
from pathlib import Path
from typing import Dict, List, Set, Tuple

from testcrewai.adapters.common import non_overlapping_ranges
from testcrewai.models import (
    EvidenceItem,
    FieldBoundaryCandidate,
    FieldSemanticCandidate,
    ProtocolField,
    ProtocolSchema,
    TrafficProfile,
)
from testcrewai.utils.io import write_json


TOOL_RELIABILITY = {
    # 融合时的工具基础可信度（可按实验调参）。
    "netzob_adapter": 0.88,
    "nemesys_adapter": 0.82,
    "fallback_segmenter": 0.55,
    "netplier_adapter": 0.78,
    "binaryinferno_adapter": 0.75,
    "fallback_semantic": 0.5,
}


def _range_key(start: int, end: int) -> str:
    return f"{start}:{end}"


def _safe_float_env(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except ValueError:
        return default


def _safe_int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _cluster_length(cluster) -> int:
    if cluster.representative_lengths:
        return max(1, int(cluster.representative_lengths[0]))
    if cluster.mean_length > 0:
        return max(1, int(round(cluster.mean_length)))
    return 1


def _reason_quality_factor(reason: str) -> float:
    value = reason.lower()
    factor = 1.0
    if "backend=official" in value or "official " in value:
        factor *= 1.05
    if "aligned_to_boundary" in value:
        factor *= 1.04
    if "fallback" in value or "heuristic" in value:
        factor *= 0.90
    if "unavailable" in value:
        factor *= 0.92
    return max(0.7, min(1.2, factor))


def _dominance_penalty(
    item: FieldSemanticCandidate,
    collapse_ratio: float,
    collapse_penalty: float,
    collapse_min_count: int,
    collapse_types: Set[str],
    source_semantic_counts: Dict[Tuple[str, str], Dict[str, int]],
    source_totals: Dict[Tuple[str, str], int],
) -> float:
    key = (item.message_cluster, item.source_tool)
    total = source_totals.get(key, 0)
    if total < max(1, collapse_min_count):
        return 1.0
    if item.semantic_type not in collapse_types:
        return 1.0

    counts = source_semantic_counts.get(key, {})
    ratio = counts.get(item.semantic_type, 0) / max(1, total)
    if ratio >= collapse_ratio:
        return collapse_penalty
    return 1.0


def _semantic_weight(
    item: FieldSemanticCandidate,
    unknown_penalty: float,
    collapse_ratio: float,
    collapse_penalty: float,
    collapse_min_count: int,
    collapse_types: Set[str],
    source_semantic_counts: Dict[Tuple[str, str], Dict[str, int]],
    source_totals: Dict[Tuple[str, str], int],
) -> float:
    reliability = TOOL_RELIABILITY.get(item.source_tool, 0.6)
    score = item.confidence * reliability * _reason_quality_factor(item.reason)
    if item.semantic_type == "unknown":
        score *= unknown_penalty
    score *= _dominance_penalty(
        item=item,
        collapse_ratio=collapse_ratio,
        collapse_penalty=collapse_penalty,
        collapse_min_count=collapse_min_count,
        collapse_types=collapse_types,
        source_semantic_counts=source_semantic_counts,
        source_totals=source_totals,
    )
    return score


class FusionAgentStage:
    # 融合阶段：将边界证据 + 语义证据整合为 final_schema.json
    def run(
        self,
        profile: TrafficProfile,
        boundaries: List[FieldBoundaryCandidate],
        semantics: List[FieldSemanticCandidate],
        output_dir: str,
        logger,
    ) -> ProtocolSchema:
        grouped_boundaries: Dict[str, Dict[Tuple[int, int], List[FieldBoundaryCandidate]]] = defaultdict(lambda: defaultdict(list))
        for boundary in boundaries:
            grouped_boundaries[boundary.message_cluster][(boundary.start, boundary.end)].append(boundary)

        semantics_by_cluster_range: Dict[str, Dict[str, List[FieldSemanticCandidate]]] = defaultdict(lambda: defaultdict(list))
        source_semantic_counts: Dict[Tuple[str, str], Dict[str, int]] = defaultdict(dict)
        source_totals: Dict[Tuple[str, str], int] = defaultdict(int)
        for semantic in semantics:
            semantics_by_cluster_range[semantic.message_cluster][semantic.field_range].append(semantic)
            key = (semantic.message_cluster, semantic.source_tool)
            counter = source_semantic_counts.setdefault(key, {})
            counter[semantic.semantic_type] = counter.get(semantic.semantic_type, 0) + 1
            source_totals[key] = source_totals.get(key, 0) + 1

        fields: List[ProtocolField] = []
        conflict_notes: List[str] = []
        unknown_penalty = _safe_float_env("FUSION_UNKNOWN_PENALTY", 0.85)
        unknown_penalty = max(0.0, min(1.0, unknown_penalty))

        prefer_non_unknown_ratio = _safe_float_env("FUSION_PREFER_NON_UNKNOWN_RATIO", 0.92)
        prefer_non_unknown_ratio = max(0.0, min(1.0, prefer_non_unknown_ratio))
        prefer_non_generic_ratio = max(0.0, min(1.0, _safe_float_env("FUSION_PREFER_NON_GENERIC_RATIO", 0.95)))

        collapse_ratio = max(0.0, min(1.0, _safe_float_env("FUSION_SEMANTIC_COLLAPSE_RATIO", 0.85)))
        collapse_penalty = max(0.0, min(1.0, _safe_float_env("FUSION_SEMANTIC_COLLAPSE_PENALTY", 0.82)))
        collapse_min_count = max(1, _safe_int_env("FUSION_SEMANTIC_COLLAPSE_MIN_COUNT", 8))
        collapse_types_raw = str(os.getenv("FUSION_COLLAPSE_TYPES", "type,id,unknown")).strip().lower()
        collapse_types = {
            item.strip()
            for item in collapse_types_raw.replace(";", ",").split(",")
            if item.strip()
        }
        if not collapse_types:
            collapse_types = {"type", "id", "unknown"}

        large_type_penalty = max(0.0, min(1.0, _safe_float_env("FUSION_LARGE_FIELD_TYPE_PENALTY", 0.78)))
        payload_tail_boost = max(0.5, min(2.0, _safe_float_env("FUSION_PAYLOAD_TAIL_BOOST", 1.20)))
        length_header_boost = max(0.5, min(2.0, _safe_float_env("FUSION_LENGTH_HEADER_BOOST", 1.10)))
        id_width_boost = max(0.5, min(2.0, _safe_float_env("FUSION_ID_WIDTH_BOOST", 1.05)))

        for cluster in profile.message_clusters:
            cluster_id = cluster.cluster_id
            candidate_map = grouped_boundaries.get(cluster_id, {})
            if not candidate_map:
                continue

            cluster_len = _cluster_length(cluster)
            scored_ranges: List[Tuple[int, int, float]] = []
            for (start, end), group in candidate_map.items():
                scores = []
                for item in group:
                    reliability = TOOL_RELIABILITY.get(item.source_tool, 0.6)
                    scores.append(item.confidence * reliability * _reason_quality_factor(item.reason))
                score = sum(scores) / max(1, len(scores))
                scored_ranges.append((start, end, score))

            selected_ranges = non_overlapping_ranges(scored_ranges)
            total_ranges = max(1, len(selected_ranges))
            for idx, (start, end, boundary_score) in enumerate(selected_ranges, start=1):
                semantic_candidates = semantics_by_cluster_range.get(cluster_id, {}).get(_range_key(start, end), [])
                semantic_score = 0.35
                semantic_type = "unknown"
                semantic_source = "none"
                semantic_reason = "无语义证据"

                if semantic_candidates:
                    span = max(0, end - start)
                    type_votes: Dict[str, float] = defaultdict(float)
                    best_per_type: Dict[str, Tuple[FieldSemanticCandidate, float]] = {}

                    for candidate in semantic_candidates:
                        score = _semantic_weight(
                            candidate,
                            unknown_penalty=unknown_penalty,
                            collapse_ratio=collapse_ratio,
                            collapse_penalty=collapse_penalty,
                            collapse_min_count=collapse_min_count,
                            collapse_types=collapse_types,
                            source_semantic_counts=source_semantic_counts,
                            source_totals=source_totals,
                        )

                        # Structural prior: prevent large tail fields from being trivially labeled as `type`.
                        if (
                            candidate.semantic_type == "type"
                            and idx >= total_ranges - 1
                            and span >= max(6, int(cluster_len * 0.16))
                        ):
                            score *= large_type_penalty
                        elif (
                            candidate.semantic_type == "payload"
                            and idx == total_ranges
                            and span >= max(6, int(cluster_len * 0.14))
                        ):
                            score *= payload_tail_boost
                        elif (
                            candidate.semantic_type == "length"
                            and idx <= 2
                            and span <= 4
                        ):
                            score *= length_header_boost
                        elif (
                            candidate.semantic_type in {"id", "session_id"}
                            and 2 <= span <= 8
                            and idx < total_ranges
                        ):
                            score *= id_width_boost

                        score = max(0.0, min(1.0, score))
                        type_votes[candidate.semantic_type] += score
                        cached = best_per_type.get(candidate.semantic_type)
                        if not cached or score > cached[1]:
                            best_per_type[candidate.semantic_type] = (candidate, score)

                    ranked_types = sorted(type_votes.items(), key=lambda item: item[1], reverse=True)
                    best_type, best_vote = ranked_types[0]

                    if best_type == "unknown" and len(ranked_types) >= 2:
                        for challenger_type, challenger_vote in ranked_types[1:]:
                            if challenger_type == "unknown":
                                continue
                            if challenger_vote >= best_vote * prefer_non_unknown_ratio:
                                conflict_notes.append(
                                    (
                                        f"{cluster_id} {start}:{end} 语义平票裁决: "
                                        f"优先选择非 unknown 的 `{challenger_type}` "
                                        f"(votes {challenger_vote:.3f} vs {best_vote:.3f})"
                                    )
                                )
                                best_type = challenger_type
                                best_vote = challenger_vote
                                break

                    if best_type in collapse_types and len(ranked_types) >= 2:
                        for challenger_type, challenger_vote in ranked_types[1:]:
                            if challenger_type in collapse_types:
                                continue
                            if challenger_vote >= best_vote * prefer_non_generic_ratio:
                                conflict_notes.append(
                                    (
                                        f"{cluster_id} {start}:{end} 语义平票裁决: "
                                        f"优先选择更具体的 `{challenger_type}`，而非 `{best_type}` "
                                        f"(votes {challenger_vote:.3f} vs {best_vote:.3f})"
                                    )
                                )
                                best_type = challenger_type
                                best_vote = challenger_vote
                                break

                    best_item, best_item_score = best_per_type[best_type]
                    semantic_type = best_type
                    semantic_source = best_item.source_tool
                    semantic_reason = (
                        f"{best_item.reason}; fusion_vote={best_vote:.3f}; "
                        f"candidate_score={best_item_score:.3f}"
                    )
                    semantic_score = max(0.0, min(0.95, max(best_vote, best_item_score)))

                    if len(ranked_types) >= 2:
                        top_type, top_vote = ranked_types[0]
                        second_type, second_vote = ranked_types[1]
                        if abs(top_vote - second_vote) <= 0.08 and top_type != second_type:
                            conflict_notes.append(
                                (
                                    f"{cluster_id} {start}:{end} 语义冲突: "
                                    f"{top_type} vs {second_type}，聚合票数接近"
                                )
                            )

                final_confidence = max(0.0, min(1.0, boundary_score * 0.6 + semantic_score * 0.4))
                fields.append(
                    ProtocolField(
                        message_cluster=cluster_id,
                        name=f"f{idx}_{semantic_type}",
                        start=start,
                        end=end,
                        semantic_type=semantic_type,
                        confidence=round(final_confidence, 3),
                        evidences=[
                            EvidenceItem(
                                evidence_type="boundary",
                                source="fusion",
                                score=round(boundary_score, 3),
                                detail="由边界候选置信度与工具可靠度加权得到",
                            ),
                            EvidenceItem(
                                evidence_type="semantic",
                                source=semantic_source,
                                score=round(semantic_score, 3),
                                detail=semantic_reason,
                            ),
                        ],
                    )
                )

        global_confidence = round(sum(field.confidence for field in fields) / max(1, len(fields)), 3)
        schema = ProtocolSchema(
            input_file=profile.input_file,
            message_clusters=profile.message_clusters,
            fields=fields,
            conflict_resolutions=conflict_notes,
            global_confidence=global_confidence,
            limitations=[
                "该原型依赖采样 payload 与启发式评分，并非完整语法归纳。",
                "当外部工具不可用时，会触发 fallback 逻辑，结构精度可能下降。",
            ],
        )

        output_path = Path(output_dir) / "final_schema.json"
        write_json(output_path, schema)
        logger.info("Fusion completed -> %s", output_path)
        return schema
