from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
import sys
from typing import Any, Dict, List, Tuple

"""
    字段分割适配器。支持 official/heuristic/auto，官方路径会尝试 NEMESYS 的分段流程，
    失败回退启发式；输出 nemesys_segments_raw.json。

"""


PROJECT_SRC = Path(__file__).resolve().parents[2]
if str(PROJECT_SRC) not in sys.path:
    sys.path.insert(0, str(PROJECT_SRC))

from testcrewai.adapters.common import cluster_messages_by_length, shannon_entropy


def _cluster_id_by_length(profile: Dict[str, Any], message_len: int) -> str:
    # 将 NEMESYS 分段结果映射回预处理 cluster，减少后续融合错位。
    clusters = profile.get("message_clusters", [])
    for item in clusters:
        lengths = item.get("representative_lengths", [])
        if isinstance(lengths, list) and message_len in lengths:
            cluster_id = str(item.get("cluster_id", "")).strip()
            if cluster_id:
                return cluster_id

    best_cluster = ""
    best_diff: int | None = None
    best_ref = 0
    for item in clusters:
        cluster_id = str(item.get("cluster_id", "")).strip()
        if not cluster_id:
            continue

        refs: List[int] = []
        lengths = item.get("representative_lengths", [])
        if isinstance(lengths, list):
            for value in lengths:
                try:
                    refs.append(int(value))
                except Exception:
                    continue
        if not refs:
            try:
                mean_int = int(round(float(item.get("mean_length", 0))))
            except Exception:
                mean_int = 0
            if mean_int > 0:
                refs.append(mean_int)
        if not refs:
            continue

        nearest = min(refs, key=lambda value: abs(value - message_len))
        diff = abs(nearest - message_len)
        if best_diff is None or diff < best_diff:
            best_diff = diff
            best_ref = nearest
            best_cluster = cluster_id

    if best_cluster and best_diff is not None:
        tolerance = max(4, int(max(message_len, best_ref) * 0.25))
        if best_diff <= tolerance:
            return best_cluster
        # Keep nearest profile cluster even when noisy to avoid orphan len_* clusters.
        return best_cluster

    return f"len_{message_len}"


def _entropy_boundaries(messages: List[bytes]) -> List[Dict[str, Any]]:
    # 启发式分段（降级）：按列熵差构造边界。
    if not messages:
        return []
    min_len = min(len(msg) for msg in messages)
    if min_len <= 1:
        return []

    entropies: List[float] = []
    for idx in range(min_len):
        column = [msg[idx] for msg in messages]
        entropies.append(shannon_entropy(column))

    boundaries = {0, min_len}
    for idx in range(1, min_len):
        if abs(entropies[idx] - entropies[idx - 1]) >= 0.75:
            boundaries.add(idx)

    if len(boundaries) <= 2:
        if min_len >= 6:
            boundaries.update({1, 3, min_len - 2})
        elif min_len >= 4:
            boundaries.update({1, min_len - 1})

    ordered = sorted(pos for pos in boundaries if 0 <= pos <= min_len)
    candidates: List[Dict[str, Any]] = []
    for start, end in zip(ordered[:-1], ordered[1:]):
        if end <= start:
            continue
        avg_entropy = sum(entropies[start:end]) / max(1, end - start)
        confidence = max(0.4, min(0.86, 0.72 - avg_entropy / 12.0))
        candidates.append(
            {
                "start": start,
                "end": end,
                "confidence": round(confidence, 3),
                "reason": f"nemesys heuristic entropy-window mean={avg_entropy:.3f}",
            }
        )
    return candidates


def _build_official_candidates(
    profile: Dict[str, Any],
    nemesys_home: str,
    sigma: float,
    layer: int,
    layer_candidates: List[int],
    relative_to_ip: bool,
    auto_relative_to_ip: bool,
    use_refinement: bool,
    consensus_min_support: float,
    consensus_max_fields: int,
    enable_consensus: bool,
) -> Tuple[List[Dict[str, Any]], List[str]]:
    # 官方路径：SpecimenLoader + bcDeltaGaussMessageSegmentation。
    input_file = str(profile.get("input_file", "")).strip()
    if not input_file:
        raise ValueError("traffic_profile.input_file is empty")
    pcap_path = Path(input_file)
    if not pcap_path.exists():
        raise FileNotFoundError(f"pcap not found: {pcap_path}")

    home = Path(nemesys_home).expanduser().resolve()
    src_dir = home / "src"
    if not src_dir.exists():
        raise FileNotFoundError(f"NEMESYS src directory not found: {src_dir}")
    if str(src_dir) not in sys.path:
        sys.path.insert(0, str(src_dir))

    from nemere.inference.segmentHandler import bcDeltaGaussMessageSegmentation, refinements  # type: ignore
    from nemere.utils.loader import SpecimenLoader  # type: ignore

    attempts: List[Tuple[int, bool]] = []
    # 自动尝试多组 layer / relative_to_ip，提升官方路径稳定性。
    for candidate_layer in [layer, *layer_candidates]:
        if candidate_layer <= 0:
            continue
        if auto_relative_to_ip:
            for candidate_relative in [relative_to_ip, not relative_to_ip]:
                pair = (candidate_layer, candidate_relative)
                if pair not in attempts:
                    attempts.append(pair)
        else:
            pair = (candidate_layer, relative_to_ip)
            if pair not in attempts:
                attempts.append(pair)

    segments_per_msg = None
    resolved_layer = layer
    resolved_relative = relative_to_ip
    attempt_notes: List[str] = []
    for candidate_layer, candidate_relative in attempts:
        try:
            specimens = SpecimenLoader(
                str(pcap_path),
                layer=candidate_layer,
                relativeToIP=candidate_relative,
            )
            current_segments = bcDeltaGaussMessageSegmentation(specimens, sigma=sigma)
            if use_refinement:
                current_segments = refinements(current_segments)

            if current_segments:
                segments_per_msg = current_segments
                resolved_layer = candidate_layer
                resolved_relative = candidate_relative
                attempt_notes.append(
                    f"attempt layer={candidate_layer} relative_to_ip={candidate_relative}: success"
                )
                break

            attempt_notes.append(
                f"attempt layer={candidate_layer} relative_to_ip={candidate_relative}: empty result"
            )
        except Exception as exc:
            attempt_notes.append(
                f"attempt layer={candidate_layer} relative_to_ip={candidate_relative}: failed ({exc})"
            )

    if segments_per_msg is None:
        raise RuntimeError(" ; ".join(attempt_notes) if attempt_notes else "NEMESYS attempts failed")

    cluster_message_counts: Dict[str, int] = {}
    range_supports: Dict[Tuple[str, int, int], int] = {}
    cluster_boundary_supports: Dict[str, Dict[int, int]] = defaultdict(dict)
    cluster_max_lengths: Dict[str, int] = {}
    parsed_messages = 0

    for per_msg in segments_per_msg:
        if not per_msg:
            continue

        first_segment = per_msg[0]
        message = getattr(first_segment, "message", None)
        message_data = getattr(message, "data", b"")
        message_len = len(message_data)
        cluster_id = _cluster_id_by_length(profile, message_len)

        cluster_message_counts[cluster_id] = cluster_message_counts.get(cluster_id, 0) + 1
        cluster_max_lengths[cluster_id] = max(cluster_max_lengths.get(cluster_id, 0), message_len)
        parsed_messages += 1

        valid_segments: List[Tuple[int, int]] = []
        for seg in per_msg:
            try:
                start = int(getattr(seg, "offset", 0))
            except Exception:
                continue
            try:
                length = int(getattr(seg, "length", 0))
            except Exception:
                continue
            if length <= 0:
                continue
            valid_segments.append((start, start + length))

        if not valid_segments:
            continue

        ordered = sorted(valid_segments, key=lambda item: item[0])
        message_boundaries: set[int] = {0, message_len}
        for start, end in ordered:
            if end <= start:
                continue
            key = (cluster_id, start, end)
            range_supports[key] = range_supports.get(key, 0) + 1
            message_boundaries.add(start)
            message_boundaries.add(end)

        support_map = cluster_boundary_supports.setdefault(cluster_id, {})
        for pos in message_boundaries:
            support_map[pos] = support_map.get(pos, 0) + 1

    def _compress_consensus_ranges(
        support_map: Dict[int, int],
        total_messages: int,
        max_length: int,
    ) -> List[Tuple[int, int, float]]:
        # 共识压缩：抑制过分段，把每条消息的小波动过滤掉。
        if total_messages <= 0 or max_length <= 0:
            return []

        support_threshold = max(0.0, min(1.0, consensus_min_support))
        max_fields = max(2, consensus_max_fields)
        # Keep field count proportional to message length to avoid over-segmentation on noisy traces.
        max_fields = min(max_fields, max(4, int(max_length / 3)))
        boundaries = {0, max_length}

        internal_positions: List[Tuple[int, float]] = []
        for pos, count in support_map.items():
            if pos <= 0 or pos >= max_length:
                continue
            ratio = count / max(1, total_messages)
            internal_positions.append((pos, ratio))
            if ratio >= support_threshold:
                boundaries.add(pos)

        if len(boundaries) <= 2 and internal_positions:
            # Keep top supports so official output is still usable on noisy captures.
            for pos, _ in sorted(internal_positions, key=lambda item: item[1], reverse=True)[:3]:
                boundaries.add(pos)

        internal = [pos for pos in boundaries if pos not in {0, max_length}]
        max_internal = max(1, max_fields - 1)
        if len(internal) > max_internal:
            ranked = sorted(
                internal,
                key=lambda pos: support_map.get(pos, 0),
                reverse=True,
            )[:max_internal]
            boundaries = {0, max_length, *ranked}

        ordered = sorted(boundaries)
        # Drop low-support micro-fragment boundaries.
        changed = True
        while changed and len(ordered) > 2:
            changed = False
            for idx in range(1, len(ordered) - 1):
                pos = ordered[idx]
                left_span = pos - ordered[idx - 1]
                right_span = ordered[idx + 1] - pos
                ratio = support_map.get(pos, 0) / max(1, total_messages)
                if (left_span <= 1 or right_span <= 1) and ratio < max(0.85, support_threshold + 0.15):
                    ordered.pop(idx)
                    changed = True
                    break

        changed = True
        while changed and len(ordered) > 2:
            changed = False
            for idx in range(1, len(ordered) - 1):
                left_span = ordered[idx] - ordered[idx - 1]
                right_span = ordered[idx + 1] - ordered[idx]
                if left_span > 1 and right_span > 1:
                    continue
                ratio = support_map.get(ordered[idx], 0) / max(1, total_messages)
                if ratio < max(0.92, support_threshold + 0.20):
                    ordered.pop(idx)
                    changed = True
                    break

        compressed: List[Tuple[int, int, float]] = []
        for start, end in zip(ordered[:-1], ordered[1:]):
            if end <= start:
                continue
            left_support = 1.0 if start == 0 else support_map.get(start, 0) / max(1, total_messages)
            right_support = 1.0 if end == max_length else support_map.get(end, 0) / max(1, total_messages)
            edge_support = min(left_support, right_support)
            compressed.append((start, end, edge_support))
        return compressed

    candidates: List[Dict[str, Any]] = []
    raw_candidate_count = len(range_supports)
    if enable_consensus:
        for cluster_id, support_map in sorted(cluster_boundary_supports.items()):
            total = cluster_message_counts.get(cluster_id, 0)
            max_length = cluster_max_lengths.get(cluster_id, 0)
            compressed = _compress_consensus_ranges(
                support_map=support_map,
                total_messages=total,
                max_length=max_length,
            )
            for start, end, edge_support in compressed:
                confidence = 0.45 + 0.45 * edge_support
                candidates.append(
                    {
                        "message_cluster": cluster_id,
                        "start": start,
                        "end": end,
                        "confidence": round(max(0.4, min(0.95, confidence)), 3),
                        "source_tool": "nemesys_adapter",
                        "reason": (
                            f"NEMESYS consensus support~{edge_support:.2f}, "
                            f"cluster_messages={total}, sigma={sigma}"
                        ),
                    }
                )

    if not candidates:
        for (cluster_id, start, end), support in sorted(range_supports.items()):
            total = cluster_message_counts.get(cluster_id, 1)
            confidence = 0.45 + 0.45 * (support / max(1, total))
            candidates.append(
                {
                    "message_cluster": cluster_id,
                    "start": start,
                    "end": end,
                    "confidence": round(max(0.4, min(0.95, confidence)), 3),
                    "source_tool": "nemesys_adapter",
                    "reason": f"NEMESYS official support={support}/{total}, sigma={sigma}",
                }
            )

    notes = [
        "official NEMESYS API used (SpecimenLoader + bcDeltaGaussMessageSegmentation)",
        f"nemesys_home={home}",
        f"sigma={sigma}",
        f"layer={resolved_layer}",
        f"relative_to_ip={resolved_relative}",
        f"refinement={use_refinement}",
        f"parsed_messages={parsed_messages}",
        f"attempts={attempt_notes}",
        (
            f"consensus_enabled={enable_consensus}, min_support={consensus_min_support:.2f}, "
            f"max_fields={consensus_max_fields}, raw_candidates={raw_candidate_count}, "
            f"compressed_candidates={len(candidates)}"
        ),
    ]
    return candidates, notes


def _build_heuristic_candidates(profile: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[str]]:
    # 降级路径：使用本地熵分段生成候选边界。
    hex_messages = profile.get("sample_messages_hex", [])
    messages: List[bytes] = []
    for raw_hex in hex_messages:
        if not isinstance(raw_hex, str):
            continue
        try:
            messages.append(bytes.fromhex(raw_hex))
        except ValueError:
            continue

    clusters = cluster_messages_by_length(messages)
    candidates: List[Dict[str, Any]] = []
    for cluster_id, cluster_messages in clusters.items():
        for item in _entropy_boundaries(cluster_messages):
            candidates.append(
                {
                    "message_cluster": cluster_id,
                    "start": item["start"],
                    "end": item["end"],
                    "confidence": item["confidence"],
                    "source_tool": "nemesys_adapter",
                    "reason": item["reason"],
                }
            )

    notes = [
        "nemesys fallback heuristic used (entropy-based segmentation)",
    ]
    return candidates, notes


def main() -> None:
    # 适配器入口：auto=官方优先失败降级，official=仅官方，heuristic=仅启发式。
    parser = argparse.ArgumentParser(description="NEMESYS segmentation adapter")
    parser.add_argument("--input", required=True, help="traffic_profile.json path")
    parser.add_argument("--output", required=True, help="output json path")
    parser.add_argument(
        "--mode",
        default="auto",
        choices=["auto", "official", "heuristic"],
        help="auto: official NEMESYS then fallback, official: only official API, heuristic: local fallback only",
    )
    parser.add_argument("--nemesys-home", default="", help="Path to NEMESYS repository root")
    parser.add_argument("--sigma", type=float, default=0.6, help="NEMESYS sigma parameter")
    parser.add_argument("--layer", type=int, default=2, help="Layer for SpecimenLoader")
    parser.add_argument(
        "--layer-candidates",
        default="",
        help="Optional comma-separated fallback layers, e.g. '2,3,4'",
    )
    parser.add_argument("--relative-to-ip", action="store_true", help="Interpret layer relative to IP")
    parser.add_argument(
        "--relative-to-ip-mode",
        default="auto",
        choices=["auto", "fixed"],
        help="auto: try both relative_to_ip settings, fixed: use only --relative-to-ip value",
    )
    parser.add_argument("--no-refinement", action="store_true", help="Disable NEMESYS refinements() step")
    parser.add_argument(
        "--consensus-min-support",
        type=float,
        default=0.6,
        help="Minimum boundary support ratio for consensus compression",
    )
    parser.add_argument(
        "--consensus-max-fields",
        type=int,
        default=64,
        help="Maximum consensus fields per cluster",
    )
    parser.add_argument(
        "--disable-consensus",
        action="store_true",
        help="Disable consensus compression and keep raw per-range supports",
    )
    args = parser.parse_args()

    profile = json.loads(Path(args.input).read_text(encoding="utf-8"))
    backend = "heuristic"
    notes: List[str] = []
    candidates: List[Dict[str, Any]] = []
    layer_candidates: List[int] = []
    for token in args.layer_candidates.replace(";", ",").split(","):
        token = token.strip()
        if not token:
            continue
        try:
            layer_candidates.append(int(token))
        except ValueError:
            continue

    if args.mode in {"auto", "official"}:
        try:
            candidates, notes = _build_official_candidates(
                profile,
                nemesys_home=args.nemesys_home,
                sigma=args.sigma,
                layer=args.layer,
                layer_candidates=layer_candidates,
                relative_to_ip=bool(args.relative_to_ip),
                auto_relative_to_ip=(args.relative_to_ip_mode == "auto"),
                use_refinement=not args.no_refinement,
                consensus_min_support=args.consensus_min_support,
                consensus_max_fields=args.consensus_max_fields,
                enable_consensus=not args.disable_consensus,
            )
            backend = "official_nemesys_api"
        except Exception as exc:
            notes.append(f"official NEMESYS API failed: {exc}")
            if args.mode == "official":
                raise

    if not candidates:
        fallback_candidates, fallback_notes = _build_heuristic_candidates(profile)
        candidates = fallback_candidates
        notes.extend(fallback_notes)

    payload: Dict[str, Any] = {
        "tool_name": "nemesys_adapter",
        "success": True,
        "backend": backend,
        "candidates": candidates,
        "notes": notes,
    }

    Path(args.output).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
