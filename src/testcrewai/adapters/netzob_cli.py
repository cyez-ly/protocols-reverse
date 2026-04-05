from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Tuple

"""
    字段分割适配器。优先走 Netzob 官方思路（可配置）
    失败时走启发式分割；输出 netzob_segments_raw.json。

"""



PROJECT_SRC = Path(__file__).resolve().parents[2]
if str(PROJECT_SRC) not in sys.path:
    sys.path.insert(0, str(PROJECT_SRC))

from testcrewai.adapters.common import cluster_messages_by_length, printable_ratio, shannon_entropy


def build_candidates(messages: List[bytes]) -> List[Dict[str, Any]]:
    # 启发式分段：基于“按字节位熵变化”寻找候选边界。
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
        if abs(entropies[idx] - entropies[idx - 1]) >= 0.8:
            boundaries.add(idx)

    if len(boundaries) <= 2:
        if min_len >= 6:
            boundaries.update({1, 3, min_len - 2})
        elif min_len >= 4:
            boundaries.update({1, min_len - 1})

    ordered = sorted(pos for pos in boundaries if 0 <= pos <= min_len)
    results: List[Dict[str, Any]] = []
    for start, end in zip(ordered[:-1], ordered[1:]):
        if end <= start:
            continue
        avg_entropy = sum(entropies[start:end]) / max(1, end - start)
        confidence = max(0.4, min(0.9, 0.75 - avg_entropy / 10.0))
        results.append(
            {
                "start": start,
                "end": end,
                "confidence": round(confidence, 3),
                "reason": f"entropy-window mean={avg_entropy:.3f}",
            }
        )

    return results


def _bytes_len(value: Any) -> int:
    if value is None:
        return 0
    if isinstance(value, bytes):
        return len(value)
    return len(str(value))


def _to_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        try:
            return bytes.fromhex(value)
        except ValueError:
            return value.encode("utf-8", errors="ignore")
    return bytes(value)


def _cluster_id_by_length(profile: Dict[str, Any], message_len: int) -> Optional[str]:
    # 先精确匹配长度，再做近邻匹配，尽量与预处理 cluster 对齐。
    clusters = profile.get("message_clusters", [])
    # 1) Exact representative length match.
    for item in clusters:
        lengths = item.get("representative_lengths", [])
        if isinstance(lengths, list) and message_len in lengths:
            cluster_id = item.get("cluster_id")
            if isinstance(cluster_id, str) and cluster_id:
                return cluster_id

    # 2) Fuzzy match by nearest representative/mean length.
    best_cluster_id: Optional[str] = None
    best_diff: Optional[int] = None
    best_ref_len = 0
    for item in clusters:
        cluster_id = item.get("cluster_id")
        if not isinstance(cluster_id, str) or not cluster_id:
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
            mean_length = item.get("mean_length", 0)
            try:
                mean_int = int(round(float(mean_length)))
            except Exception:
                mean_int = 0
            if mean_int > 0:
                refs.append(mean_int)
        if not refs:
            continue

        nearest_ref = min(refs, key=lambda ref: abs(message_len - ref))
        diff = abs(message_len - nearest_ref)
        if best_diff is None or diff < best_diff:
            best_diff = diff
            best_cluster_id = cluster_id
            best_ref_len = nearest_ref

    if best_cluster_id is not None and best_diff is not None:
        tolerance = max(4, int(max(message_len, best_ref_len) * 0.2))
        if best_diff <= tolerance:
            return best_cluster_id
    return None


def _nearest_cluster_id(profile: Dict[str, Any], message_len: int) -> Optional[str]:
    clusters = profile.get("message_clusters", [])
    best_cluster_id: Optional[str] = None
    best_diff: Optional[int] = None
    for item in clusters:
        cluster_id = item.get("cluster_id")
        if not isinstance(cluster_id, str) or not cluster_id:
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
            best_cluster_id = cluster_id
    return best_cluster_id


def _symbol_messages(symbol: Any) -> List[bytes]:
    results: List[bytes] = []
    for message in getattr(symbol, "messages", []):
        data = getattr(message, "data", b"")
        raw = _to_bytes(data)
        if raw:
            results.append(raw)
    return results


def _collect_text_delimiter_support(messages: List[bytes]) -> Dict[int, float]:
    # 文本协议增强：统计 CRLF / header-body 分隔符在位置上的支持度。
    if not messages:
        return {}
    min_len = min(len(msg) for msg in messages)
    if min_len <= 2:
        return {}

    printable = [printable_ratio(msg[:min_len]) for msg in messages if len(msg) >= min_len]
    if not printable:
        return {}
    if (sum(printable) / len(printable)) < 0.72:
        return {}

    counts: Dict[int, int] = {}
    total = len(messages)
    for msg in messages:
        view = msg[:min_len]
        seen: set[int] = set()
        start = 0
        while True:
            idx = view.find(b"\r\n\r\n", start)
            if idx < 0:
                break
            pos = idx + 4
            if 0 < pos < min_len:
                seen.add(pos)
            start = idx + 1
        start = 0
        while True:
            idx = view.find(b"\r\n", start)
            if idx < 0:
                break
            pos = idx + 2
            if 0 < pos < min_len:
                seen.add(pos)
            start = idx + 1
        for pos in seen:
            counts[pos] = counts.get(pos, 0) + 1

    supports: Dict[int, float] = {}
    for pos, count in counts.items():
        ratio = count / max(1, total)
        if ratio >= 0.55:
            supports[pos] = ratio
    return supports


def _refine_text_symbol_candidates(
    symbol_candidates: List[Dict[str, Any]],
    messages: List[bytes],
) -> Tuple[List[Dict[str, Any]], int]:
    # 对文本流量做“微碎片合并”，提升边界可解释性。
    if not symbol_candidates or not messages:
        return symbol_candidates, 0

    min_len = min(len(msg) for msg in messages)
    if min_len <= 2:
        return symbol_candidates, 0

    delimiter_supports = _collect_text_delimiter_support(messages)
    if not delimiter_supports:
        return symbol_candidates, 0

    boundaries: set[int] = {0, min_len}
    for item in symbol_candidates:
        boundaries.add(int(item.get("start", 0)))
        boundaries.add(int(item.get("end", 0)))
    boundaries.update(delimiter_supports.keys())

    ordered = sorted(pos for pos in boundaries if 0 <= pos <= min_len)
    removed = 0
    changed = True
    while changed and len(ordered) > 2:
        changed = False
        for idx in range(1, len(ordered) - 1):
            pos = ordered[idx]
            if pos in delimiter_supports:
                continue
            left = pos - ordered[idx - 1]
            right = ordered[idx + 1] - pos
            if left <= 1 or right <= 1:
                ordered.pop(idx)
                removed += 1
                changed = True
                break

    refined: List[Dict[str, Any]] = []
    for start, end in zip(ordered[:-1], ordered[1:]):
        if end <= start:
            continue
        boundary_support = delimiter_supports.get(end, delimiter_supports.get(start, 0.0))
        if boundary_support > 0:
            confidence = 0.84
            reason = f"netzob official + text delimiter boundary support={boundary_support:.2f}"
        else:
            confidence = 0.82
            reason = "netzob official + text micro-fragment coalescing"
        refined.append(
            {
                "start": start,
                "end": end,
                "confidence": confidence,
                "reason": reason,
            }
        )

    return refined or symbol_candidates, removed


def _field_candidates_from_symbol(symbol: Any, messages: List[bytes]) -> List[Dict[str, Any]]:
    if not messages:
        return []

    fields = getattr(symbol, "fields", [])
    if len(fields) <= 1:
        return []

    try:
        cells = symbol.getCells()
    except Exception:
        cells = []

    if not cells:
        return []

    field_count = min(len(fields), len(cells[0]))
    if field_count <= 1:
        return []

    avg_lengths: List[int] = []
    for field_idx in range(field_count):
        lengths = [_bytes_len(row[field_idx]) for row in cells if field_idx < len(row)]
        lengths = [length for length in lengths if length > 0]
        if not lengths:
            return []
        avg_lengths.append(max(1, int(round(sum(lengths) / len(lengths)))))

    min_len = min(len(message) for message in messages)
    points = [0]
    offset = 0
    for field_len in avg_lengths:
        offset += field_len
        points.append(offset)
    points.append(min_len)
    points = sorted(set(point for point in points if 0 <= point <= min_len))

    results: List[Dict[str, Any]] = []
    for start, end in zip(points[:-1], points[1:]):
        if end <= start:
            continue
        results.append(
            {
                "start": start,
                "end": end,
                "confidence": 0.86,
                "reason": "netzob official API field partition",
            }
        )
    return results


def _build_official_candidates(profile: Dict[str, Any], import_layer: int) -> Tuple[List[Dict[str, Any]], List[str]]:
    # 官方路径：调用 Netzob API（PCAPImporter + Format.clusterBySize）。
    from netzob.all import Format, PCAPImporter  # type: ignore

    input_file = str(profile.get("input_file", "")).strip()
    if not input_file:
        raise ValueError("traffic_profile.input_file is empty")

    pcap_path = Path(input_file)
    if not pcap_path.exists():
        raise FileNotFoundError(f"pcap not found: {pcap_path}")

    layer_candidates_raw = str(profile.get("__netzob_import_layer_candidates", "")).strip()
    parsed_candidates: List[int] = []
    if layer_candidates_raw:
        for token in layer_candidates_raw.replace(";", ",").split(","):
            token = token.strip()
            if not token:
                continue
            try:
                parsed_candidates.append(int(token))
            except ValueError:
                continue

    trial_layers: List[int] = []
    for layer in [import_layer, *parsed_candidates, 5, 4, 3, 2, 1]:
        if layer not in trial_layers and layer > 0:
            trial_layers.append(layer)

    raw_messages: List[Any] = []
    resolved_layer: Optional[int] = None
    layer_errors: List[str] = []
    for layer in trial_layers:
        try:
            imported = list(PCAPImporter.readFile(str(pcap_path), importLayer=layer).values())
            if imported:
                raw_messages = imported
                resolved_layer = layer
                break
            layer_errors.append(f"layer={layer} imported 0 messages")
        except Exception as exc:
            layer_errors.append(f"layer={layer} failed: {exc}")

    if not raw_messages:
        raise RuntimeError(" ; ".join(layer_errors) if layer_errors else "no messages imported")

    symbols = Format.clusterBySize(raw_messages)

    candidates: List[Dict[str, Any]] = []
    skipped_symbols = 0
    weak_cluster_mapped_symbols = 0
    text_refined_symbols = 0
    text_removed_boundaries = 0
    for index, symbol in enumerate(symbols):
        symbol_messages = _symbol_messages(symbol)
        if not symbol_messages:
            continue

        length_ref = int(round(sum(len(item) for item in symbol_messages) / max(1, len(symbol_messages))))
        cluster_id = _cluster_id_by_length(profile, length_ref)
        if not cluster_id:
            cluster_id = _nearest_cluster_id(profile, length_ref)
            if cluster_id:
                weak_cluster_mapped_symbols += 1
            else:
                skipped_symbols += 1
                continue
        symbol_candidates = _field_candidates_from_symbol(symbol, symbol_messages)
        if not symbol_candidates:
            for item in build_candidates(symbol_messages):
                item["reason"] = f"official cluster + {item['reason']}"
                symbol_candidates.append(item)
        refined_candidates, removed = _refine_text_symbol_candidates(symbol_candidates, symbol_messages)
        if removed > 0:
            text_refined_symbols += 1
            text_removed_boundaries += removed
        symbol_candidates = refined_candidates

        for item in symbol_candidates:
            candidates.append(
                {
                    "message_cluster": cluster_id,
                    "start": item["start"],
                    "end": item["end"],
                    "confidence": item["confidence"],
                    "source_tool": "netzob_adapter",
                    "reason": item["reason"],
                }
            )

    notes = [
        "official netzob API used (PCAPImporter + Format.clusterBySize)",
        f"import_layer={resolved_layer if resolved_layer is not None else import_layer}",
        f"symbols={len(symbols)}",
        f"skipped_symbols_without_profile_cluster={skipped_symbols}",
        f"weak_cluster_mapped_symbols={weak_cluster_mapped_symbols}",
        f"import_layer_trials={trial_layers}",
    ]
    if text_refined_symbols > 0:
        notes.append(
            f"text delimiter refinement applied: symbols={text_refined_symbols}, removed_boundaries={text_removed_boundaries}"
        )
    return candidates, notes


def _build_heuristic_candidates(profile: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[str]]:
    # 降级路径：仅基于样本消息做熵分段。
    hex_messages = profile.get("sample_messages_hex", [])
    messages: List[bytes] = []
    for raw_hex in hex_messages:
        try:
            messages.append(bytes.fromhex(raw_hex))
        except ValueError:
            continue

    clusters = cluster_messages_by_length(messages)
    candidates: List[Dict[str, Any]] = []
    for cluster_id, cluster_messages in clusters.items():
        for candidate in build_candidates(cluster_messages):
            candidates.append(
                {
                    "message_cluster": cluster_id,
                    "start": candidate["start"],
                    "end": candidate["end"],
                    "confidence": candidate["confidence"],
                    "source_tool": "netzob_adapter",
                    "reason": candidate["reason"],
                }
            )

    return candidates, ["heuristic entropy segmentation used"]


def main() -> None:
    # 适配器入口：auto=官方优先失败降级，official=仅官方，heuristic=仅启发式。
    parser = argparse.ArgumentParser(description="Heuristic Netzob-compatible segmentation adapter")
    parser.add_argument("--input", required=True, help="traffic_profile.json path")
    parser.add_argument("--output", required=True, help="output json path")
    parser.add_argument(
        "--mode",
        default="auto",
        choices=["auto", "official", "heuristic"],
        help="auto: official Netzob API then fallback, official: only official API, heuristic: local fallback only",
    )
    parser.add_argument(
        "--import-layer",
        default=5,
        type=int,
        help="Netzob PCAP import layer when official API mode is used",
    )
    parser.add_argument(
        "--import-layer-candidates",
        default="",
        help="Optional comma-separated fallback import layers, e.g. '5,4,3,2,1'",
    )
    args = parser.parse_args()

    profile = json.loads(Path(args.input).read_text(encoding="utf-8"))
    backend = "heuristic"
    notes: List[str] = []
    candidates: List[Dict[str, Any]] = []

    if args.import_layer_candidates:
        profile["__netzob_import_layer_candidates"] = args.import_layer_candidates

    if args.mode in {"auto", "official"}:
        try:
            candidates, notes = _build_official_candidates(profile, import_layer=args.import_layer)
            backend = "official_netzob_api"
        except Exception as exc:
            notes.append(f"official netzob API failed: {exc}")
            if args.mode == "official":
                raise

    if not candidates:
        fallback_candidates, fallback_notes = _build_heuristic_candidates(profile)
        candidates = fallback_candidates
        notes.extend(fallback_notes)

    payload: Dict[str, Any] = {
        "tool_name": "netzob_adapter",
        "success": True,
        "backend": backend,
        "candidates": candidates,
        "notes": notes,
    }

    Path(args.output).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
