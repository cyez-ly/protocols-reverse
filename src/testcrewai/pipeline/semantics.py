from __future__ import annotations

import json
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

from testcrewai.adapters.common import parse_range, range_to_str
from testcrewai.models import ExecutionPlan, FieldBoundaryCandidate, FieldSemanticCandidate
from testcrewai.pipeline.preprocess import _cluster_key_for_payload, _normalize_protocol_name
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


def _load_profile_payload(traffic_profile_path: str) -> Dict[str, Any]:
    try:
        payload = json.loads(Path(traffic_profile_path).read_text(encoding="utf-8"))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _profile_protocols(profile_payload: Dict[str, Any]) -> set[str]:
    raw = profile_payload.get("protocols_observed", [])
    if not isinstance(raw, list):
        return set()
    return {_normalize_protocol_name(str(item)) for item in raw if str(item).strip()}


def _decode_profile_messages(profile_payload: Dict[str, Any]) -> List[bytes]:
    values: List[bytes] = []
    raw_messages = profile_payload.get("sample_messages_hex", [])
    if not isinstance(raw_messages, list):
        return values
    for item in raw_messages:
        try:
            payload = bytes.fromhex(str(item))
        except ValueError:
            continue
        if payload:
            values.append(payload)
    return values


def _profile_cluster_payloads(profile_payload: Dict[str, Any], protos: set[str]) -> Dict[str, bytes]:
    clusters = profile_payload.get("message_clusters", [])
    if not isinstance(clusters, list):
        return {}

    protocol_style = str(profile_payload.get("protocol_style", "unknown"))
    basis_to_cluster: Dict[str, str] = {}
    length_to_cluster: Dict[int, str] = {}
    for cluster in clusters:
        if not isinstance(cluster, dict):
            continue
        cluster_id = str(cluster.get("cluster_id", ""))
        if not cluster_id:
            continue
        basis = str(cluster.get("basis", ""))
        if basis.startswith("content:key="):
            basis_to_cluster[basis.split("content:key=", maxsplit=1)[1]] = cluster_id
        lengths = cluster.get("representative_lengths") or []
        if isinstance(lengths, list):
            for length in lengths:
                try:
                    length_to_cluster[int(length)] = cluster_id
                except Exception:
                    continue

    result: Dict[str, bytes] = {}
    for payload in _decode_profile_messages(profile_payload):
        cluster_id = ""
        if basis_to_cluster:
            key = _cluster_key_for_payload(payload, protocol_style, protos)
            cluster_id = basis_to_cluster.get(key, "")
        if not cluster_id:
            cluster_id = length_to_cluster.get(len(payload), "")
        if cluster_id and cluster_id not in result:
            result[cluster_id] = payload
    return result


def _line_bounds(payload: bytes, start: int) -> tuple[int, int]:
    line_start = payload.rfind(b"\n", 0, max(0, start)) + 1
    line_end = payload.find(b"\n", start)
    if line_end < 0:
        line_end = len(payload)
    if line_end > line_start and payload[line_end - 1 : line_end] == b"\r":
        line_end -= 1
    return line_start, line_end


def _field_text(payload: bytes, start: int, end: int) -> str:
    try:
        return payload[start:end].decode("ascii", errors="ignore").strip(" \t\r\n:")
    except Exception:
        return ""


def _token_index_in_line(payload: bytes, start: int, line_start: int) -> int:
    prefix = payload[line_start:start].decode("ascii", errors="ignore")
    return len([part for part in re.split(r"\s+", prefix.strip()) if part])


def _text_semantic_for_boundary(
    boundary: FieldBoundaryCandidate,
    protos: set[str],
    payload: bytes,
) -> tuple[str, float, str] | None:
    if not payload:
        return None

    start = max(0, min(boundary.start, len(payload)))
    end = max(start, min(boundary.end, len(payload)))
    if end <= start:
        return None

    text_protocols = {"http", "smtp", "ftp", "imap", "pop", "sip"}
    if not (protos & text_protocols):
        return None

    header_end_candidates = [payload.find(b"\r\n\r\n"), payload.find(b"\n\n")]
    header_end_candidates = [item for item in header_end_candidates if item >= 0]
    header_end = min(header_end_candidates) if header_end_candidates else -1
    header_body_cut = header_end + 4 if header_end >= 0 else len(payload) + 1
    if header_end >= 0 and start >= header_body_cut:
        return "body", 0.74, "文本协议正文区域"

    line_start, line_end = _line_bounds(payload, start)
    line = payload[line_start:line_end]
    field = _field_text(payload, start, end)
    token_index = _token_index_in_line(payload, start, line_start)
    line_parts = _field_text(payload, line_start, min(line_end, line_start + 48)).split(maxsplit=1) if line else []
    first_token = line_parts[0].upper() if line_parts else ""

    colon_offset = line.find(b":")
    if colon_offset >= 0 and not (line_start == 0 and first_token.startswith("HTTP/")):
        colon_pos = line_start + colon_offset
        if end <= colon_pos + 1 or start <= colon_pos < end:
            return "header_name", 0.78, "文本协议头部名称字段"
        if start > colon_pos:
            return "header_value", 0.76, "文本协议头部取值字段"

    if "http" in protos and line_start == 0:
        http_methods = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT"}
        upper_field = field.upper()
        if token_index == 0 and upper_field in http_methods:
            return "method", 0.82, "HTTP 请求方法字段"
        if token_index == 0 and upper_field.startswith("HTTP/"):
            return "version", 0.80, "HTTP 响应版本字段"
        if token_index == 1 and first_token.startswith("HTTP/"):
            return "status_code", 0.80, "HTTP 响应状态码字段"
        if token_index == 1:
            return "uri", 0.78, "HTTP 请求 URI 字段"
        if token_index == 2:
            return "version", 0.76, "HTTP 协议版本字段"
        return "parameter", 0.68, "HTTP 首行参数字段"

    if "smtp" in protos and line_start == 0:
        smtp_commands = {"HELO", "EHLO", "MAIL", "RCPT", "DATA", "RSET", "NOOP", "QUIT", "STARTTLS", "AUTH"}
        upper_field = field.upper()
        if token_index == 0 and upper_field.isdigit() and len(upper_field) == 3:
            return "status_code", 0.80, "SMTP 响应状态码字段"
        if token_index == 0 and upper_field in smtp_commands:
            return "command", 0.82, "SMTP 命令字段"
        if token_index >= 1:
            return "parameter", 0.72, "SMTP 命令参数字段"

    if header_end >= 0 and start < header_body_cut:
        return "header_value", 0.66, "文本协议头部或首部延续字段"
    if end - start >= 16:
        return "body", 0.66, "文本协议较长文本区域"
    return "parameter", 0.62, "文本协议短参数字段"


def _rule_type_for_boundary(
    boundary: FieldBoundaryCandidate,
    ordered_index: int,
    total_fields: int,
    cluster_len: int,
    protos: set[str],
    printable_ratio: float,
) -> tuple[str, float, str] | None:
    start = boundary.start
    end = boundary.end
    span = max(0, end - start)
    if span <= 0:
        return None

    if "modbus" in protos:
        if start < 2:
            return "id", 0.72, "Modbus MBAP transaction id 区域"
        if 2 <= start < 4:
            return "type", 0.68, "Modbus MBAP protocol id 区域"
        if 4 <= start < 7:
            return "length", 0.72, "Modbus MBAP length/unit 区域"
        if 7 <= start < 9:
            return "type", 0.70, "Modbus function code 区域"
        return "payload", 0.64, "Modbus PDU 数据区"

    if "dhcp" in protos:
        if start == 0 or (start < 2 and span <= 4):
            return "type", 0.70, "DHCP/BOOTP 报文头部操作类型区域"
        if start < 12:
            return "session_id", 0.66, "DHCP 事务与标志相关头部区域"
        if 236 <= start < 240:
            return "type", 0.72, "DHCP magic cookie 附近区域"
        if start >= 240 or ordered_index >= total_fields - 2:
            return "payload", 0.67, "DHCP options/可变负载区域"
        return "id", 0.58, "DHCP 固定头部标识相关区域"

    if "dns" in protos:
        if start < 2:
            return "id", 0.72, "DNS transaction id 区域"
        if start < 4:
            return "type", 0.70, "DNS flags/control 区域"
        if start < 12:
            return "length", 0.66, "DNS count 字段区域"
        return "payload", 0.62, "DNS question/answer 记录区域"

    if "ntp" in protos:
        if start < 4:
            return "type", 0.70, "NTP 首部 LI/VN/Mode 与基础控制字段"
        if start >= 16 and span >= 4:
            return "timestamp", 0.72, "NTP 时间戳相关字段区域"
        if ordered_index >= total_fields - 1:
            return "payload", 0.60, "NTP 扩展/尾部负载区域"
        return "id", 0.56, "NTP 固定头部数值字段"

    if "dnp3" in protos:
        if start < 2:
            return "type", 0.68, "DNP3 start/control 区域"
        if start < 4:
            return "length", 0.64, "DNP3 长度/控制相关区域"
        if ordered_index >= total_fields - 1:
            return "payload", 0.62, "DNP3 数据负载区域"
        return "id", 0.56, "DNP3 地址/控制相关区域"

    text_protocols = {"http", "smtp", "ftp", "imap", "pop", "sip"}
    if protos & text_protocols or printable_ratio >= 0.65:
        if ordered_index == 0 and span <= 32:
            return "type", 0.66, "文本协议首行命令/状态码区域"
        return "payload", 0.62, "文本协议参数、头部或正文区域"

    if ordered_index == 0 and span <= 4:
        return "type", 0.58, "通用规则：头部短字段更可能是类型/控制字段"
    if ordered_index == 1 and span <= 4:
        return "length", 0.56, "通用规则：第二个短字段可能为长度字段"
    if ordered_index >= total_fields - 1 and span >= max(4, int(cluster_len * 0.12)):
        return "payload", 0.58, "通用规则：尾部较大字段更可能是负载"
    return None


def _rule_based_semantics(
    boundaries: List[FieldBoundaryCandidate],
    profile_payload: Dict[str, Any],
) -> List[FieldSemanticCandidate]:
    if not profile_payload.get("protocols_observed") and not profile_payload.get("message_clusters"):
        return []

    protos = _profile_protocols(profile_payload)
    cluster_payloads = _profile_cluster_payloads(profile_payload, protos)
    try:
        printable_ratio = float(profile_payload.get("mean_printable_ratio", 0.0))
    except Exception:
        printable_ratio = 0.0

    cluster_lengths: Dict[str, int] = {}
    for cluster in profile_payload.get("message_clusters", []) if isinstance(profile_payload.get("message_clusters"), list) else []:
        if not isinstance(cluster, dict):
            continue
        cluster_id = str(cluster.get("cluster_id", ""))
        lengths = cluster.get("representative_lengths") or []
        if cluster_id and lengths:
            try:
                cluster_lengths[cluster_id] = max(int(length) for length in lengths)
            except Exception:
                pass
        elif cluster_id:
            try:
                cluster_lengths[cluster_id] = int(round(float(cluster.get("mean_length", 1))))
            except Exception:
                pass

    grouped: Dict[str, List[FieldBoundaryCandidate]] = {}
    for boundary in boundaries:
        grouped.setdefault(boundary.message_cluster, []).append(boundary)

    results: List[FieldSemanticCandidate] = []
    for cluster_id, items in grouped.items():
        ordered = sorted(items, key=lambda item: (item.start, item.end))
        cluster_len = cluster_lengths.get(cluster_id, max((item.end for item in ordered), default=1))
        payload = cluster_payloads.get(cluster_id, b"")
        for idx, boundary in enumerate(ordered):
            rule = _text_semantic_for_boundary(boundary, protos, payload)
            if rule is None:
                rule = _rule_type_for_boundary(
                    boundary=boundary,
                    ordered_index=idx,
                    total_fields=len(ordered),
                    cluster_len=cluster_len,
                    protos=protos,
                    printable_ratio=printable_ratio,
                )
            if rule is None:
                continue
            semantic_type, confidence, reason = rule
            results.append(
                FieldSemanticCandidate(
                    message_cluster=cluster_id,
                    field_range=range_to_str(boundary.start, boundary.end),
                    semantic_type=semantic_type,  # type: ignore[arg-type]
                    confidence=confidence,
                    source_tool="semantic_rules",
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
            # 若完全无重叠，则回退到“最近边界”，降低跨工具边界不一致损耗。
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
    # 语义阶段：先跑主语义工具；未知占比过高或语义过于单一时触发备份工具。
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
        # 输出统一结构：字段语义候选结果文件。
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

        profile_payload = _load_profile_payload(traffic_profile_path)
        protos = _profile_protocols(profile_payload)
        text_fast_path_enabled = str(os.getenv("SEMANTIC_TEXT_FAST_PATH", "true")).strip().lower() not in {
            "0",
            "false",
            "no",
            "off",
        }
        text_protocols = {"http", "smtp", "ftp", "imap", "pop", "sip"}
        if (
            text_fast_path_enabled
            and boundaries
            and (protos & text_protocols)
            and all(item.source_tool == "text_segmenter" for item in boundaries)
        ):
            semantic_candidates = _rule_based_semantics(boundaries, profile_payload)
            runtime_info["semantic_text_fast_path"] = "true"
            runtime_info["semantic_rule_candidates"] = str(len(semantic_candidates))
            output_path = Path(output_dir) / "semantic_candidates.json"
            payload = {
                "candidates": [item.model_dump(mode="json") for item in semantic_candidates],
                "tool_errors": tool_errors,
                "runtime_info": runtime_info,
            }
            write_json(output_path, payload)
            logger.info("Semantic inference completed -> %s", output_path)
            return semantic_candidates

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
            # 触发备份的两个条件：
            # 1) 未知比例过高；2) 语义类型过于单一（塌缩）。
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

        rule_candidates = _rule_based_semantics(boundaries, profile_payload)
        if rule_candidates:
            semantic_candidates.extend(rule_candidates)
            runtime_info["semantic_rule_candidates"] = str(len(rule_candidates))

        output_path = Path(output_dir) / "semantic_candidates.json"
        payload = {
            "candidates": [item.model_dump(mode="json") for item in semantic_candidates],
            "tool_errors": tool_errors,
            "runtime_info": runtime_info,
        }
        write_json(output_path, payload)
        logger.info("Semantic inference completed -> %s", output_path)
        return semantic_candidates
