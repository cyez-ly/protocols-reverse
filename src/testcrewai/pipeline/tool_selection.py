from __future__ import annotations

from pathlib import Path
from typing import List, Set

from testcrewai.models import ExecutionPlan, ToolDecision, TrafficProfile
from testcrewai.utils.io import write_json


def _protocols(profile: TrafficProfile) -> Set[str]:
    return {item.strip().lower() for item in profile.protocols_observed if item.strip()}


def _choose_segmentation_primary(profile: TrafficProfile, protos: Set[str]) -> tuple[str, str, float]:
    style = profile.protocol_style
    printable = profile.mean_printable_ratio

    # Text traffic: Netzob tends to be more stable for coarse boundary partitioning.
    if style == "text" or printable >= 0.45:
        return (
            "netzob_adapter",
            "流量更偏文本协议，优先使用 Netzob（基于熵/聚类）进行字段切分。",
            0.82,
        )

    # Hybrid/unknown but clearly binary-ish or known binary protocol clues.
    binary_hints = {"dhcp", "dns", "ntp", "tls", "dtls", "quic", "smb", "opcua", "s7comm"}
    if style == "binary" or printable <= 0.2 or bool(protos & binary_hints):
        return (
            "nemesys_adapter",
            "流量更偏二进制协议，优先使用 NEMESYS（基于消息内转折）进行切分。",
            0.81,
        )

    return (
        "netzob_adapter",
        "协议风格不明确，回退到更稳健的默认切分器 Netzob。",
        0.74,
    )


def _choose_semantic_primary(profile: TrafficProfile, protos: Set[str]) -> tuple[str, str, float]:
    style = profile.protocol_style

    binary_friendly = {"dhcp", "dns", "ntp", "tls", "dtls", "quic", "smb", "modbus", "s7comm"}
    if style == "binary" or bool(protos & binary_friendly):
        return (
            "binaryinferno_adapter",
            "二进制协议线索较强，优先使用 BinaryInferno 做语义推断。",
            0.81,
        )

    # Text/request-response protocols usually align well with NetPlier semantics.
    netplier_friendly = {"http", "sip", "smtp", "ftp", "imap", "pop"}
    if style == "text" or bool(protos & netplier_friendly):
        return (
            "netplier_adapter",
            "存在明显 type/length 风格线索，优先使用 NetPlier 做语义推断。",
            0.8,
        )

    return (
        "binaryinferno_adapter",
        "默认采用面向二进制场景的语义推断工具 BinaryInferno（id/checksum/timestamp/payload）。",
        0.79,
    )


class ToolSelectorAgentStage:
    def run(self, profile: TrafficProfile, output_dir: str, logger) -> ExecutionPlan:
        # 选主工具 + 备份工具：默认单工具优先，失败再触发备份。
        if profile.capture_format in {"pcap", "pcapng"} and profile.packet_count == 0 and not profile.sample_messages_hex:
            plan = ExecutionPlan(
                execution_mode="single",
                decisions=[],
                selected_tools=[],
                rationale=["未提取到可解析数据包，跳过后续逆向工具执行。"],
                warnings=[
                    "输入抓包解析失败，请检查 pcap/pcapng 文件完整性与解析环境。",
                ],
            )
            output_path = Path(output_dir) / "execution_plan.json"
            write_json(output_path, plan)
            logger.info("Tool selection completed -> %s", output_path)
            return plan

        decisions: List[ToolDecision] = []
        rationale: List[str] = []
        warnings: List[str] = []

        protos = _protocols(profile)
        seg_primary, seg_primary_reason, seg_primary_conf = _choose_segmentation_primary(profile, protos)
        sem_primary, sem_primary_reason, sem_primary_conf = _choose_semantic_primary(profile, protos)

        seg_backup = "nemesys_adapter" if seg_primary == "netzob_adapter" else "netzob_adapter"
        sem_backup = "binaryinferno_adapter" if sem_primary == "netplier_adapter" else "netplier_adapter"

        decisions.extend(
            [
                ToolDecision(
                    tool_name=seg_primary,
                    selected=True,
                    mode="single",
                    confidence=seg_primary_conf,
                    reason=seg_primary_reason,
                ),
                ToolDecision(
                    tool_name=seg_backup,
                    selected=False,
                    mode="single",
                    confidence=round(max(0.5, seg_primary_conf - 0.08), 3),
                    reason="分段备份工具；当主分段失败或产出为空时触发。",
                ),
                ToolDecision(
                    tool_name=sem_primary,
                    selected=True,
                    mode="single",
                    confidence=sem_primary_conf,
                    reason=sem_primary_reason,
                ),
                ToolDecision(
                    tool_name=sem_backup,
                    selected=False,
                    mode="single",
                    confidence=round(max(0.5, sem_primary_conf - 0.08), 3),
                    reason=(
                        "语义备份工具；当主语义失败/为空，或 unknown 占比过高时触发。"
                    ),
                ),
            ]
        )

        rationale.append(
            (
                "采用“单工具优先”策略：分段与语义各选择一个主工具，并保留备份工具按条件触发。"
            )
        )
        rationale.append(
            (
                f"主工具 -> segmentation: {seg_primary}, semantics: {sem_primary}; "
                f"备份工具 -> segmentation: {seg_backup}, semantics: {sem_backup}。"
            )
        )

        selected_tools = [decision.tool_name for decision in decisions if decision.selected]
        if not selected_tools:
            warnings.append("策略未选出工具，回退到 netzob_adapter + netplier_adapter")
            selected_tools = ["netzob_adapter", "netplier_adapter"]

        execution_mode = "single"
        plan = ExecutionPlan(
            execution_mode=execution_mode,
            decisions=decisions,
            selected_tools=selected_tools,
            rationale=rationale,
            warnings=warnings,
        )

        output_path = Path(output_dir) / "execution_plan.json"
        write_json(output_path, plan)
        logger.info("Tool selection completed -> %s", output_path)
        return plan
