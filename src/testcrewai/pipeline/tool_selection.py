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
            "Text-like traffic favors Netzob entropy/cluster partition as the primary segmenter.",
            0.82,
        )

    # Hybrid/unknown but clearly binary-ish or known binary protocol clues.
    binary_hints = {"dhcp", "dns", "ntp", "tls", "dtls", "quic", "smb", "opcua", "s7comm"}
    if style == "binary" or printable <= 0.2 or bool(protos & binary_hints):
        return (
            "nemesys_adapter",
            "Binary-like traffic favors NEMESYS intrinsic per-message transition segmentation.",
            0.81,
        )

    return (
        "netzob_adapter",
        "Fallback to Netzob as a robust default segmenter under ambiguous style.",
        0.74,
    )


def _choose_semantic_primary(profile: TrafficProfile, protos: Set[str]) -> tuple[str, str, float]:
    style = profile.protocol_style

    binary_friendly = {"dhcp", "dns", "ntp", "tls", "dtls", "quic", "smb", "modbus", "s7comm"}
    if style == "binary" or bool(protos & binary_friendly):
        return (
            "binaryinferno_adapter",
            "Binary-like protocol cues favor BinaryInferno as the primary semantic inferencer.",
            0.81,
        )

    # Text/request-response protocols usually align well with NetPlier semantics.
    netplier_friendly = {"http", "sip", "smtp", "ftp", "imap", "pop"}
    if style == "text" or bool(protos & netplier_friendly):
        return (
            "netplier_adapter",
            "Type/length-style semantic cues are likely; choose NetPlier as primary semantic inferencer.",
            0.8,
        )

    return (
        "binaryinferno_adapter",
        "Binary-oriented semantic inference (id/checksum/timestamp/payload cues) favors BinaryInferno.",
        0.79,
    )


class ToolSelectorAgentStage:
    def run(self, profile: TrafficProfile, output_dir: str, logger) -> ExecutionPlan:
        if profile.capture_format in {"pcap", "pcapng"} and profile.packet_count == 0 and not profile.sample_messages_hex:
            plan = ExecutionPlan(
                execution_mode="single",
                decisions=[],
                selected_tools=[],
                rationale=["No parseable packets were extracted; skip downstream reverse tools."],
                warnings=[
                    "Input capture parsing failed. Please validate pcap/pcapng file integrity and parser environment.",
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
                    reason="Backup segmentation tool; trigger when primary segmentation fails or yields empty candidates.",
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
                        "Backup semantic tool; trigger when primary semantic fails/empty "
                        "or unknown ratio is too high."
                    ),
                ),
            ]
        )

        rationale.append(
            (
                "Single-tool-first strategy: pick one primary tool for segmentation and one for semantics, "
                "keep backups for conditional fallback."
            )
        )
        rationale.append(
            (
                f"Primary tools -> segmentation: {seg_primary}, semantics: {sem_primary}; "
                f"backup tools -> segmentation: {seg_backup}, semantics: {sem_backup}."
            )
        )

        selected_tools = [decision.tool_name for decision in decisions if decision.selected]
        if not selected_tools:
            warnings.append("No tools selected by strategy; fallback to netzob_adapter")
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
