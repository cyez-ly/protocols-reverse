from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


class ShellCommandResult(BaseModel):
    command: List[str]
    return_code: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    duration_sec: float = 0.0


class ToolRunResult(BaseModel):
    tool_name: str
    success: bool
    input_path: str
    output_path: Optional[str] = None
    command_result: Optional[ShellCommandResult] = None
    data: Dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None


class SessionFeature(BaseModel):
    session_id: str
    protocol: str
    packet_count: int
    mean_payload_len: float
    direction_ratio: float = Field(
        default=0.5,
        description="Approximate outbound packet ratio in [0, 1].",
    )


class MessageCluster(BaseModel):
    cluster_id: str
    basis: str = "length"
    sample_count: int
    mean_length: float
    representative_lengths: List[int] = Field(default_factory=list)


class TrafficProfile(BaseModel):
    input_file: str
    capture_format: Literal["pcap", "pcapng", "unknown"] = "unknown"
    packet_count: int = 0
    session_count: int = 0
    avg_packet_length: float = 0.0
    min_packet_length: int = 0
    max_packet_length: int = 0
    std_packet_length: float = 0.0
    mean_entropy: float = 0.0
    mean_printable_ratio: float = 0.0
    protocol_style: Literal["text", "binary", "hybrid", "unknown"] = "unknown"
    protocols_observed: List[str] = Field(default_factory=list)
    session_features: List[SessionFeature] = Field(default_factory=list)
    message_clusters: List[MessageCluster] = Field(default_factory=list)
    sample_messages_hex: List[str] = Field(default_factory=list)
    notes: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)


class ToolDecision(BaseModel):
    tool_name: str
    selected: bool = True
    mode: Literal["single", "parallel"] = "single"
    confidence: float = Field(ge=0.0, le=1.0)
    reason: str


class ExecutionPlan(BaseModel):
    execution_mode: Literal["single", "parallel"] = "parallel"
    decisions: List[ToolDecision] = Field(default_factory=list)
    selected_tools: List[str] = Field(default_factory=list)
    rationale: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)


class FieldBoundaryCandidate(BaseModel):
    message_cluster: str
    start: int = Field(ge=0)
    end: int = Field(gt=0)
    confidence: float = Field(ge=0.0, le=1.0)
    source_tool: str
    reason: str = ""


class FieldSemanticCandidate(BaseModel):
    message_cluster: str
    field_range: str
    semantic_type: Literal[
        "type",
        "length",
        "timestamp",
        "id",
        "session_id",
        "payload",
        "checksum",
        "unknown",
    ]
    confidence: float = Field(ge=0.0, le=1.0)
    source_tool: str
    reason: str = ""


class EvidenceItem(BaseModel):
    evidence_type: str
    source: str
    score: float = Field(ge=0.0, le=1.0)
    detail: str


class ProtocolField(BaseModel):
    message_cluster: str
    name: str
    start: int
    end: int
    semantic_type: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidences: List[EvidenceItem] = Field(default_factory=list)


class ProtocolSchema(BaseModel):
    input_file: str
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    message_clusters: List[MessageCluster] = Field(default_factory=list)
    fields: List[ProtocolField] = Field(default_factory=list)
    conflict_resolutions: List[str] = Field(default_factory=list)
    global_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    limitations: List[str] = Field(default_factory=list)


class AnalysisReport(BaseModel):
    title: str
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    markdown: str
    output_path: Optional[str] = None


class RunArtifacts(BaseModel):
    traffic_profile_path: Optional[Path] = None
    execution_plan_path: Optional[Path] = None
    segment_candidates_path: Optional[Path] = None
    semantic_candidates_path: Optional[Path] = None
    final_schema_path: Optional[Path] = None
    report_path: Optional[Path] = None


class ProtocolReverseState(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    pcap_path: str = ""
    output_dir: str = ""
    python_bin: str = "python3"
    netzob_python_bin: str = ""
    nemesys_python_bin: str = ""
    netplier_python_bin: str = ""
    binaryinferno_python_bin: str = ""
    timeout_sec: int = 60
    use_llm: bool = False

    traffic_profile: Optional[TrafficProfile] = None
    execution_plan: Optional[ExecutionPlan] = None
    segment_candidates: List[FieldBoundaryCandidate] = Field(default_factory=list)
    semantic_candidates: List[FieldSemanticCandidate] = Field(default_factory=list)
    final_schema: Optional[ProtocolSchema] = None
    report: Optional[AnalysisReport] = None
    llm_notes: Dict[str, str] = Field(default_factory=dict)

    warnings: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
    artifacts: RunArtifacts = Field(default_factory=RunArtifacts)
