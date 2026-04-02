from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict

from crewai.flow.flow import Flow, listen, start

from testcrewai.crew import ProtocolReverseCrew
from testcrewai.models import (
    AnalysisReport,
    ExecutionPlan,
    FieldBoundaryCandidate,
    FieldSemanticCandidate,
    ProtocolReverseState,
    ProtocolSchema,
    TrafficProfile,
)
from testcrewai.pipeline.fusion import FusionAgentStage
from testcrewai.pipeline.preprocess import PreprocessAgentStage
from testcrewai.pipeline.report import ReportAgentStage
from testcrewai.pipeline.segmentation import SegmentationAgentStage
from testcrewai.pipeline.semantics import SemanticInferenceAgentStage
from testcrewai.pipeline.tool_selection import ToolSelectorAgentStage
from testcrewai.utils.io import ensure_dir
from testcrewai.utils.logging import setup_logger


class ProtocolReverseFlow(Flow[ProtocolReverseState]):
    initial_state = ProtocolReverseState

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.preprocess_stage = PreprocessAgentStage()
        self.selector_stage = ToolSelectorAgentStage()
        self.segmentation_stage = SegmentationAgentStage()
        self.semantic_stage = SemanticInferenceAgentStage()
        self.fusion_stage = FusionAgentStage()
        self.report_stage = ReportAgentStage()

        self.logger = None
        self.crew_helper = ProtocolReverseCrew()

    def _llm_enabled(self) -> bool:
        if not self.state.use_llm:
            return False
        return any(
            os.getenv(key)
            for key in [
                "DEEPSEEK_API_KEY",
                "OPENAI_API_KEY",
                "OPENROUTER_API_KEY",
                "ANTHROPIC_API_KEY",
                "GEMINI_API_KEY",
                "GOOGLE_API_KEY",
                "AZURE_OPENAI_API_KEY",
            ]
        )

    def _collect_llm_note(self, agent_name: str, prompt: str) -> None:
        if not self._llm_enabled():
            return
        try:
            agent_callable = getattr(self.crew_helper, agent_name)
            agent = agent_callable()
            result = agent.kickoff(prompt)
            self.state.llm_notes[agent_name] = (result.raw or "")[:1200]
        except Exception as exc:
            self.state.warnings.append(f"LLM note skipped for {agent_name}: {exc}")

    @start()
    def bootstrap(self) -> str:
        pcap_path = Path(self.state.pcap_path)
        if not pcap_path.exists():
            raise FileNotFoundError(f"Input capture not found: {pcap_path}")

        output_dir = ensure_dir(self.state.output_dir)
        self.logger = setup_logger(output_dir / "run.log")
        self.logger.info("Flow bootstrap done. Input=%s Output=%s", pcap_path, output_dir)
        if self.state.use_llm and not self._llm_enabled():
            self.state.warnings.append(
                "LLM is enabled by flag, but no supported API key was found in environment."
            )

        self.state.artifacts.traffic_profile_path = output_dir / "traffic_profile.json"
        self.state.artifacts.execution_plan_path = output_dir / "execution_plan.json"
        self.state.artifacts.segment_candidates_path = output_dir / "segment_candidates.json"
        self.state.artifacts.semantic_candidates_path = output_dir / "semantic_candidates.json"
        self.state.artifacts.final_schema_path = output_dir / "final_schema.json"
        self.state.artifacts.report_path = output_dir / "report.md"
        return "bootstrap_ok"

    @listen(bootstrap)
    def run_preprocess(self, _signal: str) -> TrafficProfile:
        assert self.logger is not None
        self.logger.info("Step: preprocess")
        try:
            profile = self.preprocess_stage.run(
                pcap_path=self.state.pcap_path,
                output_dir=self.state.output_dir,
                timeout_sec=self.state.timeout_sec,
                python_bin=self.state.python_bin,
                logger=self.logger,
            )
            self.state.traffic_profile = profile
            for item in profile.errors:
                self.state.errors.append(f"preprocess: {item}")
        except Exception as exc:
            self.state.errors.append(f"preprocess failed: {exc}")
            self.state.traffic_profile = TrafficProfile(input_file=self.state.pcap_path, errors=[str(exc)])
        self._collect_llm_note(
            "preprocess_agent",
            f"Summarize this traffic profile in <=120 words with caveats: {self.state.traffic_profile.model_dump_json()}",
        )
        return self.state.traffic_profile

    @listen(run_preprocess)
    def run_tool_selection(self, profile: TrafficProfile) -> ExecutionPlan:
        assert self.logger is not None
        self.logger.info("Step: tool_selection")
        try:
            plan = self.selector_stage.run(profile=profile, output_dir=self.state.output_dir, logger=self.logger)
            self.state.execution_plan = plan
            for item in plan.warnings:
                self.state.warnings.append(f"tool_selection: {item}")
        except Exception as exc:
            self.state.errors.append(f"tool_selection failed: {exc}")
            self.state.execution_plan = ExecutionPlan(
                execution_mode="single",
                selected_tools=["netzob_adapter"],
                rationale=["fallback default plan"],
            )
        self._collect_llm_note(
            "tool_selector_agent",
            f"Briefly justify this plan in Chinese: {self.state.execution_plan.model_dump_json()}",
        )
        return self.state.execution_plan

    @listen(run_tool_selection)
    def run_segmentation(self, plan: ExecutionPlan) -> list[FieldBoundaryCandidate]:
        assert self.logger is not None
        self.logger.info("Step: segmentation")

        profile = self.state.traffic_profile or TrafficProfile(input_file=self.state.pcap_path)
        traffic_profile_path = str(self.state.artifacts.traffic_profile_path or Path(self.state.output_dir) / "traffic_profile.json")
        try:
            boundaries = self.segmentation_stage.run(
                profile=profile,
                execution_plan=plan,
                traffic_profile_path=traffic_profile_path,
                output_dir=self.state.output_dir,
                timeout_sec=self.state.timeout_sec,
                python_bin=self.state.python_bin,
                netzob_python_bin=self.state.netzob_python_bin,
                nemesys_python_bin=self.state.nemesys_python_bin,
                logger=self.logger,
            )
            self.state.segment_candidates = boundaries
        except Exception as exc:
            self.state.errors.append(f"segmentation failed: {exc}")
            self.state.segment_candidates = []

        self._collect_llm_note(
            "segmentation_agent",
            f"Given candidates, provide 3 risks and 3 improvement tips: {len(self.state.segment_candidates)} candidates.",
        )
        return self.state.segment_candidates

    @listen(run_segmentation)
    def run_semantic_inference(self, boundaries: list[FieldBoundaryCandidate]) -> list[FieldSemanticCandidate]:
        assert self.logger is not None
        self.logger.info("Step: semantic_inference")

        plan = self.state.execution_plan or ExecutionPlan(selected_tools=["netplier_adapter"], execution_mode="single")
        segment_candidates_path = str(self.state.artifacts.segment_candidates_path or Path(self.state.output_dir) / "segment_candidates.json")
        traffic_profile_path = str(self.state.artifacts.traffic_profile_path or Path(self.state.output_dir) / "traffic_profile.json")

        try:
            semantics = self.semantic_stage.run(
                execution_plan=plan,
                segment_candidates_path=segment_candidates_path,
                traffic_profile_path=traffic_profile_path,
                boundaries=boundaries,
                output_dir=self.state.output_dir,
                timeout_sec=self.state.timeout_sec,
                python_bin=self.state.python_bin,
                netplier_python_bin=self.state.netplier_python_bin,
                binaryinferno_python_bin=self.state.binaryinferno_python_bin,
                logger=self.logger,
            )
            self.state.semantic_candidates = semantics
        except Exception as exc:
            self.state.errors.append(f"semantic inference failed: {exc}")
            self.state.semantic_candidates = []

        self._collect_llm_note(
            "semantic_inference_agent",
            f"Explain semantic uncertainty for these candidates: {len(self.state.semantic_candidates)} items.",
        )
        return self.state.semantic_candidates

    @listen(run_semantic_inference)
    def run_fusion(self, semantics: list[FieldSemanticCandidate]) -> ProtocolSchema:
        assert self.logger is not None
        self.logger.info("Step: fusion")

        profile = self.state.traffic_profile or TrafficProfile(input_file=self.state.pcap_path)
        try:
            schema = self.fusion_stage.run(
                profile=profile,
                boundaries=self.state.segment_candidates,
                semantics=semantics,
                output_dir=self.state.output_dir,
                logger=self.logger,
            )
            self.state.final_schema = schema
        except Exception as exc:
            self.state.errors.append(f"fusion failed: {exc}")
            self.state.final_schema = ProtocolSchema(input_file=self.state.pcap_path)

        self._collect_llm_note(
            "fusion_agent",
            f"Review schema confidence and mention top 2 weak points: {self.state.final_schema.model_dump_json()}",
        )
        return self.state.final_schema

    @listen(run_fusion)
    def run_report(self, schema: ProtocolSchema) -> AnalysisReport:
        assert self.logger is not None
        self.logger.info("Step: report")

        profile = self.state.traffic_profile or TrafficProfile(input_file=self.state.pcap_path)
        plan = self.state.execution_plan or ExecutionPlan(selected_tools=[], execution_mode="single")

        try:
            report = self.report_stage.run(
                profile=profile,
                execution_plan=plan,
                boundaries=self.state.segment_candidates,
                semantics=self.state.semantic_candidates,
                schema=schema,
                output_dir=self.state.output_dir,
                logger=self.logger,
            )
            self.state.report = report
        except Exception as exc:
            self.state.errors.append(f"report generation failed: {exc}")
            self.state.report = AnalysisReport(title="failed", markdown=str(exc))

        self._collect_llm_note(
            "report_agent",
            "Write one paragraph for thesis defense: what is novel in this prototype?",
        )
        return self.state.report

    @listen(run_report)
    def finish(self, _report: AnalysisReport) -> Dict[str, Any]:
        assert self.logger is not None
        self.logger.info("Flow finished with %d warnings and %d errors", len(self.state.warnings), len(self.state.errors))

        summary = {
            "input": self.state.pcap_path,
            "output_dir": self.state.output_dir,
            "artifacts": {
                "traffic_profile": str(self.state.artifacts.traffic_profile_path),
                "execution_plan": str(self.state.artifacts.execution_plan_path),
                "segment_candidates": str(self.state.artifacts.segment_candidates_path),
                "semantic_candidates": str(self.state.artifacts.semantic_candidates_path),
                "final_schema": str(self.state.artifacts.final_schema_path),
                "report": str(self.state.artifacts.report_path),
                "log": str(Path(self.state.output_dir) / "run.log"),
            },
            "warnings": self.state.warnings,
            "errors": self.state.errors,
            "llm_notes": self.state.llm_notes,
        }
        return summary
