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

# 父类flow
class ProtocolReverseFlow(Flow[ProtocolReverseState]):
    # 统一编排：预处理 -> 选工具 -> 分段 -> 语义 -> 融合 -> 报告
    initial_state = ProtocolReverseState

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        # 预处理阶段
        self.preprocess_stage = PreprocessAgentStage()
        # 工具选择阶段
        self.selector_stage = ToolSelectorAgentStage()
        # 字段分割阶段
        self.segmentation_stage = SegmentationAgentStage()
        # 语义推断阶段
        self.semantic_stage = SemanticInferenceAgentStage()
        # 结果融合阶段
        self.fusion_stage = FusionAgentStage()
        # 报告输出阶段
        self.report_stage = ReportAgentStage()

        self.logger = None
        self.crew_helper = ProtocolReverseCrew()
    
    # 检查环境变量中是否有大模型 API Key
    def _llm_enabled(self) -> bool:
        # 仅当用户开启 --use-llm 且存在可用 API Key 时才启用。
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

    # 让 LLM 给每个阶段写总结 / 注释，方便查看
    def _collect_llm_note(self, agent_name: str, prompt: str) -> None:
        # LLM 在本项目中是“可选注释增强”，不是主决策路径。
        if not self._llm_enabled():
            return
        try:
            agent_callable = getattr(self.crew_helper, agent_name)
            agent = agent_callable()
            result = agent.kickoff(prompt)
            self.state.llm_notes[agent_name] = (result.raw or "")[:1200]
        except Exception as exc:
            self.state.warnings.append(f"LLM note skipped for {agent_name}: {exc}")
    
    # 起点（用 @start + @listen 装饰器定义固定执行顺序，Flow 框架会自动按顺序运行）
    @start()
    def bootstrap(self) -> str:
        # 校验文件、创建输出目录、初始化日志、定义所有结果文件的保存路径。
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
        # 阶段1：流量预处理与统计特征提取（解析 pcap，提取流量特征，生成流量档案）。
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
            # 预处理失败时的兜底逻辑
            self.state.errors.append(f"preprocess failed: {exc}")
            self.state.traffic_profile = TrafficProfile(input_file=self.state.pcap_path, errors=[str(exc)])
        self._collect_llm_note(
            "preprocess_agent",
            f"Summarize this traffic profile in <=120 words with caveats: {self.state.traffic_profile.model_dump_json()}",
        )
        return self.state.traffic_profile

    @listen(run_preprocess)
    def run_tool_selection(self, profile: TrafficProfile) -> ExecutionPlan:
        # 阶段2：根据流量特征选择主工具与备份工具。
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
        # 阶段3：字段边界切分（单工具优先，必要时启用备份）。
        assert self.logger is not None
        self.logger.info("Step: segmentation")

        profile = self.state.traffic_profile or TrafficProfile(input_file=self.state.pcap_path)
        traffic_profile_path = str(self.state.artifacts.traffic_profile_path or Path(self.state.output_dir) / "traffic_profile.json")
        try:
            # 调用分割阶段的run方法，（netzobTool or NEMESYStool）
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
        # 阶段4：字段语义推断，并对齐到分段边界。
        assert self.logger is not None
        self.logger.info("Step: semantic_inference")

        plan = self.state.execution_plan or ExecutionPlan(selected_tools=["netplier_adapter"], execution_mode="single")
        segment_candidates_path = str(self.state.artifacts.segment_candidates_path or Path(self.state.output_dir) / "segment_candidates.json")
        traffic_profile_path = str(self.state.artifacts.traffic_profile_path or Path(self.state.output_dir) / "traffic_profile.json")

        try:
            # 调用语义推断阶段的run方法，（netplier-adapter or binaryinferno-adapter）
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
        # 阶段5：融合边界与语义证据，得到最终协议模板。
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
        # 阶段6：生成 markdown 报告，便于答辩展示与复盘。
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
        # 返回运行摘要，包含产物路径、warning/error 与可选 LLM 注释。
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
