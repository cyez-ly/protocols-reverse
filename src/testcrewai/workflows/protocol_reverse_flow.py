from __future__ import annotations

import json
import os
from pathlib import Path
import re
from typing import Any, Dict, List

from crewai.flow.flow import Flow, listen, start

from testcrewai.crew import ProtocolReverseCrew
from testcrewai.models import (
    AnalysisReport,
    EvidenceItem,
    ExecutionPlan,
    FieldBoundaryCandidate,
    FieldSemanticCandidate,
    ToolDecision,
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
from testcrewai.utils.io import ensure_dir, write_json
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

    def _llm_stage_enabled(self, env_name: str, default: bool = True) -> bool:
        if not self._llm_enabled():
            return False
        value = str(os.getenv(env_name, "1" if default else "0")).strip().lower()
        if value in {"0", "false", "no", "off"}:
            return False
        return True

    def _extract_json_object(self, text: str) -> Dict[str, Any] | None:
        content = text.strip()
        if not content:
            return None
        try:
            payload = json.loads(content)
            if isinstance(payload, dict):
                return payload
        except Exception:
            pass

        # 尝试从自由文本中截取首个 JSON 对象。
        match = re.search(r"\{.*\}", content, flags=re.DOTALL)
        if not match:
            return None
        snippet = match.group(0).strip()
        try:
            payload = json.loads(snippet)
            if isinstance(payload, dict):
                return payload
        except Exception:
            return None
        return None

    def _kickoff_agent_json(self, agent_name: str, prompt: str) -> Dict[str, Any] | None:
        if not self._llm_enabled():
            return None
        try:
            agent_callable = getattr(self.crew_helper, agent_name)
            agent = agent_callable()
            result = agent.kickoff(prompt)

            pydantic_payload = getattr(result, "pydantic", None)
            if pydantic_payload is not None:
                if hasattr(pydantic_payload, "model_dump"):
                    dumped = pydantic_payload.model_dump(mode="json")
                    if isinstance(dumped, dict):
                        return dumped
                if isinstance(pydantic_payload, dict):
                    return pydantic_payload

            raw = str(getattr(result, "raw", "") or "")
            parsed = self._extract_json_object(raw)
            if parsed is None:
                self.state.warnings.append(f"LLM JSON 解析失败（{agent_name}）")
            return parsed
        except Exception as exc:
            self.state.warnings.append(f"LLM 核心策略调用失败（{agent_name}）: {exc}")
            return None

    def _clamp(self, value: float, low: float = 0.0, high: float = 1.0) -> float:
        return max(low, min(high, value))

    def _apply_llm_preprocess_review(self, profile: TrafficProfile) -> TrafficProfile:
        # 受控参与：LLM只做特征完整性审查与建议，不替代统计计算。
        if not self._llm_stage_enabled("LLM_PREPROCESS_REVIEW_ENABLE", default=True):
            return profile

        payload = profile.model_dump(mode="json")
        samples = payload.get("sample_messages_hex", [])
        if isinstance(samples, list) and len(samples) > 24:
            payload["sample_messages_hex"] = samples[:24]
            payload["sample_messages_hex_truncated"] = True

        prompt = (
            "You are a preprocessing quality auditor for protocol reverse engineering.\n"
            "Given the traffic profile JSON, provide a strict JSON object only with keys:\n"
            "{\n"
            '  "completeness_score": 0.0-1.0,\n'
            '  "risk_level": "low|medium|high",\n'
            '  "issues": ["..."],\n'
            '  "recommended_actions": ["..."],\n'
            '  "suggested_protocol_style": "text|binary|hybrid|unknown",\n'
            '  "style_confidence": 0.0-1.0\n'
            "}\n"
            "Do not invent packet facts. Keep issues/actions concise.\n"
            f"traffic_profile={json.dumps(payload, ensure_ascii=False)}"
        )
        review = self._kickoff_agent_json("preprocess_agent", prompt)
        if not review:
            return profile

        completeness_score = review.get("completeness_score", 0.0)
        try:
            completeness_score = self._clamp(float(completeness_score))
        except Exception:
            completeness_score = 0.0
        risk_level = str(review.get("risk_level", "unknown")).strip().lower()
        issues = review.get("issues", [])
        actions = review.get("recommended_actions", [])
        suggested_style = str(review.get("suggested_protocol_style", "")).strip().lower()
        style_confidence_raw = review.get("style_confidence", 0.0)
        try:
            style_confidence = self._clamp(float(style_confidence_raw))
        except Exception:
            style_confidence = 0.0

        if isinstance(issues, list) and issues:
            top_issue = "; ".join(str(item) for item in issues[:3])
            profile.notes.append(f"LLM 预处理审查问题: {top_issue}")
        if isinstance(actions, list) and actions:
            top_actions = "; ".join(str(item) for item in actions[:3])
            profile.notes.append(f"LLM 建议的后续提取动作: {top_actions}")
        if completeness_score < 0.45:
            self.state.warnings.append(
                f"LLM 评估预处理完整性较低：score={completeness_score:.2f}, risk={risk_level}"
            )

        # 仅在风格不明确时允许 LLM 提供软覆盖，保持可复现主路径。
        valid_styles = {"text", "binary", "hybrid", "unknown"}
        if (
            suggested_style in valid_styles
            and suggested_style != "unknown"
            and profile.protocol_style in {"unknown", "hybrid"}
            and style_confidence >= 0.82
        ):
            old_style = profile.protocol_style
            profile.protocol_style = suggested_style  # type: ignore[assignment]
            profile.notes.append(
                f"LLM 软覆盖协议风格: {old_style} -> {suggested_style} (confidence={style_confidence:.2f})"
            )

        self.state.llm_policy["preprocess_review"] = {
            "completeness_score": round(completeness_score, 3),
            "risk_level": risk_level,
            "issues": issues if isinstance(issues, list) else [],
            "recommended_actions": actions if isinstance(actions, list) else [],
            "suggested_protocol_style": suggested_style,
            "style_confidence": round(style_confidence, 3),
        }
        return profile

    def _refine_execution_plan_with_llm(self, profile: TrafficProfile, baseline: ExecutionPlan) -> ExecutionPlan:
        # 受控参与：LLM做二次决策，规则计划始终作为可回退基线。
        if not self._llm_stage_enabled("LLM_TOOL_SELECTION_ENABLE", default=True):
            return baseline
        if not baseline.selected_tools:
            return baseline

        baseline_payload = baseline.model_dump(mode="json")
        profile_payload = profile.model_dump(mode="json")
        # 控制上下文大小，避免在选择阶段塞入过多样本字节。
        if isinstance(profile_payload.get("sample_messages_hex"), list):
            profile_payload["sample_messages_hex"] = profile_payload["sample_messages_hex"][:12]

        prompt = (
            "You are a protocol reverse tool-selection policy layer.\n"
            "Return strict JSON only with keys:\n"
            "{\n"
            '  "apply": true|false,\n'
            '  "segmentation_primary": "netzob_adapter|nemesys_adapter",\n'
            '  "segmentation_backup": "netzob_adapter|nemesys_adapter",\n'
            '  "semantic_primary": "netplier_adapter|binaryinferno_adapter",\n'
            '  "semantic_backup": "netplier_adapter|binaryinferno_adapter",\n'
            '  "confidence_adjust": {"tool_name": -0.10..0.10},\n'
            '  "reasoning": ["..."]\n'
            "}\n"
            "Constraints: exactly one primary per stage and one backup per stage.\n"
            "Prefer reliability and explainability over aggressiveness.\n"
            f"traffic_profile={json.dumps(profile_payload, ensure_ascii=False)}\n"
            f"baseline_plan={json.dumps(baseline_payload, ensure_ascii=False)}"
        )
        decision = self._kickoff_agent_json("tool_selector_agent", prompt)
        if not decision:
            return baseline

        apply_flag = bool(decision.get("apply", True))
        seg_primary = str(decision.get("segmentation_primary", "")).strip()
        seg_backup = str(decision.get("segmentation_backup", "")).strip()
        sem_primary = str(decision.get("semantic_primary", "")).strip()
        sem_backup = str(decision.get("semantic_backup", "")).strip()
        reasoning = decision.get("reasoning", [])
        confidence_adjust = decision.get("confidence_adjust", {})

        seg_tools = {"netzob_adapter", "nemesys_adapter"}
        sem_tools = {"netplier_adapter", "binaryinferno_adapter"}
        if seg_primary not in seg_tools or sem_primary not in sem_tools:
            self.state.warnings.append("LLM 工具选择输出非法，已回退规则计划。")
            return baseline

        if seg_backup not in seg_tools or seg_backup == seg_primary:
            seg_backup = next(item for item in sorted(seg_tools) if item != seg_primary)
        if sem_backup not in sem_tools or sem_backup == sem_primary:
            sem_backup = next(item for item in sorted(sem_tools) if item != sem_primary)

        if not apply_flag:
            self.state.llm_policy["tool_selection_refine"] = {
                "applied": False,
                "reasoning": reasoning if isinstance(reasoning, list) else [],
            }
            return baseline

        decisions_by_tool: Dict[str, ToolDecision] = {
            item.tool_name: item.model_copy(deep=True) for item in baseline.decisions
        }

        def _ensure_decision(tool_name: str, default_reason: str) -> ToolDecision:
            cached = decisions_by_tool.get(tool_name)
            if cached:
                return cached
            created = ToolDecision(
                tool_name=tool_name,
                selected=False,
                mode="single",
                confidence=0.72,
                reason=default_reason,
            )
            decisions_by_tool[tool_name] = created
            return created

        _ensure_decision(seg_primary, "LLM policy selected segmentation primary")
        _ensure_decision(seg_backup, "LLM policy selected segmentation backup")
        _ensure_decision(sem_primary, "LLM policy selected semantic primary")
        _ensure_decision(sem_backup, "LLM policy selected semantic backup")

        for name, item in decisions_by_tool.items():
            if name in seg_tools:
                item.selected = name == seg_primary
                item.mode = "single"
            if name in sem_tools:
                item.selected = name == sem_primary
                item.mode = "single"

            if isinstance(confidence_adjust, dict) and name in confidence_adjust:
                try:
                    delta = float(confidence_adjust[name])
                    item.confidence = round(self._clamp(item.confidence + delta), 3)
                except Exception:
                    pass

        ordered_tools: List[str] = []
        for item in baseline.decisions:
            if item.tool_name in decisions_by_tool and item.tool_name not in ordered_tools:
                ordered_tools.append(item.tool_name)
        for item in [seg_primary, seg_backup, sem_primary, sem_backup]:
            if item not in ordered_tools:
                ordered_tools.append(item)

        refined_decisions = [decisions_by_tool[item] for item in ordered_tools]
        refined = ExecutionPlan(
            execution_mode="single",
            decisions=refined_decisions,
            selected_tools=[seg_primary, sem_primary],
            rationale=list(baseline.rationale),
            warnings=list(baseline.warnings),
        )
        if isinstance(reasoning, list) and reasoning:
            refined.rationale.append("LLM 二次裁决: " + " | ".join(str(item) for item in reasoning[:4]))
        else:
            refined.rationale.append("LLM 二次裁决已应用。")

        self.state.llm_policy["tool_selection_refine"] = {
            "applied": True,
            "segmentation_primary": seg_primary,
            "segmentation_backup": seg_backup,
            "semantic_primary": sem_primary,
            "semantic_backup": sem_backup,
            "reasoning": reasoning if isinstance(reasoning, list) else [],
            "confidence_adjust": confidence_adjust if isinstance(confidence_adjust, dict) else {},
        }
        return refined

    def _apply_llm_fusion_arbitration(self, schema: ProtocolSchema) -> ProtocolSchema:
        # 受控参与：仅对低置信度/冲突字段做语义仲裁，不触碰底层边界统计。
        if not self._llm_stage_enabled("LLM_FUSION_ARBITRATION_ENABLE", default=True):
            return schema
        if not schema.fields:
            return schema

        try:
            weak_threshold = float(os.getenv("LLM_FUSION_WEAK_FIELD_THRESHOLD", "0.72"))
        except ValueError:
            weak_threshold = 0.72
        weak_threshold = self._clamp(weak_threshold)

        focus_fields = [item for item in schema.fields if item.confidence <= weak_threshold]
        if not focus_fields and not schema.conflict_resolutions:
            return schema

        focus_payload = [
            {
                "message_cluster": item.message_cluster,
                "name": item.name,
                "start": item.start,
                "end": item.end,
                "semantic_type": item.semantic_type,
                "confidence": item.confidence,
                "evidences": [ev.model_dump(mode="json") for ev in item.evidences[:3]],
            }
            for item in focus_fields[:36]
        ]
        prompt = (
            "You are a schema fusion arbiter.\n"
            "For weak/conflicting fields, propose conservative semantic adjustments.\n"
            "Return strict JSON only:\n"
            "{\n"
            '  "adjustments": [\n'
            "    {\n"
            '      "message_cluster": "...",\n'
            '      "start": 0,\n'
            '      "end": 1,\n'
            '      "semantic_type": "type|length|timestamp|id|session_id|payload|checksum|unknown",\n'
            '      "confidence": 0.0-1.0,\n'
            '      "reason": "..."\n'
            "    }\n"
            "  ],\n"
            '  "notes": ["..."]\n'
            "}\n"
            "Do not create ranges not present in input. Keep suggestions conservative.\n"
            f"focus_fields={json.dumps(focus_payload, ensure_ascii=False)}\n"
            f"existing_conflicts={json.dumps(schema.conflict_resolutions[:20], ensure_ascii=False)}"
        )
        decision = self._kickoff_agent_json("fusion_agent", prompt)
        if not decision:
            return schema

        raw_adjustments = decision.get("adjustments", [])
        if not isinstance(raw_adjustments, list) or not raw_adjustments:
            return schema

        valid_semantics = {"type", "length", "timestamp", "id", "session_id", "payload", "checksum", "unknown"}
        field_index = {(item.message_cluster, item.start, item.end): item for item in schema.fields}
        applied = 0
        for raw in raw_adjustments[:40]:
            if not isinstance(raw, dict):
                continue
            try:
                cluster_id = str(raw.get("message_cluster", "")).strip()
                start = int(raw.get("start"))
                end = int(raw.get("end"))
                semantic_type = str(raw.get("semantic_type", "")).strip()
                confidence = self._clamp(float(raw.get("confidence", 0.0)))
                reason = str(raw.get("reason", "")).strip() or "LLM arbitration suggestion"
            except Exception:
                continue

            if semantic_type not in valid_semantics or end <= start:
                continue
            key = (cluster_id, start, end)
            field = field_index.get(key)
            if field is None:
                continue

            # 保守门控：避免 LLM 在低证据下大幅改写分数。
            min_accept = max(0.0, field.confidence - 0.08)
            if confidence < min_accept:
                continue

            changed = False
            if semantic_type != field.semantic_type:
                old_sem = field.semantic_type
                field.semantic_type = semantic_type
                if field.name.startswith("f") and "_" in field.name:
                    prefix = field.name.split("_", maxsplit=1)[0]
                    field.name = f"{prefix}_{semantic_type}"
                schema.conflict_resolutions.append(
                    f"{cluster_id} {start}:{end} LLM仲裁语义: {old_sem} -> {semantic_type}"
                )
                changed = True

            if abs(confidence - field.confidence) >= 0.01:
                field.confidence = round(confidence, 3)
                changed = True

            if changed:
                field.evidences.append(
                    EvidenceItem(
                        evidence_type="semantic",
                        source="llm_arbiter",
                        score=round(confidence, 3),
                        detail=reason,
                    )
                )
                applied += 1

        if applied > 0:
            schema.global_confidence = round(
                sum(item.confidence for item in schema.fields) / max(1, len(schema.fields)),
                3,
            )
            if "启用 LLM 仲裁可能引入一定输出波动。" not in schema.limitations:
                schema.limitations.append("启用 LLM 仲裁可能引入一定输出波动。")

        notes = decision.get("notes", [])
        self.state.llm_policy["fusion_arbitration"] = {
            "applied_count": applied,
            "weak_threshold": round(weak_threshold, 3),
            "notes": notes if isinstance(notes, list) else [],
        }
        return schema

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
            self.state.warnings.append(f"LLM 注释已跳过（{agent_name}）: {exc}")
    
    # 起点（用 @start + @listen 装饰器定义固定执行顺序，Flow 框架会自动按顺序运行）
    @start()
    def bootstrap(self) -> str:
        # 校验文件、创建输出目录、初始化日志、定义所有结果文件的保存路径。
        pcap_path = Path(self.state.pcap_path)
        if not pcap_path.exists():
            raise FileNotFoundError(f"未找到输入抓包文件: {pcap_path}")

        output_dir = ensure_dir(self.state.output_dir)
        self.logger = setup_logger(output_dir / "run.log")
        self.logger.info("Flow 初始化完成。输入=%s 输出=%s", pcap_path, output_dir)
        if self.state.use_llm and not self._llm_enabled():
            self.state.warnings.append(
                "已开启 --use-llm，但环境中未检测到受支持的 API Key。"
            )

        self.state.artifacts.traffic_profile_path = output_dir / "traffic_profile.json"
        self.state.artifacts.execution_plan_path = output_dir / "execution_plan.json"
        self.state.artifacts.segment_candidates_path = output_dir / "segment_candidates.json"
        self.state.artifacts.semantic_candidates_path = output_dir / "semantic_candidates.json"
        self.state.artifacts.final_schema_path = output_dir / "final_schema.json"
        self.state.artifacts.report_path = output_dir / "report.md"
        self.state.artifacts.llm_policy_path = output_dir / "llm_policy.json"
        return "bootstrap_ok"

    @listen(bootstrap)
    def run_preprocess(self, _signal: str) -> TrafficProfile:
        # 阶段1：流量预处理与统计特征提取（解析 pcap，提取流量特征，生成流量档案）。
        assert self.logger is not None
        self.logger.info("步骤：预处理（preprocess）")
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
            self.state.errors.append(f"预处理失败: {exc}")
            self.state.traffic_profile = TrafficProfile(input_file=self.state.pcap_path, errors=[str(exc)])
        self.state.traffic_profile = self._apply_llm_preprocess_review(self.state.traffic_profile)
        self._collect_llm_note(
            "preprocess_agent",
            f"请用中文在 120 字以内总结这个流量画像，并说明局限：{self.state.traffic_profile.model_dump_json()}",
        )
        return self.state.traffic_profile

    @listen(run_preprocess)
    def run_tool_selection(self, profile: TrafficProfile) -> ExecutionPlan:
        # 阶段2：根据流量特征选择主工具与备份工具。
        assert self.logger is not None
        self.logger.info("步骤：工具选择（tool_selection）")
        try:
            plan = self.selector_stage.run(profile=profile, output_dir=self.state.output_dir, logger=self.logger)
            self.state.execution_plan = plan
            for item in plan.warnings:
                self.state.warnings.append(f"tool_selection: {item}")
        except Exception as exc:
            self.state.errors.append(f"工具选择失败: {exc}")
            self.state.execution_plan = ExecutionPlan(
                execution_mode="single",
                selected_tools=["netzob_adapter"],
                rationale=["使用默认兜底计划"],
            )
        self.state.execution_plan = self._refine_execution_plan_with_llm(profile, self.state.execution_plan)
        self._collect_llm_note(
            "tool_selector_agent",
            f"Briefly justify this plan in Chinese: {self.state.execution_plan.model_dump_json()}",
        )
        return self.state.execution_plan

    @listen(run_tool_selection)
    def run_segmentation(self, plan: ExecutionPlan) -> list[FieldBoundaryCandidate]:
        # 阶段3：字段边界切分（单工具优先，必要时启用备份）。
        assert self.logger is not None
        self.logger.info("步骤：字段切分（segmentation）")

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
            self.state.errors.append(f"字段切分失败: {exc}")
            self.state.segment_candidates = []

        self._collect_llm_note(
            "segmentation_agent",
            f"请基于候选切分结果给出 3 个风险点和 3 个改进建议。当前候选数量：{len(self.state.segment_candidates)}。",
        )
        return self.state.segment_candidates

    @listen(run_segmentation)
    def run_semantic_inference(self, boundaries: list[FieldBoundaryCandidate]) -> list[FieldSemanticCandidate]:
        # 阶段4：字段语义推断，并对齐到分段边界。
        assert self.logger is not None
        self.logger.info("步骤：语义推断（semantic_inference）")

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
            self.state.errors.append(f"语义推断失败: {exc}")
            self.state.semantic_candidates = []

        self._collect_llm_note(
            "semantic_inference_agent",
            f"请解释这些语义候选中的不确定性来源，候选数量：{len(self.state.semantic_candidates)}。",
        )
        return self.state.semantic_candidates

    @listen(run_semantic_inference)
    def run_fusion(self, semantics: list[FieldSemanticCandidate]) -> ProtocolSchema:
        # 阶段5：融合边界与语义证据，得到最终协议模板。
        assert self.logger is not None
        self.logger.info("步骤：结果融合（fusion）")

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
            self.state.errors.append(f"融合失败: {exc}")
            self.state.final_schema = ProtocolSchema(input_file=self.state.pcap_path)
        self.state.final_schema = self._apply_llm_fusion_arbitration(self.state.final_schema)

        self._collect_llm_note(
            "fusion_agent",
            f"请审阅该 schema 的置信度，并指出最关键的 2 个薄弱点：{self.state.final_schema.model_dump_json()}",
        )
        return self.state.final_schema

    @listen(run_fusion)
    def run_report(self, schema: ProtocolSchema) -> AnalysisReport:
        # 阶段6：生成 markdown 报告，便于答辩展示与复盘。
        assert self.logger is not None
        self.logger.info("步骤：报告生成（report）")

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
            self.state.errors.append(f"报告生成失败: {exc}")
            self.state.report = AnalysisReport(title="失败", markdown=str(exc))

        self._collect_llm_note(
            "report_agent",
            "请写一段用于中期/毕业答辩的说明：本原型的创新点是什么？",
        )
        return self.state.report

    @listen(run_report)
    def finish(self, _report: AnalysisReport) -> Dict[str, Any]:
        # 返回运行摘要，包含产物路径、warning/error 与可选 LLM 注释。
        assert self.logger is not None
        self.logger.info("Flow 结束：warnings=%d, errors=%d", len(self.state.warnings), len(self.state.errors))
        if self.state.llm_policy and self.state.artifacts.llm_policy_path:
            write_json(self.state.artifacts.llm_policy_path, self.state.llm_policy)

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
                "llm_policy": str(self.state.artifacts.llm_policy_path),
                "log": str(Path(self.state.output_dir) / "run.log"),
            },
            "warnings": self.state.warnings,
            "errors": self.state.errors,
            "llm_notes": self.state.llm_notes,
            "llm_policy": self.state.llm_policy,
        }
        return summary
