from __future__ import annotations

from datetime import datetime
from pathlib import Path
from collections import Counter
from typing import List

from testcrewai.models import (
    AnalysisReport,
    ExecutionPlan,
    FieldBoundaryCandidate,
    FieldSemanticCandidate,
    ProtocolSchema,
    TrafficProfile,
)
from testcrewai.utils.io import write_text


def _format_boundary_table(candidates: List[FieldBoundaryCandidate], max_rows: int = 20) -> str:
    lines = ["| cluster | range(start:end) | confidence | source | reason |", "|---|---:|---:|---|---|"]
    for item in candidates[:max_rows]:
        lines.append(
            f"| {item.message_cluster} | {item.start}:{item.end} | {item.confidence:.3f} | {item.source_tool} | {item.reason} |"
        )
    if len(candidates) > max_rows:
        lines.append(f"| ... | ... | ... | ... | 仅展示前 {max_rows} 行 |")
    return "\n".join(lines)


def _format_semantic_table(candidates: List[FieldSemanticCandidate], max_rows: int = 24) -> str:
    lines = ["| cluster | field_range | semantic | confidence | source | reason |", "|---|---:|---|---:|---|---|"]
    for item in candidates[:max_rows]:
        lines.append(
            f"| {item.message_cluster} | {item.field_range} | {item.semantic_type} | {item.confidence:.3f} | {item.source_tool} | {item.reason} |"
        )
    if len(candidates) > max_rows:
        lines.append(f"| ... | ... | ... | ... | ... | 仅展示前 {max_rows} 行 |")
    return "\n".join(lines)


def _format_schema_table(schema: ProtocolSchema) -> str:
    lines = ["| cluster | field_name | range | semantic | confidence |", "|---|---|---:|---|---:|"]
    for field in schema.fields:
        lines.append(
            f"| {field.message_cluster} | {field.name} | {field.start}:{field.end} | {field.semantic_type} | {field.confidence:.3f} |"
        )
    return "\n".join(lines)


def _result_quality_summary(
    profile: TrafficProfile,
    boundaries: List[FieldBoundaryCandidate],
    semantics: List[FieldSemanticCandidate],
    schema: ProtocolSchema,
) -> tuple[str, List[str]]:
    field_count = len(schema.fields)
    semantic_field_count = max(1, field_count)
    non_unknown = sum(1 for field in schema.fields if field.semantic_type != "unknown")
    semantic_coverage = non_unknown / semantic_field_count

    type_counter = Counter(field.semantic_type for field in schema.fields)
    dominant_ratio = 1.0
    if type_counter and field_count > 0:
        dominant_ratio = type_counter.most_common(1)[0][1] / field_count

    cluster_count = max(1, len(schema.message_clusters))
    avg_fields_per_cluster = field_count / cluster_count
    protocol_count = len({item for item in profile.protocols_observed if item not in {"tcp", "udp", "other"}})

    sample_score = min(1.0, profile.packet_count / 50.0)
    diversity_score = max(0.0, 1.0 - dominant_ratio)
    score = (
        schema.global_confidence * 0.45
        + semantic_coverage * 0.25
        + sample_score * 0.15
        + diversity_score * 0.15
    )

    reasons = [
        f"字段数量: {field_count}",
        f"语义覆盖率: {semantic_coverage:.2%}",
        f"主导语义占比: {dominant_ratio:.2%}",
        f"平均每簇字段数: {avg_fields_per_cluster:.2f}",
        f"全局置信度: {schema.global_confidence:.3f}",
    ]

    if protocol_count >= 3:
        score -= 0.12
        reasons.append("协议线索较杂，可能影响结构归纳稳定性")
    if avg_fields_per_cluster >= 24:
        score -= 0.08
        reasons.append("平均字段数偏多，存在过度切分风险")
    if dominant_ratio >= 0.85 and field_count >= 5:
        score -= 0.10
        reasons.append("语义类型过于集中，说明语义解释偏粗")
    if not boundaries or not semantics:
        score -= 0.20
        reasons.append("缺少边界或语义候选，中间证据不足")

    if score >= 0.68:
        level = "高"
    elif score >= 0.52:
        level = "中"
    else:
        level = "低"
    reasons.append(f"综合质量得分: {max(0.0, min(1.0, score)):.3f}")
    return level, reasons


class ReportAgentStage:
    # 报告阶段：把各阶段中间结果整理成答辩友好的文档报告。
    def run(
        self,
        profile: TrafficProfile,
        execution_plan: ExecutionPlan,
        boundaries: List[FieldBoundaryCandidate],
        semantics: List[FieldSemanticCandidate],
        schema: ProtocolSchema,
        output_dir: str,
        logger,
    ) -> AnalysisReport:
        # 报告只汇总结构化产物，不重新推理，确保与结构化结果一致。
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        md_lines = [
            "# 未知网络协议结构逆向推断报告",
            "",
            f"- 生成时间: {now}",
            f"- 输入文件: `{profile.input_file}`",
            "",
            "## 1. 输入与流量概况",
            f"- 抓包格式: `{profile.capture_format}`",
            f"- 样本消息数: `{profile.packet_count}`",
            f"- 会话数: `{profile.session_count}`",
            f"- 平均消息长度: `{profile.avg_packet_length}`",
            f"- 长度范围: `{profile.min_packet_length} ~ {profile.max_packet_length}`",
            f"- 平均熵: `{profile.mean_entropy}`",
            f"- 可打印字符比例: `{profile.mean_printable_ratio}`",
            f"- 协议风格判定: `{profile.protocol_style}`",
            f"- 协议线索: `{', '.join(profile.protocols_observed) if profile.protocols_observed else '无'}`",
            "",
            "## 2. 工具选择策略",
            f"- 执行模式: `{execution_plan.execution_mode}`",
            f"- 选中工具: `{', '.join(execution_plan.selected_tools)}`",
            "",
            "### 2.1 决策明细",
        ]

        for decision in execution_plan.decisions:
            md_lines.append(
                (
                    f"- `{decision.tool_name}` | selected(是否选中)={decision.selected} | "
                    f"confidence(置信度)={decision.confidence:.3f} | reason(原因)={decision.reason}"
                )
            )

        if execution_plan.rationale:
            md_lines.append("")
            md_lines.append("### 2.2 选择理由")
            for item in execution_plan.rationale:
                md_lines.append(f"- {item}")

        md_lines.extend(
            [
                "",
                "## 3. 字段切分候选",
                _format_boundary_table(boundaries),
                "",
                "## 4. 字段语义候选",
                _format_semantic_table(semantics),
                "",
                "## 5. 融合后协议结构模板",
                f"- 全局置信度: `{schema.global_confidence}`",
                _format_schema_table(schema),
                "",
                "## 6. 结果质量评估",
            ]
        )

        quality_level, quality_reasons = _result_quality_summary(profile, boundaries, semantics, schema)
        md_lines.append(f"- 质量等级: `{quality_level}`")
        for item in quality_reasons:
            md_lines.append(f"- {item}")

        md_lines.extend(["", "## 7. 冲突消解说明"])

        if schema.conflict_resolutions:
            for item in schema.conflict_resolutions:
                md_lines.append(f"- {item}")
        else:
            md_lines.append("- 未检测到高强度冲突，按最高加权分直接选择。")

        md_lines.extend(["", "## 8. 局限性分析"])
        if schema.limitations:
            for item in schema.limitations:
                md_lines.append(f"- {item}")
        else:
            md_lines.append("- 当前样本规模较小，后续需增加多会话样本进行稳定性验证。")

        if profile.notes:
            md_lines.extend(["", "## 9. 运行备注"])
            for note in profile.notes:
                md_lines.append(f"- {note}")

        if profile.errors:
            md_lines.extend(["", "## 10. 错误信息"])
            for err in profile.errors:
                md_lines.append(f"- {err}")

        markdown = "\n".join(md_lines) + "\n"
        report_path = Path(output_dir) / "report.md"
        write_text(report_path, markdown)
        logger.info("报告已生成 -> %s", report_path)

        return AnalysisReport(
            title="未知协议逆向分析报告",
            markdown=markdown,
            output_path=str(report_path),
        )
