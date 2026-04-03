from __future__ import annotations

from datetime import datetime
from pathlib import Path
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
        lines.append(f"| ... | ... | ... | ... | only first {max_rows} rows shown |")
    return "\n".join(lines)


def _format_semantic_table(candidates: List[FieldSemanticCandidate], max_rows: int = 24) -> str:
    lines = ["| cluster | field_range | semantic | confidence | source | reason |", "|---|---:|---|---:|---|---|"]
    for item in candidates[:max_rows]:
        lines.append(
            f"| {item.message_cluster} | {item.field_range} | {item.semantic_type} | {item.confidence:.3f} | {item.source_tool} | {item.reason} |"
        )
    if len(candidates) > max_rows:
        lines.append(f"| ... | ... | ... | ... | ... | only first {max_rows} rows shown |")
    return "\n".join(lines)


def _format_schema_table(schema: ProtocolSchema) -> str:
    lines = ["| cluster | field_name | range | semantic | confidence |", "|---|---|---:|---|---:|"]
    for field in schema.fields:
        lines.append(
            f"| {field.message_cluster} | {field.name} | {field.start}:{field.end} | {field.semantic_type} | {field.confidence:.3f} |"
        )
    return "\n".join(lines)


class ReportAgentStage:
    # 报告阶段：把各阶段中间结果整理成答辩友好的 Markdown 报告。
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
            f"- 协议线索: `{', '.join(profile.protocols_observed) if profile.protocols_observed else 'N/A'}`",
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
                    f"- `{decision.tool_name}` | selected={decision.selected} | "
                    f"confidence={decision.confidence:.3f} | reason={decision.reason}"
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
                "## 6. 冲突消解说明",
            ]
        )

        if schema.conflict_resolutions:
            for item in schema.conflict_resolutions:
                md_lines.append(f"- {item}")
        else:
            md_lines.append("- 未检测到高强度冲突，按最高加权分直接选择。")

        md_lines.extend(["", "## 7. 局限性分析"])
        if schema.limitations:
            for item in schema.limitations:
                md_lines.append(f"- {item}")
        else:
            md_lines.append("- 当前样本规模较小，后续需增加多会话样本进行稳定性验证。")

        if profile.notes:
            md_lines.extend(["", "## 8. 运行备注"])
            for note in profile.notes:
                md_lines.append(f"- {note}")

        if profile.errors:
            md_lines.extend(["", "## 9. 错误信息"])
            for err in profile.errors:
                md_lines.append(f"- {err}")

        markdown = "\n".join(md_lines) + "\n"
        report_path = Path(output_dir) / "report.md"
        write_text(report_path, markdown)
        logger.info("Report generated -> %s", report_path)

        return AnalysisReport(
            title="Unknown Protocol Reverse Report",
            markdown=markdown,
            output_path=str(report_path),
        )
