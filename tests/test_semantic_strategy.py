from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from testcrewai.models import (
    ExecutionPlan,
    FieldBoundaryCandidate,
    ToolDecision,
    ToolRunResult,
)
from testcrewai.pipeline.semantics import SemanticInferenceAgentStage
from testcrewai.utils.logging import setup_logger


class _FakeAdapter:
    def __init__(self, tool_name: str, candidates: list[dict]) -> None:
        self.tool_name = tool_name
        self._candidates = candidates

    def run(self, input_path: str, output_dir: str, extra_args=None) -> ToolRunResult:  # type: ignore[override]
        return ToolRunResult(
            tool_name=self.tool_name,
            success=True,
            input_path=input_path,
            output_path=str(Path(output_dir) / f"{self.tool_name}.json"),
            data={
                "tool_name": self.tool_name,
                "success": True,
                "candidates": self._candidates,
                "python_bin": "python3",
            },
        )


class SemanticStrategyTestCase(unittest.TestCase):
    def test_backup_triggered_on_dominant_semantic_type(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = setup_logger(f"{tmpdir}/run.log", logger_name="semantic_strategy_test")
            boundaries = [
                FieldBoundaryCandidate(
                    message_cluster="cluster_1",
                    start=0,
                    end=2,
                    confidence=0.8,
                    source_tool="test",
                    reason="",
                )
                for _ in range(6)
            ]

            primary = [
                {
                    "message_cluster": "cluster_1",
                    "field_range": f"{idx}:{idx+1}",
                    "semantic_type": "id",
                    "confidence": 0.6,
                    "source_tool": "netplier_adapter",
                    "reason": "test-primary",
                }
                for idx in range(6)
            ]
            backup = [
                {
                    "message_cluster": "cluster_1",
                    "field_range": f"{idx}:{idx+1}",
                    "semantic_type": "payload",
                    "confidence": 0.62,
                    "source_tool": "binaryinferno_adapter",
                    "reason": "test-backup",
                }
                for idx in range(6)
            ]

            stage = SemanticInferenceAgentStage(
                netplier_adapter=_FakeAdapter("netplier_adapter", primary),  # type: ignore[arg-type]
                binaryinferno_adapter=_FakeAdapter("binaryinferno_adapter", backup),  # type: ignore[arg-type]
            )
            plan = ExecutionPlan(
                execution_mode="single",
                decisions=[
                    ToolDecision(
                        tool_name="netplier_adapter",
                        selected=True,
                        mode="single",
                        confidence=0.8,
                        reason="primary",
                    ),
                    ToolDecision(
                        tool_name="binaryinferno_adapter",
                        selected=False,
                        mode="single",
                        confidence=0.72,
                        reason="backup",
                    ),
                ],
                selected_tools=["netplier_adapter"],
            )

            segment_path = Path(tmpdir) / "segment_candidates.json"
            profile_path = Path(tmpdir) / "traffic_profile.json"
            segment_path.write_text(json.dumps({"candidates": []}), encoding="utf-8")
            profile_path.write_text(json.dumps({"sample_messages_hex": []}), encoding="utf-8")

            results = stage.run(
                execution_plan=plan,
                segment_candidates_path=str(segment_path),
                traffic_profile_path=str(profile_path),
                boundaries=boundaries,
                output_dir=tmpdir,
                timeout_sec=30,
                python_bin="python3",
                netplier_python_bin="python3",
                binaryinferno_python_bin="python3",
                logger=logger,
            )

            self.assertEqual(len(results), 12)
            payload = json.loads((Path(tmpdir) / "semantic_candidates.json").read_text(encoding="utf-8"))
            self.assertTrue(any("backup tool triggered" in item.lower() for item in payload.get("tool_errors", [])))

    def test_semantic_candidates_are_aligned_to_boundary_ranges(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = setup_logger(f"{tmpdir}/run.log", logger_name="semantic_alignment_test")
            boundaries = [
                FieldBoundaryCandidate(
                    message_cluster="cluster_1",
                    start=0,
                    end=2,
                    confidence=0.8,
                    source_tool="test",
                    reason="",
                ),
                FieldBoundaryCandidate(
                    message_cluster="cluster_1",
                    start=2,
                    end=6,
                    confidence=0.8,
                    source_tool="test",
                    reason="",
                ),
            ]

            primary = [
                {
                    "message_cluster": "cluster_1",
                    "field_range": "1:5",
                    "semantic_type": "id",
                    "confidence": 0.7,
                    "source_tool": "netplier_adapter",
                    "reason": "mismatch range",
                }
            ]

            stage = SemanticInferenceAgentStage(
                netplier_adapter=_FakeAdapter("netplier_adapter", primary),  # type: ignore[arg-type]
                binaryinferno_adapter=_FakeAdapter("binaryinferno_adapter", []),  # type: ignore[arg-type]
            )
            plan = ExecutionPlan(
                execution_mode="single",
                decisions=[
                    ToolDecision(
                        tool_name="netplier_adapter",
                        selected=True,
                        mode="single",
                        confidence=0.8,
                        reason="primary",
                    )
                ],
                selected_tools=["netplier_adapter"],
            )

            segment_path = Path(tmpdir) / "segment_candidates.json"
            profile_path = Path(tmpdir) / "traffic_profile.json"
            segment_path.write_text(json.dumps({"candidates": []}), encoding="utf-8")
            profile_path.write_text(json.dumps({"sample_messages_hex": []}), encoding="utf-8")

            results = stage.run(
                execution_plan=plan,
                segment_candidates_path=str(segment_path),
                traffic_profile_path=str(profile_path),
                boundaries=boundaries,
                output_dir=tmpdir,
                timeout_sec=30,
                python_bin="python3",
                netplier_python_bin="python3",
                binaryinferno_python_bin="python3",
                logger=logger,
            )

            self.assertEqual(len(results), 1)
            self.assertEqual(results[0].field_range, "2:6")
            self.assertIn("aligned_to_boundary", results[0].reason)


if __name__ == "__main__":
    unittest.main()
