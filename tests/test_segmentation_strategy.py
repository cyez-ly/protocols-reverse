from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from testcrewai.models import (
    ExecutionPlan,
    MessageCluster,
    ToolDecision,
    ToolRunResult,
    TrafficProfile,
)
from testcrewai.pipeline.segmentation import SegmentationAgentStage
from testcrewai.utils.logging import setup_logger


class _FakeSegTool:
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
                "nemesys_home": "/tmp/nemesys",
            },
        )


class SegmentationStrategyTestCase(unittest.TestCase):
    def test_backup_triggered_on_coarse_primary_segmentation(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = setup_logger(f"{tmpdir}/run.log", logger_name="segmentation_strategy_test")
            profile = TrafficProfile(
                input_file="dummy.pcap",
                capture_format="pcap",
                packet_count=4,
                protocol_style="binary",
                message_clusters=[
                    MessageCluster(
                        cluster_id="cluster_1",
                        sample_count=4,
                        mean_length=100.0,
                        representative_lengths=[100],
                    )
                ],
            )
            primary = [
                {
                    "message_cluster": "cluster_1",
                    "start": 0,
                    "end": 100,
                    "confidence": 0.7,
                    "source_tool": "netzob_adapter",
                    "reason": "coarse",
                }
            ]
            backup = [
                {
                    "message_cluster": "cluster_1",
                    "start": 0,
                    "end": 10,
                    "confidence": 0.8,
                    "source_tool": "nemesys_adapter",
                    "reason": "refined",
                },
                {
                    "message_cluster": "cluster_1",
                    "start": 10,
                    "end": 100,
                    "confidence": 0.8,
                    "source_tool": "nemesys_adapter",
                    "reason": "refined",
                },
            ]
            stage = SegmentationAgentStage(
                netzob_tool=_FakeSegTool("netzob_adapter", primary),  # type: ignore[arg-type]
                nemesys_tool=_FakeSegTool("nemesys_adapter", backup),  # type: ignore[arg-type]
            )
            plan = ExecutionPlan(
                execution_mode="single",
                decisions=[
                    ToolDecision(
                        tool_name="netzob_adapter",
                        selected=True,
                        mode="single",
                        confidence=0.8,
                        reason="primary",
                    ),
                    ToolDecision(
                        tool_name="nemesys_adapter",
                        selected=False,
                        mode="single",
                        confidence=0.72,
                        reason="backup",
                    ),
                ],
                selected_tools=["netzob_adapter"],
            )

            traffic_profile_path = Path(tmpdir) / "traffic_profile.json"
            traffic_profile_path.write_text(json.dumps({"dummy": True}), encoding="utf-8")

            results = stage.run(
                profile=profile,
                execution_plan=plan,
                traffic_profile_path=str(traffic_profile_path),
                output_dir=tmpdir,
                timeout_sec=30,
                python_bin="python3",
                netzob_python_bin="python3",
                nemesys_python_bin="python3",
                logger=logger,
            )

            # Backup output replaces coarse primary output when quality gate is triggered.
            self.assertEqual(len(results), 2)
            self.assertTrue(all(item.source_tool == "nemesys_adapter" for item in results))
            payload = json.loads((Path(tmpdir) / "segment_candidates.json").read_text(encoding="utf-8"))
            self.assertTrue(any("backup tool triggered" in item.lower() for item in payload.get("tool_errors", [])))
            self.assertEqual(payload.get("runtime_info", {}).get("segmentation_quality_triggered"), "true")

    def test_backup_triggered_on_high_one_byte_ratio(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = setup_logger(f"{tmpdir}/run.log", logger_name="segmentation_strategy_onebyte_test")
            profile = TrafficProfile(
                input_file="dummy_text.pcap",
                capture_format="pcap",
                packet_count=5,
                protocol_style="text",
                message_clusters=[
                    MessageCluster(
                        cluster_id="cluster_1",
                        sample_count=5,
                        mean_length=20.0,
                        representative_lengths=[20],
                    )
                ],
            )
            primary = [
                {
                    "message_cluster": "cluster_1",
                    "start": idx,
                    "end": idx + 1,
                    "confidence": 0.7,
                    "source_tool": "netzob_adapter",
                    "reason": "micro-fragment",
                }
                for idx in range(0, 12)
            ]
            backup = [
                {
                    "message_cluster": "cluster_1",
                    "start": 0,
                    "end": 4,
                    "confidence": 0.82,
                    "source_tool": "nemesys_adapter",
                    "reason": "stable",
                },
                {
                    "message_cluster": "cluster_1",
                    "start": 4,
                    "end": 20,
                    "confidence": 0.82,
                    "source_tool": "nemesys_adapter",
                    "reason": "stable",
                },
            ]

            stage = SegmentationAgentStage(
                netzob_tool=_FakeSegTool("netzob_adapter", primary),  # type: ignore[arg-type]
                nemesys_tool=_FakeSegTool("nemesys_adapter", backup),  # type: ignore[arg-type]
            )
            plan = ExecutionPlan(
                execution_mode="single",
                decisions=[
                    ToolDecision(
                        tool_name="netzob_adapter",
                        selected=True,
                        mode="single",
                        confidence=0.8,
                        reason="primary",
                    ),
                    ToolDecision(
                        tool_name="nemesys_adapter",
                        selected=False,
                        mode="single",
                        confidence=0.72,
                        reason="backup",
                    ),
                ],
                selected_tools=["netzob_adapter"],
            )

            traffic_profile_path = Path(tmpdir) / "traffic_profile.json"
            traffic_profile_path.write_text(json.dumps({"dummy": True}), encoding="utf-8")

            results = stage.run(
                profile=profile,
                execution_plan=plan,
                traffic_profile_path=str(traffic_profile_path),
                output_dir=tmpdir,
                timeout_sec=30,
                python_bin="python3",
                netzob_python_bin="python3",
                nemesys_python_bin="python3",
                logger=logger,
            )

            self.assertEqual(len(results), 2)
            self.assertTrue(all(item.source_tool == "nemesys_adapter" for item in results))
            payload = json.loads((Path(tmpdir) / "segment_candidates.json").read_text(encoding="utf-8"))
            reason = payload.get("runtime_info", {}).get("segmentation_quality_reason", "")
            self.assertIn("one_byte_ratio", reason)

    def test_backup_triggered_on_low_boundary_stability_ratio_hint(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = setup_logger(f"{tmpdir}/run.log", logger_name="segmentation_strategy_stability_test")
            profile = TrafficProfile(
                input_file="dummy_binary.pcap",
                capture_format="pcap",
                packet_count=8,
                protocol_style="binary",
                message_clusters=[
                    MessageCluster(
                        cluster_id="cluster_1",
                        sample_count=8,
                        mean_length=20.0,
                        representative_lengths=[20],
                    )
                ],
            )
            primary = [
                {
                    "message_cluster": "cluster_1",
                    "start": 0,
                    "end": 5,
                    "confidence": 0.75,
                    "source_tool": "netzob_adapter",
                    "reason": "NEMESYS consensus support~0.10, cluster_messages=8",
                },
                {
                    "message_cluster": "cluster_1",
                    "start": 5,
                    "end": 10,
                    "confidence": 0.75,
                    "source_tool": "netzob_adapter",
                    "reason": "NEMESYS consensus support~0.10, cluster_messages=8",
                },
                {
                    "message_cluster": "cluster_1",
                    "start": 10,
                    "end": 15,
                    "confidence": 0.75,
                    "source_tool": "netzob_adapter",
                    "reason": "NEMESYS consensus support~0.10, cluster_messages=8",
                },
                {
                    "message_cluster": "cluster_1",
                    "start": 15,
                    "end": 20,
                    "confidence": 0.75,
                    "source_tool": "netzob_adapter",
                    "reason": "NEMESYS consensus support~0.10, cluster_messages=8",
                },
            ]
            backup = [
                {
                    "message_cluster": "cluster_1",
                    "start": 0,
                    "end": 10,
                    "confidence": 0.82,
                    "source_tool": "nemesys_adapter",
                    "reason": "stable",
                },
                {
                    "message_cluster": "cluster_1",
                    "start": 10,
                    "end": 20,
                    "confidence": 0.82,
                    "source_tool": "nemesys_adapter",
                    "reason": "stable",
                },
            ]

            stage = SegmentationAgentStage(
                netzob_tool=_FakeSegTool("netzob_adapter", primary),  # type: ignore[arg-type]
                nemesys_tool=_FakeSegTool("nemesys_adapter", backup),  # type: ignore[arg-type]
            )
            plan = ExecutionPlan(
                execution_mode="single",
                decisions=[
                    ToolDecision(
                        tool_name="netzob_adapter",
                        selected=True,
                        mode="single",
                        confidence=0.8,
                        reason="primary",
                    ),
                    ToolDecision(
                        tool_name="nemesys_adapter",
                        selected=False,
                        mode="single",
                        confidence=0.72,
                        reason="backup",
                    ),
                ],
                selected_tools=["netzob_adapter"],
            )

            traffic_profile_path = Path(tmpdir) / "traffic_profile.json"
            traffic_profile_path.write_text(json.dumps({"dummy": True}), encoding="utf-8")

            results = stage.run(
                profile=profile,
                execution_plan=plan,
                traffic_profile_path=str(traffic_profile_path),
                output_dir=tmpdir,
                timeout_sec=30,
                python_bin="python3",
                netzob_python_bin="python3",
                nemesys_python_bin="python3",
                logger=logger,
            )

            self.assertEqual(len(results), 2)
            self.assertTrue(all(item.source_tool == "nemesys_adapter" for item in results))
            payload = json.loads((Path(tmpdir) / "segment_candidates.json").read_text(encoding="utf-8"))
            reason = payload.get("runtime_info", {}).get("segmentation_quality_reason", "")
            self.assertIn("boundary_stability", reason)


if __name__ == "__main__":
    unittest.main()
