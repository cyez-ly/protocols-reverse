from __future__ import annotations

import os
import tempfile
import unittest

from testcrewai.models import (
    FieldBoundaryCandidate,
    FieldSemanticCandidate,
    MessageCluster,
    TrafficProfile,
)
from testcrewai.pipeline.fusion import FusionAgentStage
from testcrewai.utils.logging import setup_logger


class FusionStageTestCase(unittest.TestCase):
    def test_fusion_generates_schema(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = setup_logger(f"{tmpdir}/run.log", logger_name="fusion_test")
            profile = TrafficProfile(
                input_file="dummy.pcap",
                message_clusters=[
                    MessageCluster(
                        cluster_id="cluster_1",
                        sample_count=5,
                        mean_length=16.0,
                        representative_lengths=[16],
                    )
                ],
            )
            boundaries = [
                FieldBoundaryCandidate(
                    message_cluster="cluster_1",
                    start=0,
                    end=2,
                    confidence=0.8,
                    source_tool="netzob_adapter",
                    reason="header",
                ),
                FieldBoundaryCandidate(
                    message_cluster="cluster_1",
                    start=2,
                    end=4,
                    confidence=0.75,
                    source_tool="netzob_adapter",
                    reason="length",
                ),
            ]
            semantics = [
                FieldSemanticCandidate(
                    message_cluster="cluster_1",
                    field_range="0:2",
                    semantic_type="type",
                    confidence=0.8,
                    source_tool="netplier_adapter",
                    reason="low cardinality",
                ),
                FieldSemanticCandidate(
                    message_cluster="cluster_1",
                    field_range="2:4",
                    semantic_type="length",
                    confidence=0.82,
                    source_tool="netplier_adapter",
                    reason="matches packet length",
                ),
            ]

            schema = FusionAgentStage().run(
                profile=profile,
                boundaries=boundaries,
                semantics=semantics,
                output_dir=tmpdir,
                logger=logger,
            )

            self.assertGreaterEqual(len(schema.fields), 2)
            semantic_types = {field.semantic_type for field in schema.fields}
            self.assertIn("type", semantic_types)
            self.assertIn("length", semantic_types)

    def test_fusion_prefers_non_unknown_when_scores_close(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = setup_logger(f"{tmpdir}/run.log", logger_name="fusion_tie_break_test")
            profile = TrafficProfile(
                input_file="dummy.pcap",
                message_clusters=[
                    MessageCluster(
                        cluster_id="cluster_1",
                        sample_count=4,
                        mean_length=12.0,
                        representative_lengths=[12],
                    )
                ],
            )
            boundaries = [
                FieldBoundaryCandidate(
                    message_cluster="cluster_1",
                    start=0,
                    end=4,
                    confidence=0.8,
                    source_tool="netzob_adapter",
                    reason="header",
                )
            ]
            semantics = [
                FieldSemanticCandidate(
                    message_cluster="cluster_1",
                    field_range="0:4",
                    semantic_type="unknown",
                    confidence=0.52,
                    source_tool="netplier_adapter",
                    reason="primary ambiguous",
                ),
                FieldSemanticCandidate(
                    message_cluster="cluster_1",
                    field_range="0:4",
                    semantic_type="checksum",
                    confidence=0.5,
                    source_tool="binaryinferno_adapter",
                    reason="backup checksum cue",
                ),
            ]

            old_penalty = os.environ.get("FUSION_UNKNOWN_PENALTY")
            old_ratio = os.environ.get("FUSION_PREFER_NON_UNKNOWN_RATIO")
            os.environ["FUSION_UNKNOWN_PENALTY"] = "0.85"
            os.environ["FUSION_PREFER_NON_UNKNOWN_RATIO"] = "0.92"
            try:
                schema = FusionAgentStage().run(
                    profile=profile,
                    boundaries=boundaries,
                    semantics=semantics,
                    output_dir=tmpdir,
                    logger=logger,
                )
            finally:
                if old_penalty is None:
                    os.environ.pop("FUSION_UNKNOWN_PENALTY", None)
                else:
                    os.environ["FUSION_UNKNOWN_PENALTY"] = old_penalty
                if old_ratio is None:
                    os.environ.pop("FUSION_PREFER_NON_UNKNOWN_RATIO", None)
                else:
                    os.environ["FUSION_PREFER_NON_UNKNOWN_RATIO"] = old_ratio

            self.assertEqual(len(schema.fields), 1)
            self.assertEqual(schema.fields[0].semantic_type, "checksum")

    def test_fusion_breaks_type_collapse_for_large_tail_field(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = setup_logger(f"{tmpdir}/run.log", logger_name="fusion_type_collapse_test")
            profile = TrafficProfile(
                input_file="dummy.pcap",
                message_clusters=[
                    MessageCluster(
                        cluster_id="cluster_1",
                        sample_count=20,
                        mean_length=48.0,
                        representative_lengths=[48],
                    )
                ],
            )
            boundaries = [
                FieldBoundaryCandidate(
                    message_cluster="cluster_1",
                    start=0,
                    end=4,
                    confidence=0.86,
                    source_tool="nemesys_adapter",
                    reason="header",
                ),
                FieldBoundaryCandidate(
                    message_cluster="cluster_1",
                    start=4,
                    end=16,
                    confidence=0.82,
                    source_tool="nemesys_adapter",
                    reason="middle",
                ),
                FieldBoundaryCandidate(
                    message_cluster="cluster_1",
                    start=16,
                    end=48,
                    confidence=0.88,
                    source_tool="nemesys_adapter",
                    reason="tail",
                ),
            ]
            semantics = [
                FieldSemanticCandidate(
                    message_cluster="cluster_1",
                    field_range="0:4",
                    semantic_type="type",
                    confidence=0.95,
                    source_tool="netplier_adapter",
                    reason="netplier type",
                ),
                FieldSemanticCandidate(
                    message_cluster="cluster_1",
                    field_range="4:16",
                    semantic_type="type",
                    confidence=0.95,
                    source_tool="netplier_adapter",
                    reason="netplier type",
                ),
                FieldSemanticCandidate(
                    message_cluster="cluster_1",
                    field_range="16:48",
                    semantic_type="type",
                    confidence=0.95,
                    source_tool="netplier_adapter",
                    reason="netplier type",
                ),
                FieldSemanticCandidate(
                    message_cluster="cluster_1",
                    field_range="0:4",
                    semantic_type="id",
                    confidence=0.5,
                    source_tool="binaryinferno_adapter",
                    reason="inferno id",
                ),
                FieldSemanticCandidate(
                    message_cluster="cluster_1",
                    field_range="4:16",
                    semantic_type="id",
                    confidence=0.5,
                    source_tool="binaryinferno_adapter",
                    reason="inferno id",
                ),
                FieldSemanticCandidate(
                    message_cluster="cluster_1",
                    field_range="16:48",
                    semantic_type="payload",
                    confidence=0.62,
                    source_tool="binaryinferno_adapter",
                    reason="inferno payload",
                ),
            ]

            old_env = {
                "FUSION_SEMANTIC_COLLAPSE_RATIO": os.environ.get("FUSION_SEMANTIC_COLLAPSE_RATIO"),
                "FUSION_SEMANTIC_COLLAPSE_PENALTY": os.environ.get("FUSION_SEMANTIC_COLLAPSE_PENALTY"),
                "FUSION_SEMANTIC_COLLAPSE_MIN_COUNT": os.environ.get("FUSION_SEMANTIC_COLLAPSE_MIN_COUNT"),
                "FUSION_COLLAPSE_TYPES": os.environ.get("FUSION_COLLAPSE_TYPES"),
                "FUSION_LARGE_FIELD_TYPE_PENALTY": os.environ.get("FUSION_LARGE_FIELD_TYPE_PENALTY"),
                "FUSION_PAYLOAD_TAIL_BOOST": os.environ.get("FUSION_PAYLOAD_TAIL_BOOST"),
            }
            os.environ["FUSION_SEMANTIC_COLLAPSE_RATIO"] = "0.85"
            os.environ["FUSION_SEMANTIC_COLLAPSE_PENALTY"] = "0.82"
            os.environ["FUSION_SEMANTIC_COLLAPSE_MIN_COUNT"] = "3"
            os.environ["FUSION_COLLAPSE_TYPES"] = "type,id,unknown"
            os.environ["FUSION_LARGE_FIELD_TYPE_PENALTY"] = "0.78"
            os.environ["FUSION_PAYLOAD_TAIL_BOOST"] = "1.20"
            try:
                schema = FusionAgentStage().run(
                    profile=profile,
                    boundaries=boundaries,
                    semantics=semantics,
                    output_dir=tmpdir,
                    logger=logger,
                )
            finally:
                for key, value in old_env.items():
                    if value is None:
                        os.environ.pop(key, None)
                    else:
                        os.environ[key] = value

            tail = next(field for field in schema.fields if field.start == 16 and field.end == 48)
            self.assertEqual(tail.semantic_type, "payload")


if __name__ == "__main__":
    unittest.main()
