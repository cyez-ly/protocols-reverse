from __future__ import annotations

import tempfile
import unittest

from testcrewai.models import MessageCluster, TrafficProfile
from testcrewai.pipeline.tool_selection import ToolSelectorAgentStage
from testcrewai.utils.logging import setup_logger


class ToolSelectionStageTestCase(unittest.TestCase):
    def test_binary_profile_selects_single_primary_tools(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = setup_logger(f"{tmpdir}/run.log", logger_name="tool_selection_test")
            profile = TrafficProfile(
                input_file="dummy.pcap",
                protocol_style="binary",
                message_clusters=[MessageCluster(cluster_id="cluster_1", sample_count=3, mean_length=12.0)],
            )
            stage = ToolSelectorAgentStage()
            plan = stage.run(profile=profile, output_dir=tmpdir, logger=logger)

            self.assertEqual(plan.execution_mode, "single")
            self.assertEqual(len(plan.selected_tools), 2)
            self.assertIn("nemesys_adapter", plan.selected_tools)
            self.assertIn("binaryinferno_adapter", plan.selected_tools)

            decisions = {item.tool_name: item.selected for item in plan.decisions}
            self.assertTrue(decisions["nemesys_adapter"])
            self.assertFalse(decisions["netzob_adapter"])
            self.assertTrue(decisions["binaryinferno_adapter"])
            self.assertFalse(decisions["netplier_adapter"])

    def test_dhcp_hybrid_prefers_binaryinferno_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = setup_logger(f"{tmpdir}/run.log", logger_name="tool_selection_dhcp_test")
            profile = TrafficProfile(
                input_file="dhcp_sample.pcap",
                protocol_style="hybrid",
                protocols_observed=["udp", "dhcp"],
                message_clusters=[MessageCluster(cluster_id="cluster_1", sample_count=6, mean_length=48.0)],
            )
            stage = ToolSelectorAgentStage()
            plan = stage.run(profile=profile, output_dir=tmpdir, logger=logger)

            decisions = {item.tool_name: item.selected for item in plan.decisions}
            self.assertTrue(decisions["binaryinferno_adapter"])
            self.assertFalse(decisions["netplier_adapter"])


if __name__ == "__main__":
    unittest.main()
