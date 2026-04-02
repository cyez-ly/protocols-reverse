from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

from testcrewai.adapters.nemesys_cli import _cluster_id_by_length
from testcrewai.tools.protocol_tools import NemesysTool


class NemesysAdapterTestCase(unittest.TestCase):
    def test_cluster_id_by_length_uses_nearest_profile_cluster(self) -> None:
        profile = {
            "message_clusters": [
                {"cluster_id": "cluster_1", "representative_lengths": [48], "mean_length": 48.0},
                {"cluster_id": "cluster_2", "representative_lengths": [96], "mean_length": 96.0},
            ]
        }
        self.assertEqual(_cluster_id_by_length(profile, 53), "cluster_1")
        self.assertEqual(_cluster_id_by_length(profile, 88), "cluster_2")

    def test_nemesys_tool_heuristic_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            profile_path = Path(tmpdir) / "traffic_profile.json"
            profile = {
                "input_file": str(Path(tmpdir) / "dummy.pcap"),
                "message_clusters": [
                    {
                        "cluster_id": "cluster_1",
                        "representative_lengths": [8],
                        "sample_count": 3,
                        "mean_length": 8.0,
                    }
                ],
                "sample_messages_hex": [
                    "0108000001020304",
                    "0208000102030405",
                    "0308000203040506",
                ],
            }
            profile_path.write_text(json.dumps(profile), encoding="utf-8")

            tool = NemesysTool()
            result = tool.run(
                input_path=str(profile_path),
                output_dir=tmpdir,
                extra_args={
                    "nemesys_mode": "heuristic",
                    "nemesys_python_bin": sys.executable,
                    "timeout_sec": "30",
                },
            )

            self.assertTrue(result.success, msg=result.error)
            self.assertTrue((Path(tmpdir) / "nemesys_segments_raw.json").exists())
            self.assertTrue(len(result.data.get("candidates", [])) >= 1)


if __name__ == "__main__":
    unittest.main()
