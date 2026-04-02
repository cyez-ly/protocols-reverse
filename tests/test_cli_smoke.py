from __future__ import annotations

import argparse
import tempfile
import unittest
from pathlib import Path

from testcrewai.main import execute


class CliSmokeTestCase(unittest.TestCase):
    def test_cli_execute_generates_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            pcap_path = Path(tmpdir) / "sample.pcap"
            pcap_path.write_bytes(b"\xd4\xc3\xb2\xa1" + b"A" * 512)

            output_dir = Path(tmpdir) / "outputs"
            args = argparse.Namespace(
                pcap=str(pcap_path),
                output=str(output_dir),
                python_bin="python3",
                timeout=10,
                use_llm=False,
                print_json=False,
            )

            result = execute(args)
            artifacts = result.get("artifacts", {})

            self.assertTrue(Path(artifacts["traffic_profile"]).exists())
            self.assertTrue(Path(artifacts["execution_plan"]).exists())
            self.assertTrue(Path(artifacts["segment_candidates"]).exists())
            self.assertTrue(Path(artifacts["semantic_candidates"]).exists())
            self.assertTrue(Path(artifacts["final_schema"]).exists())
            self.assertTrue(Path(artifacts["report"]).exists())
            self.assertTrue(Path(artifacts["log"]).exists())


if __name__ == "__main__":
    unittest.main()
