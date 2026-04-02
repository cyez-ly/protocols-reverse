from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

from testcrewai.models import ShellCommandResult
from testcrewai.pipeline import preprocess


def _shell_result(stdout: str = "", stderr: str = "", return_code: int = 0) -> ShellCommandResult:
    return ShellCommandResult(
        command=["tshark"],
        return_code=return_code,
        stdout=stdout,
        stderr=stderr,
        timed_out=False,
        duration_sec=0.01,
    )


class PreprocessPayloadExtractionTestCase(unittest.TestCase):
    def test_tshark_udp_payload_is_parsed(self) -> None:
        def fake_run(_self, command, timeout_sec=60, cwd=None, env=None, stdin_text=None):  # type: ignore[no-untyped-def]
            field = command[command.index("-e") + 1]
            if field == "udp.payload":
                return _shell_result(stdout="01:02:03:04\n")
            return _shell_result(stdout="")

        with patch("testcrewai.pipeline.preprocess.shutil.which", return_value="/usr/bin/tshark"):
            with patch.object(preprocess.ShellRunner, "run", new=fake_run):
                payloads, notes = preprocess._extract_messages_with_tshark(Path("/tmp/demo.pcap"), timeout_sec=5, max_samples=5)

        self.assertEqual(payloads, [b"\x01\x02\x03\x04"])
        self.assertTrue(any("udp.payload" in note for note in notes))

    def test_tshark_field_fallback_to_data_data(self) -> None:
        def fake_run(_self, command, timeout_sec=60, cwd=None, env=None, stdin_text=None):  # type: ignore[no-untyped-def]
            field = command[command.index("-e") + 1]
            if field == "data.data":
                return _shell_result(stdout="aa:bb,ccdd\nnot-hex\n")
            return _shell_result(stdout="")

        with patch("testcrewai.pipeline.preprocess.shutil.which", return_value="/usr/bin/tshark"):
            with patch.object(preprocess.ShellRunner, "run", new=fake_run):
                payloads, notes = preprocess._extract_messages_with_tshark(Path("/tmp/demo.pcap"), timeout_sec=5, max_samples=5)

        self.assertEqual(payloads, [b"\xaa\xbb", b"\xcc\xdd"])
        self.assertTrue(any("data.data" in note for note in notes))

    def test_downselect_payloads_for_mixed_lengths(self) -> None:
        payloads = []
        payloads.extend([b"a" * 20 for _ in range(45)])
        payloads.extend([b"b" * 24 for _ in range(30)])
        payloads.extend([b"c" * 60 for _ in range(5)])
        payloads.extend([bytes([idx]) * (idx % 11 + 1) for idx in range(20)])  # noisy mixed outliers

        selected, notes = preprocess._downselect_payloads_for_reverse(payloads)
        self.assertLess(len(selected), len(payloads))
        kept_lengths = {len(item) for item in selected}
        self.assertIn(20, kept_lengths)
        self.assertIn(24, kept_lengths)
        self.assertTrue(any("down-selection" in note for note in notes))


if __name__ == "__main__":
    unittest.main()
