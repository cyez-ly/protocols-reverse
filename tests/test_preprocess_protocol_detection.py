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


class PreprocessProtocolDetectionTestCase(unittest.TestCase):
    def test_dns_payload_heuristic(self) -> None:
        # Minimal DNS query payload (ID + flags + counts + qname + qtype + qclass)
        payload = bytes.fromhex("002a0100000100000000000002757304706f6f6c036e7470036f72670000010001")
        self.assertTrue(preprocess._looks_like_dns_payload(payload))

    def test_tshark_frame_protocols_parser(self) -> None:
        def fake_run(_self, command, timeout_sec=60, cwd=None, env=None, stdin_text=None):  # type: ignore[no-untyped-def]
            return _shell_result(stdout="eth:ip:udp:dns\neth:ip:udp\n")

        with patch("testcrewai.pipeline.preprocess.shutil.which", return_value="/usr/bin/tshark"):
            with patch.object(preprocess.ShellRunner, "run", new=fake_run):
                protocols, notes = preprocess._extract_protocols_with_tshark(Path("/tmp/demo.pcap"), timeout_sec=5)

        self.assertGreaterEqual(protocols.get("dns", 0), 1)
        self.assertGreaterEqual(protocols.get("udp", 0), 1)
        self.assertTrue(any("frame.protocols" in note for note in notes))


if __name__ == "__main__":
    unittest.main()
