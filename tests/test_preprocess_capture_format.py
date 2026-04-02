from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from testcrewai.pipeline.preprocess import (
    _detect_capture_format,
    _detect_capture_format_from_magic,
    _detect_extension_format,
    _has_valid_capture_magic,
)


class PreprocessCaptureFormatTestCase(unittest.TestCase):
    def test_magic_takes_priority_over_suffix(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "mismatch.pcap"
            # pcapng magic + random bytes
            p.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 32)

            self.assertEqual(_detect_extension_format(p), "pcap")
            self.assertEqual(_detect_capture_format_from_magic(p), "pcapng")
            self.assertEqual(_detect_capture_format(p), "pcapng")
            self.assertTrue(_has_valid_capture_magic(p, "pcapng"))

    def test_invalid_magic_falls_back_to_suffix_and_fails_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "broken.pcap"
            p.write_bytes(b"NOTP" + b"\x00" * 16)

            self.assertEqual(_detect_capture_format_from_magic(p), "unknown")
            self.assertEqual(_detect_capture_format(p), "pcap")
            self.assertFalse(_has_valid_capture_magic(p, "pcap"))


if __name__ == "__main__":
    unittest.main()
