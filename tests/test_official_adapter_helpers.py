from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from testcrewai.tools.protocol_tools import (
    _binaryinferno_hints_useful,
    _extract_binaryinferno_field_hints,
    _map_binaryinferno_hints_to_segments,
    _parse_netplier_fields_info_with_meta,
)


class OfficialAdapterHelpersTestCase(unittest.TestCase):
    def test_extract_binaryinferno_hints_and_mapping(self) -> None:
        stdout = """
        INFERRED DESCRIPTION
        --------------------------------------------------------------------------------
        0 ? UNKNOWN TYPE 1 BYTE(S) 3.0
        1 L BE UINT16 LENGTH + 0 = TOTAL MESSAGE LENGTH 6.0
        2 T BE 32BIT SPAN SECONDS 2001-02-08 11:41:41 TO 2028-02-08 11:41:41 1.0 12.0
        3 R 0T_1L_V_BIG* 23.0
        QTY SAMPLES
        3
        """
        hints = _extract_binaryinferno_field_hints(stdout)
        self.assertEqual(len(hints), 4)
        self.assertTrue(_binaryinferno_hints_useful(hints))

        segment_candidates = [
            {"message_cluster": "cluster_1", "start": 0, "end": 1},
            {"message_cluster": "cluster_1", "start": 1, "end": 3},
            {"message_cluster": "cluster_1", "start": 3, "end": 7},
            {"message_cluster": "cluster_1", "start": 7, "end": 20},
        ]
        mapped = _map_binaryinferno_hints_to_segments(segment_candidates, hints)
        semantic_types = [item["semantic_type"] for item in mapped]
        self.assertEqual(semantic_types, ["type", "length", "timestamp", "payload"])

    def test_binaryinferno_hints_not_useful(self) -> None:
        hints = [("?", "UNCLASSIFIED PATTERN WITHOUT CLUES")]
        self.assertFalse(_binaryinferno_hints_useful(hints))

    def test_parse_netplier_fields_info_auto_width_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            fields_info = Path(tmpdir) / "msa_fields_info.txt"
            fields_info.write_text(
                "\n".join(
                    [
                        "Raw 0 16 D",
                        "Raw 0 48 S",
                        "Raw 0 16 D",
                        "Raw 0 272 V",
                    ]
                ),
                encoding="utf-8",
            )

            parsed, meta = _parse_netplier_fields_info_with_meta(fields_info)
            self.assertEqual(meta["mode"], "width_bits")
            self.assertEqual(len(parsed), 4)
            self.assertEqual(parsed[0], (0, 2, "D"))
            self.assertEqual(parsed[1], (2, 8, "S"))


if __name__ == "__main__":
    unittest.main()
