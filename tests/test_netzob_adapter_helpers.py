from __future__ import annotations

import unittest

from testcrewai.adapters.netzob_cli import _cluster_id_by_length, _refine_text_symbol_candidates


class NetzobAdapterHelpersTestCase(unittest.TestCase):
    def test_cluster_id_by_length_supports_fuzzy_match(self) -> None:
        profile = {
            "message_clusters": [
                {
                    "cluster_id": "cluster_1",
                    "representative_lengths": [100],
                    "mean_length": 100.0,
                },
                {
                    "cluster_id": "cluster_2",
                    "representative_lengths": [220],
                    "mean_length": 220.0,
                },
            ]
        }

        self.assertEqual(_cluster_id_by_length(profile, 108), "cluster_1")
        self.assertEqual(_cluster_id_by_length(profile, 212), "cluster_2")
        self.assertIsNone(_cluster_id_by_length(profile, 380))

    def test_text_refinement_coalesces_non_delimiter_micro_fragments(self) -> None:
        messages = [
            b"GET / HTTP/1.1\r\nHost: aa\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: bb\r\n\r\n",
        ]
        # Simulate over-fragmented boundaries containing non-delimiter 1-byte fields.
        symbol_candidates = [
            {"start": 0, "end": 6, "confidence": 0.86, "reason": "official"},
            {"start": 6, "end": 7, "confidence": 0.86, "reason": "official"},
            {"start": 7, "end": 15, "confidence": 0.86, "reason": "official"},
            {"start": 15, "end": 16, "confidence": 0.86, "reason": "official"},
            {"start": 16, "end": 24, "confidence": 0.86, "reason": "official"},
        ]

        refined, removed = _refine_text_symbol_candidates(symbol_candidates, messages)
        self.assertGreaterEqual(removed, 1)
        original_one_byte = sum(1 for item in symbol_candidates if item["end"] - item["start"] == 1)
        refined_one_byte = sum(1 for item in refined if item["end"] - item["start"] == 1)
        self.assertLess(refined_one_byte, original_one_byte)


if __name__ == "__main__":
    unittest.main()
