"""Contract tests for deterministic evidence-grounded review briefs."""
from __future__ import annotations

import unittest

from backend.app.analysis import build_review_brief


class ReviewBriefTests(unittest.TestCase):
    def setUp(self):
        self.finding = {
            "id": "finding-1", "title": "SQL injection", "severity": "high",
            "state": "investigating", "target": "api/search", "rule_id": "SQL-001",
        }

    def test_extracts_scanner_metadata_evidence_and_locations(self):
        brief = build_review_brief(
            self.finding,
            [{"tool_name": "Semgrep", "tool_version": "1.2",
              "rule_id": "SQL-001", "source_sha256": "a" * 64,
              "normalized_location": '{"uri":"src/app.py","line":42}'}],
            [{"kind": "snippet", "locator": "src/app.py:42",
              "excerpt": "query(user_input)", "content_sha256": "b" * 64}],
        )
        self.assertEqual(brief["scanner_tools"][0]["name"], "Semgrep")
        self.assertEqual(brief["locations"][0]["line"], 42)
        self.assertEqual(brief["evidence"][0]["excerpt"], "query(user_input)")
        self.assertEqual(brief["source_count"], 1)

    def test_reports_missing_observation_evidence_location_and_rule(self):
        finding = {"id": "f", "title": "Unknown", "severity": "unknown"}
        brief = build_review_brief(finding, [], [])
        self.assertEqual(brief["observations"], 0)
        self.assertIn("No imported observation is linked to this finding.", brief["gaps"])
        self.assertIn("The report supplied no evidence records.", brief["gaps"])
        self.assertIn("No normalized source location is available.", brief["gaps"])
        self.assertIn("No scanner rule identifier is available.", brief["gaps"])
        self.assertIn("No affected resource is identified.", brief["gaps"])

    def test_locator_without_excerpt_is_reported_as_gap(self):
        brief = build_review_brief(
            self.finding,
            [{"tool_name": "Scanner", "source_sha256": "a" * 64,
              "normalized_location": "{}"}],
            [{"kind": "file", "locator": "src/app.py"}],
        )
        self.assertIn(
            "Evidence locators exist, but no source excerpts were supplied.",
            brief["gaps"],
        )

    def test_multiple_observations_count_distinct_source_reports(self):
        observations = [
            {"tool_name": "A", "source_sha256": "a" * 64,
             "normalized_location": {"line": 1}},
            {"tool_name": "B", "source_sha256": "b" * 64,
             "normalized_location": {"line": 2}},
            {"tool_name": "B", "source_sha256": "b" * 64,
             "normalized_location": {"line": 3}},
        ]
        brief = build_review_brief(self.finding, observations, [])
        self.assertEqual(brief["observations"], 3)
        self.assertEqual(brief["source_count"], 2)
        self.assertEqual(len(brief["locations"]), 3)

    def test_never_claims_independent_verification(self):
        brief = build_review_brief(self.finding, [], [])
        self.assertEqual(brief["review_status"], "review_required")
        self.assertEqual(brief["verification_claim"], "not_performed")
        self.assertIn("not an independent validation", brief["summary"])
        self.assertTrue(any("No target" in item for item in brief["limitations"]))

    def test_malformed_location_and_missing_fields_are_handled_safely(self):
        brief = build_review_brief(
            {"title": None},
            [{"normalized_location": "{broken", "tool_name": None}],
            [{"kind": None, "locator": None, "excerpt": None}],
        )
        self.assertEqual(brief["locations"], [])
        self.assertEqual(brief["scanner_tools"][0]["name"], "Unknown tool")
        self.assertEqual(brief["evidence"][0]["kind"], "unspecified")
        self.assertFalse(brief["evidence"][0]["has_excerpt"])

    def test_untrusted_text_is_truncated_and_treated_as_data(self):
        long_text = "x" * 3000
        brief = build_review_brief(
            self.finding, [],
            [{"kind": "snippet", "excerpt": long_text}],
        )
        self.assertEqual(len(brief["evidence"][0]["excerpt"]), 2000)
        self.assertEqual(brief["verification_claim"], "not_performed")


if __name__ == "__main__":
    unittest.main()
