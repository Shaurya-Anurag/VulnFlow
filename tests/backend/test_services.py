"""Stdlib contract tests for VulnFlow's backend services.

Run after integration is declared ready with:
    python -m unittest discover -s tests/backend -v
"""
from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from backend.app import audit, db, importers, workflow
from backend.app.models import (
    ApprovalError,
    FINDING_STATES,
    ImportLimits,
    ImportValidationError,
    WorkflowConflict,
)


def sarif_result(uri: str = "src/example.py", line: int = 12,
                 message: str = "Example alert", evidence: str = "") -> dict:
    region = {"startLine": line}
    if evidence:
        region["snippet"] = {"text": evidence}
    return {
        "ruleId": "DEMO-001",
        "level": "warning",
        "message": {"text": message},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": uri}, "region": region,
        }}],
    }


def sarif_document(*results: dict) -> bytes:
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "UnitTestScanner", "version": "1.2"}},
            "results": list(results),
        }],
    }, separators=(",", ":")).encode("utf-8")


def import_into(conn: sqlite3.Connection, data: bytes, filename: str = "fixture.sarif"):
    request = importers.parse_import(data, filename)
    observations = importers.normalize_import(request)
    result = importers.persist_import(conn, request, observations)
    return request, result


class DatabaseTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self._temp.name) / "vulnflow.sqlite3")
        db.initialize(self.db_path)
        self.conn = db.connect(self.db_path)

    def tearDown(self) -> None:
        self.conn.close()
        self._temp.cleanup()

    def scalar(self, sql: str, params: tuple = ()) -> int:
        return self.conn.execute(sql, params).fetchone()[0]

    def make_finding(self, data: bytes | None = None) -> str:
        data = data or sarif_document(sarif_result())
        before = {row[0] for row in self.conn.execute("SELECT id FROM findings")}
        import_into(self.conn, data)
        after = {row[0] for row in self.conn.execute("SELECT id FROM findings")}
        created = after - before
        self.assertEqual(len(created), 1, "fixture import should create exactly one distinct finding")
        return created.pop()


class ImportContractTests(DatabaseTestCase):
    def test_byte_limit_rejects_before_database_changes(self) -> None:
        before = (self.scalar("SELECT COUNT(*) FROM imports"),
                  self.scalar("SELECT COUNT(*) FROM findings"),
                  self.scalar("SELECT COUNT(*) FROM audit_events"))
        with self.assertRaises(ImportValidationError):
            importers.parse_import(sarif_document(sarif_result()), "large.sarif",
                                   ImportLimits(max_bytes=8))
        after = (self.scalar("SELECT COUNT(*) FROM imports"),
                 self.scalar("SELECT COUNT(*) FROM findings"),
                 self.scalar("SELECT COUNT(*) FROM audit_events"))
        self.assertEqual(after, before)

    def test_schema_depth_result_count_and_duplicate_json_keys_are_rejected(self) -> None:
        valid = sarif_document(sarif_result())
        with self.assertRaises(ImportValidationError):
            importers.parse_import(
                json.dumps({"version": "1.0.0", "runs": []}).encode(), "wrong-version.sarif")
        with self.assertRaises(ImportValidationError):
            importers.parse_import(valid, "deep.sarif", ImportLimits(max_depth=2))
        with self.assertRaises(ImportValidationError):
            importers.parse_import(valid, "count.sarif", ImportLimits(max_results=0))
        with self.assertRaises(ImportValidationError):
            importers.parse_import(b'{"version":"2.1.0","version":"2.1.0","runs":[]}', "dupe.json")

    def test_rejects_oversized_strings_and_unsupported_json_schema(self) -> None:
        with self.assertRaises(ImportValidationError):
            importers.parse_import(sarif_document(sarif_result(message="x" * 50)), "long.sarif",
                                   ImportLimits(max_string=20))
        unsupported = {"schema_version": "2", "tool": {"name": "x"}, "results": []}
        with self.assertRaises(ImportValidationError):
            importers.parse_import(json.dumps(unsupported).encode(), "unsupported.json")

    def test_mid_transaction_failure_rolls_back_import_findings_observations_and_audit(self) -> None:
        request = importers.parse_import(
            sarif_document(sarif_result(evidence="captured")), "rollback.sarif")
        observations = importers.normalize_import(request)
        before = [self.scalar(f"SELECT COUNT(*) FROM {table}") for table in
                  ("imports", "findings", "observations", "evidence", "audit_events")]
        with patch("backend.app.importers.append_event", side_effect=RuntimeError("injected audit failure")):
            with self.assertRaises(RuntimeError):
                importers.persist_import(self.conn, request, observations)
        after = [self.scalar(f"SELECT COUNT(*) FROM {table}") for table in
                 ("imports", "findings", "observations", "evidence", "audit_events")]
        self.assertEqual(after, before)

    def test_identical_source_retry_is_idempotent(self) -> None:
        data = sarif_document(sarif_result())
        request1, first = import_into(self.conn, data, "same.sarif")
        request2 = importers.parse_import(data, "renamed.sarif")
        second = importers.persist_import(self.conn, request2, importers.normalize_import(request2))
        self.assertEqual(request1.source_sha256, request2.source_sha256)
        self.assertEqual(first.import_id, second.import_id)
        self.assertFalse(first.duplicate_import)
        self.assertTrue(second.duplicate_import)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM imports"), 1)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM observations"), 1)

    def test_dedup_preserves_each_import_observation_and_evidence(self) -> None:
        first = sarif_document(sarif_result(message="Original text", evidence="evidence one"))
        second = sarif_document(sarif_result(message="Updated text", evidence="evidence two"))
        import_into(self.conn, first, "first.sarif")
        import_into(self.conn, second, "second.sarif")
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM findings"), 1)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM observations"), 2)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM evidence"), 2)
        excerpts = {row[0] for row in self.conn.execute("SELECT excerpt FROM evidence")}
        self.assertEqual(excerpts, {"evidence one", "evidence two"})
        source_metadata = self.conn.execute(
            "SELECT source_sha256,tool_name,tool_version FROM imports JOIN observations ON observations.import_id=imports.id"
        ).fetchall()
        self.assertEqual(len(source_metadata), 2)
        self.assertTrue(all(len(row[0]) == 64 and row[1] == "UnitTestScanner" and row[2] == "1.2"
                            for row in source_metadata))

    def test_distinct_locations_do_not_deduplicate(self) -> None:
        import_into(self.conn, sarif_document(sarif_result(uri="src/a.py", line=4)), "a.sarif")
        import_into(self.conn, sarif_document(sarif_result(uri="src/b.py", line=4)), "b.sarif")
        import_into(self.conn, sarif_document(sarif_result(uri="src/a.py", line=5)), "c.sarif")
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM findings"), 3)


class LifecycleApprovalAndAuditTests(DatabaseTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.finding_id = self.make_finding()

    def test_stale_lifecycle_write_is_rejected_without_second_audit_event(self) -> None:
        initial_events = len(audit.list_events(self.conn))
        updated = workflow.transition_finding(
            self.conn, self.finding_id, "investigating", "reviewer", "Initial review", 1)
        self.assertEqual(updated.state, "investigating")
        self.assertEqual(updated.version, 2)
        committed_event_count = len(audit.list_events(self.conn))
        self.assertEqual(committed_event_count, initial_events + 1)

        with self.assertRaises(WorkflowConflict):
            workflow.transition_finding(
                self.conn, self.finding_id, "planned", "reviewer", "Stale write", 1)
        current = self.conn.execute("SELECT state,version FROM findings WHERE id=?",
                                    (self.finding_id,)).fetchone()
        self.assertEqual(tuple(current), ("investigating", 2))
        self.assertEqual(len(audit.list_events(self.conn)), committed_event_count)

    def test_requested_lifecycle_path_and_rejected_transition(self) -> None:
        self.assertEqual(FINDING_STATES, {
            "reported", "investigating", "planned", "patching", "verifying", "resolved", "rejected",
        })
        with self.assertRaises(WorkflowConflict):
            workflow.transition_finding(
                self.conn, self.finding_id, "resolved", "reviewer", "Cannot skip review", 1)
        with self.assertRaises(WorkflowConflict):
            workflow.transition_finding(
                self.conn, self.finding_id, "closed", "reviewer", "Unknown state", 1)

        expected_states = [
            "investigating", "planned", "patching", "verifying",
            "patching", "verifying", "resolved",
        ]
        for version, state in enumerate(expected_states, start=1):
            finding = workflow.transition_finding(
                self.conn, self.finding_id, state, "reviewer", "Lifecycle acceptance", version)
            self.assertEqual(finding.state, state)
            self.assertEqual(finding.version, version + 1)

        reopened = workflow.transition_finding(
            self.conn, self.finding_id, "investigating", "reviewer", "Reopened after verification", 8)
        self.assertEqual(reopened.state, "investigating")
        rejected_id = self.make_finding(sarif_document(sarif_result(uri="src/rejected.py")))
        rejected = workflow.transition_finding(
            self.conn, rejected_id, "rejected", "reviewer", "Not in scope", 1)
        self.assertEqual(rejected.state, "rejected")
        reported = workflow.transition_finding(
            self.conn, rejected_id, "reported", "reviewer", "Reopened for more evidence", 2)
        self.assertEqual(reported.state, "reported")
        investigating = workflow.transition_finding(
            self.conn, rejected_id, "investigating", "reviewer", "Review again", 3)
        self.assertEqual(investigating.state, "investigating")
        rejected_again = workflow.transition_finding(
            self.conn, rejected_id, "rejected", "reviewer", "Still not applicable", 4)
        self.assertEqual(rejected_again.state, "rejected")

    def create_approval(self, expires_at: datetime | None = None):
        expires_at = expires_at or (datetime.now(timezone.utc) + timedelta(hours=1))
        return workflow.create_approval(
            self.conn, self.finding_id, "propose_remediation", "finding:" + self.finding_id,
            {"ticket": "VF-123", "change": "patch"}, "vulnflow-remediation", expires_at.isoformat())

    def test_pending_approval_creation_is_idempotent_for_same_finding_and_action(self) -> None:
        first = self.create_approval()
        second = self.create_approval()
        third = self.create_approval()

        self.assertEqual(first.id, second.id)
        self.assertEqual(first.id, third.id)
        self.assertEqual(first.state, "pending")
        self.assertEqual(second.state, "pending")
        self.assertEqual(third.state, "pending")
        self.assertEqual(
            self.scalar(
                "SELECT COUNT(*) FROM approvals WHERE finding_id=? AND action=? AND state='pending'",
                (self.finding_id, "propose_remediation"),
            ),
            1,
        )
        created_events = [
            event for event in audit.list_events(
                self.conn, entity_type="approval", entity_id=first.id
            )
            if event.event_type == "approval.created"
        ]
        self.assertEqual(len(created_events), 1)

    def test_approval_is_parameter_bound_replay_protected_and_not_self_approved(self) -> None:
        approval = self.create_approval()
        self.assertEqual(approval.requester, "vulnflow-remediation")
        with self.assertRaises(ApprovalError):
            workflow.decide_approval(self.conn, approval.id, "approved", "local-operator",
                                     "0" * 64, now=datetime.now(timezone.utc))
        self.assertEqual(self.conn.execute("SELECT state FROM approvals WHERE id=?",
                                           (approval.id,)).fetchone()[0], "pending")

        decided = workflow.decide_approval(
            self.conn, approval.id, "approved", "local-operator", approval.parameter_sha256,
            now=datetime.now(timezone.utc), reason="Reviewed proposal")
        self.assertEqual(decided.state, "approved")
        decision_events = audit.list_events(
            self.conn, entity_type="approval", entity_id=approval.id)
        approved_event = next(event for event in decision_events
                              if event.event_type == "approval.approved")
        self.assertEqual(approved_event.actor, "local-operator")
        self.assertEqual(approved_event.payload["reason"], "Reviewed proposal")
        with self.assertRaises(ApprovalError):
            workflow.decide_approval(
                self.conn, approval.id, "approved", "local-operator", approval.parameter_sha256,
                now=datetime.now(timezone.utc))

        self_approval = self.create_approval()
        with self.assertRaises(ApprovalError):
            workflow.decide_approval(
                self.conn, self_approval.id, "approved", "vulnflow-remediation",
                self_approval.parameter_sha256, now=datetime.now(timezone.utc))

    def test_expired_approval_commits_expired_state_and_audit_event(self) -> None:
        now = datetime.now(timezone.utc)
        approval = self.create_approval(now + timedelta(minutes=1))
        decision_time = now + timedelta(minutes=2)
        result = workflow.decide_approval(
            self.conn, approval.id, "approved", "local-operator", approval.parameter_sha256,
            now=decision_time)
        self.assertEqual(result.state, "expired")
        events = audit.list_events(self.conn, entity_type="approval", entity_id=approval.id)
        self.assertEqual({event.event_type for event in events},
                         {"approval.created", "approval.expired"})

    def test_state_and_audit_roll_back_together_on_outer_transaction_failure(self) -> None:
        before_events = len(audit.list_events(self.conn, entity_type="finding", entity_id=self.finding_id))
        with self.assertRaisesRegex(RuntimeError, "abort outer unit of work"):
            with db.transaction(self.conn):
                workflow.transition_finding(
                    self.conn, self.finding_id, "investigating", "reviewer", "will roll back", 1)
                raise RuntimeError("abort outer unit of work")
        row = self.conn.execute("SELECT state,version FROM findings WHERE id=?",
                                (self.finding_id,)).fetchone()
        self.assertEqual(tuple(row), ("reported", 1))
        self.assertEqual(len(audit.list_events(self.conn, entity_type="finding", entity_id=self.finding_id)),
                         before_events)

    def test_audit_events_are_append_only_and_hash_chain_links(self) -> None:
        audit.append_event(self.conn, "tester", "test.one", "finding", self.finding_id, {"ok": True})
        audit.append_event(self.conn, "tester", "test.two", "finding", self.finding_id, {"token": "secret"})
        events = list(reversed(audit.list_events(self.conn, entity_type="finding", entity_id=self.finding_id)))
        self.assertEqual(events[-1].previous_hash, events[-2].event_hash)
        self.assertEqual(events[-1].payload["token"], "[REDACTED]")
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("UPDATE audit_events SET payload_json='{}' WHERE id=?", (events[0].id,))
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("DELETE FROM audit_events WHERE id=?", (events[0].id,))


class AgentOrchestrationTests(DatabaseTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.finding_id = self.make_finding(
            sarif_document(sarif_result(evidence="user input reaches database query"))
        )

    def test_specialist_agents_receive_handoffs_and_persist_trace(self) -> None:
        from backend.app import orchestration

        outputs = [
            "Triage: scanner reports SQL injection. Evidence is limited.",
            "Analysis: exploitability depends on controllable input and query construction.",
            "Plan: use parameterized queries and add regression tests.",
            "Review: proposal is reasonable; verify query call sites and authorization boundaries.",
        ]
        calls = []

        class FakeBifrost:
            def complete(self, system, user, fault=None, max_tokens=512):
                calls.append(user)
                return {"output": outputs[len(calls) - 1], "model": "test/fake"}

        finding = {
            "id": self.finding_id, "title": "Example alert", "severity": "high",
            "status": "reported", "resource": "src/example.py", "rule_id": "DEMO-001",
            "description": "Example alert", "evidence": [{"excerpt": "user input reaches database query"}],
            "observations": [{"tool_name": "UnitTestScanner"}],
        }
        with patch.object(orchestration, "BifrostClient", FakeBifrost):
            result = orchestration.run_agent_workflow(self.db_path, finding)

        self.assertEqual(result["status"], "completed")
        self.assertEqual([item["agent"] for item in result["agents"]],
                         ["sentinel", "analyst", "architect", "verifier"])
        self.assertEqual(len(calls), 4)
        self.assertIn(outputs[0], calls[1])
        self.assertIn(outputs[1], calls[2])
        self.assertIn(outputs[2], calls[3])
        self.assertIn("no repository access", result["execution_policy"])
        detail = orchestration.get_agent_workflow(self.db_path, result["run_id"])
        self.assertEqual(detail["run"]["status"], "completed")
        self.assertEqual([step["status"] for step in detail["steps"]],
                         ["completed"] * 4)


if __name__ == "__main__":
    unittest.main()
