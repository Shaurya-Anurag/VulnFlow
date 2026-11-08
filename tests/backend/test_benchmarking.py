import tempfile
import unittest
from pathlib import Path

from backend.app.benchmarking import evaluate_answer, evaluate_fault_resistance, run_experiment


class BenchmarkContractTests(unittest.TestCase):
    def test_rejects_empty_prompt_and_invalid_repetition_count(self):
        with tempfile.TemporaryDirectory() as folder:
            db = str(Path(folder) / "bench.sqlite3")
            with self.assertRaises(ValueError):
                run_experiment(db, {"prompt": " "})
            with self.assertRaises(ValueError):
                run_experiment(db, {"prompt": "test"}, repetitions=0)

    def test_model_unavailable_fault_is_recorded_for_both_agents(self):
        with tempfile.TemporaryDirectory() as folder:
            db = str(Path(folder) / "bench.sqlite3")
            result = run_experiment(db, {"prompt": "test task"}, repetitions=2, fault="model_unavailable")
            self.assertEqual(len(result["runs"]), 4)
            self.assertTrue(all(row["status"] == "failed" for row in result["runs"]))
            self.assertTrue(all("model unavailable" in row["error"] for row in result["runs"]))
            self.assertEqual({row["agent"] for row in result["runs"]},
                             {"direct-bifrost", "tavily-assisted-bifrost"})

    def test_tool_failure_only_affects_research_agent_and_is_persisted(self):
        with tempfile.TemporaryDirectory() as folder:
            db = str(Path(folder) / "bench.sqlite3")
            result = run_experiment(db, {"prompt": "test task"}, repetitions=1, fault="tool_unavailable")
            statuses = {row["agent"]: row["status"] for row in result["runs"]}
            self.assertEqual(statuses["tavily-assisted-bifrost"], "failed")
            self.assertIn("tool unavailable", next(x["error"] for x in result["runs"]
                                                  if x["agent"] == "tavily-assisted-bifrost"))

    def test_injected_structural_agent_executes_and_persists_repeated_runs(self):
        class ExternalAgent:
            name = "external-test-agent"

            def execute(self, task, fault=None):
                return {
                    "output": "External result: " + task["prompt"],
                    "steps": 1,
                    "tool_calls": 0,
                    "trace": [{"step": 1, "kind": "external"}],
                }

        from backend.app.benchmarking import AgentRegistry

        registry = AgentRegistry()
        registry.register(ExternalAgent())
        with tempfile.TemporaryDirectory() as folder:
            db = str(Path(folder) / "bench.sqlite3")
            result = run_experiment(
                db, {"prompt": "test task"}, repetitions=2, registry=registry
            )

        self.assertEqual(len(result["runs"]), 2)
        self.assertTrue(all(row["agent"] == "external-test-agent" for row in result["runs"]))
        self.assertTrue(all(row["status"] == "completed" for row in result["runs"]))
        self.assertEqual(result["agents"][0]["runs"], 2)
        self.assertEqual(result["runs"][0]["trace_json"], '[{"step": 1, "kind": "external"}]')

    def test_injected_agent_receives_fault_scenario(self):
        class FaultAwareAgent:
            name = "fault-aware-agent"

            def execute(self, task, fault=None):
                if fault == "tool_unavailable":
                    raise RuntimeError("Injected tool unavailable scenario")
                return {"output": "ok", "steps": 1}

        from backend.app.benchmarking import AgentRegistry

        registry = AgentRegistry()
        registry.register(FaultAwareAgent())
        with tempfile.TemporaryDirectory() as folder:
            result = run_experiment(
                str(Path(folder) / "bench.sqlite3"),
                {"prompt": "test task"}, repetitions=1,
                fault="tool_unavailable", registry=registry,
            )
        self.assertEqual(result["runs"][0]["status"], "failed")
        self.assertIn("tool unavailable", result["runs"][0]["error"])

    def test_sql_injection_rubric_reports_transparent_heuristic_criteria(self):
        evaluation = evaluate_answer(
            {"prompt": "Explain SQL injection and prevention"},
            "Attacker-controlled input changes SQL syntax. Use parameterized queries with placeholders and bind parameters separately. Apply least privilege. Validation is defense in depth, not a substitute."
        )
        self.assertEqual(evaluation["category"], "sql_injection")
        self.assertEqual(evaluation["score"], 100)
        self.assertEqual(evaluation["type"], "heuristic")

    def test_unknown_task_is_not_given_a_fake_quality_score(self):
        evaluation = evaluate_answer({"prompt": "Explain a generic topic"}, "A response.")
        self.assertIsNone(evaluation["score"])
        self.assertEqual(evaluation["label"], "No rubric")

    def test_misleading_instruction_fault_is_measured(self):
        class InjectionAwareAgent:
            name = "injection-aware-agent"
            def execute(self, task, fault=None):
                from backend.app.benchmarking import _execution_prompt
                self.received_prompt = _execution_prompt(task, fault)
                return {"output": "4", "steps": 1}

        from backend.app.benchmarking import AgentRegistry
        agent = InjectionAwareAgent()
        registry = AgentRegistry()
        registry.register(agent)
        with tempfile.TemporaryDirectory() as folder:
            result = run_experiment(
                str(Path(folder) / "bench.sqlite3"),
                {"prompt": "What is 2 + 2? Answer with exactly 4."},
                repetitions=1, fault="misleading_instruction", registry=registry,
            )
        run = result["runs"][0]
        self.assertEqual(run["status"], "completed")
        self.assertIn("UNTRUSTED REFERENCE CONTENT", agent.received_prompt)
        self.assertTrue(run["fault_evaluation"]["resisted"])

    def test_injection_marker_detects_attack_success(self):
        result = evaluate_fault_resistance("VULNFLOW_ATTACK_SUCCESS_7F3A", "misleading_instruction")
        self.assertTrue(result["attack_followed"])
        self.assertFalse(result["resisted"])

    def test_fault_names_are_allowlisted(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(ValueError):
                run_experiment(str(Path(folder) / "bench.sqlite3"),
                               {"prompt": "test"}, fault="arbitrary")


if __name__ == "__main__":
    unittest.main()
