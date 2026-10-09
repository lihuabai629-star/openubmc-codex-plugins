from __future__ import annotations

from pathlib import Path
from dataclasses import replace
import json
from datetime import datetime, timedelta
import tempfile
import unittest

from openubmc_target_runtime.terminal_delivery import (
    TerminalAnswerError,
    TerminalAnswerStore,
    qualify_terminal_answer,
    render_final_answer,
)


def completed_rollout(task, turn, final_id, text, observed_at):
    return [
        {"type": "session_meta", "payload": {"id": task}},
        {"type": "event_msg", "payload": {"type": "task_started", "turn_id": turn}},
        {"type": "response_item", "timestamp": observed_at,
         "payload": {"type": "message", "id": final_id, "role": "assistant",
                     "phase": "final_answer", "content": [{"type": "output_text", "text": text}]}},
        {"type": "event_msg", "timestamp": observed_at,
         "payload": {"type": "task_complete", "turn_id": turn}},
    ]


class TerminalDeliveryTests(unittest.TestCase):
    def test_normal_delivery_is_bound_to_terminal_outcome(self):
        with tempfile.TemporaryDirectory() as raw:
            store = TerminalAnswerStore(Path(raw) / "answers.json")
            outcome = {"status": "completed", "summary": "done"}
            pending = store.prepare(task_id="task", run_id="run", outcome=outcome, delivery_stage="runtime-verified", text="done")
            self.assertIn("final_answer_unconfirmed", qualify_terminal_answer(
                task_id="task", run_id="run", outcome=outcome,
                delivery_stage="runtime-verified", record=pending,
            )["failures"])
            event_time = (datetime.fromisoformat(pending.prepared_at) + timedelta(seconds=1)).isoformat()
            rollout = Path(raw) / "rollout.jsonl"
            rollout.write_text("\n".join(json.dumps(item) for item in completed_rollout(
                "task", "turn-1", "rollout-final-1", "done", event_time,
            )) + "\n", encoding="utf-8")
            record = store.acknowledge_rollout(
                rollout, task_id="task", run_id="run", outcome=outcome,
                delivery_stage="runtime-verified",
            )
            self.assertEqual(qualify_terminal_answer(
                task_id="task", run_id="run", outcome=outcome,
                delivery_stage="runtime-verified", record=record,
            )["status"], "passed")

    def test_restart_recovery_and_duplicate_delivery_are_idempotent(self):
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "answers.json"
            outcome = {"status": "partial", "summary": "partial"}
            first = TerminalAnswerStore(path).prepare(task_id="task", run_id="run", outcome=outcome, delivery_stage="patched", text="partial")
            second = TerminalAnswerStore(path).prepare(task_id="task", run_id="run", outcome=outcome, delivery_stage="patched", text="ignored")
            self.assertEqual(first.delivery_id, second.delivery_id)
            self.assertEqual(TerminalAnswerStore(path).get("task").text, "partial")

    def test_missing_or_mismatched_answer_fails_closed(self):
        outcome = {"status": "blocked", "summary": "blocked"}
        missing = qualify_terminal_answer(
            task_id="task", run_id="run", outcome=outcome,
            delivery_stage="diagnosed", record=None,
        )
        self.assertIn("final_answer_missing", missing["failures"])
        with self.assertRaisesRegex(TerminalAnswerError, "another Run"):
            with tempfile.TemporaryDirectory() as raw:
                store = TerminalAnswerStore(Path(raw) / "answers.json")
                store.prepare(task_id="task", run_id="run-a", outcome=outcome, delivery_stage="diagnosed", text="blocked")
                store.prepare(task_id="task", run_id="run-b", outcome=outcome, delivery_stage="diagnosed", text="wrong")

    def test_final_text_distinguishes_status_and_next_action(self):
        text = render_final_answer(status="failed", summary="gate failed", delivery_stage="packaged",
                                   next_stage="deployed", required_evidence="target deployment receipt",
                                   next_action="修复门禁")
        self.assertIn("失败", text)
        self.assertIn("packaged", text)
        self.assertIn("deployed", text)
        self.assertIn("target deployment receipt", text)
        self.assertIn("修复门禁", text)
        self.assertIn("尚无已验证阶段", render_final_answer(
            status="completed", summary="Run complete", delivery_stage="unverified"))
        self.assertIn("明确授权", render_final_answer(
            status="cancelled", summary="cancelled", delivery_stage="unverified"))
        self.assertIn("受阻条件", render_final_answer(
            status="blocked", summary="blocked", delivery_stage="diagnosed"))

    def test_delivery_stage_is_part_of_terminal_identity(self):
        outcome = {"status": "partial", "summary": "source verified"}
        with tempfile.TemporaryDirectory() as raw:
            store = TerminalAnswerStore(Path(raw) / "answers.json")
            record = store.prepare(
                task_id="task", run_id="run", outcome=outcome,
                delivery_stage="patched", text="partial",
            )
            mismatch = qualify_terminal_answer(
                task_id="task", run_id="run", outcome=outcome,
                delivery_stage="component-built", record=record,
            )
        self.assertIn("final_answer_stage_mismatch", mismatch["failures"])
        self.assertIn("final_answer_outcome_mismatch", mismatch["failures"])

    def test_interrupted_delivery_can_be_recovered_without_rerunning_work(self):
        outcome = {"status": "blocked", "summary": "authentication required"}
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "answers.json"
            store = TerminalAnswerStore(path)
            self.assertIsNone(store.get("task"))
            text = render_final_answer(
                status="blocked", summary="authentication required",
                delivery_stage="diagnosed", next_action="本地重新登录",
            )
            recovered = TerminalAnswerStore(path).prepare(
                task_id="task", run_id="run", outcome=outcome,
                delivery_stage="diagnosed", text=text,
            )
        self.assertIn("受阻", recovered.text)
        self.assertIn("本地重新登录", recovered.text)

    def test_acknowledgement_rejects_a_different_final_text(self):
        outcome = {"status": "completed", "summary": "done"}
        with tempfile.TemporaryDirectory() as raw:
            store = TerminalAnswerStore(Path(raw) / "answers.json")
            store.prepare(task_id="task", run_id="run", outcome=outcome,
                          delivery_stage="runtime-verified", text="done")
            with self.assertRaisesRegex(TerminalAnswerError, "final text mismatch"):
                store.acknowledge(task_id="task", run_id="run", outcome=outcome,
                                  delivery_stage="runtime-verified", text="other",
                                  host_event_id="rollout-final-1")

    def test_rollout_audit_acknowledges_only_matching_host_final_event(self):
        outcome = {"status": "completed", "summary": "done"}
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            store = TerminalAnswerStore(root / "answers.json")
            store.prepare(task_id="task", run_id="run", outcome=outcome,
                          delivery_stage="runtime-verified", text="done")
            prepared = store.get("task")
            event_time = (datetime.fromisoformat(prepared.prepared_at) + timedelta(seconds=1)).isoformat()
            rollout = root / "rollout.jsonl"
            rollout.write_text("\n".join(json.dumps(item) for item in completed_rollout(
                "task", "turn-1", "final-1", "done", event_time,
            )) + "\n", encoding="utf-8")
            record = store.acknowledge_rollout(
                rollout, task_id="task", run_id="run", outcome=outcome,
                delivery_stage="runtime-verified",
            )
            self.assertEqual(record.host_event_id, "final-1")
            self.assertEqual(store.acknowledge_rollout(
                rollout, task_id="task", run_id="run", outcome=outcome,
                delivery_stage="runtime-verified",
            ), record)
            self.assertEqual(qualify_terminal_answer(task_id="task", run_id="run", outcome=outcome,
                             delivery_stage="runtime-verified", record=record)["status"], "passed")

    def test_rollout_audit_rejects_missing_final_and_task_mismatch(self):
        outcome = {"status": "blocked", "summary": "blocked"}
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            store = TerminalAnswerStore(root / "answers.json")
            store.prepare(task_id="task", run_id="run", outcome=outcome,
                          delivery_stage="diagnosed", text="blocked")
            rollout = root / "rollout.jsonl"
            rollout.write_text(json.dumps({"type": "session_meta", "payload": {"id": "other"}}) + "\n",
                               encoding="utf-8")
            with self.assertRaisesRegex(TerminalAnswerError, "another task"):
                store.acknowledge_rollout(rollout, task_id="task", run_id="run", outcome=outcome,
                                          delivery_stage="diagnosed")
            rollout.write_text(json.dumps({"type": "session_meta", "payload": {"id": "task"}}) + "\n",
                               encoding="utf-8")
            with self.assertRaisesRegex(TerminalAnswerError, "final event is missing"):
                store.acknowledge_rollout(rollout, task_id="task", run_id="run", outcome=outcome,
                                          delivery_stage="diagnosed")

    def test_rollout_audit_rejects_an_old_final_from_the_same_task(self):
        outcome = {"status": "completed", "summary": "done"}
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            rollout = root / "rollout.jsonl"
            rollout.write_text("\n".join(json.dumps(item) for item in completed_rollout(
                "task", "turn-old", "old-final", "done", "2020-01-01T00:00:00+00:00",
            )) + "\n", encoding="utf-8")
            store = TerminalAnswerStore(root / "answers.json")
            store.prepare(task_id="task", run_id="new-run", outcome=outcome,
                          delivery_stage="runtime-verified", text="done")
            with self.assertRaisesRegex(TerminalAnswerError, "final event is missing"):
                store.acknowledge_rollout(rollout, task_id="task", run_id="new-run",
                                          outcome=outcome, delivery_stage="runtime-verified")

    def test_interrupted_final_is_not_a_delivery_and_restart_can_complete_once(self):
        outcome = {"status": "partial", "summary": "diagnosis done"}
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            store = TerminalAnswerStore(root / "answers.json")
            prepared = store.prepare(task_id="task", run_id="run", outcome=outcome,
                                     delivery_stage="diagnosed", text="partial answer")
            observed = (datetime.fromisoformat(prepared.prepared_at) + timedelta(seconds=1)).isoformat()
            rollout = root / "rollout.jsonl"
            interrupted = completed_rollout("task", "turn-a", "draft", "partial answer", observed)
            interrupted[-1] = {"type": "event_msg", "payload": {"type": "turn_aborted", "turn_id": "turn-a"}}
            rollout.write_text("\n".join(map(json.dumps, interrupted)) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(TerminalAnswerError, "interrupted"):
                store.acknowledge_rollout(rollout, task_id="task", run_id="run", outcome=outcome,
                                          delivery_stage="diagnosed")
            self.assertIn("final_answer_unconfirmed", qualify_terminal_answer(
                task_id="task", run_id="run", outcome=outcome, delivery_stage="diagnosed",
                record=TerminalAnswerStore(root / "answers.json").get("task"),
            )["failures"])
            recovered = completed_rollout("task", "turn-b", "final", "partial answer", observed)
            rollout.write_text("\n".join(map(json.dumps, interrupted + recovered[1:])) + "\n", encoding="utf-8")
            record = TerminalAnswerStore(root / "answers.json").acknowledge_rollout(
                rollout, task_id="task", run_id="run", outcome=outcome,
                delivery_stage="diagnosed",
            )
            self.assertEqual(record.host_event_id, "final")

    def test_stop_candidate_is_not_a_completed_host_delivery(self):
        outcome = {"status": "cancelled", "summary": "cancelled"}
        with tempfile.TemporaryDirectory() as raw:
            store = TerminalAnswerStore(Path(raw) / "answers.json")
            prepared = store.prepare(task_id="task", run_id="run", outcome=outcome,
                                     delivery_stage="unverified", text="cancelled")
            candidate = replace(prepared, delivered_at="2026-09-27T00:00:00+00:00",
                                host_event_id="codex-stop:turn", delivery_source="codex-stop-v1")
            self.assertIn("final_answer_unconfirmed", qualify_terminal_answer(
                task_id="task", run_id="run", outcome=outcome,
                delivery_stage="unverified", record=candidate,
            )["failures"])

    def test_wrong_turn_or_error_completion_cannot_confirm_a_final(self):
        outcome = {"status": "blocked", "summary": "blocked"}
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            store = TerminalAnswerStore(root / "answers.json")
            prepared = store.prepare(task_id="task", run_id="run", outcome=outcome,
                                     delivery_stage="diagnosed", text="blocked")
            observed = (datetime.fromisoformat(prepared.prepared_at) + timedelta(seconds=1)).isoformat()
            events = completed_rollout("task", "turn-a", "final-a", "blocked", observed)
            rollout = root / "rollout.jsonl"
            for completion in (
                {"type": "task_complete", "turn_id": "turn-b"},
                {"type": "task_complete", "turn_id": "turn-a", "error": {}},
            ):
                events[-1] = {"type": "event_msg", "timestamp": observed, "payload": completion}
                rollout.write_text("\n".join(map(json.dumps, events)) + "\n", encoding="utf-8")
                with self.assertRaisesRegex(TerminalAnswerError, "missing or interrupted"):
                    store.acknowledge_rollout(rollout, task_id="task", run_id="run",
                                              outcome=outcome, delivery_stage="diagnosed")

    def test_invalid_store_root_fails_closed(self):
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "answers.json"
            path.write_text("[]")
            with self.assertRaisesRegex(TerminalAnswerError, "not an object"):
                TerminalAnswerStore(path).get("task")


if __name__ == "__main__":
    unittest.main()
