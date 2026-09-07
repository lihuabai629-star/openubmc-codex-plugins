from __future__ import annotations
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest

REPO_ROOT = Path(os.environ['OPENUBMC_TEST_PLUGIN_ROOT']) / 'skills' if os.environ.get('OPENUBMC_TEST_PLUGIN_ROOT') else Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / 'openubmc-target-runtime'))
sys.path.insert(0, str(REPO_ROOT / 'openubmc-upgrade'))
from openubmc_target_runtime import MutationJournalStore, RuntimeMcpService
from openubmc_upgrade.runtime_backend import UpgradeMcpBackend, RedfishResponse
from redfish_fixture import FakeRedfishSession, FakeRedfishTransport

TEST_DEADLINE_SECONDS = 30


class UpgradeTaskStateTests(unittest.TestCase):
    def test_interrupted_task_resumes_and_verifies_without_reupload_on_replay(self) -> None:
        class ResumingSession(FakeRedfishSession):
            def __init__(self, number):
                super().__init__(number)
                self.states = iter(("Interrupted", "Running", "Completed"))

            def request_json(self, method, path, **kwargs):
                if path == "/redfish/v1/TaskService/Tasks/1":
                    self.calls.append((method, path))
                    return RedfishResponse(status=200, headers={}, payload={"TaskState": next(self.states)})
                return super().request_json(method, path, **kwargs)

        class ResumingTransport(FakeRedfishTransport):
            def open_session(self, **kwargs):
                self.opens += 1
                session = ResumingSession(self.opens)
                self.sessions.append(session)
                return session

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            artifact = root / "firmware.hpm"
            artifact.write_bytes(b"firmware")
            transport = ResumingTransport()
            service = RuntimeMcpService(UpgradeMcpBackend(
                journal_store=MutationJournalStore(root / "journals"),
                credential_loader=lambda _arguments: {"redfish": {"user": "operator", "password": "dummy-secret"}},
                redfish_transport_factory=lambda _arguments: transport,
            ))
            arguments = {
                "intent": "upgrade-and-verify", "ip": "bmc.example",
                "artifact_path": str(artifact), "artifact_sha256": hashlib.sha256(b"firmware").hexdigest(),
                "product_version": "2.0.0", "deadline": TEST_DEADLINE_SECONDS,
            }
            try:
                result = service.call_tool("upgrade_run", arguments, task_id="task-upgrade", operation_id="upgrade-1")
                replayed = service.call_tool("upgrade_run", arguments, task_id="task-upgrade", operation_id="upgrade-1")
            finally:
                service.close()
            self.assertEqual(result["journal"]["stage"], "verified")
            self.assertEqual(result["verification"]["installed_version"], "2.0.0")
            self.assertTrue(replayed["idempotent_replay"])
            uploads = [call for session in transport.sessions for call in session.calls
                       if call == ("POST", "/redfish/v1/UpdateService/upload")]
            self.assertEqual(len(uploads), 1)
            self.assertGreaterEqual(transport.opens, 2)

    def test_interrupted_task_obeys_deadline_and_real_failures_still_fail(self) -> None:
        for state, error in (("Interrupted", TimeoutError), ("Exception", RuntimeError), ("Cancelled", RuntimeError)):
            with self.subTest(state=state), tempfile.TemporaryDirectory() as raw:
                class TaskSession(FakeRedfishSession):
                    def request_json(self, method, path, **kwargs):
                        if path == "/redfish/v1/TaskService/Tasks/1":
                            self.calls.append((method, path))
                            return RedfishResponse(status=200, headers={}, payload={"TaskState": state})
                        return super().request_json(method, path, **kwargs)

                class TaskTransport(FakeRedfishTransport):
                    def open_session(self, **kwargs):
                        self.opens += 1
                        session = TaskSession(self.opens)
                        self.sessions.append(session)
                        return session

                root = Path(raw)
                artifact = root / "firmware.hpm"
                artifact.write_bytes(b"firmware")
                transport = TaskTransport()
                service = RuntimeMcpService(UpgradeMcpBackend(
                    journal_store=MutationJournalStore(root / "journals"),
                    credential_loader=lambda _arguments: {"redfish": {"user": "operator", "password": "dummy-secret"}},
                    redfish_transport_factory=lambda _arguments: transport,
                ))
                started = time.monotonic()
                try:
                    with self.assertRaises(error):
                        service.call_tool("upgrade_run", {
                            "intent": "upgrade-and-verify", "ip": "bmc.example",
                            "artifact_path": str(artifact), "artifact_sha256": hashlib.sha256(b"firmware").hexdigest(),
                            "product_version": "2.0.0", "deadline": 1.0,
                        }, task_id="task-upgrade", operation_id="upgrade-1")
                finally:
                    service.close()
                self.assertLess(time.monotonic() - started, 5)
                uploads = [call for session in transport.sessions for call in session.calls
                           if call == ("POST", "/redfish/v1/UpdateService/upload")]
                self.assertEqual(len(uploads), 1)



if __name__ == "__main__":
    unittest.main()
