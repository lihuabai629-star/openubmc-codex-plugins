from __future__ import annotations

import json
import hashlib
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch


RUNTIME_ROOT = Path(os.environ['OPENUBMC_TEST_PLUGIN_ROOT']) / 'skills/openubmc-target-runtime' if os.environ.get('OPENUBMC_TEST_PLUGIN_ROOT') else Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RUNTIME_ROOT))

from openubmc_target_runtime import (  # noqa: E402
    ArtifactRef,
    LocalArtifactStore,
    ReferenceViolation,
    SQLiteArtifactRepository,
)




class ArtifactRetentionTests(unittest.TestCase):
    def test_gc_and_new_registration_leave_the_new_reference_readable(self) -> None:
        for persistent in (False, True):
            with self.subTest(persistent=persistent), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                now = [100.0]
                store = LocalArtifactStore(
                    content_root=root / "content",
                    repository=SQLiteArtifactRepository(root / "artifacts.sqlite") if persistent else None,
                    clock=lambda: now[0], temporary_retention_seconds=1,
                )
                source = root / "evidence.log"
                source.write_bytes(b"shared evidence")

                def register(run_id: str, retention: str):
                    return store.put(
                        source, kind="test-evidence", provenance="test",
                        retention_hint=retention, target="192.0.2.1", run_id=run_id,
                        created_by_effect=run_id + "-effect",
                    )

                old = register("old-run", "temporary")
                content_path = store.resolve(old)
                now[0] = 200.0
                deleting = threading.Event()
                resume_delete = threading.Event()
                unlink = os.unlink

                def delayed_unlink(path, *args, **kwargs):
                    if os.fspath(path) == str(content_path):
                        deleting.set()
                        if not resume_delete.wait(5):
                            raise TimeoutError("filesystem deletion was not released")
                    return unlink(path, *args, **kwargs)

                with patch("os.unlink", side_effect=delayed_unlink), ThreadPoolExecutor(max_workers=2) as executor:
                    collection = executor.submit(store.garbage_collect)
                    try:
                        self.assertTrue(deleting.wait(5), "GC did not reach the filesystem")
                        registration = executor.submit(register, "new-run", "audit")
                        try:
                            registration.result(timeout=2)
                        except FutureTimeout:
                            # Atomic implementations may serialize registration behind GC.
                            pass
                    finally:
                        resume_delete.set()
                    collection.result(timeout=5)
                    fresh = registration.result(timeout=5)
                self.assertEqual(store.resolve(fresh).read_bytes(), b"shared evidence")

    def test_managed_artifact_survives_store_restart_and_is_content_addressed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = root / "bundle.tar.gz"
            source.write_bytes(b"durable bundle")
            database = root / "artifacts.sqlite3"
            content = root / "content"

            first = LocalArtifactStore(
                content_root=content,
                repository=SQLiteArtifactRepository(database),
            )
            reference = first.put(
                source,
                kind="openubmc-log-bundle",
                provenance="log-bundle-collect",
                retention_hint="run-lifetime",
                target="192.0.2.10",
                run_id="run-artifact-1",
                created_by_effect="effect-collect-1",
            )

            self.assertEqual(
                reference.handle,
                f"artifact://sha256/{reference.digest}",
            )
            self.assertNotEqual(first.resolve(reference), source)

            reopened = LocalArtifactStore(
                content_root=content,
                repository=SQLiteArtifactRepository(database),
            )
            self.assertEqual(reopened.resolve(reference).read_bytes(), b"durable bundle")
            self.assertEqual(
                reopened.find(
                    kind="openubmc-log-bundle",
                    target="192.0.2.10",
                    run_id="run-artifact-1",
                    created_by_effect="effect-collect-1",
                ),
                reference,
            )

    def test_managed_artifact_fails_closed_for_scope_tampering_and_deleted_content(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = root / "bundle.tar.gz"
            source.write_bytes(b"trusted bundle")
            store = LocalArtifactStore(content_root=root / "content")
            reference = store.put(
                source,
                kind="openubmc-log-bundle",
                provenance="log-bundle-collect",
                retention_hint="temporary",
                target="192.0.2.20",
                run_id="run-artifact-2",
                created_by_effect="effect-collect-2",
            )

            with self.assertRaisesRegex(ReferenceViolation, "target"):
                store.resolve(reference, expected_target="192.0.2.21")
            with self.assertRaisesRegex(ReferenceViolation, "run_id"):
                store.resolve(reference, expected_run_id="another-run")
            with self.assertRaisesRegex(ReferenceViolation, "kind"):
                store.resolve(reference, expected_kinds=("openubmc-log-index",))

            managed_path = store.resolve(reference)
            managed_path.write_bytes(b"tampered bundle")
            with self.assertRaisesRegex(ReferenceViolation, "digest"):
                store.resolve(reference)

    def test_retention_release_and_gc_remove_only_expired_unprotected_records(self) -> None:
        now = [100.0]
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            store = LocalArtifactStore(
                content_root=root / "content",
                clock=lambda: now[0],
                temporary_retention_seconds=10,
            )
            source = root / "shared.json"
            source.write_text('{"password":"secret"}', encoding="utf-8")
            temporary = store.put(
                source,
                kind="temporary-result",
                provenance="test",
                retention_hint="temporary",
                target="192.0.2.30",
                run_id="run-temporary",
                created_by_effect="effect-temporary",
            )
            run_lifetime = store.put(
                source,
                kind="run-result",
                provenance="test",
                retention_hint="run-lifetime",
                target="192.0.2.30",
                run_id="run-retained",
                created_by_effect="effect-run",
            )
            audit = store.put(
                source,
                kind="audit-result",
                provenance="test",
                retention_hint="audit",
                target="192.0.2.30",
                run_id="run-audit",
                created_by_effect="effect-audit",
            )

            now[0] = 111.0
            first_gc = store.garbage_collect()
            self.assertEqual(first_gc["deleted_records"], 1)
            with self.assertRaisesRegex(ReferenceViolation, "unavailable"):
                store.resolve(temporary)
            self.assertTrue(store.resolve(run_lifetime).is_file())
            self.assertTrue(store.resolve(audit).is_file())

            self.assertEqual(store.release_run("run-retained"), 1)
            second_gc = store.garbage_collect()
            self.assertEqual(second_gc["deleted_records"], 1)
            with self.assertRaisesRegex(ReferenceViolation, "unavailable"):
                store.resolve(run_lifetime)
            self.assertTrue(store.resolve(audit).is_file())



if __name__ == "__main__":
    unittest.main()
