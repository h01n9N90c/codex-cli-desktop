#!/usr/bin/env python3
"""
Unit & integration tests for scripts/sync-sessions.py.
Author    : Lê Hoàng Ngọc Tươi
License   : Apache-2.0
"""
from __future__ import annotations

import importlib.util
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

KIT_ROOT = Path(__file__).resolve().parent.parent
SYNC_SCRIPT = KIT_ROOT / "scripts" / "sync-sessions.py"

spec = importlib.util.spec_from_file_location("sync_sessions", SYNC_SCRIPT)
assert spec and spec.loader
sync_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sync_mod)


class TestSyncSessionsUpsert(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.lane1 = os.path.join(self.tmp.name, "lane1")
        self.lane2 = os.path.join(self.tmp.name, "lane2")
        os.makedirs(self.lane1, exist_ok=True)
        os.makedirs(self.lane2, exist_ok=True)

        self.st1 = os.path.join(self.lane1, "state_5.sqlite")
        self.st2 = os.path.join(self.lane2, "state_5.sqlite")

        # Source DB with 2 threads (1 pinned, 1 unpinned)
        c1 = sqlite3.connect(self.st1)
        c1.execute(
            """
            CREATE TABLE threads (
                id TEXT PRIMARY KEY,
                name TEXT,
                is_pinned INTEGER,
                thread_section_id TEXT,
                section_position INTEGER,
                section_entered_at_ms INTEGER,
                project_id TEXT,
                model_provider TEXT,
                approval_mode TEXT,
                cwd TEXT,
                created_at_ms INTEGER NOT NULL
            )
            """
        )
        c1.execute(
            "INSERT INTO threads VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "t-pinned-1",
                "Pinned Core Task",
                1,
                "sec-1",
                0,
                1000,
                "proj-1",
                "OpenAI",
                "on-request",
                "C:\\old\\path",
                123456,
            ),
        )
        c1.execute(
            "INSERT INTO threads VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "t-unpinned-2",
                "Casual Chat",
                0,
                None,
                None,
                None,
                None,
                "OpenAI",
                "on-request",
                "C:\\old\\path",
                123457,
            ),
        )
        c1.commit()
        c1.close()

        # Target DB starts COMPLETELY EMPTY (0 rows in threads!) + has an extra target-only NOT NULL column
        c2 = sqlite3.connect(self.st2)
        c2.execute(
            """
            CREATE TABLE threads (
                id TEXT PRIMARY KEY,
                name TEXT,
                is_pinned INTEGER,
                thread_section_id TEXT,
                section_position INTEGER,
                section_entered_at_ms INTEGER,
                project_id TEXT,
                model_provider TEXT,
                approval_mode TEXT,
                cwd TEXT,
                created_at_ms INTEGER NOT NULL,
                target_extra_flag INTEGER NOT NULL
            )
            """
        )
        c2.commit()
        c2.close()

        with open(os.path.join(self.lane1, "session_index.jsonl"), "w", encoding="utf-8") as f:
            f.write(json.dumps({"id": "t-pinned-1", "thread_name": "Pinned Core Task"}) + "\n")
            f.write(json.dumps({"id": "t-unpinned-2", "thread_name": "Casual Chat"}) + "\n")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_insert_missing_threads_into_empty_target_db(self) -> None:
        db_name, inserted, updated, pinned, synced_ids = sync_mod.sync_state_db(
            self.lane1,
            self.lane2,
            repo_path=self.tmp.name,
            approval_mode="on-request",
            pinned_only=False,
            dry_run=False,
        )
        self.assertEqual(db_name, "state_5.sqlite")
        self.assertEqual(inserted, 2)
        self.assertEqual(updated, 0)
        self.assertEqual(pinned, 1)
        self.assertEqual(synced_ids, {"t-pinned-1", "t-unpinned-2"})

        c2 = sqlite3.connect(self.st2)
        rows = {
            r[0]: r[1:]
            for r in c2.execute(
                "SELECT id, name, is_pinned, model_provider, approval_mode, cwd, target_extra_flag FROM threads"
            ).fetchall()
        }
        c2.close()

        self.assertIn("t-pinned-1", rows)
        self.assertIn("t-unpinned-2", rows)
        self.assertEqual(rows["t-pinned-1"][0], "Pinned Core Task")
        self.assertEqual(rows["t-pinned-1"][1], 1)
        self.assertEqual(rows["t-pinned-1"][2], "openai")
        self.assertEqual(rows["t-pinned-1"][3], "on-request")
        self.assertTrue(str(rows["t-pinned-1"][4]).endswith(os.path.basename(self.tmp.name)))
        self.assertEqual(rows["t-pinned-1"][5], 0)

        # Second run should UPDATE existing rows (0 inserted, 2 updated)
        _, inserted2, updated2, pinned2, _ = sync_mod.sync_state_db(
            self.lane1,
            self.lane2,
            repo_path=self.tmp.name,
            approval_mode="never",
            pinned_only=False,
            dry_run=False,
        )
        self.assertEqual(inserted2, 0)
        self.assertEqual(updated2, 2)
        self.assertEqual(pinned2, 1)

    def test_pinned_only_syncs_only_pinned_threads(self) -> None:
        _, inserted, updated, pinned, synced_ids = sync_mod.sync_state_db(
            self.lane1,
            self.lane2,
            repo_path=self.tmp.name,
            approval_mode="on-request",
            pinned_only=True,
            dry_run=False,
        )
        self.assertEqual(inserted, 1)
        self.assertEqual(updated, 0)
        self.assertEqual(pinned, 1)
        self.assertEqual(synced_ids, {"t-pinned-1"})

        idx_count = sync_mod.sync_session_index(
            self.lane1, self.lane2, dry_run=False, allowed_ids=synced_ids
        )
        self.assertEqual(idx_count, 1)

    def test_dry_run_does_not_mutate_target_db(self) -> None:
        _, inserted, updated, pinned, _ = sync_mod.sync_state_db(
            self.lane1,
            self.lane2,
            repo_path=self.tmp.name,
            approval_mode="on-request",
            pinned_only=False,
            dry_run=True,
        )
        self.assertEqual(inserted, 2)
        self.assertEqual(updated, 0)
        self.assertEqual(pinned, 1)

        c2 = sqlite3.connect(self.st2)
        count = c2.execute("SELECT COUNT(*) FROM threads").fetchone()[0]
        c2.close()
        self.assertEqual(count, 0)


if __name__ == "__main__":
    unittest.main()
