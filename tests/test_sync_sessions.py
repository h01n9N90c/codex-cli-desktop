#!/usr/bin/env python3
"""
Unit & adversarial safety tests for scripts/sync-sessions.py.

Author    : Lê Hoàng Ngọc Tươi
Copyright : Copyright 2026 Lê Hoàng Ngọc Tươi
License   : Apache-2.0 (https://www.apache.org/licenses/LICENSE-2.0)

Each test documents:
  - WHAT behavior or security invariant is verified
  - WHICH threat, data-loss mode, or regression it prevents
"""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

KIT_ROOT = Path(__file__).resolve().parent.parent
SYNC_SCRIPT = KIT_ROOT / "scripts" / "sync-sessions.py"

# Avoid polluting scripts/__pycache__ when loading the hyphenated script module directly.
_prev_dont_write_bytecode = sys.dont_write_bytecode
sys.dont_write_bytecode = True
try:
    spec = importlib.util.spec_from_file_location("sync_sessions", SYNC_SCRIPT)
    assert spec and spec.loader
    sync_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sync_mod)
finally:
    sys.dont_write_bytecode = _prev_dont_write_bytecode


def _sha256_file(path: str | Path) -> str:
    """Compute hex SHA-256 digest of a file for byte-for-byte immutability assertions."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _dir_snapshot(directory: str | Path) -> dict[str, str]:
    """Return {relative_path: sha256} for every regular file under a directory."""
    root = Path(directory)
    snap: dict[str, str] = {}
    for entry in sorted(root.rglob("*")):
        if entry.is_file() and not entry.is_symlink():
            snap[str(entry.relative_to(root))] = _sha256_file(entry)
    return snap


def _can_create_symlinks(tmp_dir: str) -> bool:
    """Detect whether the current OS account has privilege to create filesystem symlinks."""
    probe_target = os.path.join(tmp_dir, "_symlink_probe_target")
    probe_link = os.path.join(tmp_dir, "_symlink_probe_link")
    with open(probe_target, "w", encoding="utf-8") as handle:
        handle.write("probe")
    try:
        os.symlink(probe_target, probe_link)
        return True
    except (OSError, NotImplementedError):
        return False
    finally:
        for p in (probe_link, probe_target):
            try:
                os.unlink(p)
            except OSError:
                pass


class TestSyncSessionsSafetyAndUpsert(unittest.TestCase):
    """Comprehensive functional and adversarial safety tests for scripts/sync-sessions.py."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.lane1 = os.path.join(self.tmp.name, "lane1")
        self.lane2 = os.path.join(self.tmp.name, "lane2")
        os.makedirs(self.lane1, exist_ok=True)
        os.makedirs(self.lane2, exist_ok=True)

        self.st1 = os.path.join(self.lane1, "state_5.sqlite")
        self.st2 = os.path.join(self.lane2, "state_5.sqlite")

        # Seed Lane 1 source DB with 1 pinned thread, 1 unpinned thread, and shared metadata.
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
            """
            CREATE TABLE thread_sections (
                id TEXT PRIMARY KEY,
                title TEXT
            )
            """
        )
        c1.execute("INSERT INTO thread_sections VALUES (?, ?)", ("sec-1", "Core"))
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

        # Seed Lane 2 target DB completely empty (0 rows) plus a target-only NOT NULL
        # column with no DEFAULT to exercise forward schema-drift resilience.
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
        c2.execute(
            """
            CREATE TABLE thread_sections (
                id TEXT PRIMARY KEY,
                title TEXT
            )
            """
        )
        c2.commit()
        c2.close()

        with open(
            os.path.join(self.lane1, "session_index.jsonl"),
            "w",
            encoding="utf-8",
            newline="\n",
        ) as handle:
            handle.write(
                json.dumps({"id": "t-pinned-1", "thread_name": "Pinned Core Task"}) + "\n"
            )
            handle.write(
                json.dumps({"id": "t-unpinned-2", "thread_name": "Casual Chat"}) + "\n"
            )

    def tearDown(self) -> None:
        # Ensure any read-only permissions set during tests are cleared before cleanup on Windows.
        for root, _, files in os.walk(self.tmp.name):
            for fname in files:
                fpath = os.path.join(root, fname)
                if not os.path.islink(fpath):
                    try:
                        os.chmod(fpath, stat.S_IWRITE | stat.S_IREAD)
                    except OSError:
                        pass
        self.tmp.cleanup()

    # ------------------------------------------------------------------
    # 1. Read-Only Source DB Enforcement
    # ------------------------------------------------------------------

    def test_source_db_is_opened_strictly_readonly_and_never_mutated(self) -> None:
        """
        WHAT: Verifies `connect_readonly` enforces SQLite `?mode=ro` + `PRAGMA query_only=ON`,
              and full `sync_state_db` leaves Lane 1 source DB byte-identical even when
              the source file is marked OS read-only.
        PREVENTS: Blocking active Lane 1 Codex Desktop/CLI sessions with write locks or
                  accidentally mutating primary user conversation history.
        """
        conn = sync_mod.connect_readonly(self.st1)
        try:
            query_only = conn.execute("PRAGMA query_only").fetchone()[0]
            self.assertEqual(query_only, 1)
            with self.assertRaises(sqlite3.OperationalError):
                conn.execute("DELETE FROM threads")
        finally:
            conn.close()

        # Mark source DB read-only at the OS permission level and hash before sync.
        os.chmod(self.st1, stat.S_IREAD)
        src_hash_before = _sha256_file(self.st1)

        db_name, inserted, updated, pinned, _ = sync_mod.sync_state_db(
            self.lane1,
            self.lane2,
            repo_path=self.tmp.name,
            approval_mode="on-request",
            pinned_only=False,
            dry_run=False,
        )
        self.assertEqual(db_name, "state_5.sqlite")
        self.assertEqual((inserted, updated, pinned), (2, 0, 1))
        self.assertEqual(_sha256_file(self.st1), src_hash_before)

    # ------------------------------------------------------------------
    # 2. SQLite UPSERT Idempotency & Data-Loss Prevention
    # ------------------------------------------------------------------

    def test_upsert_idempotency_insert_update_without_data_loss(self) -> None:
        """
        WHAT: Verifies first sync inserts missing rows into an empty target DB (filling
              target-only NOT NULL columns safely), second sync updates existing rows
              idempotently without deleting Lane-2-only rows, and COALESCE prevents a NULL
              source title from wiping an existing Lane 2 thread name.
        PREVENTS: Data loss of Lane 2 local threads, duplicate rows on repeated syncs,
                  NOT NULL constraint crashes across Codex schema versions, and blanked titles.
        """
        # Seed a Lane-2-only thread that does NOT exist in Lane 1.
        c2 = sqlite3.connect(self.st2)
        c2.execute(
            "INSERT INTO threads VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "t-lane2-local",
                "Lane 2 Native Work",
                1,
                None,
                None,
                None,
                None,
                "openai",
                "on-request",
                "C:\\lane2\\only",
                999999,
                7,
            ),
        )
        c2.commit()
        c2.close()

        # Pass 1: INSERT the 2 Lane 1 rows while preserving t-lane2-local.
        db_name, inserted, updated, pinned, synced_ids = sync_mod.sync_state_db(
            self.lane1,
            self.lane2,
            repo_path=self.tmp.name,
            approval_mode="on-request",
            pinned_only=False,
            dry_run=False,
        )
        self.assertEqual(db_name, "state_5.sqlite")
        self.assertEqual((inserted, updated, pinned), (2, 0, 1))
        self.assertEqual(synced_ids, {"t-pinned-1", "t-unpinned-2"})

        c2 = sqlite3.connect(self.st2)
        rows = {
            r[0]: r[1:]
            for r in c2.execute(
                "SELECT id, name, is_pinned, model_provider, approval_mode, cwd, target_extra_flag FROM threads"
            ).fetchall()
        }
        sections = c2.execute("SELECT id, title FROM thread_sections").fetchall()
        c2.close()

        self.assertEqual(set(rows.keys()), {"t-pinned-1", "t-unpinned-2", "t-lane2-local"})
        self.assertEqual(rows["t-pinned-1"][0], "Pinned Core Task")
        self.assertEqual(rows["t-pinned-1"][1], 1)
        self.assertEqual(rows["t-pinned-1"][2], "openai")
        self.assertEqual(rows["t-pinned-1"][3], "on-request")
        self.assertTrue(str(rows["t-pinned-1"][4]).endswith(os.path.basename(self.tmp.name)))
        self.assertEqual(rows["t-pinned-1"][5], 0)
        # Target-only row and its target-only column remain untouched.
        self.assertEqual(rows["t-lane2-local"][0], "Lane 2 Native Work")
        self.assertEqual(rows["t-lane2-local"][5], 7)
        self.assertEqual(sections, [("sec-1", "Core")])

        # Mutate source: set t-pinned-1 name to NULL to verify COALESCE preserves target title.
        c1 = sqlite3.connect(self.st1)
        c1.execute("UPDATE threads SET name = NULL WHERE id = ?", ("t-pinned-1",))
        c1.commit()
        c1.close()

        # Pass 2: UPDATE existing rows idempotently (0 inserted, 2 updated).
        _, inserted2, updated2, pinned2, _ = sync_mod.sync_state_db(
            self.lane1,
            self.lane2,
            repo_path=self.tmp.name,
            approval_mode="never",
            pinned_only=False,
            dry_run=False,
        )
        self.assertEqual((inserted2, updated2, pinned2), (0, 2, 1))

        # Pass 3: Re-running a third time stays idempotent (still 3 total rows, 0 inserted).
        _, inserted3, updated3, pinned3, _ = sync_mod.sync_state_db(
            self.lane1,
            self.lane2,
            repo_path=self.tmp.name,
            approval_mode="never",
            pinned_only=False,
            dry_run=False,
        )
        self.assertEqual((inserted3, updated3, pinned3), (0, 2, 1))

        c2 = sqlite3.connect(self.st2)
        rows_after = {
            r[0]: r[1:]
            for r in c2.execute(
                "SELECT id, name, approval_mode, target_extra_flag FROM threads"
            ).fetchall()
        }
        c2.close()
        self.assertEqual(len(rows_after), 3)
        self.assertEqual(rows_after["t-pinned-1"][0], "Pinned Core Task")
        self.assertEqual(rows_after["t-pinned-1"][1], "never")
        self.assertEqual(rows_after["t-lane2-local"][0], "Lane 2 Native Work")
        self.assertEqual(rows_after["t-lane2-local"][2], 7)

    def test_pinned_only_syncs_only_pinned_threads_and_index_entries(self) -> None:
        """
        WHAT: Verifies `--pinned-only` syncs only pinned threads into SQLite and filters
              `session_index.jsonl` via `allowed_ids`.
        PREVENTS: Leaking casual/unpinned Lane 1 sessions into Lane 2 when users opt into
                  minimal pinned-only metadata sharing.
        """
        _, inserted, updated, pinned, synced_ids = sync_mod.sync_state_db(
            self.lane1,
            self.lane2,
            repo_path=self.tmp.name,
            approval_mode="on-request",
            pinned_only=True,
            dry_run=False,
        )
        self.assertEqual((inserted, updated, pinned), (1, 0, 1))
        self.assertEqual(synced_ids, {"t-pinned-1"})

        idx_count = sync_mod.sync_session_index(
            self.lane1, self.lane2, dry_run=False, allowed_ids=synced_ids
        )
        self.assertEqual(idx_count, 1)
        idx2_content = Path(self.lane2, "session_index.jsonl").read_text(encoding="utf-8")
        self.assertIn("t-pinned-1", idx2_content)
        self.assertNotIn("t-unpinned-2", idx2_content)

    def test_goals_db_sync_is_idempotent(self) -> None:
        """
        WHAT: Verifies `sync_goals_db` mirrors `thread_goals` idempotently from Lane 1 to Lane 2.
        PREVENTS: Regressions in Goals database synchronization or duplicate goal records.
        """
        g1 = os.path.join(self.lane1, "goals_2.sqlite")
        g2 = os.path.join(self.lane2, "goals_2.sqlite")
        for db in (g1, g2):
            conn = sqlite3.connect(db)
            conn.execute("CREATE TABLE thread_goals (id TEXT PRIMARY KEY, title TEXT)")
            conn.commit()
            conn.close()
        c1 = sqlite3.connect(g1)
        c1.execute("INSERT INTO thread_goals VALUES (?, ?)", ("g-1", "Ship hardening"))
        c1.commit()
        c1.close()

        self.assertEqual(sync_mod.sync_goals_db(self.lane1, self.lane2, dry_run=False), 1)
        self.assertEqual(sync_mod.sync_goals_db(self.lane1, self.lane2, dry_run=False), 1)

        c2 = sqlite3.connect(g2)
        rows = c2.execute("SELECT id, title FROM thread_goals").fetchall()
        c2.close()
        self.assertEqual(rows, [("g-1", "Ship hardening")])

    def test_sql_identifier_allowlist_blocks_second_order_sqli(self) -> None:
        """
        WHAT: Verifies `validate_sql_identifier` and `quote_identifier` reject crafted SQL
              identifiers and non-allowlisted table names.
        PREVENTS: Second-order SQL injection via malicious column or table names embedded in
                  an untrusted SQLite schema.
        """
        for bad_ident in (
            "threads; DROP TABLE threads--",
            'col"name',
            "1starts_with_digit",
            "",
            "name WITH SPACE",
        ):
            with self.assertRaises(ValueError):
                sync_mod.validate_sql_identifier(bad_ident)

        with self.assertRaises(ValueError):
            sync_mod.quote_identifier("sqlite_master", allowed_tables=sync_mod.ALLOWED_TABLES)
        with self.assertRaises(ValueError):
            sync_mod.quote_identifier("arbitrary_table", allowed_tables=sync_mod.ALLOWED_TABLES)

        self.assertEqual(
            sync_mod.quote_identifier("threads", allowed_tables=sync_mod.ALLOWED_TABLES),
            '"threads"',
        )

    # ------------------------------------------------------------------
    # 3. Atomic JSONL Sync
    # ------------------------------------------------------------------

    def test_atomic_jsonl_sync_merges_safely_and_survives_replace_failure(self) -> None:
        """
        WHAT: Verifies `sync_session_index` preserves existing Lane 2 entries, ignores malformed
              JSON lines and non-object JSON records, writes LF-only UTF-8 atomically with zero
              leftover `.tmp` files, enforces `0600` on POSIX, and leaves the original file
              untouched if `os.replace` fails mid-flight.
        PREVENTS: Truncation/corruption of `session_index.jsonl` on crash/disk-full, loss of
                  Lane 2 local index entries, and world-readable session metadata on Unix.
        """
        idx1 = Path(self.lane1, "session_index.jsonl")
        idx2 = Path(self.lane2, "session_index.jsonl")

        # Include malformed JSON, JSON arrays, missing ids, and valid entries in source.
        idx1.write_text(
            "\n".join(
                [
                    json.dumps({"id": "t-pinned-1", "thread_name": "Updated From Lane 1"}),
                    "{not valid json",
                    '["not-an-object"]',
                    '{"id": true, "thread_name": "bool-id-ignored"}',
                    json.dumps({"id": "t-unpinned-2", "thread_name": "Casual Chat"}),
                ]
            )
            + "\n",
            encoding="utf-8",
            newline="\n",
        )
        # Pre-seed Lane 2 with its own entry plus an older version of t-pinned-1.
        orig_lane2_content = (
            json.dumps({"id": "t-lane2-only", "thread_name": "Keep Me"})
            + "\n"
            + json.dumps({"id": "t-pinned-1", "thread_name": "Old Title"})
            + "\n"
        )
        idx2.write_text(orig_lane2_content, encoding="utf-8", newline="\n")

        # 1) Simulate failure during os.replace: original file must remain intact and no .tmp left.
        with mock.patch.object(sync_mod.os, "replace", side_effect=OSError("simulated disk full")):
            with self.assertRaises(OSError):
                sync_mod.sync_session_index(self.lane1, self.lane2, dry_run=False)
        self.assertEqual(idx2.read_text(encoding="utf-8"), orig_lane2_content)
        leftover_tmps = list(Path(self.lane2).glob("*.tmp"))
        self.assertEqual(leftover_tmps, [])

        # 2) Normal atomic sync succeeds cleanly with LF line endings and zero temp leftovers.
        count = sync_mod.sync_session_index(self.lane1, self.lane2, dry_run=False)
        self.assertEqual(count, 3)
        raw_bytes = idx2.read_bytes()
        self.assertNotIn(b"\r\n", raw_bytes)
        merged = {
            json.loads(line)["id"]: json.loads(line)["thread_name"]
            for line in raw_bytes.decode("utf-8").splitlines()
            if line.strip()
        }
        self.assertEqual(
            merged,
            {
                "t-lane2-only": "Keep Me",
                "t-pinned-1": "Updated From Lane 1",
                "t-unpinned-2": "Casual Chat",
            },
        )
        self.assertEqual(list(Path(self.lane2).glob("*.tmp")), [])
        if os.name == "posix":
            mode = stat.S_IMODE(os.stat(idx2).st_mode)
            self.assertEqual(mode, 0o600)

    # ------------------------------------------------------------------
    # 4. Path-Traversal, Symlink & Same-Lane Rejection
    # ------------------------------------------------------------------

    def test_path_traversal_and_escape_rejected(self) -> None:
        """
        WHAT: Verifies `ensure_contained_path` rejects `..` traversal, NUL bytes, sibling
              directory escapes, and base-directory self-references, and `_assert_distinct_lanes`
              rejects syncing a CODEX_HOME onto itself.
        PREVENTS: Arbitrary file read/overwrite outside CODEX_HOME and self-clobbering syncs.
        """
        with self.assertRaises(ValueError):
            sync_mod.ensure_contained_path(self.lane1, os.path.join(self.lane1, "..", "escape.txt"))
        with self.assertRaises(ValueError):
            sync_mod.ensure_contained_path(self.lane1, "../escape.txt")
        with self.assertRaises(ValueError):
            sync_mod.ensure_contained_path(self.lane1, "bad\x00name")
        with self.assertRaises(ValueError):
            sync_mod.ensure_contained_path(self.lane1, self.lane2)
        with self.assertRaises(ValueError):
            sync_mod.ensure_contained_path(self.lane1, self.lane1)

        # Identical lane1 and lane2 must fail closed with ValueError (and CLI exit code 1).
        with self.assertRaises(ValueError):
            sync_mod.sync_state_db(self.lane1, self.lane1, None, None, False, False)

        stderr_buf = io.StringIO()
        with (
            mock.patch.object(sys, "argv", ["sync-sessions.py", "--lane1", self.lane1, "--lane2", self.lane1]),
            contextlib.redirect_stderr(stderr_buf),
        ):
            rc = sync_mod.main()
        self.assertEqual(rc, 1)
        self.assertIn("Security violation", stderr_buf.getvalue())

    def test_symlink_rejection_in_session_index_and_sqlite_and_sidecars(self) -> None:
        """
        WHAT: Verifies symlinks planted for `session_index.jsonl`, `state_*.sqlite`, or
              SQLite `-wal` sidecars are rejected with ValueError (exercised via real OS
              symlinks when supported AND via mocked `os.path.islink` so Windows CI without
              SeCreateSymbolicLinkPrivilege still verifies every rejection branch).
        PREVENTS: Symlink-clobbering attacks redirecting reads or atomic writes outside CODEX_HOME.
        """
        # Part A: Deterministic mocked symlink checks (always runs on every OS/privilege level).
        idx2_path = os.path.join(self.lane2, "session_index.jsonl")
        real_islink = os.path.islink

        def fake_islink_idx2(p: object) -> bool:
            return os.path.abspath(os.fspath(p)) == os.path.abspath(idx2_path) or real_islink(p)

        with mock.patch.object(sync_mod.os.path, "islink", side_effect=fake_islink_idx2):
            with self.assertRaises(ValueError):
                sync_mod.sync_session_index(self.lane1, self.lane2, dry_run=False)

        wal_path = self.st2 + "-wal"
        Path(wal_path).write_bytes(b"")

        def fake_islink_wal(p: object) -> bool:
            return os.path.abspath(os.fspath(p)) == os.path.abspath(wal_path) or real_islink(p)

        with mock.patch.object(sync_mod.os.path, "islink", side_effect=fake_islink_wal):
            with self.assertRaises(ValueError):
                sync_mod.sync_state_db(self.lane1, self.lane2, None, None, False, False)
        os.unlink(wal_path)

        # Intra-root loop symlink (lane2/loop -> lane2) must be rejected before base_real short-circuit.
        loop_path = os.path.join(self.lane2, "loop")

        def fake_islink_loop(p: object) -> bool:
            return os.path.abspath(os.fspath(p)) == os.path.abspath(loop_path) or real_islink(p)

        with mock.patch.object(sync_mod.os.path, "islink", side_effect=fake_islink_loop):
            with self.assertRaises(ValueError):
                sync_mod.ensure_contained_path(
                    self.lane2, os.path.join(loop_path, "state_5.sqlite"), reject_symlinks=True
                )

        # Part B: Real filesystem symlink checks whenever OS allows symlink creation.
        if _can_create_symlinks(self.tmp.name):
            outside_file = os.path.join(self.tmp.name, "outside_secret.txt")
            Path(outside_file).write_text("DO_NOT_OVERWRITE", encoding="utf-8")

            # Dangling or live symlink at target session_index.jsonl must be rejected.
            os.symlink(outside_file, idx2_path)
            with self.assertRaises(ValueError):
                sync_mod.sync_session_index(self.lane1, self.lane2, dry_run=False)
            self.assertEqual(Path(outside_file).read_text(encoding="utf-8"), "DO_NOT_OVERWRITE")
            os.unlink(idx2_path)

            # Symlink masquerading as state_99.sqlite in lane2 must be rejected.
            fake_db_link = os.path.join(self.lane2, "state_99.sqlite")
            os.symlink(outside_file, fake_db_link)
            with self.assertRaises(ValueError):
                sync_mod.sync_state_db(self.lane1, self.lane2, None, None, False, False)
            os.unlink(fake_db_link)

            # Real intra-root loop symlink (lane2/loop -> lane2) must also be rejected.
            os.symlink(self.lane2, loop_path, target_is_directory=True)
            try:
                with self.assertRaises(ValueError):
                    sync_mod.ensure_contained_path(
                        self.lane2, os.path.join(loop_path, "state_5.sqlite"), reject_symlinks=True
                    )
            finally:
                os.unlink(loop_path)

    # ------------------------------------------------------------------
    # 5. --dry-run Zero-Mutation Guarantee
    # ------------------------------------------------------------------

    def test_dry_run_causes_zero_filesystem_mutations(self) -> None:
        """
        WHAT: Verifies `--dry-run` reports accurate sync counts while leaving every file and
              directory entry in BOTH `lane1` and `lane2` 100% byte-identical (no SQLite writes,
              no WAL/SHM sidecars created, no `session_index.jsonl` created or modified).
        PREVENTS: `--dry-run` silently creating sidecar files, mutating target SQLite pages,
                  or writing JSONL output during preview runs.
        """
        g1 = os.path.join(self.lane1, "goals_1.sqlite")
        g2 = os.path.join(self.lane2, "goals_1.sqlite")
        for db in (g1, g2):
            conn = sqlite3.connect(db)
            conn.execute("CREATE TABLE thread_goals (id TEXT PRIMARY KEY, title TEXT)")
            conn.commit()
            conn.close()
        c1 = sqlite3.connect(g1)
        c1.execute("INSERT INTO thread_goals VALUES (?, ?)", ("g-dry", "Dry goal"))
        c1.commit()
        c1.close()

        snap_lane1_before = _dir_snapshot(self.lane1)
        snap_lane2_before = _dir_snapshot(self.lane2)

        stdout_buf = io.StringIO()
        with (
            mock.patch.object(
                sys,
                "argv",
                [
                    "sync-sessions.py",
                    "--lane1",
                    self.lane1,
                    "--lane2",
                    self.lane2,
                    "--repo",
                    self.tmp.name,
                    "--approval-mode",
                    "on-request",
                    "--dry-run",
                ],
            ),
            contextlib.redirect_stdout(stdout_buf),
        ):
            rc = sync_mod.main()

        self.assertEqual(rc, 0)
        out = stdout_buf.getvalue()
        self.assertIn("[DRY-RUN]", out)
        self.assertIn("inserted=2, updated=0, pinned=1", out)
        self.assertIn("session_index=2", out)
        self.assertIn("goals=1", out)

        # Every file hash and directory listing in both lanes must be 100% unchanged.
        self.assertEqual(_dir_snapshot(self.lane1), snap_lane1_before)
        self.assertEqual(_dir_snapshot(self.lane2), snap_lane2_before)
        self.assertFalse(os.path.exists(os.path.join(self.lane2, "session_index.jsonl")))

    # ------------------------------------------------------------------
    # 6. Missing, Corrupt, and Locked DB Graceful Handling + Zero Secret Leak
    # ------------------------------------------------------------------

    def test_missing_and_corrupt_dbs_handled_gracefully_without_target_corruption(self) -> None:
        """
        WHAT: Verifies missing source/target DBs, corrupt source DB, corrupt target DB, and
              corrupt Goals DB degrade gracefully (returning zero counts and warnings) while
              keeping any valid target database 100% byte-intact.
        PREVENTS: Unhandled crashes or half-written target corruption when one lane has not
                  been initialized yet or suffered an external SQLite disk error.
        """
        # 1) Missing target DB -> graceful no-op, must NOT create an empty placeholder DB.
        empty_lane2 = os.path.join(self.tmp.name, "empty_lane2")
        os.makedirs(empty_lane2, exist_ok=True)
        with contextlib.redirect_stdout(io.StringIO()):
            res = sync_mod.sync_state_db(self.lane1, empty_lane2, None, None, False, False)
        self.assertEqual(res, (None, 0, 0, 0, set()))
        self.assertEqual(os.listdir(empty_lane2), [])

        # 2) Corrupt source DB -> target DB remains completely untouched (exact SHA-256).
        c2 = sqlite3.connect(self.st2)
        c2.execute(
            "INSERT INTO threads VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("t-keep", "Preexisting", 1, None, None, None, None, "openai", "on-request", "C:\\x", 1, 1),
        )
        c2.commit()
        c2.close()
        target_hash_before = _sha256_file(self.st2)

        Path(self.st1).write_bytes(b"NOT_A_VALID_SQLITE_HEADER_CORRUPT_DATA" * 16)
        stderr_buf = io.StringIO()
        with contextlib.redirect_stderr(stderr_buf):
            res_corrupt = sync_mod.sync_state_db(self.lane1, self.lane2, None, None, False, False)
        self.assertEqual(res_corrupt, (None, 0, 0, 0, set()))
        self.assertIn("[WARN]", stderr_buf.getvalue())
        self.assertEqual(_sha256_file(self.st2), target_hash_before)

        # 3) Corrupt target DB -> graceful no-op, source DB remains byte-identical.
        corrupt_lane2 = os.path.join(self.tmp.name, "corrupt_lane2")
        os.makedirs(corrupt_lane2, exist_ok=True)
        Path(corrupt_lane2, "state_5.sqlite").write_bytes(b"CORRUPT_TARGET_SQLITE_BYTES" * 16)
        # Re-create a valid source DB in a separate lane1_valid dir to test corrupt target alone.
        valid_lane1 = os.path.join(self.tmp.name, "valid_lane1")
        os.makedirs(valid_lane1, exist_ok=True)
        valid_st1 = os.path.join(valid_lane1, "state_5.sqlite")
        cv = sqlite3.connect(valid_st1)
        cv.execute("CREATE TABLE threads (id TEXT PRIMARY KEY, name TEXT)")
        cv.execute("INSERT INTO threads VALUES (?, ?)", ("t-1", "Valid"))
        cv.commit()
        cv.close()
        valid_src_hash = _sha256_file(valid_st1)
        stderr_tgt = io.StringIO()
        with contextlib.redirect_stderr(stderr_tgt):
            res_tgt = sync_mod.sync_state_db(valid_lane1, corrupt_lane2, None, None, False, False)
        self.assertEqual(res_tgt, (None, 0, 0, 0, set()))
        self.assertIn("[WARN]", stderr_tgt.getvalue())
        self.assertEqual(_sha256_file(valid_st1), valid_src_hash)

        # 4) Corrupt goals DB -> graceful return 0 without crashing.
        Path(self.lane1, "goals_1.sqlite").write_bytes(b"CORRUPT_GOALS_BYTES" * 10)
        Path(self.lane2, "goals_1.sqlite").write_bytes(b"CORRUPT_GOALS_BYTES" * 10)
        stderr_goals = io.StringIO()
        with contextlib.redirect_stderr(stderr_goals):
            goals_rc = sync_mod.sync_goals_db(self.lane1, self.lane2, dry_run=False)
        self.assertEqual(goals_rc, 0)
        self.assertIn("[WARN]", stderr_goals.getvalue())

    def test_locked_target_db_times_out_gracefully_and_preserves_data(self) -> None:
        """
        WHAT: Verifies an exclusively locked target DB times out cleanly via SQLite busy
              handling (without raising an unhandled exception or corrupting existing rows).
        PREVENTS: Sync crashes or partial writes when Codex Desktop holds an exclusive lock.
        """
        c2 = sqlite3.connect(self.st2)
        c2.execute(
            "INSERT INTO threads VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("t-safe", "Safe Row", 1, None, None, None, None, "openai", "on-request", "C:\\x", 1, 1),
        )
        c2.commit()
        c2.close()

        # Hold an EXCLUSIVE lock on the target DB while using a short busy timeout for fast CI.
        locker = sqlite3.connect(self.st2, isolation_level=None)
        try:
            locker.execute("BEGIN EXCLUSIVE")
            stderr_buf = io.StringIO()
            with (
                mock.patch.object(sync_mod, "DEFAULT_BUSY_TIMEOUT_SEC", 0.05),
                contextlib.redirect_stderr(stderr_buf),
            ):
                res = sync_mod.sync_state_db(self.lane1, self.lane2, None, None, False, False)
            self.assertEqual(res, (None, 0, 0, 0, set()))
            self.assertIn("[WARN]", stderr_buf.getvalue())
        finally:
            locker.execute("ROLLBACK")
            locker.close()

        # Verify pre-existing target row survived the lock contention completely intact.
        verify = sqlite3.connect(self.st2)
        rows = verify.execute("SELECT id, name FROM threads").fetchall()
        verify.close()
        self.assertEqual(rows, [("t-safe", "Safe Row")])

    def test_cli_output_never_leaks_thread_titles_or_secrets(self) -> None:
        """
        WHAT: Verifies CLI stdout/stderr report only DB basenames and integer counts, never
              printing thread titles or JSONL contents.
        PREVENTS: Accidental secret/PII leakage into CI logs or terminal transcripts when
                  users include sensitive identifiers in thread titles.
        """
        canary = "SUPER_SECRET_CANARY_TOKEN_994422"
        c1 = sqlite3.connect(self.st1)
        c1.execute("UPDATE threads SET name = ? WHERE id = ?", (canary, "t-pinned-1"))
        c1.commit()
        c1.close()
        Path(self.lane1, "session_index.jsonl").write_text(
            json.dumps({"id": "t-pinned-1", "thread_name": canary}) + "\n",
            encoding="utf-8",
            newline="\n",
        )

        stdout_buf = io.StringIO()
        stderr_buf = io.StringIO()
        with (
            mock.patch.object(
                sys,
                "argv",
                ["sync-sessions.py", "--lane1", self.lane1, "--lane2", self.lane2],
            ),
            contextlib.redirect_stdout(stdout_buf),
            contextlib.redirect_stderr(stderr_buf),
        ):
            rc = sync_mod.main()

        self.assertEqual(rc, 0)
        self.assertNotIn(canary, stdout_buf.getvalue())
        self.assertNotIn(canary, stderr_buf.getvalue())

    # ------------------------------------------------------------------
    # 7. Bidirectional Sync, Conflict Protection, SQLite Backup & Rescue (v1.4.0)
    # ------------------------------------------------------------------

    def test_bidirectional_sync_converges_threads_pinned_goals_and_index(self) -> None:
        """
        WHAT: Verifies `--bidirectional` with `--source`/`--target` aliases and
              `--backup-target` merges unique threads, pinned flags, `thread_sections`,
              `goals_*.sqlite` (`thread_goals`), and `session_index.jsonl` created in BOTH
              Lane 1 and Lane 2 so both homes converge to the exact union without losing
              any row or clobbering GPT 1's `model_provider`.
        PREVENTS: One-way sync leaving Sandbox 2 chats/goals/pins trapped outside GPT 1
                  or reverse sync downgrading GPT 1 metadata.
        """
        # Seed Lane 2 with unique pinned & unpinned threads plus its own section.
        c2 = sqlite3.connect(self.st2)
        c2.execute("INSERT INTO thread_sections VALUES (?, ?)", ("sec-2", "Sandbox Work"))
        c2.execute(
            "INSERT INTO threads VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "t-lane2-pinned",
                "Sandbox Pinned Task",
                1,
                "sec-2",
                1,
                2000,
                "proj-2",
                "openai",
                "never",
                "C:\\lane2\\repo",
                500001,
                9,
            ),
        )
        c2.execute(
            "INSERT INTO threads VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "t-lane2-casual",
                "Sandbox Casual Chat",
                0,
                None,
                None,
                None,
                None,
                "openai",
                "on-request",
                "C:\\lane2\\repo",
                500002,
                3,
            ),
        )
        c2.commit()
        c2.close()

        Path(self.lane2, "session_index.jsonl").write_text(
            "\n".join(
                [
                    json.dumps({"id": "t-lane2-pinned", "thread_name": "Sandbox Pinned Task"}),
                    json.dumps({"id": "t-lane2-casual", "thread_name": "Sandbox Casual Chat"}),
                ]
            )
            + "\n",
            encoding="utf-8",
            newline="\n",
        )

        # Seed unique Goals in both lanes.
        g1 = os.path.join(self.lane1, "goals_2.sqlite")
        g2 = os.path.join(self.lane2, "goals_2.sqlite")
        for db in (g1, g2):
            conn = sqlite3.connect(db)
            conn.execute("CREATE TABLE thread_goals (id TEXT PRIMARY KEY, title TEXT)")
            conn.commit()
            conn.close()
        cg1 = sqlite3.connect(g1)
        cg1.execute("INSERT INTO thread_goals VALUES (?, ?)", ("g-lane1", "GPT 1 Goal"))
        cg1.commit()
        cg1.close()
        cg2 = sqlite3.connect(g2)
        cg2.execute("INSERT INTO thread_goals VALUES (?, ?)", ("g-lane2", "Sandbox 2 Goal"))
        cg2.commit()
        cg2.close()

        stdout_buf = io.StringIO()
        stderr_buf = io.StringIO()
        with (
            mock.patch.object(
                sys,
                "argv",
                [
                    "sync-sessions.py",
                    "--source",
                    self.lane1,
                    "--target",
                    self.lane2,
                    "--bidirectional",
                    "--backup-target",
                ],
            ),
            contextlib.redirect_stdout(stdout_buf),
            contextlib.redirect_stderr(stderr_buf),
        ):
            rc = sync_mod.main()

        self.assertEqual(rc, 0)
        out = stdout_buf.getvalue()
        self.assertIn("[OK] [forward]", out)
        self.assertIn("[OK] [reverse]", out)
        # Ensure zero thread/goal title leakage in CLI output.
        for secret_title in ("Pinned Core Task", "Sandbox Pinned Task", "GPT 1 Goal", "Sandbox 2 Goal"):
            self.assertNotIn(secret_title, out)
            self.assertNotIn(secret_title, stderr_buf.getvalue())

        expected_ids = {"t-pinned-1", "t-unpinned-2", "t-lane2-pinned", "t-lane2-casual"}
        for db_path in (self.st1, self.st2):
            conn = sqlite3.connect(db_path)
            rows = {
                r[0]: r[1:]
                for r in conn.execute("SELECT id, name, is_pinned, model_provider FROM threads").fetchall()
            }
            sections = dict(conn.execute("SELECT id, title FROM thread_sections").fetchall())
            conn.close()
            self.assertEqual(set(rows.keys()), expected_ids)
            self.assertEqual(rows["t-pinned-1"][1], 1)
            self.assertEqual(rows["t-lane2-pinned"][1], 1)
            self.assertEqual(sections, {"sec-1": "Core", "sec-2": "Sandbox Work"})

        # Verify reverse sync did NOT clobber Lane 1's existing model_provider ("OpenAI").
        c1_check = sqlite3.connect(self.st1)
        l1_provider = c1_check.execute(
            "SELECT model_provider FROM threads WHERE id = ?", ("t-pinned-1",)
        ).fetchone()[0]
        c1_check.close()
        self.assertEqual(l1_provider, "OpenAI")

        # Verify Goals converged to exact union in both lanes.
        for gdb in (g1, g2):
            cg = sqlite3.connect(gdb)
            grows = dict(cg.execute("SELECT id, title FROM thread_goals").fetchall())
            cg.close()
            self.assertEqual(grows, {"g-lane1": "GPT 1 Goal", "g-lane2": "Sandbox 2 Goal"})

        # Verify session_index.jsonl converged to exact union in both lanes.
        for lane_dir in (self.lane1, self.lane2):
            idx_ids = {
                json.loads(line)["id"]
                for line in Path(lane_dir, "session_index.jsonl").read_text(encoding="utf-8").splitlines()
                if line.strip()
            }
            self.assertEqual(idx_ids, expected_ids)

        # Verify backups were created in both lanes.
        self.assertGreaterEqual(len(list(Path(self.lane1).glob("state_5.sqlite.sync-backup-*"))), 1)
        self.assertGreaterEqual(len(list(Path(self.lane2).glob("state_5.sqlite.sync-backup-*"))), 1)

        # Re-run --bidirectional a second time to verify idempotency (no duplicates).
        with (
            mock.patch.object(
                sys,
                "argv",
                ["sync-sessions.py", "--source", self.lane1, "--target", self.lane2, "--bidirectional"],
            ),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            rc2 = sync_mod.main()
        self.assertEqual(rc2, 0)
        c1_again = sqlite3.connect(self.st1)
        self.assertEqual(c1_again.execute("SELECT COUNT(*) FROM threads").fetchone()[0], 4)
        c1_again.close()

    def test_conflict_safe_merge_preserves_newer_updated_at_and_monotonic_pinned(self) -> None:
        """
        WHAT: Verifies conflict-safe merge across `threads`, `goals_*.sqlite`, and
              `session_index.jsonl`:
              1) Older source rows NEVER clobber newer target metadata (`updated_at`),
                 while still filling NULL/empty target fields.
              2) `pinned = 1` / `is_pinned = 1` is preserved monotonically whenever EITHER
                 source or target has it set, even when a newer row has `pinned = 0` or
                 an older row has `pinned = 1`.
        PREVENTS: Syncing Sandbox 2 back to GPT 1 from downgrading newer GPT 1 titles,
                  timestamps, goals, or unpinning pinned conversations.
        """
        l1 = os.path.join(self.tmp.name, "conflict_lane1")
        l2 = os.path.join(self.tmp.name, "conflict_lane2")
        os.makedirs(l1, exist_ok=True)
        os.makedirs(l2, exist_ok=True)
        db1 = os.path.join(l1, "state_6.sqlite")
        db2 = os.path.join(l2, "state_6.sqlite")

        schema = """
            CREATE TABLE threads (
                id TEXT PRIMARY KEY,
                name TEXT,
                pinned INTEGER,
                is_pinned INTEGER,
                updated_at INTEGER,
                summary TEXT,
                model_provider TEXT
            )
        """
        for db in (db1, db2):
            conn = sqlite3.connect(db)
            conn.execute(schema)
            conn.commit()
            conn.close()

        # Seed GPT 1 (target of reverse sync).
        c1 = sqlite3.connect(db1)
        c1.executemany(
            "INSERT INTO threads VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
                # Newer in GPT 1, pinned=1, missing summary (should keep newer name/ts/pinned, fill summary).
                ("t-gpt1-newer", "GPT 1 Newer Title", 1, 1, 2000, None, "OpenAI"),
                # Older in GPT 1, pinned=1 (newer Sandbox 2 name/ts should win, pinned=1 MUST stay 1).
                ("t-pin-protected", "Old GPT 1 Title", 1, 1, 1000, "Keep Summary", "OpenAI"),
                # Newer in GPT 1, pinned=0 (older Sandbox 2 has pinned=1 -> pinned upgrades to 1, name/ts stay newer).
                ("t-pin-upgrade", "Newer Unpinned Title", 0, 0, 2500, "GPT1 Summary", "OpenAI"),
            ],
        )
        c1.commit()
        c1.close()

        # Seed Sandbox 2 (source of reverse sync).
        c2 = sqlite3.connect(db2)
        c2.executemany(
            "INSERT INTO threads VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
                ("t-gpt1-newer", "Stale Sandbox 2 Title", 0, 0, 1000, "Recovered Summary", "openai"),
                ("t-pin-protected", "Newer Sandbox 2 Title", 0, 0, 3000, None, "openai"),
                ("t-pin-upgrade", "Older Pinned Title", 1, 1, 1200, "Older Summary", "openai"),
            ],
        )
        c2.commit()
        c2.close()

        # Seed session_index.jsonl with ISO-8601 updated_at timestamps.
        Path(l1, "session_index.jsonl").write_text(
            "\n".join(
                [
                    json.dumps(
                        {
                            "id": "t-gpt1-newer",
                            "thread_name": "GPT 1 Newer Index",
                            "updated_at": "2026-11-23T12:00:00Z",
                        }
                    ),
                    json.dumps(
                        {
                            "id": "t-pin-protected",
                            "thread_name": "GPT 1 Older Index",
                            "updated_at": "2026-11-23T08:00:00Z",
                        }
                    ),
                ]
            )
            + "\n",
            encoding="utf-8",
            newline="\n",
        )
        Path(l2, "session_index.jsonl").write_text(
            "\n".join(
                [
                    json.dumps(
                        {
                            "id": "t-gpt1-newer",
                            "thread_name": "Sandbox 2 Older Index",
                            "updated_at": "2026-11-23T10:00:00Z",
                        }
                    ),
                    json.dumps(
                        {
                            "id": "t-pin-protected",
                            "thread_name": "Sandbox 2 Newer Index",
                            "updated_at": "2026-11-23T11:00:00Z",
                        }
                    ),
                ]
            )
            + "\n",
            encoding="utf-8",
            newline="\n",
        )

        # Seed goals DB with updated_at column.
        g1 = os.path.join(l1, "goals_3.sqlite")
        g2 = os.path.join(l2, "goals_3.sqlite")
        for gdb in (g1, g2):
            cg = sqlite3.connect(gdb)
            cg.execute("CREATE TABLE thread_goals (id TEXT PRIMARY KEY, title TEXT, updated_at INTEGER)")
            cg.commit()
            cg.close()
        cg1 = sqlite3.connect(g1)
        cg1.executemany(
            "INSERT INTO thread_goals VALUES (?, ?, ?)",
            [("g-keep-newer", "GPT 1 Newer Goal", 5000), ("g-update-me", "Old Goal", 1000)],
        )
        cg1.commit()
        cg1.close()
        cg2 = sqlite3.connect(g2)
        cg2.executemany(
            "INSERT INTO thread_goals VALUES (?, ?, ?)",
            [("g-keep-newer", "Stale Sandbox 2 Goal", 2000), ("g-update-me", "Fresh Sandbox 2 Goal", 6000)],
        )
        cg2.commit()
        cg2.close()

        # Sync Lane 2 -> Lane 1 (simulating pre-uninstall rescue or reverse merge).
        sync_mod.sync_state_db(
            l2, l1, None, None, False, False, force_openai_provider=False
        )
        sync_mod.sync_session_index(l2, l1, dry_run=False)
        sync_mod.sync_goals_db(l2, l1, dry_run=False, preserve_existing_on_conflict=True)

        c1_after = sqlite3.connect(db1)
        rows = {
            r[0]: r[1:]
            for r in c1_after.execute(
                "SELECT id, name, pinned, is_pinned, updated_at, summary, model_provider FROM threads"
            ).fetchall()
        }
        c1_after.close()

        # Case A: Newer GPT 1 metadata preserved, NULL summary filled, pinned=1 kept.
        self.assertEqual(
            rows["t-gpt1-newer"],
            ("GPT 1 Newer Title", 1, 1, 2000, "Recovered Summary", "OpenAI"),
        )
        # Case B: Newer Sandbox 2 name/ts applied, NULL source summary did NOT erase target summary, pinned=1 preserved!
        self.assertEqual(
            rows["t-pin-protected"],
            ("Newer Sandbox 2 Title", 1, 1, 3000, "Keep Summary", "OpenAI"),
        )
        # Case C: Older Sandbox 2 upgraded pinned=1 without clobbering newer name/ts/summary!
        self.assertEqual(
            rows["t-pin-upgrade"],
            ("Newer Unpinned Title", 1, 1, 2500, "GPT1 Summary", "OpenAI"),
        )

        # Verify session_index.jsonl timestamp conflict resolution.
        idx_merged = {
            json.loads(line)["id"]: json.loads(line)
            for line in Path(l1, "session_index.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        }
        self.assertEqual(idx_merged["t-gpt1-newer"]["thread_name"], "GPT 1 Newer Index")
        self.assertEqual(idx_merged["t-pin-protected"]["thread_name"], "Sandbox 2 Newer Index")

        # Verify goals DB timestamp conflict resolution.
        cg1_after = sqlite3.connect(g1)
        goals_after = dict(cg1_after.execute("SELECT id, title FROM thread_goals").fetchall())
        cg1_after.close()
        self.assertEqual(
            goals_after,
            {"g-keep-newer": "GPT 1 Newer Goal", "g-update-me": "Fresh Sandbox 2 Goal"},
        )

    def test_backup_target_creates_valid_sqlite_snapshot_and_dry_run_is_zero_mutation(self) -> None:
        """
        WHAT: Verifies `--backup-target` creates valid online SQLite `.sync-backup-*`
              snapshots capturing the pre-write target DB state (with zero leftover `.tmp`
              files and `0600` mode on POSIX), while `--backup-target --dry-run` performs
              strictly zero filesystem mutations across both lanes.
        PREVENTS: Irrecoverable target DB loss during bidirectional/reverse writes or
                  unexpected backup file creation during `--dry-run`.
        """
        c2 = sqlite3.connect(self.st2)
        c2.execute(
            "INSERT INTO threads VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("t-pre-backup", "Pre-Backup Row", 1, None, None, None, None, "openai", "on-request", "C:\\x", 10, 5),
        )
        c2.commit()
        c2.close()

        g1 = os.path.join(self.lane1, "goals_1.sqlite")
        g2 = os.path.join(self.lane2, "goals_1.sqlite")
        for gdb in (g1, g2):
            cg = sqlite3.connect(gdb)
            cg.execute("CREATE TABLE thread_goals (id TEXT PRIMARY KEY, title TEXT)")
            cg.commit()
            cg.close()
        cg1 = sqlite3.connect(g1)
        cg1.execute("INSERT INTO thread_goals VALUES (?, ?)", ("g-from-l1", "Lane 1 Goal"))
        cg1.commit()
        cg1.close()
        cg2 = sqlite3.connect(g2)
        cg2.execute("INSERT INTO thread_goals VALUES (?, ?)", ("g-pre-backup", "Pre-Backup Goal"))
        cg2.commit()
        cg2.close()

        snap1_before = _dir_snapshot(self.lane1)
        snap2_before = _dir_snapshot(self.lane2)

        # 1) --dry-run with --bidirectional --backup-target must cause ZERO mutations.
        dry_out = io.StringIO()
        with (
            mock.patch.object(
                sys,
                "argv",
                [
                    "sync-sessions.py",
                    "--source",
                    self.lane1,
                    "--target",
                    self.lane2,
                    "--bidirectional",
                    "--backup-target",
                    "--dry-run",
                ],
            ),
            contextlib.redirect_stdout(dry_out),
        ):
            rc_dry = sync_mod.main()
        self.assertEqual(rc_dry, 0)
        self.assertIn("[DRY-RUN]", dry_out.getvalue())
        self.assertEqual(_dir_snapshot(self.lane1), snap1_before)
        self.assertEqual(_dir_snapshot(self.lane2), snap2_before)
        self.assertEqual(list(Path(self.lane2).glob("*.sync-backup-*")), [])

        # 2) Real run with --backup-target creates valid pre-sync SQLite snapshots before writing.
        with (
            mock.patch.object(
                sys,
                "argv",
                [
                    "sync-sessions.py",
                    "--source",
                    self.lane1,
                    "--target",
                    self.lane2,
                    "--backup-target",
                ],
            ),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            rc_real = sync_mod.main()
        self.assertEqual(rc_real, 0)

        state_backups = list(Path(self.lane2).glob("state_5.sqlite.sync-backup-*"))
        goal_backups = list(Path(self.lane2).glob("goals_1.sqlite.sync-backup-*"))
        self.assertEqual(len(state_backups), 1)
        self.assertEqual(len(goal_backups), 1)
        self.assertEqual(list(Path(self.lane2).glob("*.tmp")), [])

        # Open backup SQLite files: must pass quick_check and hold ONLY pre-sync rows.
        cb_state = sqlite3.connect(str(state_backups[0]))
        self.assertEqual(cb_state.execute("PRAGMA quick_check(1)").fetchone()[0].lower(), "ok")
        backup_thread_ids = {r[0] for r in cb_state.execute("SELECT id FROM threads").fetchall()}
        cb_state.close()
        self.assertEqual(backup_thread_ids, {"t-pre-backup"})

        cb_goals = sqlite3.connect(str(goal_backups[0]))
        self.assertEqual(cb_goals.execute("PRAGMA quick_check(1)").fetchone()[0].lower(), "ok")
        backup_goal_ids = {r[0] for r in cb_goals.execute("SELECT id FROM thread_goals").fetchall()}
        cb_goals.close()
        self.assertEqual(backup_goal_ids, {"g-pre-backup"})

        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(os.stat(state_backups[0]).st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(os.stat(goal_backups[0]).st_mode), 0o600)

        # Live target DB must contain both pre-existing and newly synced rows.
        c2_live = sqlite3.connect(self.st2)
        live_ids = {r[0] for r in c2_live.execute("SELECT id FROM threads").fetchall()}
        c2_live.close()
        self.assertEqual(live_ids, {"t-pre-backup", "t-pinned-1", "t-unpinned-2"})

    def test_rescue_shared_files_copies_local_files_skips_links_and_rejects_planted_symlinks(self) -> None:
        """
        WHAT: Verifies `--rescue-shared-files`:
              1) Copies missing regular files from real local `sessions`, `archived_sessions`,
                 `memories`, and `memories_v2` dirs (preserving nested subdirectories) while
                 NEVER overwriting existing GPT 1 files, respecting `--dry-run`, and leaking
                 zero filenames/contents in stdout/stderr.
              2) Skips top-level shared folders that are ALREADY symlinks or Windows NTFS
                 junctions cleanly.
              3) Rejects planted symlinks (or Windows NTFS junctions) INSIDE a real shared
                 folder fail-closed with ValueError and ZERO partial copies.
        PREVENTS: Losing local Sandbox 2 rollout/memory files on pre-uninstall, clobbering
                  existing GPT 1 files, or following attacker-planted symlinks outside CODEX_HOME.
        """
        # Part A: Non-destructive copy + --dry-run + zero secret filename/content leak.
        secret_canary = "ROLLOUT_CANARY_TOKEN_883311"
        src_rollout_new = Path(
            self.lane2, "sessions", "2026", "11", "23", f"rollout-{secret_canary}.jsonl"
        )
        src_rollout_existing = Path(self.lane2, "sessions", "2026", "11", "23", "rollout-existing.jsonl")
        src_arch = Path(self.lane2, "archived_sessions", "arch-01.jsonl")
        src_mem = Path(self.lane2, "memories", "notes", "mem-01.md")
        src_mem2 = Path(self.lane2, "memories_v2", "index.json")

        for fpath, body in (
            (src_rollout_new, f'{{"msg":"{secret_canary}"}}\n'),
            (src_rollout_existing, "SANDBOX2_MUST_NOT_OVERWRITE\n"),
            (src_arch, '{"archived":true}\n'),
            (src_mem, "# Sandbox 2 Memory\n"),
            (src_mem2, '{"v":2}\n'),
        ):
            fpath.parent.mkdir(parents=True, exist_ok=True)
            fpath.write_text(body, encoding="utf-8", newline="\n")

        dst_rollout_existing = Path(self.lane1, "sessions", "2026", "11", "23", "rollout-existing.jsonl")
        dst_rollout_existing.parent.mkdir(parents=True, exist_ok=True)
        dst_rollout_existing.write_text("GPT1_ORIGINAL_DO_NOT_OVERWRITE\n", encoding="utf-8", newline="\n")

        snap_l1_before = _dir_snapshot(self.lane1)
        snap_l2_before = _dir_snapshot(self.lane2)

        # Dry-run must report exact counts with zero mutations and zero canary leakage.
        dry_out = io.StringIO()
        dry_err = io.StringIO()
        with (
            mock.patch.object(
                sys,
                "argv",
                [
                    "sync-sessions.py",
                    "--source",
                    self.lane2,
                    "--target",
                    self.lane1,
                    "--rescue-shared-files",
                    "--backup-target",
                    "--dry-run",
                ],
            ),
            contextlib.redirect_stdout(dry_out),
            contextlib.redirect_stderr(dry_err),
        ):
            rc_dry = sync_mod.main()
        self.assertEqual(rc_dry, 0)
        self.assertIn("rescued_files=4 (skipped_existing=1, skipped_links=0)", dry_out.getvalue())
        self.assertNotIn(secret_canary, dry_out.getvalue())
        self.assertNotIn(secret_canary, dry_err.getvalue())
        self.assertEqual(_dir_snapshot(self.lane1), snap_l1_before)
        self.assertEqual(_dir_snapshot(self.lane2), snap_l2_before)

        # Real rescue run copies all 4 missing files without overwriting existing GPT 1 file.
        real_out = io.StringIO()
        real_err = io.StringIO()
        with (
            mock.patch.object(
                sys,
                "argv",
                [
                    "sync-sessions.py",
                    "--source",
                    self.lane2,
                    "--target",
                    self.lane1,
                    "--rescue-shared-files",
                    "--backup-target",
                ],
            ),
            contextlib.redirect_stdout(real_out),
            contextlib.redirect_stderr(real_err),
        ):
            rc_real = sync_mod.main()
        self.assertEqual(rc_real, 0)
        self.assertIn("rescued_files=4 (skipped_existing=1, skipped_links=0)", real_out.getvalue())
        self.assertNotIn(secret_canary, real_out.getvalue())
        self.assertNotIn(secret_canary, real_err.getvalue())

        self.assertEqual(
            dst_rollout_existing.read_text(encoding="utf-8"),
            "GPT1_ORIGINAL_DO_NOT_OVERWRITE\n",
        )
        self.assertEqual(
            Path(self.lane1, "sessions", "2026", "11", "23", f"rollout-{secret_canary}.jsonl").read_text(
                encoding="utf-8"
            ),
            f'{{"msg":"{secret_canary}"}}\n',
        )
        self.assertEqual(Path(self.lane1, "archived_sessions", "arch-01.jsonl").read_text(encoding="utf-8"), '{"archived":true}\n')
        self.assertEqual(Path(self.lane1, "memories", "notes", "mem-01.md").read_text(encoding="utf-8"), "# Sandbox 2 Memory\n")
        self.assertEqual(Path(self.lane1, "memories_v2", "index.json").read_text(encoding="utf-8"), '{"v":2}\n')

        # Part B: Top-level shared folder that is ALREADY a symlink/junction is skipped cleanly.
        real_islink = os.path.islink
        top_sessions = os.path.abspath(os.path.join(self.lane2, "sessions"))

        def fake_top_link(p: object) -> bool:
            return os.path.abspath(os.fspath(p)) == top_sessions or real_islink(p)

        with mock.patch.object(sync_mod.os.path, "islink", side_effect=fake_top_link):
            copied, skipped_ex, skipped_ln = sync_mod.rescue_shared_files(self.lane2, self.lane1, dry_run=False)
        self.assertEqual(copied, 0)
        self.assertEqual(skipped_ln, 1)
        self.assertEqual(skipped_ex, 3)

        # Real Windows NTFS Junction check (does not require admin/SeCreateSymbolicLinkPrivilege).
        if os.name == "nt":
            j_l1 = Path(self.tmp.name, "junc_l1")
            j_l2 = Path(self.tmp.name, "junc_l2")
            (j_l1 / "sessions").mkdir(parents=True)
            (j_l1 / "sessions" / "gpt1.jsonl").write_text("ok\n", encoding="utf-8")
            j_l2.mkdir(parents=True)
            j_link = j_l2 / "sessions"
            proc = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(j_link), str(j_l1 / "sessions")],
                capture_output=True,
                text=True,
                check=False,
            )
            if proc.returncode == 0:
                try:
                    self.assertEqual(
                        sync_mod.rescue_shared_files(str(j_l2), str(j_l1), dry_run=False),
                        (0, 0, 1),
                    )
                finally:
                    subprocess.run(["cmd", "/c", "rmdir", str(j_link)], capture_output=True, check=False)

        # Part C: Planted symlink INSIDE a real local shared folder fails closed with 0 partial copies.
        evil_src = Path(self.tmp.name, "evil_src")
        evil_dst = Path(self.tmp.name, "evil_dst")
        (evil_src / "sessions").mkdir(parents=True)
        evil_dst.mkdir(parents=True)
        good_file = evil_src / "sessions" / "a_good.jsonl"
        planted_file = evil_src / "sessions" / "z_planted.jsonl"
        good_file.write_text('{"ok":1}\n', encoding="utf-8")
        planted_file.write_text('{"evil":1}\n', encoding="utf-8")

        planted_abs = os.path.abspath(str(planted_file))

        def fake_planted_link(p: object) -> bool:
            return os.path.abspath(os.fspath(p)) == planted_abs or real_islink(p)

        with mock.patch.object(sync_mod.os.path, "islink", side_effect=fake_planted_link):
            with self.assertRaises(ValueError):
                sync_mod.rescue_shared_files(str(evil_src), str(evil_dst), dry_run=False)
        # Fail-closed guarantee: a_good.jsonl must NOT have been copied before rejecting z_planted.jsonl!
        self.assertFalse((evil_dst / "sessions" / "a_good.jsonl").exists())

        # Real filesystem symlink check inside a real shared dir when OS allows symlinks.
        if _can_create_symlinks(self.tmp.name):
            outside_secret = Path(self.tmp.name, "outside_rescue_secret.txt")
            outside_secret.write_text("TOP_SECRET", encoding="utf-8")
            real_link = evil_src / "sessions" / "real_symlink.jsonl"
            os.symlink(str(outside_secret), str(real_link))
            try:
                err_buf = io.StringIO()
                with (
                    mock.patch.object(
                        sys,
                        "argv",
                        [
                            "sync-sessions.py",
                            "--source",
                            str(evil_src),
                            "--target",
                            str(evil_dst),
                            "--rescue-shared-files",
                        ],
                    ),
                    contextlib.redirect_stderr(err_buf),
                ):
                    rc_evil = sync_mod.main()
                self.assertEqual(rc_evil, 1)
                self.assertIn("Security violation", err_buf.getvalue())
                self.assertFalse((evil_dst / "sessions" / "a_good.jsonl").exists())
            finally:
                os.unlink(real_link)

        # Real NTFS Junction planted INSIDE a real shared dir on Windows must also fail closed!
        if os.name == "nt":
            outside_dir = Path(self.tmp.name, "outside_dir_for_junc")
            outside_dir.mkdir(exist_ok=True)
            (outside_dir / "secret.jsonl").write_text("OUTSIDE", encoding="utf-8")
            sub_junc = evil_src / "sessions" / "nested_junc"
            proc = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(sub_junc), str(outside_dir)],
                capture_output=True,
                text=True,
                check=False,
            )
            if proc.returncode == 0:
                try:
                    with self.assertRaises(ValueError):
                        sync_mod.rescue_shared_files(str(evil_src), str(evil_dst), dry_run=False)
                    self.assertFalse((evil_dst / "sessions" / "a_good.jsonl").exists())
                finally:
                    subprocess.run(["cmd", "/c", "rmdir", str(sub_junc)], capture_output=True, check=False)

    def test_missing_state_db_still_syncs_index_and_rescues_shared_files_with_exit_0(self) -> None:
        """
        WHAT: Verifies pre-uninstall rescue (`--source Lane2 --target Lane1 --rescue-shared-files
              --backup-target`) succeeds with exit code 0 when `state_*.sqlite` and
              `goals_*.sqlite` are absent, still merging `session_index.jsonl` and rescuing
              local `sessions/` files into GPT 1.
        PREVENTS: Pre-uninstall failing needlessly on fresh/lightweight Sandbox 2 homes that
                  only contain `session_index.jsonl` and rollout files.
        """
        l1 = Path(self.tmp.name, "nodb_l1")
        l2 = Path(self.tmp.name, "nodb_l2")
        l1.mkdir()
        (l2 / "sessions" / "2026").mkdir(parents=True)
        (l1 / "session_index.jsonl").write_text(
            json.dumps({"id": "t-l1", "thread_name": "GPT 1 Only"}) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        (l2 / "session_index.jsonl").write_text(
            json.dumps({"id": "t-l2", "thread_name": "Sandbox 2 Only"}) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        (l2 / "sessions" / "2026" / "rollout-l2.jsonl").write_text('{"role":"user"}\n', encoding="utf-8")

        out_buf = io.StringIO()
        with (
            mock.patch.object(
                sys,
                "argv",
                [
                    "sync-sessions.py",
                    "--source",
                    str(l2),
                    "--target",
                    str(l1),
                    "--rescue-shared-files",
                    "--backup-target",
                ],
            ),
            contextlib.redirect_stdout(out_buf),
        ):
            rc = sync_mod.main()

        self.assertEqual(rc, 0)
        self.assertIn("session_index=2", out_buf.getvalue())
        self.assertIn("state_db=N/A", out_buf.getvalue())
        self.assertIn("rescued_files=1", out_buf.getvalue())
        merged_ids = {
            json.loads(line)["id"]
            for line in (l1 / "session_index.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        }
        self.assertEqual(merged_ids, {"t-l1", "t-l2"})
        self.assertTrue((l1 / "sessions" / "2026" / "rollout-l2.jsonl").is_file())


    def test_backup_target_rotates_old_sync_backups_and_preserves_newest(self) -> None:
        """
        WHAT: Verifies `backup_sqlite_db` and `--max-backups` retain at most the
              newest N `.sync-backup-*` files per SQLite DB, pruning older backups
              to prevent unbounded disk bloat, while refusing negative `--max-backups`.
        PREVENTS: Repeated `codex-manage` sync runs from accumulating gigabytes of
                  stale SQLite `.sync-backup-*` copies on disk.
        """
        created: list[Path] = []
        for idx in range(7):
            bkp = sync_mod.backup_sqlite_db(self.lane2, self.st2, max_backups=3)
            # Assign strictly increasing mtimes so newest-3 order is deterministic.
            ts_ns = (1700000000 + idx * 10) * 1_000_000_000
            os.utime(bkp, ns=(ts_ns, ts_ns))
            created.append(bkp)

        remaining = sorted(p.name for p in Path(self.lane2).glob("state_5.sqlite.sync-backup-*"))
        self.assertEqual(len(remaining), 3)
        self.assertEqual(remaining, sorted(p.name for p in created[-3:]))

        # Verify negative --max-backups is rejected fail-closed with exit code 1.
        err_buf = io.StringIO()
        with (
            mock.patch.object(
                sys,
                "argv",
                ["sync-sessions.py", "--lane1", self.lane1, "--lane2", self.lane2, "--max-backups", "-1"],
            ),
            contextlib.redirect_stderr(err_buf),
        ):
            rc = sync_mod.main()
        self.assertEqual(rc, 1)
        self.assertIn("--max-backups", err_buf.getvalue())

    def test_sync_status_classification_success_partial_failed_skipped(self) -> None:
        """
        WHAT: Verifies explicit sync outcome statuses (`SUCCESS`, `PARTIAL`, `FAILED`,
              `SKIPPED`) across CLI `--json` output, plain-text summary, and exit codes:
              - Both empty homes -> `SKIPPED` (exit 0)
              - Valid state + index + goals -> `SUCCESS` with `reconcile=OK` (exit 0)
              - Valid state + corrupt goals -> `PARTIAL` (exit 1)
              - Corrupt state DB with no other synced DB -> `FAILED` (exit 1)
        PREVENTS: Silent zero-exit failures where callers cannot distinguish a clean
                  skip from a partial or failed SQLite sync.
        """
        # 1) SKIPPED: two empty directories with no DBs or index.
        empty_a = os.path.join(self.tmp.name, "empty_status_a")
        empty_b = os.path.join(self.tmp.name, "empty_status_b")
        os.makedirs(empty_a, exist_ok=True)
        os.makedirs(empty_b, exist_ok=True)
        out_skip = io.StringIO()
        with (
            mock.patch.object(
                sys,
                "argv",
                ["sync-sessions.py", "--source", empty_a, "--target", empty_b, "--json"],
            ),
            contextlib.redirect_stdout(out_skip),
        ):
            rc_skip = sync_mod.main()
        self.assertEqual(rc_skip, 0)
        skip_payload = json.loads(out_skip.getvalue())
        self.assertEqual(skip_payload["status"], sync_mod.SYNC_STATUS_SKIPPED)
        self.assertEqual(skip_payload["forward"]["state_status"], sync_mod.SYNC_STATUS_SKIPPED)

        # 2) SUCCESS: valid state + index + goals with verified reconciliation.
        Path(self.lane1, "session_index.jsonl").write_text(
            json.dumps({"id": "t-pinned-1", "thread_name": "Pinned Core Task"}) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        g1 = os.path.join(self.lane1, "goals_1.sqlite")
        g2 = os.path.join(self.lane2, "goals_1.sqlite")
        for gpath, rows in (
            (g1, [("g-1", "t-pinned-1", "Goal 1")]),
            (g2, []),
        ):
            cg = sqlite3.connect(gpath)
            cg.execute("CREATE TABLE thread_goals (id TEXT PRIMARY KEY, thread_id TEXT, title TEXT)")
            cg.executemany("INSERT INTO thread_goals VALUES (?, ?, ?)", rows)
            cg.commit()
            cg.close()

        out_ok = io.StringIO()
        with (
            mock.patch.object(
                sys,
                "argv",
                ["sync-sessions.py", "--source", self.lane1, "--target", self.lane2, "--json"],
            ),
            contextlib.redirect_stdout(out_ok),
        ):
            rc_ok = sync_mod.main()
        self.assertEqual(rc_ok, 0)
        ok_payload = json.loads(out_ok.getvalue())
        self.assertEqual(ok_payload["status"], sync_mod.SYNC_STATUS_SUCCESS)
        self.assertEqual(ok_payload["forward"]["state_status"], sync_mod.SYNC_STATUS_SUCCESS)
        self.assertEqual(ok_payload["forward"]["index_status"], sync_mod.SYNC_STATUS_SUCCESS)
        self.assertEqual(ok_payload["forward"]["goals_status"], sync_mod.SYNC_STATUS_SUCCESS)
        self.assertTrue(ok_payload["forward"]["reconciliation"]["verified"])

        # 3) PARTIAL: valid state DB + corrupt goals DB -> status=PARTIAL and exit 1.
        Path(g1).write_bytes(b"CORRUPT_GOALS_HEADER_PARTIAL" * 12)
        out_partial = io.StringIO()
        err_partial = io.StringIO()
        with (
            mock.patch.object(
                sys,
                "argv",
                ["sync-sessions.py", "--source", self.lane1, "--target", self.lane2],
            ),
            contextlib.redirect_stdout(out_partial),
            contextlib.redirect_stderr(err_partial),
        ):
            rc_partial = sync_mod.main()
        self.assertEqual(rc_partial, 1)
        self.assertIn("[PARTIAL]", out_partial.getvalue())
        self.assertIn("status=PARTIAL", out_partial.getvalue())
        self.assertIn("goals=0(FAILED)", out_partial.getvalue())

        # 4) FAILED: corrupt state DB with no session_index and no goals -> status=FAILED and exit 1.
        fail_src = os.path.join(self.tmp.name, "fail_src")
        fail_dst = os.path.join(self.tmp.name, "fail_dst")
        os.makedirs(fail_src, exist_ok=True)
        os.makedirs(fail_dst, exist_ok=True)
        Path(fail_src, "state_5.sqlite").write_bytes(b"BROKEN_STATE_DB_BYTES" * 16)
        c_fd = sqlite3.connect(os.path.join(fail_dst, "state_5.sqlite"))
        c_fd.execute("CREATE TABLE threads (id TEXT PRIMARY KEY, name TEXT)")
        c_fd.commit()
        c_fd.close()

        out_fail = io.StringIO()
        err_fail = io.StringIO()
        with (
            mock.patch.object(
                sys,
                "argv",
                ["sync-sessions.py", "--source", fail_src, "--target", fail_dst],
            ),
            contextlib.redirect_stdout(out_fail),
            contextlib.redirect_stderr(err_fail),
        ):
            rc_fail = sync_mod.main()
        self.assertEqual(rc_fail, 1)
        self.assertIn("[FAIL]", out_fail.getvalue())
        self.assertIn("status=FAILED", out_fail.getvalue())

    def test_before_after_reconciliation_verifies_counts_ids_pinned_goals_and_detects_mismatch(self) -> None:
        """
        WHAT: Verifies before/after reconciliation accurately checks record counts,
              thread IDs, Pinned threads, and Goals, AND downgrades status to `PARTIAL`
              (exit 1) if post-sync verification finds a missing thread ID, lost pin,
              or missing Goal.
        PREVENTS: Silent partial commits or dropped Pinned/Goal records going unnoticed
                  after a sync run.
        """
        # Seed target with 1 pre-existing pinned thread + 1 goal.
        c2 = sqlite3.connect(self.st2)
        c2.execute(
            "INSERT INTO threads VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("t-pre-dst", "Target Pinned", 1, None, None, None, None, "openai", "on-request", "C:\\x", 10, 1),
        )
        c2.commit()
        c2.close()

        g1 = os.path.join(self.lane1, "goals_1.sqlite")
        g2 = os.path.join(self.lane2, "goals_1.sqlite")
        for gpath, rows in (
            (g1, [("g-src-1", "t-pinned-1", "Src Goal 1"), ("g-src-2", "t-unpinned-2", "Src Goal 2")]),
            (g2, [("g-dst-1", "t-pre-dst", "Dst Goal 1")]),
        ):
            cg = sqlite3.connect(gpath)
            cg.execute("CREATE TABLE thread_goals (id TEXT PRIMARY KEY, thread_id TEXT, title TEXT)")
            cg.executemany("INSERT INTO thread_goals VALUES (?, ?, ?)", rows)
            cg.commit()
            cg.close()

        state_res = sync_mod.sync_state_db_detailed(
            self.lane1, self.lane2, None, None, False, False
        )
        self.assertEqual(state_res["status"], sync_mod.SYNC_STATUS_SUCCESS)
        self.assertEqual(state_res["before"]["target_threads"], 1)
        self.assertEqual(state_res["before"]["target_pinned"], 1)
        self.assertEqual(state_res["after"]["target_threads"], 3)
        self.assertEqual(state_res["after"]["target_pinned"], 2)
        self.assertTrue(state_res["reconciliation"]["verified"])
        self.assertEqual(state_res["reconciliation"]["missing_ids_count"], 0)
        self.assertEqual(state_res["reconciliation"]["missing_pinned_count"], 0)

        goals_res = sync_mod.sync_goals_db_detailed(self.lane1, self.lane2, dry_run=False)
        self.assertEqual(goals_res["status"], sync_mod.SYNC_STATUS_SUCCESS)
        self.assertEqual(goals_res["before"]["target_goals"], 1)
        self.assertEqual(goals_res["after"]["target_goals"], 3)
        self.assertTrue(goals_res["reconciliation"]["verified"])
        self.assertEqual(goals_res["reconciliation"]["missing_goals_count"], 0)

        # Simulate a post-sync verification mismatch (dropped thread ID + dropped pin) -> MUST downgrade to PARTIAL!
        real_snapshot = sync_mod._snapshot_state_threads
        call_count = {"n": 0}

        def _tampered_after_snapshot(conn: sqlite3.Connection) -> tuple[set[str], set[str]]:
            call_count["n"] += 1
            ids, pinned = real_snapshot(conn)
            if call_count["n"] >= 2:
                return (ids - {"t-unpinned-2"}, pinned - {"t-pinned-1"})
            return (ids, pinned)

        err_buf = io.StringIO()
        with (
            mock.patch.object(sync_mod, "_snapshot_state_threads", side_effect=_tampered_after_snapshot),
            contextlib.redirect_stderr(err_buf),
        ):
            mismatch_res = sync_mod.sync_state_db_detailed(
                self.lane1, self.lane2, None, None, False, False
            )
        self.assertEqual(mismatch_res["status"], sync_mod.SYNC_STATUS_PARTIAL)
        self.assertFalse(mismatch_res["reconciliation"]["verified"])
        self.assertEqual(mismatch_res["reconciliation"]["missing_ids_count"], 1)
        self.assertEqual(mismatch_res["reconciliation"]["missing_pinned_count"], 1)

    def test_strict_rescue_fails_closed_on_locked_or_corrupt_source_db(self) -> None:
        """
        WHAT: Verifies `--rescue-shared-files --strict` (used by RemoveSandbox2) fails
              closed with exit code 1 and `status=FAILED` when the source SQLite DB
              exists but is exclusively locked OR corrupt, even when target has no DB yet.
        PREVENTS: RemoveSandbox2 deleting Sandbox 2 while its SQLite chat history is
                  locked by another process or unreadable/corrupt.
        """
        # 1) Exclusively locked source DB -> MUST fail closed (exit 1, status=FAILED).
        locker = sqlite3.connect(self.st1, isolation_level=None)
        try:
            locker.execute("BEGIN EXCLUSIVE")
            out_lock = io.StringIO()
            err_lock = io.StringIO()
            with (
                mock.patch.object(
                    sys,
                    "argv",
                    [
                        "sync-sessions.py",
                        "--source",
                        self.lane1,
                        "--target",
                        self.lane2,
                        "--rescue-shared-files",
                        "--strict",
                        "--busy-timeout",
                        "0.05",
                    ],
                ),
                contextlib.redirect_stdout(out_lock),
                contextlib.redirect_stderr(err_lock),
            ):
                rc_lock = sync_mod.main()
            self.assertEqual(rc_lock, 1)
            self.assertIn("state_db=N/A(FAILED:", out_lock.getvalue())
            self.assertRegex(out_lock.getvalue(), r"status=(FAILED|PARTIAL)")
        finally:
            locker.execute("ROLLBACK")
            locker.close()

        # 2) Corrupt source DB when target has NO state DB yet -> MUST fail closed (exit 1, status=FAILED/PARTIAL).
        empty_target = os.path.join(self.tmp.name, "empty_rescue_target")
        os.makedirs(empty_target, exist_ok=True)
        Path(self.st1).write_bytes(b"CORRUPT_SOURCE_BEFORE_UNINSTALL" * 16)
        # Remove source session_index.jsonl so state_db is the only active component -> overall status=FAILED.
        src_idx = Path(self.lane1, "session_index.jsonl")
        if src_idx.exists():
            src_idx.unlink()
        out_corrupt = io.StringIO()
        err_corrupt = io.StringIO()
        with (
            mock.patch.object(
                sys,
                "argv",
                [
                    "sync-sessions.py",
                    "--source",
                    self.lane1,
                    "--target",
                    empty_target,
                    "--rescue-shared-files",
                    "--strict",
                ],
            ),
            contextlib.redirect_stdout(out_corrupt),
            contextlib.redirect_stderr(err_corrupt),
        ):
            rc_corrupt = sync_mod.main()
        self.assertEqual(rc_corrupt, 1)
        self.assertIn("status=FAILED", out_corrupt.getvalue())
        self.assertIn("state_db=N/A(FAILED:", out_corrupt.getvalue())
        self.assertEqual(os.listdir(empty_target), [])


if __name__ == "__main__":
    unittest.main()
