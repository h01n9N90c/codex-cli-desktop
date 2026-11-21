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


if __name__ == "__main__":
    unittest.main()
