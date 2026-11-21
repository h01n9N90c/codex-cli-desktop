#!/usr/bin/env python3
"""
Schema-adaptive sync of Codex session index, pinned threads/projects, and Goals
from primary CODEX_HOME (~/.codex) to secondary CODEX_HOME (~/.codex-official).

Author    : Lê Hoàng Ngọc Tươi
Copyright : Copyright 2026 Lê Hoàng Ngọc Tươi
License   : Apache-2.0 (https://www.apache.org/licenses/LICENSE-2.0)
Project   : Codex Dual-Lane & Security Kit

Automatically discovers the newest state_*.sqlite and goals_*.sqlite files and
inspects real table columns via PRAGMA table_info so it remains compatible across
different Codex CLI/Desktop versions without hardcoded schema assumptions.

Usage:
    python scripts/sync-sessions.py --repo "C:\\Projects\\my-app"
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sqlite3
import sys

__author__ = "Lê Hoàng Ngọc Tươi"
__copyright__ = "Copyright 2026 Lê Hoàng Ngọc Tươi"
__license__ = "Apache-2.0"


def find_latest_versioned_db(directory: str, prefix: str) -> str | None:
    pattern = os.path.join(directory, f"{prefix}_*.sqlite")
    candidates = glob.glob(pattern)
    if not candidates:
        return None

    def version_key(path: str) -> tuple[int, str]:
        name = os.path.basename(path)
        m = re.match(rf"^{re.escape(prefix)}_(\d+)\.sqlite$", name)
        return (int(m.group(1)) if m else -1, name)

    candidates.sort(key=version_key, reverse=True)
    return candidates[0]


def get_tables(conn: sqlite3.Connection) -> set[str]:
    return {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }


def get_columns(conn: sqlite3.Connection, table: str) -> list[str]:
    return [row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()]


def sync_session_index(lane1: str, lane2: str, dry_run: bool) -> int:
    idx1 = os.path.join(lane1, "session_index.jsonl")
    idx2 = os.path.join(lane2, "session_index.jsonl")
    if not os.path.exists(idx1):
        return 0
    by_id: dict[str, str] = {}
    for p in (idx1, idx2):
        if os.path.exists(p):
            with open(p, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        if "id" in obj:
                            by_id[str(obj["id"])] = line
                    except json.JSONDecodeError:
                        continue
    if not dry_run:
        with open(idx2, "w", encoding="utf-8") as f:
            for line in by_id.values():
                f.write(line + "\n")
    return len(by_id)


def copy_shared_table(
    c1: sqlite3.Connection,
    c2: sqlite3.Connection,
    table: str,
    dry_run: bool,
) -> int:
    if table not in get_tables(c1) or table not in get_tables(c2):
        return 0
    cols1 = get_columns(c1, table)
    cols2 = set(get_columns(c2, table))
    common = [c for c in cols1 if c in cols2]
    if not common:
        return 0
    col_sql = ", ".join(common)
    rows = c1.execute(f"SELECT {col_sql} FROM {table}").fetchall()
    if rows and not dry_run:
        placeholders = ", ".join(["?"] * len(common))
        c2.executemany(
            f"INSERT OR REPLACE INTO {table} ({col_sql}) VALUES ({placeholders})",
            rows,
        )
    return len(rows)


def sync_state_db(
    lane1: str,
    lane2: str,
    repo_path: str | None,
    approval_mode: str | None,
    dry_run: bool,
) -> tuple[str | None, int]:
    st1 = find_latest_versioned_db(lane1, "state")
    st2 = find_latest_versioned_db(lane2, "state")
    if not st1 or not st2:
        print(
            "[!] state_*.sqlite not found in both homes. Launch 'codex' once to initialize the secondary DB first."
        )
        return (None, 0)

    c1, c2 = sqlite3.connect(st1), sqlite3.connect(st2)
    try:
        for tbl in ("thread_sections", "projects", "project_roots"):
            copy_shared_table(c1, c2, tbl, dry_run)

        if "threads" not in get_tables(c1) or "threads" not in get_tables(c2):
            return (os.path.basename(st2), 0)

        cols1 = set(get_columns(c1, "threads"))
        cols2 = set(get_columns(c2, "threads"))
        desired_copy = [
            "name",
            "is_pinned",
            "thread_section_id",
            "section_position",
            "section_entered_at_ms",
            "project_id",
        ]
        copy_cols = [c for c in desired_copy if c in cols1 and c in cols2]
        if "id" not in cols1 or "id" not in cols2:
            return (os.path.basename(st2), 0)

        select_sql = ", ".join(["id"] + copy_cols)
        src_rows = c1.execute(f"SELECT {select_sql} FROM threads").fetchall()
        pinned_count = 0

        for row in src_rows:
            tid = row[0]
            values = dict(zip(copy_cols, row[1:]))
            is_pinned_val = bool(values.get("is_pinned")) or (
                values.get("thread_section_id") is not None
            )
            if is_pinned_val:
                pinned_count += 1
            if "is_pinned" in values:
                values["is_pinned"] = 1 if is_pinned_val else 0

            set_clauses: list[str] = []
            params: list[object] = []
            for col, val in values.items():
                if col == "name":
                    set_clauses.append("name = COALESCE(?, name)")
                else:
                    set_clauses.append(f"{col} = ?")
                params.append(val)

            if "model_provider" in cols2:
                set_clauses.append("model_provider = 'openai'")
            if approval_mode and "approval_mode" in cols2:
                set_clauses.append("approval_mode = ?")
                params.append(approval_mode)

            if set_clauses and not dry_run:
                params.append(tid)
                c2.execute(
                    f"UPDATE threads SET {', '.join(set_clauses)} WHERE id = ?",
                    params,
                )

        if repo_path and "cwd" in cols2 and "is_pinned" in cols2 and not dry_run:
            norm_cwd = os.path.abspath(repo_path)
            if os.name == "nt" and not norm_cwd.startswith("\\\\?\\"):
                norm_cwd = "\\\\?\\" + norm_cwd
            c2.execute("UPDATE threads SET cwd = ? WHERE is_pinned = 1", (norm_cwd,))

        if not dry_run:
            c2.commit()
            c2.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        return (os.path.basename(st2), pinned_count)
    finally:
        c1.close()
        c2.close()


def sync_goals_db(lane1: str, lane2: str, dry_run: bool) -> int:
    g1 = find_latest_versioned_db(lane1, "goals")
    g2 = find_latest_versioned_db(lane2, "goals")
    if not g1 or not g2:
        return 0

    c1, c2 = sqlite3.connect(g1), sqlite3.connect(g2)
    try:
        goals_count = copy_shared_table(c1, c2, "thread_goals", dry_run)
        copy_shared_table(c1, c2, "thread_goal_continuation_deferrals", dry_run)
        if not dry_run:
            c2.commit()
            c2.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        return goals_count
    finally:
        c1.close()
        c2.close()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Schema-adaptive sync of Codex sessions, pinned tasks, and goals between two CODEX_HOMEs."
    )
    user_home = os.path.expanduser("~")
    parser.add_argument(
        "--lane1",
        default=os.path.join(user_home, ".codex"),
        help="Primary CODEX_HOME (default: ~/.codex)",
    )
    parser.add_argument(
        "--lane2",
        default=os.path.join(user_home, ".codex-official"),
        help="Secondary CODEX_HOME (default: ~/.codex-official)",
    )
    parser.add_argument(
        "--repo",
        default=None,
        help="Optional project directory to bind pinned threads' cwd so 'codex resume' lists them immediately",
    )
    parser.add_argument(
        "--approval-mode",
        default=None,
        choices=["never", "on-request"],
        help="Optional approval_mode to apply on synced threads (omit to preserve existing values)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Inspect schemas and report what would be synced without writing any file",
    )
    args = parser.parse_args()

    idx_count = sync_session_index(args.lane1, args.lane2, args.dry_run)
    db_name, pinned_count = sync_state_db(
        args.lane1, args.lane2, args.repo, args.approval_mode, args.dry_run
    )
    goals_count = sync_goals_db(args.lane1, args.lane2, args.dry_run)

    mode = "DRY-RUN" if args.dry_run else "OK"
    print(
        f"[{mode}] session_index={idx_count} | state_db={db_name or 'N/A'} (pinned={pinned_count}) | goals={goals_count}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
