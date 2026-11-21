#!/usr/bin/env python3
"""
Schema-adaptive sync of Codex session index, pinned threads/projects, and Goals
from primary CODEX_HOME (~/.codex) to secondary CODEX_HOME (~/.codex-official).

Author    : Lê Hoàng Ngọc Tươi
Copyright : Copyright 2026 Lê Hoàng Ngọc Tươi
License   : Apache-2.0 (https://www.apache.org/licenses/LICENSE-2.0)
Project   : Codex Dual-Lane & Security Kit

Key guarantees:
  - Opens source SQLite databases in read-only URI mode (?mode=ro) so active Lane 1
    processes are never blocked by write locks.
  - Dynamically inspects table schemas via PRAGMA table_info(...) across state_*.sqlite
    and goals_*.sqlite.
  - Performs full UPSERT (INSERT missing threads + UPDATE existing threads) inside an
    atomic transaction on the target database, so pinned threads appear even when the
    target database is freshly initialized and has zero existing thread rows.
  - Supports --pinned-only to avoid syncing unpinned session metadata when desired.

Usage:
    python scripts/sync-sessions.py --repo "C:\\Projects\\my-app"
"""
from __future__ import annotations

import argparse
import glob
import json
import os
from pathlib import Path
import re
import sqlite3
import sys

__author__ = "Lê Hoàng Ngọc Tươi"
__copyright__ = "Copyright 2026 Lê Hoàng Ngọc Tươi"
__license__ = "Apache-2.0"


def connect_readonly(db_path: str) -> sqlite3.Connection:
    uri = Path(db_path).resolve().as_uri() + "?mode=ro"
    return sqlite3.connect(uri, uri=True, timeout=15.0)


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


def get_column_info(conn: sqlite3.Connection, table: str) -> dict[str, dict[str, object]]:
    info: dict[str, dict[str, object]] = {}
    for row in conn.execute(f"PRAGMA table_info({table})").fetchall():
        # cid, name, type, notnull, dflt_value, pk
        info[str(row[1])] = {
            "type": str(row[2] or "").upper(),
            "notnull": bool(row[3]),
            "dflt_value": row[4],
            "pk": bool(row[5]),
        }
    return info


def fallback_default_for_type(col_type: str) -> object:
    if "INT" in col_type or "BOOL" in col_type:
        return 0
    if "REAL" in col_type or "FLOA" in col_type or "DOUB" in col_type:
        return 0.0
    if "BLOB" in col_type:
        return b""
    return ""


def normalize_repo_cwd(repo_path: str) -> str:
    norm_cwd = os.path.abspath(repo_path)
    if os.name == "nt" and not norm_cwd.startswith("\\\\?\\"):
        norm_cwd = "\\\\?\\" + norm_cwd
    return norm_cwd


def sync_session_index(
    lane1: str,
    lane2: str,
    dry_run: bool,
    allowed_ids: set[str] | None = None,
) -> int:
    idx1 = os.path.join(lane1, "session_index.jsonl")
    idx2 = os.path.join(lane2, "session_index.jsonl")
    if not os.path.exists(idx1):
        return 0
    by_id: dict[str, str] = {}
    # Preserve existing destination entries first, then merge source entries
    for p in (idx2, idx1):
        if os.path.exists(p):
            with open(p, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        tid = str(obj.get("id", ""))
                        if not tid:
                            continue
                        if p == idx1 and allowed_ids is not None and tid not in allowed_ids:
                            continue
                        by_id[tid] = line
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
    pinned_only: bool,
    dry_run: bool,
) -> tuple[str | None, int, int, int, set[str]]:
    """
    Returns (db_basename, inserted_count, updated_count, pinned_count, synced_thread_ids).
    """
    st1 = find_latest_versioned_db(lane1, "state")
    st2 = find_latest_versioned_db(lane2, "state")
    if not st1 or not st2:
        print(
            "[!] state_*.sqlite not found in both homes. Launch 'codex' once to initialize the secondary DB first."
        )
        return (None, 0, 0, 0, set())

    c1 = connect_readonly(st1)
    c2 = sqlite3.connect(st2, timeout=15.0)
    try:
        c2.execute("PRAGMA busy_timeout = 15000")
        if "threads" not in get_tables(c1) or "threads" not in get_tables(c2):
            return (os.path.basename(st2), 0, 0, 0, set())

        cols1 = get_columns(c1, "threads")
        cols2_info = get_column_info(c2, "threads")
        cols2 = set(cols2_info.keys())
        common_cols = [c for c in cols1 if c in cols2]
        if "id" not in common_cols:
            return (os.path.basename(st2), 0, 0, 0, set())

        # Any target-only NOT NULL columns without a default need a safe fallback on INSERT
        extra_notnull_cols: list[str] = [
            col
            for col, meta in cols2_info.items()
            if col not in common_cols and meta["notnull"] and meta["dflt_value"] is None and not meta["pk"]
        ]

        existing_dst_ids = {
            str(r[0]) for r in c2.execute("SELECT id FROM threads").fetchall()
        }

        select_sql = ", ".join(common_cols)
        src_rows = c1.execute(f"SELECT {select_sql} FROM threads").fetchall()

        norm_cwd = normalize_repo_cwd(repo_path) if repo_path else None
        inserted_count = 0
        updated_count = 0
        pinned_count = 0
        synced_ids: set[str] = set()

        if not dry_run:
            c2.execute("BEGIN IMMEDIATE")

        for tbl in ("thread_sections", "projects", "project_roots"):
            copy_shared_table(c1, c2, tbl, dry_run)

        for row in src_rows:
            row_dict = dict(zip(common_cols, row))
            tid = str(row_dict["id"])
            is_pinned_val = bool(row_dict.get("is_pinned")) or (
                row_dict.get("thread_section_id") is not None
            )
            if pinned_only and not is_pinned_val:
                continue

            synced_ids.add(tid)
            if is_pinned_val:
                pinned_count += 1
            if "is_pinned" in row_dict:
                row_dict["is_pinned"] = 1 if is_pinned_val else 0
            if "model_provider" in cols2:
                row_dict["model_provider"] = "openai"
            if approval_mode and "approval_mode" in cols2:
                row_dict["approval_mode"] = approval_mode
            if norm_cwd and is_pinned_val and "cwd" in cols2:
                row_dict["cwd"] = norm_cwd

            if tid not in existing_dst_ids:
                inserted_count += 1
                if not dry_run:
                    insert_cols = list(row_dict.keys())
                    insert_vals = [row_dict[c] for c in insert_cols]
                    for extra_col in extra_notnull_cols:
                        insert_cols.append(extra_col)
                        insert_vals.append(
                            fallback_default_for_type(str(cols2_info[extra_col]["type"]))
                        )
                    col_list_sql = ", ".join(insert_cols)
                    placeholders = ", ".join(["?"] * len(insert_cols))
                    c2.execute(
                        f"INSERT INTO threads ({col_list_sql}) VALUES ({placeholders})",
                        insert_vals,
                    )
                    existing_dst_ids.add(tid)
            else:
                updated_count += 1
                if not dry_run:
                    update_candidates = [
                        "name",
                        "is_pinned",
                        "thread_section_id",
                        "section_position",
                        "section_entered_at_ms",
                        "project_id",
                        "model_provider",
                    ]
                    if approval_mode and "approval_mode" in cols2:
                        update_candidates.append("approval_mode")
                    if norm_cwd and is_pinned_val and "cwd" in cols2:
                        update_candidates.append("cwd")

                    set_clauses: list[str] = []
                    params: list[object] = []
                    for col in update_candidates:
                        if col not in row_dict:
                            continue
                        if col == "name":
                            set_clauses.append("name = COALESCE(?, name)")
                        else:
                            set_clauses.append(f"{col} = ?")
                        params.append(row_dict[col])

                    if set_clauses:
                        params.append(tid)
                        c2.execute(
                            f"UPDATE threads SET {', '.join(set_clauses)} WHERE id = ?",
                            params,
                        )

        if not dry_run:
            c2.commit()
            c2.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        return (
            os.path.basename(st2),
            inserted_count,
            updated_count,
            pinned_count,
            synced_ids,
        )
    except Exception:
        if not dry_run and c2.in_transaction:
            c2.rollback()
        raise
    finally:
        c1.close()
        c2.close()


def sync_goals_db(lane1: str, lane2: str, dry_run: bool) -> int:
    g1 = find_latest_versioned_db(lane1, "goals")
    g2 = find_latest_versioned_db(lane2, "goals")
    if not g1 or not g2:
        return 0

    c1 = connect_readonly(g1)
    c2 = sqlite3.connect(g2, timeout=15.0)
    try:
        c2.execute("PRAGMA busy_timeout = 15000")
        if not dry_run:
            c2.execute("BEGIN IMMEDIATE")
        goals_count = copy_shared_table(c1, c2, "thread_goals", dry_run)
        copy_shared_table(c1, c2, "thread_goal_continuation_deferrals", dry_run)
        if not dry_run:
            c2.commit()
            c2.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        return goals_count
    except Exception:
        if not dry_run and c2.in_transaction:
            c2.rollback()
        raise
    finally:
        c1.close()
        c2.close()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Schema-adaptive UPSERT sync of Codex sessions, pinned tasks, and goals between two CODEX_HOMEs."
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
        "--pinned-only",
        action="store_true",
        help="Only sync pinned threads (avoids sharing unpinned thread records across environments)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Inspect schemas and report what would be synced without writing any file",
    )
    args = parser.parse_args()

    db_name, inserted_count, updated_count, pinned_count, synced_ids = sync_state_db(
        args.lane1,
        args.lane2,
        args.repo,
        args.approval_mode,
        args.pinned_only,
        args.dry_run,
    )
    allowed_ids = synced_ids if args.pinned_only else None
    idx_count = sync_session_index(args.lane1, args.lane2, args.dry_run, allowed_ids)
    goals_count = sync_goals_db(args.lane1, args.lane2, args.dry_run)

    mode = "DRY-RUN" if args.dry_run else "OK"
    print(
        f"[{mode}] session_index={idx_count} | state_db={db_name or 'N/A'} "
        f"(inserted={inserted_count}, updated={updated_count}, pinned={pinned_count}) | goals={goals_count}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
