#!/usr/bin/env python3
"""
Schema-adaptive, safety-hardened sync of Codex session index, pinned threads,
and Goals from primary CODEX_HOME (~/.codex) to secondary CODEX_HOME
(~/.codex-official).

Author    : Lê Hoàng Ngọc Tươi
Copyright : Copyright 2026 Lê Hoàng Ngọc Tươi
License   : Apache-2.0 (https://www.apache.org/licenses/LICENSE-2.0)
Project   : Codex Dual-Lane & Security Kit

Security & Reliability Guarantees:
  - Read-only SQLite URI (?mode=ro) + PRAGMA query_only=ON on all source DBs
    (and on target DBs during --dry-run) so active Lane 1 processes are never
    blocked by write locks and --dry-run performs strictly zero writes.
  - Explicit SQLite busy timeout (default 15s) to ride out brief concurrent
    checkpoints from Codex Desktop/CLI without failing immediately.
  - Strictly parameterized SQL values (?) combined with allowlisted table names
    and regex-validated, double-quoted SQL identifiers (blocks even second-order
    SQL injection from malformed or untrusted SQLite schemas).
  - Full idempotent UPSERT (INSERT missing rows + UPDATE existing rows) inside
    an atomic BEGIN IMMEDIATE transaction, after reading all source rows into
    memory first so mid-read source corruption never touches the target DB.
  - Atomic JSONL replacement (same-directory temp file + fsync + os.replace
    with 0600 permissions on POSIX) so interruptions never truncate
    session_index.jsonl.
  - Strict path containment & symlink rejection across both CODEX_HOME trees
    (including SQLite -wal/-shm/-journal sidecars) to prevent path traversal
    and symlink-clobbering attacks.
  - Graceful handling of missing, locked, or corrupt SQLite databases without
    corrupting the target DB or leaking session contents/secrets in logs.

Usage:
    python scripts/sync-sessions.py --repo "/path/to/my-app"
    python scripts/sync-sessions.py --repo "/path/to/my-app" --pinned-only --dry-run
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
import tempfile

__author__ = "Lê Hoàng Ngọc Tươi"
__copyright__ = "Copyright 2026 Lê Hoàng Ngọc Tươi"
__license__ = "Apache-2.0"

# Default SQLite lock wait duration (seconds / milliseconds).
DEFAULT_BUSY_TIMEOUT_SEC: float = 15.0
DEFAULT_BUSY_TIMEOUT_MS: int = int(DEFAULT_BUSY_TIMEOUT_SEC * 1000)

# Strict allowlist for SQLite identifiers interpolated as table/column names.
# Prevents second-order SQL injection if a source DB contains crafted column names.
SQL_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
DB_PREFIX_RE = re.compile(r"^[A-Za-z0-9_]+$")

# Explicit allowlist of Codex SQLite tables this tool is permitted to inspect/sync.
ALLOWED_TABLES: frozenset[str] = frozenset(
    {
        "threads",
        "thread_sections",
        "projects",
        "project_roots",
        "thread_goals",
        "thread_goal_continuation_deferrals",
    }
)

# Tables mirrored from state_*.sqlite alongside `threads`.
SHARED_STATE_TABLES: tuple[str, ...] = ("thread_sections", "projects", "project_roots")

# Tables mirrored from goals_*.sqlite.
SHARED_GOALS_TABLES: tuple[str, ...] = (
    "thread_goals",
    "thread_goal_continuation_deferrals",
)

# SQLite auxiliary sidecar suffixes checked for symlink safety before opening a DB.
SQLITE_SIDECAR_SUFFIXES: tuple[str, ...] = ("-wal", "-shm", "-journal")


def validate_sql_identifier(
    identifier: str, *, allowed_tables: frozenset[str] | None = None
) -> str:
    """
    Validate a SQLite table or column identifier against a strict ASCII regex
    and optional table allowlist.

    Raises ValueError on any non-matching identifier so untrusted schema metadata
    can never inject SQL syntax into dynamically built column lists.
    """
    if not isinstance(identifier, str) or not SQL_IDENT_RE.fullmatch(identifier):
        raise ValueError(f"Security violation: unsafe SQL identifier rejected: {identifier!r}")
    if allowed_tables is not None and identifier not in allowed_tables:
        raise ValueError(f"Security violation: table not in allowlist: {identifier!r}")
    return identifier


def quote_identifier(
    identifier: str, *, allowed_tables: frozenset[str] | None = None
) -> str:
    """Validate and double-quote a SQLite identifier for safe SQL formatting."""
    safe = validate_sql_identifier(identifier, allowed_tables=allowed_tables)
    return f'"{safe}"'


def ensure_contained_path(
    base_dir: str | Path,
    candidate: str | Path,
    *,
    reject_symlinks: bool = True,
) -> Path:
    """
    Verify that `candidate` is strictly contained within `base_dir` and free of
    path-traversal (`..`) segments or symlink escapes.

    Why this invariant exists:
      Both CODEX_HOME trees hold sensitive local state. Rejecting `..` traversal
      and symlinks strictly below `base_dir` (while permitting OS-level symlinks
      strictly above `base_dir`, such as macOS `/var -> /private/var`) prevents
      attacker-planted symlinks from redirecting reads or atomic writes outside
      the user's Codex directories.

    Raises ValueError on any containment or symlink violation.
    """
    base_str = os.fspath(base_dir)
    cand_str = os.fspath(candidate)
    if not base_str or not cand_str:
        raise ValueError("Security violation: base directory and candidate path must be non-empty.")
    if "\x00" in base_str or "\x00" in cand_str:
        raise ValueError("Security violation: NUL byte rejected in path.")

    base_path = Path(base_str)
    cand_path = Path(cand_str)

    # Reject any lexical parent-traversal component unconditionally.
    if ".." in cand_path.parts:
        raise ValueError(
            f"Security violation: path traversal ('..') rejected in candidate path: {cand_str!r}"
        )

    full_cand = cand_path if cand_path.is_absolute() else (base_path / cand_path)
    base_real = base_path.resolve(strict=False)

    # Walk upward from `full_cand` until reaching `base_dir`/`base_real`, checking
    # `os.path.islink(cur)` BEFORE `cur.resolve() == base_real` whenever
    # `cur != base_path` so intra-root symlinks like `lane2/loop -> lane2` are
    # rejected while OS-level symlinks strictly above `base_dir` (e.g. macOS
    # `/var -> /private/var`) remain permitted.
    if reject_symlinks:
        cur = full_cand
        reached_base = False
        depth = 0
        while True:
            if depth >= 1 and cur == base_path:
                reached_base = True
                break
            if os.path.islink(cur):
                raise ValueError(
                    f"Security violation: symlink rejected inside CODEX_HOME: {os.fspath(cur)!r}"
                )
            if depth >= 1 and cur.resolve(strict=False) == base_real:
                reached_base = True
                break
            parent = cur.parent
            if parent == cur:
                break
            cur = parent
            depth += 1
        if not reached_base:
            raise ValueError(
                f"Security violation: path {cand_str!r} escapes allowed directory {base_str!r}"
            )

    # Confirm canonical resolved path stays strictly beneath `base_real`.
    cand_real = full_cand.resolve(strict=False)
    try:
        rel = cand_real.relative_to(base_real)
    except ValueError as exc:
        raise ValueError(
            f"Security violation: resolved path {os.fspath(cand_real)!r} is outside {os.fspath(base_real)!r}"
        ) from exc

    if str(rel) in ("", "."):
        raise ValueError(
            f"Security violation: candidate path {cand_str!r} must be a strict child of {base_str!r}"
        )
    return cand_real


def _assert_distinct_lanes(lane1: str, lane2: str) -> None:
    """Prevent syncing a CODEX_HOME directory onto itself."""
    if not lane1 or not lane2:
        raise ValueError("Security violation: --lane1 and --lane2 must be non-empty paths.")
    if Path(lane1).resolve(strict=False) == Path(lane2).resolve(strict=False):
        raise ValueError(
            "Security violation: lane1 and lane2 must resolve to distinct directories."
        )


def _validate_sqlite_and_sidecars(base_dir: str, db_path: str) -> Path:
    """
    Validate containment and anti-symlink invariants for a SQLite database file
    AND any existing WAL/SHM/journal sidecar files.
    """
    validated = ensure_contained_path(base_dir, db_path, reject_symlinks=True)
    for suffix in SQLITE_SIDECAR_SUFFIXES:
        sidecar = Path(str(db_path) + suffix)
        if os.path.lexists(sidecar):
            ensure_contained_path(base_dir, sidecar, reject_symlinks=True)
    return validated


def _build_sqlite_uri(db_path: str, mode: str) -> str:
    """Build a properly percent-encoded SQLite file URI (`?mode=ro` or `?mode=rw`)."""
    return Path(db_path).resolve(strict=True).as_uri() + f"?mode={mode}"


def connect_readonly(
    db_path: str, timeout: float | None = None
) -> sqlite3.Connection:
    """
    Open a SQLite database strictly in read-only URI mode (`?mode=ro`) with
    `PRAGMA query_only = ON` and an explicit busy timeout.

    Why this safeguard exists:
      Lane 1 (Codex Desktop / `codex-t3`) may be running concurrently while
      this script syncs sessions. Opening Lane 1 databases read-only prevents
      blocking active writers or accidentally mutating primary session history.
    """
    if os.path.islink(db_path):
        raise ValueError(f"Security violation: refusing to open symlink SQLite DB: {db_path!r}")
    effective_timeout = DEFAULT_BUSY_TIMEOUT_SEC if timeout is None else timeout
    uri = _build_sqlite_uri(db_path, "ro")
    conn = sqlite3.connect(uri, uri=True, timeout=effective_timeout)
    try:
        timeout_ms = max(0, int(effective_timeout * 1000))
        conn.execute(f"PRAGMA busy_timeout = {timeout_ms}")
        conn.execute("PRAGMA query_only = ON")
        return conn
    except Exception:
        conn.close()
        raise


def connect_readwrite(
    db_path: str, timeout: float | None = None
) -> sqlite3.Connection:
    """
    Open an existing target SQLite database in read-write URI mode (`?mode=rw`)
    with explicit manual transaction control (`isolation_level=None`) and busy timeout.

    Using `?mode=rw` (instead of `rwc`) ensures SQLite fails cleanly rather than
    silently creating an empty placeholder DB if the target file vanished.
    """
    if os.path.islink(db_path):
        raise ValueError(f"Security violation: refusing to open symlink SQLite DB: {db_path!r}")
    effective_timeout = DEFAULT_BUSY_TIMEOUT_SEC if timeout is None else timeout
    uri = _build_sqlite_uri(db_path, "rw")
    conn = sqlite3.connect(uri, uri=True, timeout=effective_timeout, isolation_level=None)
    try:
        timeout_ms = max(0, int(effective_timeout * 1000))
        conn.execute(f"PRAGMA busy_timeout = {timeout_ms}")
        return conn
    except Exception:
        conn.close()
        raise


def _verify_sqlite_readable(conn: sqlite3.Connection) -> None:
    """
    Perform a fast integrity check (`PRAGMA quick_check(1)`) on an open SQLite
    connection before beginning any write transaction.

    Raises sqlite3.DatabaseError if the database header/pages are corrupt so we
    abort gracefully before touching the target database.
    """
    row = conn.execute("PRAGMA quick_check(1)").fetchone()
    if not row or str(row[0]).lower() != "ok":
        raise sqlite3.DatabaseError("SQLite quick_check reported database corruption")


def find_latest_versioned_db(directory: str, prefix: str) -> str | None:
    """
    Locate the highest-numbered `<prefix>_<N>.sqlite` file directly inside
    `directory` using `os.scandir` (immune to glob brackets in path names).

    Security invariant:
      Rejects any symlink matching `<prefix>_<N>.sqlite` by raising ValueError
      rather than silently following an attacker-planted link outside `directory`.
    """
    if not DB_PREFIX_RE.fullmatch(prefix):
        raise ValueError(f"Security violation: invalid DB prefix: {prefix!r}")
    if not directory or not os.path.isdir(directory):
        return None

    name_re = re.compile(rf"^{re.escape(prefix)}_(\d+)\.sqlite$")
    candidates: list[tuple[int, str, str]] = []
    try:
        with os.scandir(directory) as entries:
            for entry in entries:
                match = name_re.fullmatch(entry.name)
                if not match:
                    continue
                # Enforce containment & reject symlinks (including dangling links).
                ensure_contained_path(directory, entry.path, reject_symlinks=True)
                if not entry.is_file(follow_symlinks=False):
                    continue
                candidates.append((int(match.group(1)), entry.name, entry.path))
    except OSError as exc:
        print(
            f"[WARN] Unable to scan directory for {prefix}_*.sqlite ({type(exc).__name__}).",
            file=sys.stderr,
        )
        return None

    if not candidates:
        return None
    candidates.sort(key=lambda item: (item[0], item[1]), reverse=True)
    return candidates[0][2]


def get_tables(conn: sqlite3.Connection) -> set[str]:
    """Return the set of user table names present in a SQLite database."""
    return {
        str(row[0])
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }


def get_columns(conn: sqlite3.Connection, table: str) -> list[str]:
    """
    Return ordered, identifier-validated column names for an allowlisted table
    via `PRAGMA table_info(...)`.
    """
    q_table = quote_identifier(table, allowed_tables=ALLOWED_TABLES)
    cols: list[str] = []
    for row in conn.execute(f"PRAGMA table_info({q_table})").fetchall():
        col_name = validate_sql_identifier(str(row[1]))
        cols.append(col_name)
    return cols


def get_column_info(
    conn: sqlite3.Connection, table: str
) -> dict[str, dict[str, object]]:
    """
    Return schema metadata (type, notnull, default, pk) keyed by validated
    column name for an allowlisted table.
    """
    q_table = quote_identifier(table, allowed_tables=ALLOWED_TABLES)
    info: dict[str, dict[str, object]] = {}
    for row in conn.execute(f"PRAGMA table_info({q_table})").fetchall():
        # PRAGMA table_info columns: cid, name, type, notnull, dflt_value, pk
        col_name = validate_sql_identifier(str(row[1]))
        info[col_name] = {
            "type": str(row[2] or "").upper(),
            "notnull": bool(row[3]),
            "dflt_value": row[4],
            "pk": bool(row[5]),
        }
    return info


def fallback_default_for_type(col_type: str) -> object:
    """
    Return a deterministic type-compatible fallback value for target-only
    NOT NULL columns lacking a schema DEFAULT (supports forward schema drift
    when Lane 2 runs a newer Codex DB version than Lane 1).
    """
    upper = col_type.upper()
    if "INT" in upper or "BOOL" in upper:
        return 0
    if "REAL" in upper or "FLOA" in upper or "DOUB" in upper:
        return 0.0
    if "BLOB" in upper:
        return b""
    return ""


def normalize_repo_cwd(repo_path: str) -> str:
    """
    Normalize a repository path to match the format stored in Codex's
    `threads.cwd` column.

    On Windows, Codex Desktop records verbatim `\\\\?\\C:\\...` paths so long
    paths work reliably; applying the same prefix ensures `codex resume`
    matches synced pinned threads immediately.
    """
    norm_cwd = os.path.abspath(repo_path)
    if os.name == "nt" and not norm_cwd.startswith("\\\\?\\"):
        norm_cwd = "\\\\?\\" + norm_cwd
    return norm_cwd


def atomic_write_text(dest_path: str | Path, content: str) -> None:
    """
    Atomically write UTF-8 (LF) text to `dest_path` with owner-only (0600)
    permissions on POSIX systems.

    Why this safeguard exists:
      Direct `open(dest, "w")` truncates the file immediately; a crash or disk
      error mid-write would wipe `session_index.jsonl`. Staging to a unique temp
      file in the same directory, flushing + fsyncing, enforcing `0600` on POSIX,
      and swapping via `os.replace` guarantees all-or-nothing durability.
    """
    dest = Path(dest_path)
    tmp_path: str | None = None
    try:
        # NamedTemporaryFile creates the file with O_CREAT|O_EXCL and mode 0600 on POSIX.
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=str(dest.parent),
            prefix=f".{dest.name}.",
            suffix=".tmp",
            delete=False,
        ) as tmp_file:
            tmp_path = tmp_file.name
            if os.name == "posix":
                os.chmod(tmp_path, 0o600)
            tmp_file.write(content)
            tmp_file.flush()
            os.fsync(tmp_file.fileno())
        os.replace(tmp_path, dest)
        tmp_path = None
    finally:
        # Clean up staged temp file if anything failed before os.replace().
        if tmp_path is not None:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def sync_session_index(
    lane1: str,
    lane2: str,
    dry_run: bool,
    allowed_ids: set[str] | None = None,
) -> int:
    """
    Merge `session_index.jsonl` entries by thread `id` from `lane1` into `lane2`,
    preserving existing Lane 2 entries first and atomically writing the merged
    JSONL file (skipped in `--dry-run`).

    Security invariants:
      - Rejects identical `lane1`/`lane2` directories and rejects symlinks or
        path traversal on either `session_index.jsonl` (including dangling links).
      - Skips malformed JSON lines and non-object JSON values safely.
      - Never prints session titles or JSONL contents to stdout/stderr.
    """
    _assert_distinct_lanes(lane1, lane2)

    idx1_raw = os.path.join(lane1, "session_index.jsonl")
    idx2_raw = os.path.join(lane2, "session_index.jsonl")

    # Always run containment & symlink checks before checking file existence so
    # dangling symlinks are rejected immediately.
    idx1 = ensure_contained_path(lane1, idx1_raw, reject_symlinks=True)
    idx2 = ensure_contained_path(lane2, idx2_raw, reject_symlinks=True)

    if not idx1.exists():
        return 0
    if not idx1.is_file():
        raise ValueError("Security violation: source session_index.jsonl is not a regular file.")
    if idx2.exists() and not idx2.is_file():
        raise ValueError("Security violation: target session_index.jsonl is not a regular file.")

    by_id: dict[str, str] = {}
    # Preserve existing destination entries first, then overlay source entries.
    for path, is_source in ((idx2, False), (idx1, True)):
        if not path.exists():
            continue
        try:
            with open(path, "r", encoding="utf-8") as handle:
                for raw_line in handle:
                    line = raw_line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if not isinstance(obj, dict):
                        continue
                    raw_id = obj.get("id")
                    if not isinstance(raw_id, (str, int)) or isinstance(raw_id, bool):
                        continue
                    tid = str(raw_id).strip()
                    if not tid:
                        continue
                    if is_source and allowed_ids is not None and tid not in allowed_ids:
                        continue
                    by_id[tid] = line
        except (OSError, UnicodeDecodeError) as exc:
            print(
                f"[WARN] Could not read {path.name} cleanly ({type(exc).__name__}); aborting session_index sync to preserve target.",
                file=sys.stderr,
            )
            return 0

    if not dry_run:
        os.makedirs(idx2.parent, mode=0o700, exist_ok=True)
        payload = "".join(f"{entry}\n" for entry in by_id.values())
        atomic_write_text(idx2, payload)
    return len(by_id)


def _prepare_shared_table_payload(
    c1: sqlite3.Connection,
    c2: sqlite3.Connection,
    table: str,
) -> tuple[list[str], list[tuple[object, ...]]]:
    """
    Read and schema-align all rows for an allowlisted shared table from `c1`
    into memory before modifying `c2`, supplying safe defaults for any
    target-only NOT NULL columns without defaults.
    """
    q_table = quote_identifier(table, allowed_tables=ALLOWED_TABLES)
    if table not in get_tables(c1) or table not in get_tables(c2):
        return ([], [])

    cols1 = get_columns(c1, table)
    cols2_info = get_column_info(c2, table)
    cols2 = set(cols2_info.keys())
    common = [c for c in cols1 if c in cols2]
    if not common:
        return ([], [])

    extra_notnull_cols = [
        col
        for col, meta in cols2_info.items()
        if col not in common
        and meta["notnull"]
        and meta["dflt_value"] is None
        and not meta["pk"]
    ]

    select_sql = ", ".join(quote_identifier(c) for c in common)
    raw_rows = c1.execute(f"SELECT {select_sql} FROM {q_table}").fetchall()

    insert_cols = common + extra_notnull_cols
    if extra_notnull_cols:
        extra_defaults = tuple(
            fallback_default_for_type(str(cols2_info[col]["type"]))
            for col in extra_notnull_cols
        )
        aligned_rows = [tuple(row) + extra_defaults for row in raw_rows]
    else:
        aligned_rows = [tuple(row) for row in raw_rows]
    return (insert_cols, aligned_rows)


def copy_shared_table(
    c1: sqlite3.Connection,
    c2: sqlite3.Connection,
    table: str,
    dry_run: bool,
) -> int:
    """
    Copy the column intersection of an allowlisted shared table from `c1` to `c2`
    using strictly parameterized `INSERT OR REPLACE`.
    """
    q_table = quote_identifier(table, allowed_tables=ALLOWED_TABLES)
    insert_cols, rows = _prepare_shared_table_payload(c1, c2, table)
    if rows and not dry_run:
        col_sql = ", ".join(quote_identifier(c) for c in insert_cols)
        placeholders = ", ".join(["?"] * len(insert_cols))
        c2.executemany(
            f"INSERT OR REPLACE INTO {q_table} ({col_sql}) VALUES ({placeholders})",
            rows,
        )
    return len(rows)


def _checkpoint_wal_best_effort(conn: sqlite3.Connection) -> None:
    """
    Flush committed WAL pages back to the main SQLite file so CLI/Desktop tools
    observe changes immediately. Contention from another reader is non-fatal
    because the transaction is already durably committed.
    """
    try:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    except sqlite3.OperationalError:
        pass


def sync_state_db(
    lane1: str,
    lane2: str,
    repo_path: str | None,
    approval_mode: str | None,
    pinned_only: bool,
    dry_run: bool,
) -> tuple[str | None, int, int, int, set[str]]:
    """
    Perform schema-adaptive, transactional UPSERT sync of `threads` and shared
    metadata tables (`thread_sections`, `projects`, `project_roots`) from Lane 1
    to Lane 2.

    Returns:
        `(db_basename, inserted_count, updated_count, pinned_count, synced_thread_ids)`

    Safety & Fault Tolerance:
      - Raises ValueError on security violations (symlinks, path traversal,
        identical lanes, unsafe SQL identifiers).
      - Handles missing, locked, or corrupt SQLite databases gracefully without
        corrupting the target DB: all source data is read while read-only BEFORE
        starting any write transaction on the target DB.
      - Opens target DB read-only as well when `dry_run=True` for zero mutation.
    """
    _assert_distinct_lanes(lane1, lane2)

    st1 = find_latest_versioned_db(lane1, "state")
    st2 = find_latest_versioned_db(lane2, "state")
    if not st1 or not st2:
        print(
            "[!] state_*.sqlite not found in both homes. Launch 'codex' once to initialize the secondary DB first."
        )
        return (None, 0, 0, 0, set())

    # Validate DB files and any existing -wal/-shm/-journal sidecars against symlinks.
    _validate_sqlite_and_sidecars(lane1, st1)
    _validate_sqlite_and_sidecars(lane2, st2)

    c1: sqlite3.Connection | None = None
    c2: sqlite3.Connection | None = None
    try:
        c1 = connect_readonly(st1)
        _verify_sqlite_readable(c1)

        # Open target DB read-only in --dry-run to guarantee zero disk/WAL writes.
        c2 = connect_readonly(st2) if dry_run else connect_readwrite(st2)
        _verify_sqlite_readable(c2)

        if "threads" not in get_tables(c1) or "threads" not in get_tables(c2):
            return (os.path.basename(st2), 0, 0, 0, set())

        cols1 = get_columns(c1, "threads")
        cols2_info = get_column_info(c2, "threads")
        cols2 = set(cols2_info.keys())
        common_cols = [c for c in cols1 if c in cols2]
        if "id" not in common_cols:
            return (os.path.basename(st2), 0, 0, 0, set())

        # Any target-only NOT NULL columns without a default need a safe fallback on INSERT.
        extra_notnull_cols: list[str] = [
            col
            for col, meta in cols2_info.items()
            if col not in common_cols
            and meta["notnull"]
            and meta["dflt_value"] is None
            and not meta["pk"]
        ]

        # Stage ALL reads from the source DB into memory BEFORE acquiring any
        # write lock on the target DB so mid-read corruption cannot touch target.
        select_sql = ", ".join(quote_identifier(c) for c in common_cols)
        src_rows = c1.execute(f'SELECT {select_sql} FROM "threads"').fetchall()
        staged_shared_tables: list[tuple[str, list[str], list[tuple[object, ...]]]] = []
        for tbl in SHARED_STATE_TABLES:
            tbl_cols, tbl_rows = _prepare_shared_table_payload(c1, c2, tbl)
            if tbl_cols and tbl_rows:
                staged_shared_tables.append((tbl, tbl_cols, tbl_rows))

        existing_dst_ids = {
            str(r[0]) for r in c2.execute('SELECT "id" FROM "threads"').fetchall()
        }

        norm_cwd = normalize_repo_cwd(repo_path) if repo_path else None
        inserted_count = 0
        updated_count = 0
        pinned_count = 0
        synced_ids: set[str] = set()

        if not dry_run:
            c2.execute("BEGIN IMMEDIATE")

        # Write mirrored metadata tables inside the same atomic transaction.
        if not dry_run:
            for tbl, tbl_cols, tbl_rows in staged_shared_tables:
                q_tbl = quote_identifier(tbl, allowed_tables=ALLOWED_TABLES)
                col_sql = ", ".join(quote_identifier(c) for c in tbl_cols)
                placeholders = ", ".join(["?"] * len(tbl_cols))
                c2.executemany(
                    f"INSERT OR REPLACE INTO {q_tbl} ({col_sql}) VALUES ({placeholders})",
                    tbl_rows,
                )

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
                        # Skip if already populated above (e.g. target-only model_provider).
                        if extra_col in row_dict:
                            continue
                        insert_cols.append(extra_col)
                        insert_vals.append(
                            fallback_default_for_type(str(cols2_info[extra_col]["type"]))
                        )
                    col_list_sql = ", ".join(quote_identifier(c) for c in insert_cols)
                    placeholders = ", ".join(["?"] * len(insert_cols))
                    c2.execute(
                        f'INSERT INTO "threads" ({col_list_sql}) VALUES ({placeholders})',
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
                        q_col = quote_identifier(col)
                        if col == "name":
                            # Never erase an existing target thread name with NULL.
                            set_clauses.append(f'{q_col} = COALESCE(?, {q_col})')
                        else:
                            set_clauses.append(f"{q_col} = ?")
                        params.append(row_dict[col])

                    if set_clauses:
                        params.append(tid)
                        c2.execute(
                            f'UPDATE "threads" SET {", ".join(set_clauses)} WHERE "id" = ?',
                            params,
                        )

        if not dry_run:
            c2.execute("COMMIT")
            _checkpoint_wal_best_effort(c2)

        return (
            os.path.basename(st2),
            inserted_count,
            updated_count,
            pinned_count,
            synced_ids,
        )
    except sqlite3.Error as exc:
        if c2 is not None and not dry_run and c2.in_transaction:
            try:
                c2.execute("ROLLBACK")
            except sqlite3.Error:
                pass
        print(
            f"[WARN] Skipping state DB sync ({os.path.basename(st2)}): {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return (None, 0, 0, 0, set())
    except Exception:
        if c2 is not None and not dry_run and c2.in_transaction:
            try:
                c2.execute("ROLLBACK")
            except sqlite3.Error:
                pass
        raise
    finally:
        if c1 is not None:
            c1.close()
        if c2 is not None:
            c2.close()


def sync_goals_db(lane1: str, lane2: str, dry_run: bool) -> int:
    """
    Sync Codex Goals tables (`thread_goals`, `thread_goal_continuation_deferrals`)
    from Lane 1 (read-only) to Lane 2 inside an atomic transaction.

    Handles missing, locked, or corrupt Goals databases gracefully without
    modifying the target database.
    """
    _assert_distinct_lanes(lane1, lane2)

    g1 = find_latest_versioned_db(lane1, "goals")
    g2 = find_latest_versioned_db(lane2, "goals")
    if not g1 or not g2:
        return 0

    _validate_sqlite_and_sidecars(lane1, g1)
    _validate_sqlite_and_sidecars(lane2, g2)

    c1: sqlite3.Connection | None = None
    c2: sqlite3.Connection | None = None
    try:
        c1 = connect_readonly(g1)
        _verify_sqlite_readable(c1)

        c2 = connect_readonly(g2) if dry_run else connect_readwrite(g2)
        _verify_sqlite_readable(c2)

        # Stage all reads from Lane 1 before starting a write transaction on Lane 2.
        staged: dict[str, tuple[list[str], list[tuple[object, ...]]]] = {}
        for tbl in SHARED_GOALS_TABLES:
            staged[tbl] = _prepare_shared_table_payload(c1, c2, tbl)

        goals_count = len(staged["thread_goals"][1])

        if not dry_run:
            c2.execute("BEGIN IMMEDIATE")
            for tbl in SHARED_GOALS_TABLES:
                tbl_cols, tbl_rows = staged[tbl]
                if not tbl_cols or not tbl_rows:
                    continue
                q_tbl = quote_identifier(tbl, allowed_tables=ALLOWED_TABLES)
                col_sql = ", ".join(quote_identifier(c) for c in tbl_cols)
                placeholders = ", ".join(["?"] * len(tbl_cols))
                c2.executemany(
                    f"INSERT OR REPLACE INTO {q_tbl} ({col_sql}) VALUES ({placeholders})",
                    tbl_rows,
                )
            c2.execute("COMMIT")
            _checkpoint_wal_best_effort(c2)

        return goals_count
    except sqlite3.Error as exc:
        if c2 is not None and not dry_run and c2.in_transaction:
            try:
                c2.execute("ROLLBACK")
            except sqlite3.Error:
                pass
        print(
            f"[WARN] Skipping goals DB sync ({os.path.basename(g2)}): {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return 0
    except Exception:
        if c2 is not None and not dry_run and c2.in_transaction:
            try:
                c2.execute("ROLLBACK")
            except sqlite3.Error:
                pass
        raise
    finally:
        if c1 is not None:
            c1.close()
        if c2 is not None:
            c2.close()


def main() -> int:
    """CLI entrypoint coordinating state DB, session index JSONL, and goals DB sync."""
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

    try:
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
    except ValueError as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1

    mode = "DRY-RUN" if args.dry_run else "OK"
    # Print only basenames and integer counts; never log thread content or secrets.
    print(
        f"[{mode}] session_index={idx_count} | state_db={db_name or 'N/A'} "
        f"(inserted={inserted_count}, updated={updated_count}, pinned={pinned_count}) | goals={goals_count}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
