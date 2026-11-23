#!/usr/bin/env python3
"""
Schema-adaptive, safety-hardened sync of Codex session index, pinned threads,
Goals, and local shared files between two CODEX_HOME directories (typically
GPT 1 `~/.codex` and Sandbox 2 `~/.codex-official`).

Author    : Lê Hoàng Ngọc Tươi
Copyright : Copyright 2026 Lê Hoàng Ngọc Tươi
License   : Apache-2.0 (https://www.apache.org/licenses/LICENSE-2.0)
Project   : Codex Dual-Lane & Security Kit

Security & Reliability Guarantees:
  - Read-only SQLite URI (?mode=ro) + PRAGMA query_only=ON on all source DBs
    (and on target DBs during --dry-run) so active processes are never blocked
    by write locks and --dry-run performs strictly zero writes.
  - Explicit SQLite busy timeout (default 15s) to ride out brief concurrent
    checkpoints from Codex Desktop/CLI without failing immediately.
  - Strictly parameterized SQL values (?) combined with allowlisted table names
    and regex-validated, double-quoted SQL identifiers (blocks even second-order
    SQL injection from malformed or untrusted SQLite schemas).
  - Conflict-safe idempotent UPSERT inside an atomic BEGIN IMMEDIATE transaction
    after staging all reads in memory first: preserves monotonic pinning
    (`is_pinned = 1` / `pinned = 1` never downgraded), respects `updated_at` /
    `updated_at_ms` recency so older rows never clobber newer metadata, and
    never erases non-empty target fields with NULL/empty values.
  - Optional online SQLite backup (`--backup-target`) via SQLite's `.backup()`
    API staged atomically before modifying any target DB (zero writes in
    `--dry-run`).
  - Bidirectional convergence (`--bidirectional`) syncing `source -> target`
    and `target -> source` so both homes retain the complete union of chats,
    pinned threads, and goals.
  - Safe non-destructive shared-file rescue (`--rescue-shared-files`) copying
    missing regular files from real local `sessions`, `archived_sessions`,
    `memories`, and `memories_v2` directories while skipping existing
    symlinks/junctions cleanly and failing closed on planted symlinks inside
    real directories.
  - Atomic JSONL replacement (same-directory temp file + fsync + os.replace
    with 0600 permissions on POSIX) so interruptions never truncate
    session_index.jsonl.
  - Strict path containment & symlink/junction rejection across both CODEX_HOME
    trees (including SQLite -wal/-shm/-journal sidecars) to prevent path
    traversal and symlink-clobbering attacks.
  - Graceful handling of missing, locked, or corrupt SQLite databases without
    corrupting the target DB or leaking session contents/secrets in logs.

Usage:
    python scripts/sync-sessions.py --repo "/path/to/my-app"
    python scripts/sync-sessions.py --source ~/.codex --target ~/.codex-official --bidirectional --backup-target
    python scripts/sync-sessions.py --source ~/.codex-official --target ~/.codex --rescue-shared-files --backup-target
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
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

# Shared chat/memory directory names inspected by --rescue-shared-files.
SHARED_RESCUE_DIRS: tuple[str, ...] = (
    "sessions",
    "archived_sessions",
    "memories",
    "memories_v2",
)

# Pinning & timestamp column names handled with conflict-safe merge semantics.
PIN_COLUMNS: frozenset[str] = frozenset({"is_pinned", "pinned"})
TIMESTAMP_COLUMNS: tuple[str, ...] = ("updated_at", "updated_at_ms")
INDEX_TIMESTAMP_KEYS: tuple[str, ...] = (
    "updated_at",
    "updated_at_ms",
    "updatedAt",
    "timestamp",
    "last_updated_at",
)
IMMUTABLE_THREAD_COLUMNS: frozenset[str] = frozenset(
    {"id", "created_at", "created_at_ms"}
)
LEGACY_THREAD_UPDATE_COLUMNS: tuple[str, ...] = (
    "name",
    "title",
    "is_pinned",
    "pinned",
    "thread_section_id",
    "section_position",
    "section_entered_at_ms",
    "project_id",
    "model_provider",
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


def _is_reparse_or_symlink(path: str | Path) -> bool:
    """
    Return True if `path` is a symlink, Windows NTFS junction, or other
    filesystem reparse point without dereferencing links.

    Checking `os.path.islink` first preserves deterministic behavior on POSIX,
    Windows symlinks, and mocked unit tests, while `os.path.isjunction` and
    `FILE_ATTRIBUTE_REPARSE_POINT` catch Windows NTFS junctions on all Python 3.9+.
    """
    if os.path.islink(path):
        return True
    isjunction = getattr(os.path, "isjunction", None)
    if callable(isjunction):
        try:
            if isjunction(path):
                return True
        except OSError:
            pass
    reparse_attr = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    if reparse_attr:
        try:
            st = os.lstat(path)
            if getattr(st, "st_file_attributes", 0) & reparse_attr:
                return True
        except OSError:
            pass
    return False


def ensure_contained_path(
    base_dir: str | Path,
    candidate: str | Path,
    *,
    reject_symlinks: bool = True,
) -> Path:
    """
    Verify that `candidate` is strictly contained within `base_dir` and free of
    path-traversal (`..`) segments or symlink/junction escapes.

    Why this invariant exists:
      Both CODEX_HOME trees hold sensitive local state. Rejecting `..` traversal
      and symlinks/junctions strictly below `base_dir` (while permitting OS-level
      symlinks strictly above `base_dir`, such as macOS `/var -> /private/var`)
      prevents attacker-planted links from redirecting reads or atomic writes
      outside the user's Codex directories.

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
    # `_is_reparse_or_symlink(cur)` BEFORE `cur.resolve() == base_real` whenever
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
            if _is_reparse_or_symlink(cur):
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
        raise ValueError("Security violation: --lane1/--source and --lane2/--target must be non-empty paths.")
    if Path(lane1).resolve(strict=False) == Path(lane2).resolve(strict=False):
        raise ValueError(
            "Security violation: source and target CODEX_HOME directories must resolve to distinct paths."
        )


def _normalize_distinct_lanes(lane1: str, lane2: str) -> tuple[str, str]:
    """Verify two distinct non-empty CODEX_HOME paths and normalize relative paths to absolute."""
    _assert_distinct_lanes(lane1, lane2)
    norm1 = lane1 if os.path.isabs(lane1) else os.path.abspath(lane1)
    norm2 = lane2 if os.path.isabs(lane2) else os.path.abspath(lane2)
    return (norm1, norm2)


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
      Codex Desktop or CLI may be running concurrently while this script syncs
      sessions. Opening source databases read-only prevents blocking active
      writers or accidentally mutating primary session history.
    """
    if _is_reparse_or_symlink(db_path):
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
    if _is_reparse_or_symlink(db_path):
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


def backup_sqlite_db(
    base_dir: str,
    db_path: str,
    src_conn: sqlite3.Connection | None = None,
) -> Path:
    """
    Create a consistent standalone SQLite backup copy at
    `<db>.sync-backup-<YYYYMMDD-HHMMSS>` inside `base_dir` using SQLite's
    online `.backup()` API, staged atomically via a same-directory temp file
    with owner-only (0600) permissions on POSIX.

    Raises ValueError on containment/symlink violations, or sqlite3.Error /
    OSError on backup failure (cleaning up any staged temp file).
    """
    validated_db = _validate_sqlite_and_sidecars(base_dir, db_path)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    backup_path = Path(f"{validated_db}.sync-backup-{ts}")
    counter = 1
    while os.path.lexists(backup_path):
        backup_path = Path(f"{validated_db}.sync-backup-{ts}-{counter}")
        counter += 1
    ensure_contained_path(base_dir, backup_path, reject_symlinks=True)

    fd, tmp_path = tempfile.mkstemp(
        dir=str(backup_path.parent),
        prefix=f".{validated_db.name}.sync-backup.",
        suffix=".tmp",
    )
    os.close(fd)
    if os.name == "posix":
        os.chmod(tmp_path, 0o600)

    owned_src = False
    dst_conn: sqlite3.Connection | None = None
    try:
        if src_conn is None:
            src_conn = connect_readonly(str(validated_db))
            owned_src = True
        dst_conn = sqlite3.connect(tmp_path)
        try:
            src_conn.backup(dst_conn)
        finally:
            dst_conn.close()
            dst_conn = None

        if os.name == "posix":
            os.chmod(tmp_path, 0o600)

        ensure_contained_path(base_dir, backup_path, reject_symlinks=True)
        os.replace(tmp_path, backup_path)
        tmp_path = None
        return backup_path
    finally:
        if dst_conn is not None:
            dst_conn.close()
        if owned_src and src_conn is not None:
            src_conn.close()
        if tmp_path is not None:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


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
    Return schema metadata (type, notnull, default, pk, pk_index) keyed by
    validated column name for an allowlisted table.
    """
    q_table = quote_identifier(table, allowed_tables=ALLOWED_TABLES)
    info: dict[str, dict[str, object]] = {}
    for row in conn.execute(f"PRAGMA table_info({q_table})").fetchall():
        # PRAGMA table_info columns: cid, name, type, notnull, dflt_value, pk
        col_name = validate_sql_identifier(str(row[1]))
        pk_index = int(row[5] or 0)
        info[col_name] = {
            "type": str(row[2] or "").upper(),
            "notnull": bool(row[3]),
            "dflt_value": row[4],
            "pk": pk_index > 0,
            "pk_index": pk_index,
        }
    return info


def fallback_default_for_type(col_type: str) -> object:
    """
    Return a deterministic type-compatible fallback value for target-only
    NOT NULL columns lacking a schema DEFAULT (supports forward schema drift
    when one lane runs a newer Codex DB version than the other).
    """
    upper = col_type.upper()
    if "INT" in upper or "BOOL" in upper:
        return 0
    if "REAL" in upper or "FLOA" in upper or "DOUB" in upper:
        return 0.0
    if "BLOB" in upper:
        return b""
    return ""


def _is_empty_value(value: object) -> bool:
    """Return True if a field value is NULL or an empty/whitespace-only string."""
    if value is None:
        return True
    if isinstance(value, str) and value.strip() == "":
        return True
    return False


def _parse_timestamp(value: object) -> float | None:
    """
    Parse a numeric (epoch seconds/ms) or ISO-8601 timestamp into a comparable
    float, returning None if absent or unparseable.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return float(text)
        except ValueError:
            pass
        iso = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
        try:
            dt = datetime.fromisoformat(iso)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except ValueError:
            return None
    return None


def _compare_timestamps(src_val: object, dst_val: object) -> bool | None:
    """
    Compare source and target timestamp values.

    Returns:
      - True  if source is strictly newer (or source has a timestamp and target does not)
      - False if target is newer or equal (or target has a timestamp and source does not)
      - None  if neither side has a parseable timestamp
    """
    src_ts = _parse_timestamp(src_val)
    dst_ts = _parse_timestamp(dst_val)
    if src_ts is not None and dst_ts is not None:
        return src_ts > dst_ts
    if src_ts is not None and dst_ts is None:
        return True
    if src_ts is None and dst_ts is not None:
        return False
    return None


def _extract_entry_timestamp(obj: dict[str, object]) -> float | None:
    """Extract the first parseable timestamp from a `session_index.jsonl` record."""
    for key in INDEX_TIMESTAMP_KEYS:
        if key in obj:
            parsed = _parse_timestamp(obj.get(key))
            if parsed is not None:
                return parsed
    return None


def _merge_index_entry(
    dst_obj: dict[str, object],
    dst_line: str,
    src_obj: dict[str, object],
    src_line: str,
) -> tuple[dict[str, object], str]:
    """
    Conflict-safe merge of two `session_index.jsonl` entries sharing the same `id`.

    Guarantees:
      - Never downgrades a newer target entry with an older source entry.
      - Fills missing/empty target fields from source when target wins.
      - Never blanks out a non-empty target field (such as `thread_name`) when
        source wins.
    """
    dst_ts = _extract_entry_timestamp(dst_obj)
    src_ts = _extract_entry_timestamp(src_obj)

    if src_ts is not None and dst_ts is not None:
        source_wins = src_ts > dst_ts
    elif src_ts is not None and dst_ts is None:
        source_wins = True
    elif src_ts is None and dst_ts is not None:
        source_wins = False
    else:
        # Neither side carries a timestamp: source overlays target while
        # preserving any non-empty target fields that source omits or blanks.
        source_wins = True

    if source_wins:
        needs_merge = any(
            not _is_empty_value(v) and (k not in src_obj or _is_empty_value(src_obj.get(k)))
            for k, v in dst_obj.items()
        )
        if not needs_merge:
            return (src_obj, src_line)
        merged = dict(dst_obj)
        for k, v in src_obj.items():
            if not _is_empty_value(v) or k not in merged:
                merged[k] = v
        return (merged, json.dumps(merged, ensure_ascii=False))

    # Target is newer or equal: preserve target metadata, only filling missing/empty keys.
    ts_keys = set(INDEX_TIMESTAMP_KEYS)
    missing_fills = {
        k: v
        for k, v in src_obj.items()
        if k not in ts_keys
        and not _is_empty_value(v)
        and (k not in dst_obj or _is_empty_value(dst_obj.get(k)))
    }
    if not missing_fills:
        return (dst_obj, dst_line)
    merged = dict(dst_obj)
    merged.update(missing_fills)
    return (merged, json.dumps(merged, ensure_ascii=False))


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


def _atomic_copy_file(src_path: str | Path, dest_path: str | Path) -> None:
    """
    Atomically copy a regular file's bytes into `dest_path` via a same-directory
    temp file (fsync + 0600 on POSIX + preserve mtime + os.replace).
    """
    src = Path(src_path)
    dest = Path(dest_path)
    src_stat = os.lstat(src)
    tmp_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=str(dest.parent),
            prefix=f".{dest.name}.",
            suffix=".tmp",
            delete=False,
        ) as tmp_file:
            tmp_path = tmp_file.name
            if os.name == "posix":
                os.chmod(tmp_path, 0o600)
            with open(src, "rb") as in_handle:
                while True:
                    chunk = in_handle.read(65536)
                    if not chunk:
                        break
                    tmp_file.write(chunk)
            tmp_file.flush()
            os.fsync(tmp_file.fileno())
        try:
            os.utime(tmp_path, (src_stat.st_atime, src_stat.st_mtime))
        except OSError:
            pass
        os.replace(tmp_path, dest)
        tmp_path = None
    finally:
        if tmp_path is not None:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def rescue_shared_files(
    source_dir: str,
    target_dir: str,
    dry_run: bool,
) -> tuple[int, int, int]:
    """
    Safely rescue regular files from shared folder names (`sessions`,
    `archived_sessions`, `memories`, `memories_v2`) inside `source_dir` into
    `target_dir` without overwriting existing target files.

    Behavior & Security Guarantees:
      - If a top-level shared folder inside `source_dir` is ALREADY a symlink or
        Windows NTFS junction (e.g., linked to GPT 1), skip it cleanly.
      - If a top-level shared folder inside `source_dir` is a real local
        directory, walk it iteratively WITHOUT following symlinks: ANY symlink
        or junction encountered inside the tree is rejected fail-closed with
        ValueError before a single file is copied.
      - Copies only regular files that do NOT already exist in `target_dir`
        (non-destructive), preserving relative subdirectories and respecting
        `dry_run`.
      - Never prints filenames, thread titles, or file contents.

    Returns:
        `(copied_count, skipped_existing_count, skipped_links_count)`
    """
    source_dir, target_dir = _normalize_distinct_lanes(source_dir, target_dir)

    copy_plan: list[tuple[str, str]] = []
    skipped_existing = 0
    skipped_links = 0

    for folder_name in SHARED_RESCUE_DIRS:
        src_folder = os.path.join(source_dir, folder_name)
        if not os.path.lexists(src_folder):
            continue

        # Top-level shared folder already linked (symlink or NTFS junction): skip cleanly.
        if _is_reparse_or_symlink(src_folder):
            skipped_links += 1
            continue

        ensure_contained_path(source_dir, src_folder, reject_symlinks=True)
        if not os.path.isdir(src_folder):
            continue

        dst_folder = os.path.join(target_dir, folder_name)
        if os.path.lexists(dst_folder):
            if _is_reparse_or_symlink(dst_folder):
                # If target's shared folder already links directly to source's folder, skip cleanly;
                # otherwise fail closed rather than writing through an untrusted link.
                if Path(dst_folder).resolve(strict=False) == Path(src_folder).resolve(strict=False):
                    skipped_links += 1
                    continue
                raise ValueError(
                    f"Security violation: target shared directory {folder_name!r} is a symlink/junction."
                )
            ensure_contained_path(target_dir, dst_folder, reject_symlinks=True)
            if not os.path.isdir(dst_folder):
                raise ValueError(
                    f"Security violation: target shared path {folder_name!r} is not a directory."
                )

        # Phase 1: Full fail-closed tree validation before performing any writes.
        stack: list[str] = [src_folder]
        while stack:
            current_dir = stack.pop()
            with os.scandir(current_dir) as entries:
                entry_list = sorted(entries, key=lambda e: e.name)
            for entry in entry_list:
                entry_path = entry.path
                if _is_reparse_or_symlink(entry_path):
                    raise ValueError(
                        f"Security violation: symlink rejected inside shared folder {folder_name!r}."
                    )
                ensure_contained_path(source_dir, entry_path, reject_symlinks=True)

                rel_path = os.path.relpath(entry_path, src_folder)
                dst_path = os.path.join(dst_folder, rel_path)
                ensure_contained_path(target_dir, dst_path, reject_symlinks=True)

                if entry.is_dir(follow_symlinks=False):
                    if os.path.lexists(dst_path) and not os.path.isdir(dst_path):
                        raise ValueError(
                            f"Security violation: target path conflict inside shared folder {folder_name!r}."
                        )
                    stack.append(entry_path)
                elif entry.is_file(follow_symlinks=False):
                    if os.path.lexists(dst_path):
                        skipped_existing += 1
                    else:
                        copy_plan.append((entry_path, dst_path))

    # Phase 2: Execute non-destructive atomic copies when not in --dry-run.
    if not dry_run:
        for src_file, dst_file in copy_plan:
            ensure_contained_path(target_dir, dst_file, reject_symlinks=True)
            if os.path.lexists(dst_file):
                continue
            os.makedirs(os.path.dirname(dst_file), mode=0o700, exist_ok=True)
            ensure_contained_path(target_dir, dst_file, reject_symlinks=True)
            _atomic_copy_file(src_file, dst_file)

    return (len(copy_plan), skipped_existing, skipped_links)


def sync_session_index(
    lane1: str,
    lane2: str,
    dry_run: bool,
    allowed_ids: set[str] | None = None,
) -> int:
    """
    Merge `session_index.jsonl` entries by thread `id` from `lane1` into `lane2`,
    preserving all existing target entries, preferring newer timestamped entries
    on conflict, and atomically writing the merged JSONL file (skipped in
    `--dry-run`).

    Security invariants:
      - Rejects identical `lane1`/`lane2` directories and rejects symlinks or
        path traversal on either `session_index.jsonl` (including dangling links).
      - Skips malformed JSON lines and non-object JSON values safely.
      - Never prints session titles or JSONL contents to stdout/stderr.
    """
    lane1, lane2 = _normalize_distinct_lanes(lane1, lane2)

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

    by_id: dict[str, tuple[dict[str, object], str]] = {}
    # Preserve existing destination entries first, then conflict-merge source entries.
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
                    if tid not in by_id:
                        by_id[tid] = (obj, line)
                    else:
                        dst_obj, dst_line = by_id[tid]
                        by_id[tid] = _merge_index_entry(dst_obj, dst_line, obj, line)
        except (OSError, UnicodeDecodeError) as exc:
            print(
                f"[WARN] Could not read {path.name} cleanly ({type(exc).__name__}); aborting session_index sync to preserve target.",
                file=sys.stderr,
            )
            return 0

    if not dry_run:
        os.makedirs(idx2.parent, mode=0o700, exist_ok=True)
        payload = "".join(f"{entry_line}\n" for _, entry_line in by_id.values())
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


def _plan_shared_table_merge(
    c1: sqlite3.Connection,
    c2: sqlite3.Connection,
    table: str,
    *,
    preserve_existing_on_conflict: bool = False,
) -> tuple[int, list[tuple[str, list[object]]]]:
    """
    Stage a conflict-safe merge plan (parameterized SQL statements) for an
    allowlisted shared table from `c1` into `c2` before starting any write
    transaction.

    Preserves target-only rows, target-only columns, newer timestamped target
    rows, and non-empty target fields.

    Returns:
        `(source_row_count, planned_statements)`
    """
    q_table = quote_identifier(table, allowed_tables=ALLOWED_TABLES)
    if table not in get_tables(c1) or table not in get_tables(c2):
        return (0, [])

    cols1 = get_columns(c1, table)
    cols2_info = get_column_info(c2, table)
    common = [c for c in cols1 if c in cols2_info]
    if not common:
        return (0, [])

    extra_notnull_cols = [
        col
        for col, meta in cols2_info.items()
        if col not in common
        and meta["notnull"]
        and meta["dflt_value"] is None
        and not meta["pk"]
    ]
    extra_defaults = [
        fallback_default_for_type(str(cols2_info[col]["type"]))
        for col in extra_notnull_cols
    ]

    select_sql = ", ".join(quote_identifier(c) for c in common)
    src_rows = c1.execute(f"SELECT {select_sql} FROM {q_table}").fetchall()
    if not src_rows:
        return (0, [])

    pk_cols = [
        col
        for _, col in sorted(
            (int(meta["pk_index"]), col)
            for col, meta in cols2_info.items()
            if int(meta["pk_index"]) > 0
        )
    ]

    statements: list[tuple[str, list[object]]] = []
    insert_cols = common + extra_notnull_cols
    insert_col_sql = ", ".join(quote_identifier(c) for c in insert_cols)
    insert_placeholders = ", ".join(["?"] * len(insert_cols))

    if not pk_cols or any(pk not in common for pk in pk_cols):
        sql = f"INSERT OR IGNORE INTO {q_table} ({insert_col_sql}) VALUES ({insert_placeholders})"
        for row in src_rows:
            statements.append((sql, list(row) + extra_defaults))
        return (len(src_rows), statements)

    pk_indices = [common.index(pk) for pk in pk_cols]
    dst_rows: dict[tuple[object, ...], dict[str, object]] = {}
    for drow in c2.execute(f"SELECT {select_sql} FROM {q_table}").fetchall():
        key = tuple(drow[i] for i in pk_indices)
        dst_rows[key] = dict(zip(common, drow))

    ts_col = next((c for c in TIMESTAMP_COLUMNS if c in common), None)
    pk_set = set(pk_cols)
    where_sql = " AND ".join(f"{quote_identifier(pk)} = ?" for pk in pk_cols)

    for srow in src_rows:
        src_dict = dict(zip(common, srow))
        key = tuple(src_dict[pk] for pk in pk_cols)
        if key not in dst_rows:
            sql = f"INSERT INTO {q_table} ({insert_col_sql}) VALUES ({insert_placeholders})"
            statements.append((sql, list(srow) + extra_defaults))
            dst_rows[key] = src_dict
            continue

        dst_dict = dst_rows[key]
        source_is_newer = (
            _compare_timestamps(src_dict.get(ts_col), dst_dict.get(ts_col))
            if ts_col is not None
            else None
        )

        set_clauses: list[str] = []
        params: list[object] = []
        for col in common:
            if col in pk_set:
                continue
            src_val = src_dict.get(col)
            dst_val = dst_dict.get(col)
            if _is_empty_value(src_val) or src_val == dst_val:
                continue

            if source_is_newer is True:
                allow_update = True
            elif source_is_newer is False or preserve_existing_on_conflict:
                allow_update = (col not in TIMESTAMP_COLUMNS) and _is_empty_value(dst_val)
            else:
                allow_update = True

            if allow_update:
                set_clauses.append(f"{quote_identifier(col)} = ?")
                params.append(src_val)
                dst_dict[col] = src_val

        if set_clauses:
            params.extend(key)
            statements.append(
                (f"UPDATE {q_table} SET {', '.join(set_clauses)} WHERE {where_sql}", params)
            )

    return (len(src_rows), statements)


def copy_shared_table(
    c1: sqlite3.Connection,
    c2: sqlite3.Connection,
    table: str,
    dry_run: bool,
) -> int:
    """
    Copy the column intersection of an allowlisted shared table from `c1` to `c2`
    using conflict-safe parameterized UPSERT statements.
    """
    row_count, statements = _plan_shared_table_merge(c1, c2, table)
    if statements and not dry_run:
        for sql, params in statements:
            c2.execute(sql, params)
    return row_count


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
    *,
    backup_target: bool = False,
    force_openai_provider: bool = True,
) -> tuple[str | None, int, int, int, set[str]]:
    """
    Perform schema-adaptive, conflict-safe, transactional UPSERT sync of
    `threads` and shared metadata tables (`thread_sections`, `projects`,
    `project_roots`) from `lane1` (source) into `lane2` (target).

    Returns:
        `(db_basename, inserted_count, updated_count, pinned_count, synced_thread_ids)`

    Safety & Fault Tolerance:
      - Raises ValueError on security violations (symlinks, path traversal,
        identical lanes, unsafe SQL identifiers).
      - Preserves `is_pinned = 1` / `pinned = 1` monotonically (never downgrades
        a pinned thread on either side).
      - When `updated_at` (or `updated_at_ms`) exists on both sides, only
        overwrites mutable fields if source is strictly newer or the target
        field is NULL/empty.
      - Creates a verified online SQLite backup via `.backup()` before writing
        when `backup_target=True` and `dry_run=False`.
      - Handles missing, locked, or corrupt SQLite databases gracefully without
        corrupting the target DB.
      - Opens target DB read-only as well when `dry_run=True` for zero mutation.
    """
    lane1, lane2 = _normalize_distinct_lanes(lane1, lane2)

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

        # Stage ALL reads from source and target DBs into memory BEFORE
        # acquiring any write lock on the target DB.
        select_sql = ", ".join(quote_identifier(c) for c in common_cols)
        src_rows = c1.execute(f'SELECT {select_sql} FROM "threads"').fetchall()

        preserve_existing = not force_openai_provider
        shared_statements: list[tuple[str, list[object]]] = []
        for tbl in SHARED_STATE_TABLES:
            _, tbl_stmts = _plan_shared_table_merge(
                c1, c2, tbl, preserve_existing_on_conflict=preserve_existing
            )
            shared_statements.extend(tbl_stmts)

        dst_extra_inspect = [
            c
            for c in (
                "model_provider",
                "approval_mode",
                "cwd",
                "is_pinned",
                "pinned",
                "thread_section_id",
            )
            if c in cols2 and c not in common_cols
        ]
        dst_select_cols = common_cols + dst_extra_inspect
        dst_select_sql = ", ".join(quote_identifier(c) for c in dst_select_cols)
        existing_dst_rows: dict[str, dict[str, object]] = {}
        for drow in c2.execute(f'SELECT {dst_select_sql} FROM "threads"').fetchall():
            dmap = dict(zip(dst_select_cols, drow))
            existing_dst_rows[str(dmap["id"])] = dmap

        ts_col = next((c for c in TIMESTAMP_COLUMNS if c in common_cols), None)
        pk_cols = {col for col, meta in cols2_info.items() if meta["pk"]}

        norm_cwd = normalize_repo_cwd(repo_path) if repo_path else None
        inserted_count = 0
        updated_count = 0
        pinned_count = 0
        synced_ids: set[str] = set()
        thread_statements: list[tuple[str, list[object]]] = []

        for row in src_rows:
            row_dict = dict(zip(common_cols, row))
            tid = str(row_dict["id"])
            src_pinned = (
                bool(row_dict.get("is_pinned"))
                or bool(row_dict.get("pinned"))
                or (row_dict.get("thread_section_id") is not None)
            )
            if pinned_only and not src_pinned:
                continue

            synced_ids.add(tid)

            if tid not in existing_dst_rows:
                inserted_count += 1
                if src_pinned:
                    pinned_count += 1
                insert_dict = dict(row_dict)
                if "is_pinned" in insert_dict:
                    insert_dict["is_pinned"] = 1 if src_pinned else 0
                if "pinned" in insert_dict:
                    insert_dict["pinned"] = 1 if src_pinned else 0
                if force_openai_provider and "model_provider" in cols2:
                    insert_dict["model_provider"] = "openai"
                if approval_mode and "approval_mode" in cols2:
                    insert_dict["approval_mode"] = approval_mode
                if norm_cwd and src_pinned and "cwd" in cols2:
                    insert_dict["cwd"] = norm_cwd

                insert_cols = list(insert_dict.keys())
                insert_vals = [insert_dict[c] for c in insert_cols]
                for extra_col in extra_notnull_cols:
                    if extra_col in insert_dict:
                        continue
                    insert_cols.append(extra_col)
                    insert_vals.append(
                        fallback_default_for_type(str(cols2_info[extra_col]["type"]))
                    )
                col_list_sql = ", ".join(quote_identifier(c) for c in insert_cols)
                placeholders = ", ".join(["?"] * len(insert_cols))
                thread_statements.append(
                    (
                        f'INSERT INTO "threads" ({col_list_sql}) VALUES ({placeholders})',
                        insert_vals,
                    )
                )
                existing_dst_rows[tid] = insert_dict
            else:
                dst_dict = existing_dst_rows[tid]
                dst_pinned = (
                    bool(dst_dict.get("is_pinned"))
                    or bool(dst_dict.get("pinned"))
                    or (dst_dict.get("thread_section_id") is not None)
                )
                merged_pinned = src_pinned or dst_pinned
                if merged_pinned:
                    pinned_count += 1

                source_is_newer = (
                    _compare_timestamps(row_dict.get(ts_col), dst_dict.get(ts_col))
                    if ts_col is not None
                    else None
                )

                updates: dict[str, object] = {}

                # Monotonic pin preservation: pinned = 1 on either side always stays 1.
                for pcol in ("is_pinned", "pinned"):
                    if pcol in common_cols:
                        target_pin_val = 1 if merged_pinned else 0
                        if source_is_newer is False or preserve_existing:
                            if bool(dst_dict.get(pcol)) != merged_pinned:
                                updates[pcol] = target_pin_val
                        else:
                            updates[pcol] = target_pin_val

                if source_is_newer is True:
                    # Source is strictly newer: update mutable fields without erasing
                    # non-empty target fields or clobbering GPT 1's model_provider.
                    for col in common_cols:
                        if col in IMMUTABLE_THREAD_COLUMNS or col in PIN_COLUMNS or col in pk_cols:
                            continue
                        src_val = row_dict.get(col)
                        dst_val = dst_dict.get(col)
                        if col == "model_provider":
                            if force_openai_provider:
                                src_val = "openai"
                            elif not _is_empty_value(dst_val):
                                continue
                        elif col == "approval_mode" and approval_mode:
                            src_val = approval_mode
                        elif col == "cwd" and norm_cwd and merged_pinned:
                            src_val = norm_cwd
                        if _is_empty_value(src_val):
                            continue
                        if src_val != dst_val:
                            updates[col] = src_val
                    if force_openai_provider and "model_provider" in cols2 and "model_provider" not in common_cols:
                        if dst_dict.get("model_provider") != "openai":
                            updates["model_provider"] = "openai"
                    if approval_mode and "approval_mode" in cols2 and "approval_mode" not in common_cols:
                        if dst_dict.get("approval_mode") != approval_mode:
                            updates["approval_mode"] = approval_mode
                    if norm_cwd and merged_pinned and "cwd" in cols2 and "cwd" not in common_cols:
                        if dst_dict.get("cwd") != norm_cwd:
                            updates["cwd"] = norm_cwd
                elif source_is_newer is False:
                    # Source is older or equal: NEVER clobber non-empty target metadata;
                    # only fill target fields that are currently NULL/empty.
                    for col in common_cols:
                        if (
                            col in IMMUTABLE_THREAD_COLUMNS
                            or col in PIN_COLUMNS
                            or col in pk_cols
                            or col in TIMESTAMP_COLUMNS
                        ):
                            continue
                        src_val = row_dict.get(col)
                        dst_val = dst_dict.get(col)
                        if _is_empty_value(dst_val) and not _is_empty_value(src_val):
                            updates[col] = src_val
                else:
                    # No timestamp available on either side.
                    if preserve_existing:
                        # Reverse / rescue sync without timestamps: fill only NULL/empty target fields.
                        for col in common_cols:
                            if (
                                col in IMMUTABLE_THREAD_COLUMNS
                                or col in PIN_COLUMNS
                                or col in pk_cols
                                or col in TIMESTAMP_COLUMNS
                            ):
                                continue
                            src_val = row_dict.get(col)
                            dst_val = dst_dict.get(col)
                            if _is_empty_value(dst_val) and not _is_empty_value(src_val):
                                updates[col] = src_val
                    else:
                        # Forward sync without timestamps: preserve legacy idempotent upsert
                        # semantics while still guarding non-empty titles/sections & pinning.
                        for col in LEGACY_THREAD_UPDATE_COLUMNS:
                            if col in PIN_COLUMNS:
                                continue
                            if col == "model_provider":
                                if "model_provider" in cols2:
                                    updates["model_provider"] = "openai"
                                continue
                            if col not in common_cols:
                                continue
                            src_val = row_dict.get(col)
                            if col in ("name", "title", "thread_section_id") and _is_empty_value(src_val):
                                continue
                            updates[col] = src_val
                        if approval_mode and "approval_mode" in cols2:
                            updates["approval_mode"] = approval_mode
                        if norm_cwd and merged_pinned and "cwd" in cols2:
                            updates["cwd"] = norm_cwd

                # For timestamped or reverse merges, skip pure no-op updates.
                if (ts_col is not None or preserve_existing) and updates:
                    updates = {
                        col: val
                        for col, val in updates.items()
                        if dst_dict.get(col) != val
                    }

                if updates:
                    updated_count += 1
                    set_clauses: list[str] = []
                    params: list[object] = []
                    for col, val in updates.items():
                        q_col = quote_identifier(col)
                        if col == "name":
                            set_clauses.append(f"{q_col} = COALESCE(?, {q_col})")
                        else:
                            set_clauses.append(f"{q_col} = ?")
                        params.append(val)
                        dst_dict[col] = val
                    params.append(tid)
                    thread_statements.append(
                        (
                            f'UPDATE "threads" SET {", ".join(set_clauses)} WHERE "id" = ?',
                            params,
                        )
                    )

        all_statements = shared_statements + thread_statements
        if not dry_run and all_statements:
            if backup_target:
                backup_sqlite_db(lane2, st2, src_conn=c2)
            c2.execute("BEGIN IMMEDIATE")
            for sql, params in all_statements:
                c2.execute(sql, params)
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


def sync_goals_db(
    lane1: str,
    lane2: str,
    dry_run: bool,
    *,
    backup_target: bool = False,
    preserve_existing_on_conflict: bool = False,
) -> int:
    """
    Sync Codex Goals tables (`thread_goals`, `thread_goal_continuation_deferrals`)
    from `lane1` (read-only) into `lane2` inside an atomic transaction using
    conflict-safe merge semantics (never deleting target-only rows or
    downgrading newer target rows).

    Handles missing, locked, or corrupt Goals databases gracefully without
    modifying the target database.
    """
    lane1, lane2 = _normalize_distinct_lanes(lane1, lane2)

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

        # Stage all reads from source and target before starting a write transaction.
        goals_count = 0
        all_statements: list[tuple[str, list[object]]] = []
        for tbl in SHARED_GOALS_TABLES:
            row_count, stmts = _plan_shared_table_merge(
                c1,
                c2,
                tbl,
                preserve_existing_on_conflict=preserve_existing_on_conflict,
            )
            if tbl == "thread_goals":
                goals_count = row_count
            all_statements.extend(stmts)

        if not dry_run and all_statements:
            if backup_target:
                backup_sqlite_db(lane2, g2, src_conn=c2)
            c2.execute("BEGIN IMMEDIATE")
            for sql, params in all_statements:
                c2.execute(sql, params)
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


def _run_directional_sync(
    source: str,
    target: str,
    *,
    repo_path: str | None,
    approval_mode: str | None,
    pinned_only: bool,
    dry_run: bool,
    backup_target: bool,
    rescue_shared: bool,
    force_openai_provider: bool,
) -> dict[str, object]:
    """Execute one full sync pass (`source -> target`) across state DB, index, goals, and optional shared files."""
    db_name, inserted_count, updated_count, pinned_count, synced_ids = sync_state_db(
        source,
        target,
        repo_path,
        approval_mode,
        pinned_only,
        dry_run,
        backup_target=backup_target,
        force_openai_provider=force_openai_provider,
    )
    allowed_ids = synced_ids if pinned_only else None
    idx_count = sync_session_index(source, target, dry_run, allowed_ids)
    goals_count = sync_goals_db(
        source,
        target,
        dry_run,
        backup_target=backup_target,
        preserve_existing_on_conflict=not force_openai_provider,
    )
    rescued = (0, 0, 0)
    if rescue_shared:
        rescued = rescue_shared_files(source, target, dry_run)

    return {
        "db_name": db_name,
        "inserted": inserted_count,
        "updated": updated_count,
        "pinned": pinned_count,
        "session_index": idx_count,
        "goals": goals_count,
        "rescued_copied": rescued[0],
        "rescued_skipped_existing": rescued[1],
        "rescued_skipped_links": rescued[2],
    }


def _format_sync_summary(
    mode: str,
    stats: dict[str, object],
    *,
    direction_label: str | None = None,
    include_rescue: bool = False,
) -> str:
    """Format a secret-free summary line containing only DB basenames and integer counts."""
    prefix = f"[{mode}] [{direction_label}]" if direction_label else f"[{mode}]"
    line = (
        f"{prefix} session_index={stats['session_index']} | "
        f"state_db={stats['db_name'] or 'N/A'} "
        f"(inserted={stats['inserted']}, updated={stats['updated']}, pinned={stats['pinned']}) | "
        f"goals={stats['goals']}"
    )
    if include_rescue:
        line += (
            f" | rescued_files={stats['rescued_copied']} "
            f"(skipped_existing={stats['rescued_skipped_existing']}, "
            f"skipped_links={stats['rescued_skipped_links']})"
        )
    return line


def main() -> int:
    """CLI entrypoint coordinating state DB, session index JSONL, goals DB, and shared-file rescue."""
    parser = argparse.ArgumentParser(
        description="Schema-adaptive conflict-safe UPSERT sync of Codex sessions, pinned tasks, goals, and shared files between two CODEX_HOMEs."
    )
    user_home = os.path.expanduser("~")
    parser.add_argument(
        "--lane1",
        "--source",
        dest="lane1",
        default=os.path.join(user_home, ".codex"),
        help="Source / Primary CODEX_HOME (default: ~/.codex)",
    )
    parser.add_argument(
        "--lane2",
        "--target",
        dest="lane2",
        default=os.path.join(user_home, ".codex-official"),
        help="Target / Secondary CODEX_HOME (default: ~/.codex-official)",
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
        "--bidirectional",
        action="store_true",
        help="Sync cleanly in both directions (source -> target and target -> source) with conflict-safe merge",
    )
    parser.add_argument(
        "--backup-target",
        action="store_true",
        help="Create a verified SQLite .sync-backup-<timestamp> copy before modifying any target DB",
    )
    parser.add_argument(
        "--rescue-shared-files",
        action="store_true",
        help="Copy missing regular files from real local sessions/archived_sessions/memories/memories_v2 directories into target (skipping existing symlinks/junctions)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Inspect schemas and report what would be synced without writing any file",
    )
    args = parser.parse_args()

    mode = "DRY-RUN" if args.dry_run else "OK"
    try:
        # When rescuing back to GPT 1 (unidirectional --rescue-shared-files), preserve
        # target's existing model_provider instead of forcing "openai".
        fwd_force_openai = not args.rescue_shared_files or args.bidirectional
        fwd_stats = _run_directional_sync(
            args.lane1,
            args.lane2,
            repo_path=args.repo,
            approval_mode=args.approval_mode,
            pinned_only=args.pinned_only,
            dry_run=args.dry_run,
            backup_target=args.backup_target,
            rescue_shared=args.rescue_shared_files,
            force_openai_provider=fwd_force_openai,
        )

        if args.bidirectional:
            # Reverse pass (`target -> source`): never clobber GPT 1's cwd, approval_mode,
            # or model_provider with Lane 2 CLI overrides.
            rev_stats = _run_directional_sync(
                args.lane2,
                args.lane1,
                repo_path=None,
                approval_mode=None,
                pinned_only=args.pinned_only,
                dry_run=args.dry_run,
                backup_target=args.backup_target,
                rescue_shared=args.rescue_shared_files,
                force_openai_provider=False,
            )
            # Print only basenames and integer counts; never log thread content or secrets.
            print(
                _format_sync_summary(
                    mode,
                    fwd_stats,
                    direction_label="forward",
                    include_rescue=args.rescue_shared_files,
                )
            )
            print(
                _format_sync_summary(
                    mode,
                    rev_stats,
                    direction_label="reverse",
                    include_rescue=args.rescue_shared_files,
                )
            )
        else:
            print(
                _format_sync_summary(
                    mode,
                    fwd_stats,
                    include_rescue=args.rescue_shared_files,
                )
            )
    except ValueError as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"[FAIL] Filesystem error ({type(exc).__name__}).", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
