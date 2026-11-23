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

# Hard RAM & Disk safety bounds.
# - MAX_JSONL_LINE_CHARS caps per-line memory allocation when reading session_index.jsonl
#   so a corrupt single-line multi-hundred-MB file without newlines can never spike RAM.
# - SQLITE_CACHE_SIZE_KIB (-8192 = 8 MiB) caps per-connection SQLite page cache in RAM.
# - SQLITE_VACUUM_MIN_FREE_PAGES triggers a page-reclaiming VACUUM during storage compaction
#   only when freelist_count exceeds this threshold.
MAX_JSONL_LINE_CHARS: int = 1024 * 1024
SQLITE_CACHE_SIZE_KIB: int = -8192
SQLITE_VACUUM_MIN_FREE_PAGES: int = 64

# Explicit sync outcome statuses (replaces raw integer-only reporting).
SYNC_STATUS_SUCCESS: str = "SUCCESS"
SYNC_STATUS_PARTIAL: str = "PARTIAL"
SYNC_STATUS_FAILED: str = "FAILED"
SYNC_STATUS_SKIPPED: str = "SKIPPED"
VALID_SYNC_STATUSES: frozenset[str] = frozenset(
    {
        SYNC_STATUS_SUCCESS,
        SYNC_STATUS_PARTIAL,
        SYNC_STATUS_FAILED,
        SYNC_STATUS_SKIPPED,
    }
)

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


def _effective_busy_timeout(timeout: float | None = None) -> float:
    """Resolve effective SQLite busy timeout (explicit arg > env override > default)."""
    if timeout is not None:
        return max(0.0, float(timeout))
    env_raw = os.environ.get("CODEX_SYNC_BUSY_TIMEOUT_SEC", "").strip()
    if env_raw:
        try:
            val = float(env_raw)
            if val >= 0.0:
                return val
        except ValueError:
            pass
    return DEFAULT_BUSY_TIMEOUT_SEC


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
    effective_timeout = _effective_busy_timeout(timeout)
    uri = _build_sqlite_uri(db_path, "ro")
    conn = sqlite3.connect(uri, uri=True, timeout=effective_timeout)
    try:
        timeout_ms = max(0, int(effective_timeout * 1000))
        conn.execute(f"PRAGMA busy_timeout = {timeout_ms}")
        conn.execute(f"PRAGMA cache_size = {SQLITE_CACHE_SIZE_KIB}")
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
    effective_timeout = _effective_busy_timeout(timeout)
    uri = _build_sqlite_uri(db_path, "rw")
    conn = sqlite3.connect(uri, uri=True, timeout=effective_timeout, isolation_level=None)
    try:
        timeout_ms = max(0, int(effective_timeout * 1000))
        conn.execute(f"PRAGMA busy_timeout = {timeout_ms}")
        conn.execute(f"PRAGMA cache_size = {SQLITE_CACHE_SIZE_KIB}")
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


DEFAULT_MAX_SYNC_BACKUPS = 5


def _prune_old_sync_backups(
    base_dir: str,
    validated_db: Path,
    *,
    max_backups: int,
) -> int:
    """
    Keep at most `max_backups` newest regular `.sync-backup-*` files for
    `validated_db`, pruning older regular files safely without ever following
    or unlinking symlinks. Returns the number of pruned files.
    """
    if max_backups <= 0:
        return 0
    prefix = f"{validated_db.name}.sync-backup-"
    candidates: list[tuple[int, str, Path]] = []
    try:
        with os.scandir(validated_db.parent) as it:
            for entry in it:
                if not entry.name.startswith(prefix):
                    continue
                if entry.is_symlink():
                    # Never follow or unlink symlinks during backup rotation.
                    continue
                if not entry.is_file(follow_symlinks=False):
                    continue
                try:
                    st = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                candidates.append((st.st_mtime_ns, entry.name, Path(entry.path)))
    except OSError:
        return 0

    if len(candidates) <= max_backups:
        return 0

    # Sort newest first by (mtime_ns, filename) so the latest backups are always kept.
    candidates.sort(key=lambda item: (item[0], item[1]), reverse=True)
    pruned = 0
    for _, _, old_path in candidates[max_backups:]:
        try:
            ensure_contained_path(base_dir, old_path, reject_symlinks=True)
            if not os.path.islink(old_path):
                os.unlink(old_path)
                pruned += 1
        except (OSError, ValueError):
            continue
    return pruned


def backup_sqlite_db(
    base_dir: str,
    db_path: str,
    src_conn: sqlite3.Connection | None = None,
    *,
    max_backups: int = DEFAULT_MAX_SYNC_BACKUPS,
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
        _prune_old_sync_backups(base_dir, validated_db, max_backups=max_backups)
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


def find_latest_versioned_db(
    directory: str, prefix: str, *, strict: bool = False
) -> str | None:
    """
    Locate the highest-numbered `<prefix>_<N>.sqlite` file directly inside
    `directory` using `os.scandir` (immune to glob brackets in path names).

    Security invariant:
      Rejects any symlink matching `<prefix>_<N>.sqlite` by raising ValueError
      rather than silently following an attacker-planted link outside `directory`.
      When `strict=True`, re-raises directory scan `OSError` fail-closed.
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
        if strict:
            raise
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


def _aggregate_sync_status(statuses: list[str]) -> str:
    """
    Aggregate component sync statuses into one overall status:
      - All SKIPPED -> SKIPPED
      - All non-SKIPPED are SUCCESS -> SUCCESS
      - Any PARTIAL, or mix of SUCCESS and FAILED -> PARTIAL
      - At least one FAILED and zero SUCCESS/PARTIAL -> FAILED
    """
    if not statuses:
        return SYNC_STATUS_SKIPPED
    non_skipped = [s for s in statuses if s != SYNC_STATUS_SKIPPED]
    if not non_skipped:
        return SYNC_STATUS_SKIPPED
    if all(s == SYNC_STATUS_SUCCESS for s in non_skipped):
        return SYNC_STATUS_SUCCESS
    if any(s == SYNC_STATUS_PARTIAL for s in non_skipped):
        return SYNC_STATUS_PARTIAL
    if any(s == SYNC_STATUS_SUCCESS for s in non_skipped) and any(
        s == SYNC_STATUS_FAILED for s in non_skipped
    ):
        return SYNC_STATUS_PARTIAL
    return SYNC_STATUS_FAILED


def _snapshot_state_threads(conn: sqlite3.Connection) -> tuple[set[str], set[str]]:
    """
    Return `(all_thread_ids, pinned_thread_ids)` from an open SQLite connection
    to `state_*.sqlite` without leaking titles or session contents.
    """
    if "threads" not in get_tables(conn):
        return (set(), set())
    cols = get_columns(conn, "threads")
    if "id" not in cols:
        return (set(), set())
    inspect_cols = ["id"] + [
        c for c in ("is_pinned", "pinned", "thread_section_id") if c in cols
    ]
    select_sql = ", ".join(quote_identifier(c) for c in inspect_cols)
    all_ids: set[str] = set()
    pinned_ids: set[str] = set()
    for row in conn.execute(f'SELECT {select_sql} FROM "threads"').fetchall():
        row_map = dict(zip(inspect_cols, row))
        tid = str(row_map["id"])
        all_ids.add(tid)
        is_pinned = (
            bool(row_map.get("is_pinned"))
            or bool(row_map.get("pinned"))
            or (row_map.get("thread_section_id") is not None)
        )
        if is_pinned:
            pinned_ids.add(tid)
    return (all_ids, pinned_ids)


def _snapshot_goals_keys(
    conn: sqlite3.Connection,
) -> tuple[int, set[tuple[object, ...]]]:
    """
    Return `(row_count, key_set)` for `thread_goals` from an open SQLite
    connection to `goals_*.sqlite`.
    """
    if "thread_goals" not in get_tables(conn):
        return (0, set())
    cols_info = get_column_info(conn, "thread_goals")
    if not cols_info:
        return (0, set())
    pk_cols = [
        col
        for _, col in sorted(
            (int(meta["pk_index"]), col)
            for col, meta in cols_info.items()
            if int(meta["pk_index"]) > 0
        )
    ]
    key_cols = pk_cols if pk_cols else list(cols_info.keys())
    select_sql = ", ".join(quote_identifier(c) for c in key_cols)
    rows = conn.execute(f'SELECT {select_sql} FROM "thread_goals"').fetchall()
    return (len(rows), {tuple(r) for r in rows})


def _iter_bounded_lines(path: Path, max_chars: int = MAX_JSONL_LINE_CHARS):
    """
    Yield lines from a UTF-8 file while capping single-line memory allocation
    at `max_chars` so a corrupt multi-hundred-MB line without newlines cannot
    spike RAM. Oversized lines are drained in 64 KiB chunks and skipped.
    """
    with open(path, "r", encoding="utf-8") as handle:
        while True:
            chunk = handle.readline(max_chars + 1)
            if not chunk:
                break
            if len(chunk) > max_chars and not chunk.endswith("\n"):
                while True:
                    drain = handle.readline(65536)
                    if not drain or drain.endswith("\n"):
                        break
                continue
            yield chunk


def _snapshot_session_index_ids(
    path: Path, *, allowed_ids: set[str] | None = None
) -> set[str]:
    """Read valid thread IDs from a `session_index.jsonl` file with bounded RAM."""
    ids: set[str] = set()
    if not path.exists():
        return ids
    for raw_line in _iter_bounded_lines(path):
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
        if allowed_ids is not None and tid not in allowed_ids:
            continue
        ids.add(tid)
    return ids


def _bootstrap_target_sqlite_from_source(
    target_dir: str,
    src_db_path: str,
    src_conn: sqlite3.Connection,
) -> Path:
    """
    Atomically clone a verified, readable source SQLite DB into
    `<target_dir>/<basename(src_db_path)>` via SQLite's online `.backup()` API
    (staged temp file + 0600 on POSIX + os.replace) when target does not yet
    have a matching SQLite DB during rescue/strict sync.
    """
    os.makedirs(target_dir, mode=0o700, exist_ok=True)
    dest_path = Path(target_dir) / os.path.basename(src_db_path)
    validated_dest = ensure_contained_path(target_dir, dest_path, reject_symlinks=True)
    fd, tmp_path = tempfile.mkstemp(
        dir=str(validated_dest.parent),
        prefix=f".{validated_dest.name}.bootstrap.",
        suffix=".tmp",
    )
    os.close(fd)
    if os.name == "posix":
        os.chmod(tmp_path, 0o600)
    dst_conn: sqlite3.Connection | None = None
    try:
        dst_conn = sqlite3.connect(tmp_path)
        try:
            src_conn.backup(dst_conn)
        finally:
            dst_conn.close()
            dst_conn = None
        if os.name == "posix":
            os.chmod(tmp_path, 0o600)
        ensure_contained_path(target_dir, validated_dest, reject_symlinks=True)
        os.replace(tmp_path, validated_dest)
        tmp_path = None
        return validated_dest
    finally:
        if dst_conn is not None:
            dst_conn.close()
        if tmp_path is not None:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def sync_session_index_detailed(
    lane1: str,
    lane2: str,
    dry_run: bool,
    allowed_ids: set[str] | None = None,
) -> dict[str, object]:
    """
    Merge `session_index.jsonl` entries by thread `id` from `lane1` into `lane2`
    and return a structured result with explicit status (`SUCCESS`, `PARTIAL`,
    `FAILED`, `SKIPPED`) and before/after ID reconciliation.
    """
    lane1, lane2 = _normalize_distinct_lanes(lane1, lane2)

    idx1_raw = os.path.join(lane1, "session_index.jsonl")
    idx2_raw = os.path.join(lane2, "session_index.jsonl")

    # Always run containment & symlink checks before checking file existence so
    # dangling symlinks are rejected immediately.
    idx1 = ensure_contained_path(lane1, idx1_raw, reject_symlinks=True)
    idx2 = ensure_contained_path(lane2, idx2_raw, reject_symlinks=True)

    if not idx1.exists():
        return {
            "status": SYNC_STATUS_SKIPPED,
            "reason": "missing_source_index",
            "count": 0,
            "source_exists": False,
            "target_exists": idx2.exists(),
            "before": {"source_count": 0, "target_count": 0},
            "after": {"target_count": 0},
            "reconciliation": {"verified": True, "missing_ids_count": 0},
        }
    if not idx1.is_file():
        raise ValueError("Security violation: source session_index.jsonl is not a regular file.")
    if idx2.exists() and not idx2.is_file():
        raise ValueError("Security violation: target session_index.jsonl is not a regular file.")

    by_id: dict[str, tuple[dict[str, object], str]] = {}
    target_before_ids: set[str] = set()
    source_eligible_ids: set[str] = set()
    # Preserve existing destination entries first, then conflict-merge source entries.
    for path, is_source in ((idx2, False), (idx1, True)):
        if not path.exists():
            continue
        try:
            for raw_line in _iter_bounded_lines(path):
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
                if is_source:
                    source_eligible_ids.add(tid)
                else:
                    target_before_ids.add(tid)
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
            return {
                "status": SYNC_STATUS_FAILED,
                "reason": f"read_error:{type(exc).__name__}",
                "count": 0,
                "source_exists": True,
                "target_exists": idx2.exists(),
                "before": {
                    "source_count": len(source_eligible_ids),
                    "target_count": len(target_before_ids),
                },
                "after": {"target_count": len(target_before_ids)},
                "reconciliation": {"verified": False, "missing_ids_count": len(source_eligible_ids)},
            }

    expected_ids = target_before_ids | source_eligible_ids
    if not dry_run:
        os.makedirs(idx2.parent, mode=0o700, exist_ok=True)
        payload = "".join(f"{entry_line}\n" for _, entry_line in by_id.values())
        atomic_write_text(idx2, payload)
        try:
            after_ids = _snapshot_session_index_ids(idx2)
        except (OSError, UnicodeDecodeError) as exc:
            return {
                "status": SYNC_STATUS_FAILED,
                "reason": f"post_verify_read_error:{type(exc).__name__}",
                "count": len(by_id),
                "source_exists": True,
                "target_exists": idx2.exists(),
                "before": {
                    "source_count": len(source_eligible_ids),
                    "target_count": len(target_before_ids),
                },
                "after": {"target_count": 0},
                "reconciliation": {"verified": False, "missing_ids_count": len(expected_ids)},
            }
        missing_ids = expected_ids - after_ids
        verified = len(missing_ids) == 0 and len(after_ids) >= len(expected_ids)
        return {
            "status": SYNC_STATUS_SUCCESS if verified else SYNC_STATUS_PARTIAL,
            "reason": "ok" if verified else "reconciliation_mismatch",
            "count": len(by_id),
            "source_exists": True,
            "target_exists": True,
            "before": {
                "source_count": len(source_eligible_ids),
                "target_count": len(target_before_ids),
            },
            "after": {"target_count": len(after_ids)},
            "reconciliation": {
                "verified": verified,
                "expected_count": len(expected_ids),
                "missing_ids_count": len(missing_ids),
            },
        }

    return {
        "status": SYNC_STATUS_SUCCESS,
        "reason": "dry_run",
        "count": len(by_id),
        "source_exists": True,
        "target_exists": idx2.exists(),
        "before": {
            "source_count": len(source_eligible_ids),
            "target_count": len(target_before_ids),
        },
        "after": {"target_count": len(expected_ids)},
        "reconciliation": {
            "verified": True,
            "expected_count": len(expected_ids),
            "missing_ids_count": 0,
        },
    }


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
    result = sync_session_index_detailed(lane1, lane2, dry_run, allowed_ids)
    return int(result["count"])


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


def compact_codex_home_storage(
    home_dir: str,
    *,
    max_backups: int = DEFAULT_MAX_SYNC_BACKUPS,
    dry_run: bool = False,
    fast: bool = False,
) -> dict[str, int]:
    """
    Safely compact and bound disk (ROM) and SQLite WAL usage inside `home_dir`
    without following symlinks/junctions or touching active sessions:
      1. Rotates `.sync-backup-*`, `config.toml.backup-*`, `config.toml.pre-*`,
         `auth.json.backup-*`, and `auth.json.pre-*` keeping at most
         `max_backups` newest regular files per family.
      2. Removes stale leftover `.*.tmp` staging files in `home_dir`.
      3. Checkpoints and truncates `-wal` sidecars (`PRAGMA wal_checkpoint(TRUNCATE)`)
         and runs `PRAGMA optimize` (plus `VACUUM` when free pages >=
         `SQLITE_VACUUM_MIN_FREE_PAGES`) on `state_*.sqlite` and `goals_*.sqlite`.

    Returns:
        `{"backups_pruned": int, "tmp_pruned": int, "dbs_compacted": int, "bytes_reclaimed": int}`
    """
    if not home_dir or not os.path.isdir(home_dir) or _is_reparse_or_symlink(home_dir):
        return {"backups_pruned": 0, "tmp_pruned": 0, "dbs_compacted": 0, "bytes_reclaimed": 0}

    backups_pruned = 0
    tmp_pruned = 0
    dbs_compacted = 0
    bytes_reclaimed = 0

    protected_backup_names: set[str] = set()
    rb_dir = Path(home_dir) / ".rollback"
    if rb_dir.is_dir() and not _is_reparse_or_symlink(rb_dir):
        for mf_name in ("latest.json", "manifest.env", "latest.tsv"):
            mf_path = rb_dir / mf_name
            if mf_path.is_file() and not _is_reparse_or_symlink(mf_path):
                try:
                    raw_mf = mf_path.read_text(encoding="utf-8", errors="ignore")
                    for m in re.findall(
                        r"[A-Za-z0-9_.-]+\.(?:backup|pre)-[0-9]{8}-[0-9]{6}(?:-[0-9]+)?",
                        raw_mf,
                    ):
                        protected_backup_names.add(m)
                except OSError:
                    pass

    backup_families: dict[str, list[tuple[int, str, Path, int]]] = {}
    tmp_candidates: list[tuple[Path, int]] = []
    try:
        with os.scandir(home_dir) as it:
            for entry in it:
                if entry.is_symlink() or _is_reparse_or_symlink(entry.path):
                    continue
                if not entry.is_file(follow_symlinks=False):
                    continue
                try:
                    st = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                name = entry.name
                if name in protected_backup_names:
                    continue
                if name.startswith(".") and name.endswith(".tmp"):
                    tmp_candidates.append((Path(entry.path), int(st.st_size)))
                    continue
                family_key: str | None = None
                if ".sync-backup-" in name:
                    family_key = name.split(".sync-backup-", 1)[0] + ".sync-backup-"
                elif name.startswith("config.toml.backup-") or name.startswith("config.toml.pre-"):
                    family_key = "config.toml.backup"
                elif name.startswith("auth.json.backup-") or name.startswith("auth.json.pre-"):
                    family_key = "auth.json.backup"
                if family_key is not None:
                    backup_families.setdefault(family_key, []).append(
                        (int(st.st_mtime_ns), name, Path(entry.path), int(st.st_size))
                    )
    except OSError:
        return {"backups_pruned": 0, "tmp_pruned": 0, "dbs_compacted": 0, "bytes_reclaimed": 0}

    if max_backups > 0:
        for _, items in backup_families.items():
            if len(items) <= max_backups:
                continue
            items.sort(key=lambda item: (item[0], item[1]), reverse=True)
            for _, _, old_path, sz in items[max_backups:]:
                try:
                    ensure_contained_path(home_dir, old_path, reject_symlinks=True)
                    if not dry_run:
                        os.unlink(old_path)
                    backups_pruned += 1
                    bytes_reclaimed += sz
                except (OSError, ValueError):
                    continue

    for tmp_path, sz in tmp_candidates:
        try:
            ensure_contained_path(home_dir, tmp_path, reject_symlinks=True)
            if not dry_run:
                os.unlink(tmp_path)
            tmp_pruned += 1
            bytes_reclaimed += sz
        except (OSError, ValueError):
            continue

    db_prefixes = ("state", "goals", "logs") if fast else ("state", "goals", "logs", "thread_history")
    for prefix in db_prefixes:
        db_file = find_latest_versioned_db(home_dir, prefix)
        if not db_file:
            continue
        try:
            _validate_sqlite_and_sidecars(home_dir, db_file)
        except ValueError:
            continue
        if dry_run:
            dbs_compacted += 1
            continue
        before_sz = 0
        for suffix in ("", "-wal", "-shm"):
            p = Path(str(db_file) + suffix)
            if p.exists() and not _is_reparse_or_symlink(p):
                try:
                    before_sz += p.stat().st_size
                except OSError:
                    pass
        conn: sqlite3.Connection | None = None
        try:
            conn = connect_readwrite(db_file, timeout=1.0)
            _verify_sqlite_readable(conn)
            tables = get_tables(conn)
            did_prune_rows = False

            if fast:
                # Fast non-blocking pass for 1-Touch QuickThirdParty / Launch:
                # never block on multi-hundred-MiB DELETE/VACUUM.
                conn.execute("PRAGMA wal_checkpoint(PASSIVE)")
                dbs_compacted += 1
                continue

            # 1) Bounded log table rotation in logs_*.sqlite (keep newest 200 rows).
            if prefix == "logs" and "logs" in tables:
                try:
                    row_cnt = int(conn.execute('SELECT COUNT(*) FROM "logs"').fetchone()[0])
                    if row_cnt > 200:
                        conn.execute("BEGIN IMMEDIATE")
                        cur = conn.execute(
                            'DELETE FROM "logs" WHERE rowid NOT IN (SELECT rowid FROM "logs" ORDER BY rowid DESC LIMIT 200)'
                        )
                        conn.execute("COMMIT")
                        if cur.rowcount and cur.rowcount > 0:
                            did_prune_rows = True
                except sqlite3.Error:
                    try:
                        conn.rollback()
                    except sqlite3.Error:
                        pass

            # 2) Bounded projection-cache pruning in thread_history_*.sqlite when file exceeds 32 MiB:
            #    preserves 100% of pinned threads + 25 most recently updated threads from state_*.sqlite
            #    (real chat transcripts in sessions/*.jsonl and state_*.sqlite are NEVER touched).
            if prefix == "thread_history" and before_sz > 32 * 1024 * 1024:
                keep_thread_ids: set[str] = set()
                st_file = find_latest_versioned_db(home_dir, "state")
                if st_file:
                    c_st: sqlite3.Connection | None = None
                    try:
                        c_st = connect_readonly(st_file, timeout=1.0)
                        _, pinned_ids = _snapshot_state_threads(c_st)
                        keep_thread_ids.update(pinned_ids)
                        if "threads" in get_tables(c_st):
                            st_cols = get_columns(c_st, "threads")
                            order_col = next(
                                (
                                    c
                                    for c in ("updated_at_ms", "updated_at", "created_at_ms", "created_at")
                                    if c in st_cols
                                ),
                                "rowid",
                            )
                            q_order = quote_identifier(order_col) if order_col != "rowid" else "rowid"
                            recent_rows = c_st.execute(
                                f'SELECT "id" FROM "threads" ORDER BY {q_order} DESC LIMIT 25'
                            ).fetchall()
                            for r in recent_rows:
                                if r and r[0]:
                                    keep_thread_ids.add(str(r[0]))
                    except sqlite3.Error:
                        pass
                    finally:
                        if c_st is not None:
                            c_st.close()

                if keep_thread_ids and "thread_items" in tables:
                    placeholders = ", ".join(["?"] * len(keep_thread_ids))
                    keep_params = list(keep_thread_ids)
                    try:
                        prunable_tables: list[str] = []
                        for hist_tbl in (
                            "thread_items",
                            "thread_turns",
                            "thread_history_projection_state",
                            "thread_realtime_items",
                        ):
                            if hist_tbl not in tables:
                                continue
                            tbl_cols = {
                                str(row[1])
                                for row in conn.execute(f'PRAGMA table_info("{hist_tbl}")').fetchall()
                                if row and len(row) > 1
                            }
                            if "thread_id" in tbl_cols:
                                prunable_tables.append(hist_tbl)
                        if prunable_tables:
                            deleted_rows = 0
                            conn.execute("BEGIN IMMEDIATE")
                            for hist_tbl in prunable_tables:
                                cur = conn.execute(
                                    f'DELETE FROM "{hist_tbl}" WHERE thread_id NOT IN ({placeholders})',
                                    keep_params,
                                )
                                if cur.rowcount and cur.rowcount > 0:
                                    deleted_rows += cur.rowcount
                            conn.execute("COMMIT")
                            if deleted_rows > 0:
                                did_prune_rows = True
                    except sqlite3.Error:
                        try:
                            conn.rollback()
                        except sqlite3.Error:
                            pass

            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            conn.execute("PRAGMA optimize")
            free_row = conn.execute("PRAGMA freelist_count").fetchone()
            free_pages = int(free_row[0]) if free_row and free_row[0] is not None else 0
            # Avoid rewriting massive (>256 MiB) databases if no rows were actually deleted.
            allow_vacuum = did_prune_rows or (
                free_pages >= SQLITE_VACUUM_MIN_FREE_PAGES and before_sz <= 256 * 1024 * 1024
            )
            if allow_vacuum:
                conn.execute("VACUUM")
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            dbs_compacted += 1
        except sqlite3.Error:
            if conn is not None and conn.in_transaction:
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
        finally:
            if conn is not None:
                conn.close()
        after_sz = 0
        for suffix in ("", "-wal", "-shm"):
            p = Path(str(db_file) + suffix)
            if p.exists() and not _is_reparse_or_symlink(p):
                try:
                    after_sz += p.stat().st_size
                except OSError:
                    pass
        if before_sz > after_sz:
            bytes_reclaimed += before_sz - after_sz

    # 3) Clean non-reparse temporary staging directories (.tmp / tmp) inside home_dir.
    for tmp_dir_name in (".tmp", "tmp"):
        tdir = Path(home_dir) / tmp_dir_name
        if not tdir.exists() or _is_reparse_or_symlink(tdir) or not tdir.is_dir():
            continue
        try:
            ensure_contained_path(home_dir, tdir, reject_symlinks=True)
        except ValueError:
            continue
        for root, dirs, files in os.walk(tdir, topdown=False):
            root_path = Path(root)
            if _is_reparse_or_symlink(root_path):
                continue
            for fname in files:
                if fname.endswith(".lock"):
                    continue
                fpath = root_path / fname
                if _is_reparse_or_symlink(fpath):
                    continue
                try:
                    ensure_contained_path(home_dir, fpath, reject_symlinks=True)
                    sz = fpath.stat().st_size
                    if not dry_run:
                        fpath.unlink()
                    tmp_pruned += 1
                    bytes_reclaimed += sz
                except (OSError, ValueError):
                    continue
            for dname in dirs:
                dpath = root_path / dname
                if _is_reparse_or_symlink(dpath):
                    continue
                if not dry_run:
                    try:
                        dpath.rmdir()
                    except OSError:
                        pass

    return {
        "backups_pruned": backups_pruned,
        "tmp_pruned": tmp_pruned,
        "dbs_compacted": dbs_compacted,
        "bytes_reclaimed": bytes_reclaimed,
    }


def sync_state_db_detailed(
    lane1: str,
    lane2: str,
    repo_path: str | None,
    approval_mode: str | None,
    pinned_only: bool,
    dry_run: bool,
    *,
    backup_target: bool = False,
    max_backups: int = DEFAULT_MAX_SYNC_BACKUPS,
    force_openai_provider: bool = True,
    require_source_db: bool = False,
) -> dict[str, object]:
    """
    Perform schema-adaptive, conflict-safe, transactional UPSERT sync of
    `threads` and shared metadata tables (`thread_sections`, `projects`,
    `project_roots`) from `lane1` (source) into `lane2` (target), returning a
    structured result with explicit status (`SUCCESS`, `PARTIAL`, `FAILED`,
    `SKIPPED`) and before/after reconciliation of record counts, thread IDs,
    and Pinned threads.
    """
    lane1, lane2 = _normalize_distinct_lanes(lane1, lane2)

    st1 = find_latest_versioned_db(lane1, "state", strict=require_source_db)
    st2 = find_latest_versioned_db(lane2, "state", strict=require_source_db)
    if not st1:
        return {
            "status": SYNC_STATUS_SKIPPED,
            "reason": "missing_source_db",
            "db_name": None,
            "inserted": 0,
            "updated": 0,
            "pinned": 0,
            "synced_ids": set(),
            "source_exists": False,
            "target_exists": bool(st2),
            "before": {
                "source_threads": 0,
                "source_pinned": 0,
                "target_threads": 0,
                "target_pinned": 0,
            },
            "after": {"target_threads": 0, "target_pinned": 0},
            "reconciliation": {
                "verified": True,
                "expected_threads": 0,
                "expected_pinned": 0,
                "missing_ids_count": 0,
                "missing_pinned_count": 0,
            },
        }

    if not st2:
        if not require_source_db:
            print(
                "[!] state_*.sqlite not found in both homes. Launch 'codex' once to initialize the secondary DB first."
            )
            return {
                "status": SYNC_STATUS_SKIPPED,
                "reason": "missing_target_db",
                "db_name": None,
                "inserted": 0,
                "updated": 0,
                "pinned": 0,
                "synced_ids": set(),
                "source_exists": True,
                "target_exists": False,
                "before": {
                    "source_threads": 0,
                    "source_pinned": 0,
                    "target_threads": 0,
                    "target_pinned": 0,
                },
                "after": {"target_threads": 0, "target_pinned": 0},
                "reconciliation": {
                    "verified": True,
                    "expected_threads": 0,
                    "expected_pinned": 0,
                    "missing_ids_count": 0,
                    "missing_pinned_count": 0,
                },
            }

        # Strict / rescue mode: source state_*.sqlite exists while target has none.
        # Verify source DB is readable (fail closed if locked/corrupt) and atomically
        # bootstrap target via SQLite online backup when not in --dry-run.
        _validate_sqlite_and_sidecars(lane1, st1)
        c1_boot: sqlite3.Connection | None = None
        try:
            c1_boot = connect_readonly(st1)
            _verify_sqlite_readable(c1_boot)
            src_ids_all, src_pinned_all = _snapshot_state_threads(c1_boot)
            if dry_run:
                return {
                    "status": SYNC_STATUS_SUCCESS,
                    "reason": "dry_run_bootstrap",
                    "db_name": os.path.basename(st1),
                    "inserted": len(src_ids_all),
                    "updated": 0,
                    "pinned": len(src_pinned_all),
                    "synced_ids": set(src_ids_all),
                    "source_exists": True,
                    "target_exists": False,
                    "before": {
                        "source_threads": len(src_ids_all),
                        "source_pinned": len(src_pinned_all),
                        "target_threads": 0,
                        "target_pinned": 0,
                    },
                    "after": {
                        "target_threads": len(src_ids_all),
                        "target_pinned": len(src_pinned_all),
                    },
                    "reconciliation": {
                        "verified": True,
                        "expected_threads": len(src_ids_all),
                        "expected_pinned": len(src_pinned_all),
                        "missing_ids_count": 0,
                        "missing_pinned_count": 0,
                    },
                }
            boot_dest = _bootstrap_target_sqlite_from_source(lane2, st1, c1_boot)
        except sqlite3.Error as exc:
            print(
                f"[WARN] Source state DB ({os.path.basename(st1)}) could not be read or rescued: {type(exc).__name__}: {exc}",
                file=sys.stderr,
            )
            return {
                "status": SYNC_STATUS_FAILED,
                "reason": f"source_db_error:{type(exc).__name__}",
                "db_name": None,
                "inserted": 0,
                "updated": 0,
                "pinned": 0,
                "synced_ids": set(),
                "source_exists": True,
                "target_exists": False,
                "before": {
                    "source_threads": 0,
                    "source_pinned": 0,
                    "target_threads": 0,
                    "target_pinned": 0,
                },
                "after": {"target_threads": 0, "target_pinned": 0},
                "reconciliation": {
                    "verified": False,
                    "expected_threads": 0,
                    "expected_pinned": 0,
                    "missing_ids_count": 0,
                    "missing_pinned_count": 0,
                },
            }
        finally:
            if c1_boot is not None:
                c1_boot.close()

        # Reconcile bootstrapped target DB with a fresh read-only connection.
        c_verify: sqlite3.Connection | None = None
        try:
            c_verify = connect_readonly(str(boot_dest))
            _verify_sqlite_readable(c_verify)
            after_ids, after_pinned = _snapshot_state_threads(c_verify)
        except sqlite3.Error as exc:
            print(
                f"[WARN] Post-rescue verification failed for {boot_dest.name}: {type(exc).__name__}: {exc}",
                file=sys.stderr,
            )
            return {
                "status": SYNC_STATUS_FAILED,
                "reason": f"post_verify_error:{type(exc).__name__}",
                "db_name": boot_dest.name,
                "inserted": len(src_ids_all),
                "updated": 0,
                "pinned": len(src_pinned_all),
                "synced_ids": set(src_ids_all),
                "source_exists": True,
                "target_exists": True,
                "before": {
                    "source_threads": len(src_ids_all),
                    "source_pinned": len(src_pinned_all),
                    "target_threads": 0,
                    "target_pinned": 0,
                },
                "after": {"target_threads": 0, "target_pinned": 0},
                "reconciliation": {
                    "verified": False,
                    "expected_threads": len(src_ids_all),
                    "expected_pinned": len(src_pinned_all),
                    "missing_ids_count": len(src_ids_all),
                    "missing_pinned_count": len(src_pinned_all),
                },
            }
        finally:
            if c_verify is not None:
                c_verify.close()

        missing_ids = src_ids_all - after_ids
        missing_pinned = src_pinned_all - after_pinned
        verified = len(missing_ids) == 0 and len(missing_pinned) == 0
        return {
            "status": SYNC_STATUS_SUCCESS if verified else SYNC_STATUS_PARTIAL,
            "reason": "ok" if verified else "reconciliation_mismatch",
            "db_name": boot_dest.name,
            "inserted": len(src_ids_all),
            "updated": 0,
            "pinned": len(src_pinned_all),
            "synced_ids": set(src_ids_all),
            "source_exists": True,
            "target_exists": True,
            "before": {
                "source_threads": len(src_ids_all),
                "source_pinned": len(src_pinned_all),
                "target_threads": 0,
                "target_pinned": 0,
            },
            "after": {
                "target_threads": len(after_ids),
                "target_pinned": len(after_pinned),
            },
            "reconciliation": {
                "verified": verified,
                "expected_threads": len(src_ids_all),
                "expected_pinned": len(src_pinned_all),
                "missing_ids_count": len(missing_ids),
                "missing_pinned_count": len(missing_pinned),
            },
        }

    # Validate DB files and any existing -wal/-shm/-journal sidecars against symlinks.
    _validate_sqlite_and_sidecars(lane1, st1)
    _validate_sqlite_and_sidecars(lane2, st2)

    c1: sqlite3.Connection | None = None
    c2: sqlite3.Connection | None = None
    target_before_ids: set[str] = set()
    target_before_pinned: set[str] = set()
    eligible_source_ids: set[str] = set()
    eligible_source_pinned: set[str] = set()
    inserted_count = 0
    updated_count = 0
    pinned_count = 0
    synced_ids: set[str] = set()

    try:
        c1 = connect_readonly(st1)
        _verify_sqlite_readable(c1)

        # Open target DB read-only in --dry-run to guarantee zero disk/WAL writes.
        c2 = connect_readonly(st2) if dry_run else connect_readwrite(st2)
        _verify_sqlite_readable(c2)

        c1_tables = get_tables(c1)
        c2_tables = get_tables(c2)
        if "threads" not in c1_tables or "threads" not in c2_tables:
            incompatible_strict = require_source_db and ("threads" in c1_tables) and ("threads" not in c2_tables)
            return {
                "status": SYNC_STATUS_FAILED if incompatible_strict else SYNC_STATUS_SKIPPED,
                "reason": "target_schema_missing_threads" if incompatible_strict else "missing_threads_table",
                "db_name": os.path.basename(st2),
                "inserted": 0,
                "updated": 0,
                "pinned": 0,
                "synced_ids": set(),
                "source_exists": True,
                "target_exists": True,
                "before": {
                    "source_threads": 0,
                    "source_pinned": 0,
                    "target_threads": 0,
                    "target_pinned": 0,
                },
                "after": {"target_threads": 0, "target_pinned": 0},
                "reconciliation": {
                    "verified": not incompatible_strict,
                    "expected_threads": 0,
                    "expected_pinned": 0,
                    "missing_ids_count": 0,
                    "missing_pinned_count": 0,
                },
            }

        cols1 = get_columns(c1, "threads")
        cols2_info = get_column_info(c2, "threads")
        cols2 = set(cols2_info.keys())
        common_cols = [c for c in cols1 if c in cols2]
        if "id" not in common_cols:
            incompatible_strict = require_source_db and ("id" in cols1)
            return {
                "status": SYNC_STATUS_FAILED if incompatible_strict else SYNC_STATUS_SKIPPED,
                "reason": "target_schema_missing_id" if incompatible_strict else "missing_id_column",
                "db_name": os.path.basename(st2),
                "inserted": 0,
                "updated": 0,
                "pinned": 0,
                "synced_ids": set(),
                "source_exists": True,
                "target_exists": True,
                "before": {
                    "source_threads": 0,
                    "source_pinned": 0,
                    "target_threads": 0,
                    "target_pinned": 0,
                },
                "after": {"target_threads": 0, "target_pinned": 0},
                "reconciliation": {
                    "verified": not incompatible_strict,
                    "expected_threads": 0,
                    "expected_pinned": 0,
                    "missing_ids_count": 0,
                    "missing_pinned_count": 0,
                },
            }

        # Pre-sync baseline snapshot for before/after reconciliation.
        target_before_ids, target_before_pinned = _snapshot_state_threads(c2)

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

            eligible_source_ids.add(tid)
            if src_pinned:
                eligible_source_pinned.add(tid)
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
                backup_sqlite_db(lane2, st2, src_conn=c2, max_backups=max_backups)
            c2.execute("BEGIN IMMEDIATE")
            for sql, params in all_statements:
                c2.execute(sql, params)
            c2.execute("COMMIT")
            _checkpoint_wal_best_effort(c2)
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
        return {
            "status": SYNC_STATUS_FAILED,
            "reason": f"sqlite_error:{type(exc).__name__}",
            "db_name": None,
            "inserted": 0,
            "updated": 0,
            "pinned": 0,
            "synced_ids": set(),
            "source_exists": True,
            "target_exists": True,
            "before": {
                "source_threads": len(eligible_source_ids),
                "source_pinned": len(eligible_source_pinned),
                "target_threads": len(target_before_ids),
                "target_pinned": len(target_before_pinned),
            },
            "after": {
                "target_threads": len(target_before_ids),
                "target_pinned": len(target_before_pinned),
            },
            "reconciliation": {
                "verified": False,
                "expected_threads": len(target_before_ids | eligible_source_ids),
                "expected_pinned": len(target_before_pinned | eligible_source_pinned),
                "missing_ids_count": len(eligible_source_ids - target_before_ids),
                "missing_pinned_count": len(eligible_source_pinned - target_before_pinned),
            },
        }
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

    expected_ids = target_before_ids | eligible_source_ids
    expected_pinned = target_before_pinned | eligible_source_pinned
    if dry_run:
        return {
            "status": SYNC_STATUS_SUCCESS,
            "reason": "dry_run",
            "db_name": os.path.basename(st2),
            "inserted": inserted_count,
            "updated": updated_count,
            "pinned": pinned_count,
            "synced_ids": synced_ids,
            "source_exists": True,
            "target_exists": True,
            "before": {
                "source_threads": len(eligible_source_ids),
                "source_pinned": len(eligible_source_pinned),
                "target_threads": len(target_before_ids),
                "target_pinned": len(target_before_pinned),
            },
            "after": {
                "target_threads": len(expected_ids),
                "target_pinned": len(expected_pinned),
            },
            "reconciliation": {
                "verified": True,
                "expected_threads": len(expected_ids),
                "expected_pinned": len(expected_pinned),
                "missing_ids_count": 0,
                "missing_pinned_count": 0,
            },
        }

    # Post-sync reconciliation using a fresh read-only connection on target DB.
    c_verify: sqlite3.Connection | None = None
    try:
        c_verify = connect_readonly(st2)
        _verify_sqlite_readable(c_verify)
        target_after_ids, target_after_pinned = _snapshot_state_threads(c_verify)
    except sqlite3.Error as exc:
        print(
            f"[WARN] Post-sync verification failed for state DB ({os.path.basename(st2)}): {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return {
            "status": SYNC_STATUS_FAILED,
            "reason": f"post_verify_error:{type(exc).__name__}",
            "db_name": os.path.basename(st2),
            "inserted": inserted_count,
            "updated": updated_count,
            "pinned": pinned_count,
            "synced_ids": synced_ids,
            "source_exists": True,
            "target_exists": True,
            "before": {
                "source_threads": len(eligible_source_ids),
                "source_pinned": len(eligible_source_pinned),
                "target_threads": len(target_before_ids),
                "target_pinned": len(target_before_pinned),
            },
            "after": {"target_threads": 0, "target_pinned": 0},
            "reconciliation": {
                "verified": False,
                "expected_threads": len(expected_ids),
                "expected_pinned": len(expected_pinned),
                "missing_ids_count": len(expected_ids),
                "missing_pinned_count": len(expected_pinned),
            },
        }
    finally:
        if c_verify is not None:
            c_verify.close()

    missing_ids = expected_ids - target_after_ids
    missing_pinned = expected_pinned - target_after_pinned
    verified = (
        len(missing_ids) == 0
        and len(missing_pinned) == 0
        and len(target_after_ids) >= len(expected_ids)
        and len(target_after_pinned) >= len(expected_pinned)
    )
    if not verified:
        print(
            f"[WARN] Post-sync reconciliation mismatch on {os.path.basename(st2)}: "
            f"missing_ids={len(missing_ids)}, missing_pinned={len(missing_pinned)}",
            file=sys.stderr,
        )

    return {
        "status": SYNC_STATUS_SUCCESS if verified else SYNC_STATUS_PARTIAL,
        "reason": "ok" if verified else "reconciliation_mismatch",
        "db_name": os.path.basename(st2),
        "inserted": inserted_count,
        "updated": updated_count,
        "pinned": pinned_count,
        "synced_ids": synced_ids,
        "source_exists": True,
        "target_exists": True,
        "before": {
            "source_threads": len(eligible_source_ids),
            "source_pinned": len(eligible_source_pinned),
            "target_threads": len(target_before_ids),
            "target_pinned": len(target_before_pinned),
        },
        "after": {
            "target_threads": len(target_after_ids),
            "target_pinned": len(target_after_pinned),
        },
        "reconciliation": {
            "verified": verified,
            "expected_threads": len(expected_ids),
            "expected_pinned": len(expected_pinned),
            "missing_ids_count": len(missing_ids),
            "missing_pinned_count": len(missing_pinned),
        },
    }


def sync_state_db(
    lane1: str,
    lane2: str,
    repo_path: str | None,
    approval_mode: str | None,
    pinned_only: bool,
    dry_run: bool,
    *,
    backup_target: bool = False,
    max_backups: int = DEFAULT_MAX_SYNC_BACKUPS,
    force_openai_provider: bool = True,
) -> tuple[str | None, int, int, int, set[str]]:
    """
    Backward-compatible tuple wrapper around `sync_state_db_detailed(...)`.

    Returns:
        `(db_basename, inserted_count, updated_count, pinned_count, synced_thread_ids)`
    """
    res = sync_state_db_detailed(
        lane1,
        lane2,
        repo_path,
        approval_mode,
        pinned_only,
        dry_run,
        backup_target=backup_target,
        max_backups=max_backups,
        force_openai_provider=force_openai_provider,
    )
    return (
        res["db_name"],
        int(res["inserted"]),
        int(res["updated"]),
        int(res["pinned"]),
        set(res["synced_ids"]),
    )


def sync_goals_db_detailed(
    lane1: str,
    lane2: str,
    dry_run: bool,
    *,
    backup_target: bool = False,
    max_backups: int = DEFAULT_MAX_SYNC_BACKUPS,
    preserve_existing_on_conflict: bool = False,
    require_source_db: bool = False,
) -> dict[str, object]:
    """
    Sync Codex Goals tables (`thread_goals`, `thread_goal_continuation_deferrals`)
    from `lane1` (read-only) into `lane2` inside an atomic transaction, returning
    a structured result with explicit status (`SUCCESS`, `PARTIAL`, `FAILED`,
    `SKIPPED`) and before/after Goals reconciliation.
    """
    lane1, lane2 = _normalize_distinct_lanes(lane1, lane2)

    g1 = find_latest_versioned_db(lane1, "goals", strict=require_source_db)
    g2 = find_latest_versioned_db(lane2, "goals", strict=require_source_db)
    if not g1:
        return {
            "status": SYNC_STATUS_SKIPPED,
            "reason": "missing_source_db",
            "db_name": None,
            "count": 0,
            "source_exists": False,
            "target_exists": bool(g2),
            "before": {"source_goals": 0, "target_goals": 0},
            "after": {"target_goals": 0},
            "reconciliation": {
                "verified": True,
                "expected_goals": 0,
                "missing_goals_count": 0,
            },
        }

    if not g2:
        if not require_source_db:
            return {
                "status": SYNC_STATUS_SKIPPED,
                "reason": "missing_target_db",
                "db_name": None,
                "count": 0,
                "source_exists": True,
                "target_exists": False,
                "before": {"source_goals": 0, "target_goals": 0},
                "after": {"target_goals": 0},
                "reconciliation": {
                    "verified": True,
                    "expected_goals": 0,
                    "missing_goals_count": 0,
                },
            }

        # Strict / rescue mode: source goals_*.sqlite exists while target has none.
        _validate_sqlite_and_sidecars(lane1, g1)
        c1_boot: sqlite3.Connection | None = None
        try:
            c1_boot = connect_readonly(g1)
            _verify_sqlite_readable(c1_boot)
            src_count, src_keys = _snapshot_goals_keys(c1_boot)
            if dry_run:
                return {
                    "status": SYNC_STATUS_SUCCESS,
                    "reason": "dry_run_bootstrap",
                    "db_name": os.path.basename(g1),
                    "count": src_count,
                    "source_exists": True,
                    "target_exists": False,
                    "before": {"source_goals": src_count, "target_goals": 0},
                    "after": {"target_goals": src_count},
                    "reconciliation": {
                        "verified": True,
                        "expected_goals": len(src_keys),
                        "missing_goals_count": 0,
                    },
                }
            boot_dest = _bootstrap_target_sqlite_from_source(lane2, g1, c1_boot)
        except sqlite3.Error as exc:
            print(
                f"[WARN] Source goals DB ({os.path.basename(g1)}) could not be read or rescued: {type(exc).__name__}: {exc}",
                file=sys.stderr,
            )
            return {
                "status": SYNC_STATUS_FAILED,
                "reason": f"source_db_error:{type(exc).__name__}",
                "db_name": None,
                "count": 0,
                "source_exists": True,
                "target_exists": False,
                "before": {"source_goals": 0, "target_goals": 0},
                "after": {"target_goals": 0},
                "reconciliation": {
                    "verified": False,
                    "expected_goals": 0,
                    "missing_goals_count": 0,
                },
            }
        finally:
            if c1_boot is not None:
                c1_boot.close()

        c_verify: sqlite3.Connection | None = None
        try:
            c_verify = connect_readonly(str(boot_dest))
            _verify_sqlite_readable(c_verify)
            after_count, after_keys = _snapshot_goals_keys(c_verify)
        except sqlite3.Error as exc:
            print(
                f"[WARN] Post-rescue verification failed for goals DB ({boot_dest.name}): {type(exc).__name__}: {exc}",
                file=sys.stderr,
            )
            return {
                "status": SYNC_STATUS_FAILED,
                "reason": f"post_verify_error:{type(exc).__name__}",
                "db_name": boot_dest.name,
                "count": src_count,
                "source_exists": True,
                "target_exists": True,
                "before": {"source_goals": src_count, "target_goals": 0},
                "after": {"target_goals": 0},
                "reconciliation": {
                    "verified": False,
                    "expected_goals": len(src_keys),
                    "missing_goals_count": len(src_keys),
                },
            }
        finally:
            if c_verify is not None:
                c_verify.close()

        missing_keys = src_keys - after_keys
        verified = len(missing_keys) == 0 and after_count >= len(src_keys)
        return {
            "status": SYNC_STATUS_SUCCESS if verified else SYNC_STATUS_PARTIAL,
            "reason": "ok" if verified else "reconciliation_mismatch",
            "db_name": boot_dest.name,
            "count": src_count,
            "source_exists": True,
            "target_exists": True,
            "before": {"source_goals": src_count, "target_goals": 0},
            "after": {"target_goals": after_count},
            "reconciliation": {
                "verified": verified,
                "expected_goals": len(src_keys),
                "missing_goals_count": len(missing_keys),
            },
        }

    _validate_sqlite_and_sidecars(lane1, g1)
    _validate_sqlite_and_sidecars(lane2, g2)

    c1: sqlite3.Connection | None = None
    c2: sqlite3.Connection | None = None
    src_goals_count = 0
    src_goal_keys: set[tuple[object, ...]] = set()
    target_before_count = 0
    target_before_keys: set[tuple[object, ...]] = set()
    goals_count = 0

    try:
        c1 = connect_readonly(g1)
        _verify_sqlite_readable(c1)

        c2 = connect_readonly(g2) if dry_run else connect_readwrite(g2)
        _verify_sqlite_readable(c2)

        src_goals_count, src_goal_keys = _snapshot_goals_keys(c1)
        target_before_count, target_before_keys = _snapshot_goals_keys(c2)

        # Stage all reads from source and target before starting a write transaction.
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
                backup_sqlite_db(lane2, g2, src_conn=c2, max_backups=max_backups)
            c2.execute("BEGIN IMMEDIATE")
            for sql, params in all_statements:
                c2.execute(sql, params)
            c2.execute("COMMIT")
            _checkpoint_wal_best_effort(c2)
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
        return {
            "status": SYNC_STATUS_FAILED,
            "reason": f"sqlite_error:{type(exc).__name__}",
            "db_name": None,
            "count": 0,
            "source_exists": True,
            "target_exists": True,
            "before": {
                "source_goals": src_goals_count,
                "target_goals": target_before_count,
            },
            "after": {"target_goals": target_before_count},
            "reconciliation": {
                "verified": False,
                "expected_goals": len(target_before_keys | src_goal_keys),
                "missing_goals_count": len(src_goal_keys - target_before_keys),
            },
        }
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

    expected_goal_keys = target_before_keys | src_goal_keys
    if dry_run:
        return {
            "status": SYNC_STATUS_SUCCESS,
            "reason": "dry_run",
            "db_name": os.path.basename(g2),
            "count": goals_count,
            "source_exists": True,
            "target_exists": True,
            "before": {
                "source_goals": src_goals_count,
                "target_goals": target_before_count,
            },
            "after": {"target_goals": len(expected_goal_keys)},
            "reconciliation": {
                "verified": True,
                "expected_goals": len(expected_goal_keys),
                "missing_goals_count": 0,
            },
        }

    c_verify: sqlite3.Connection | None = None
    try:
        c_verify = connect_readonly(g2)
        _verify_sqlite_readable(c_verify)
        target_after_count, target_after_keys = _snapshot_goals_keys(c_verify)
    except sqlite3.Error as exc:
        print(
            f"[WARN] Post-sync verification failed for goals DB ({os.path.basename(g2)}): {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return {
            "status": SYNC_STATUS_FAILED,
            "reason": f"post_verify_error:{type(exc).__name__}",
            "db_name": os.path.basename(g2),
            "count": goals_count,
            "source_exists": True,
            "target_exists": True,
            "before": {
                "source_goals": src_goals_count,
                "target_goals": target_before_count,
            },
            "after": {"target_goals": 0},
            "reconciliation": {
                "verified": False,
                "expected_goals": len(expected_goal_keys),
                "missing_goals_count": len(expected_goal_keys),
            },
        }
    finally:
        if c_verify is not None:
            c_verify.close()

    missing_keys = expected_goal_keys - target_after_keys
    verified = len(missing_keys) == 0 and target_after_count >= len(expected_goal_keys)
    if not verified:
        print(
            f"[WARN] Post-sync reconciliation mismatch on {os.path.basename(g2)}: "
            f"missing_goals={len(missing_keys)}",
            file=sys.stderr,
        )

    return {
        "status": SYNC_STATUS_SUCCESS if verified else SYNC_STATUS_PARTIAL,
        "reason": "ok" if verified else "reconciliation_mismatch",
        "db_name": os.path.basename(g2),
        "count": goals_count,
        "source_exists": True,
        "target_exists": True,
        "before": {
            "source_goals": src_goals_count,
            "target_goals": target_before_count,
        },
        "after": {"target_goals": target_after_count},
        "reconciliation": {
            "verified": verified,
            "expected_goals": len(expected_goal_keys),
            "missing_goals_count": len(missing_keys),
        },
    }


def sync_goals_db(
    lane1: str,
    lane2: str,
    dry_run: bool,
    *,
    backup_target: bool = False,
    max_backups: int = DEFAULT_MAX_SYNC_BACKUPS,
    preserve_existing_on_conflict: bool = False,
) -> int:
    """
    Backward-compatible integer wrapper around `sync_goals_db_detailed(...)`.
    """
    res = sync_goals_db_detailed(
        lane1,
        lane2,
        dry_run,
        backup_target=backup_target,
        max_backups=max_backups,
        preserve_existing_on_conflict=preserve_existing_on_conflict,
    )
    return int(res["count"])


def _run_directional_sync(
    source: str,
    target: str,
    *,
    repo_path: str | None,
    approval_mode: str | None,
    pinned_only: bool,
    dry_run: bool,
    backup_target: bool,
    max_backups: int = DEFAULT_MAX_SYNC_BACKUPS,
    rescue_shared: bool,
    force_openai_provider: bool,
    require_source_dbs: bool = False,
) -> dict[str, object]:
    """Execute one full sync pass (`source -> target`) across state DB, index, goals, and optional shared files."""
    state_res = sync_state_db_detailed(
        source,
        target,
        repo_path,
        approval_mode,
        pinned_only,
        dry_run,
        backup_target=backup_target,
        max_backups=max_backups,
        force_openai_provider=force_openai_provider,
        require_source_db=require_source_dbs,
    )
    allowed_ids = set(state_res["synced_ids"]) if pinned_only else None
    index_res = sync_session_index_detailed(source, target, dry_run, allowed_ids)
    goals_res = sync_goals_db_detailed(
        source,
        target,
        dry_run,
        backup_target=backup_target,
        max_backups=max_backups,
        preserve_existing_on_conflict=not force_openai_provider,
        require_source_db=require_source_dbs,
    )
    rescued = (0, 0, 0)
    rescue_status = SYNC_STATUS_SKIPPED
    if rescue_shared:
        rescued = rescue_shared_files(source, target, dry_run)
        rescue_status = (
            SYNC_STATUS_SUCCESS
            if (rescued[0] > 0 or rescued[1] > 0 or rescued[2] > 0)
            else SYNC_STATUS_SKIPPED
        )

    component_statuses = [
        str(state_res["status"]),
        str(index_res["status"]),
        str(goals_res["status"]),
    ]
    if rescue_shared:
        component_statuses.append(rescue_status)
    overall_status = _aggregate_sync_status(component_statuses)

    state_before = dict(state_res["before"])
    state_after = dict(state_res["after"])
    state_rec = dict(state_res["reconciliation"])
    index_rec = dict(index_res["reconciliation"])
    goals_before = dict(goals_res["before"])
    goals_after = dict(goals_res["after"])
    goals_rec = dict(goals_res["reconciliation"])

    reconcile_verified = (
        bool(state_rec.get("verified", True))
        and bool(index_rec.get("verified", True))
        and bool(goals_rec.get("verified", True))
    )
    total_missing_ids = int(state_rec.get("missing_ids_count", 0)) + int(
        index_rec.get("missing_ids_count", 0)
    )
    total_missing_pinned = int(state_rec.get("missing_pinned_count", 0))
    total_missing_goals = int(goals_rec.get("missing_goals_count", 0))

    return {
        "status": overall_status,
        "state_status": str(state_res["status"]),
        "state_reason": str(state_res["reason"]),
        "index_status": str(index_res["status"]),
        "index_reason": str(index_res["reason"]),
        "goals_status": str(goals_res["status"]),
        "goals_reason": str(goals_res["reason"]),
        "rescue_status": rescue_status,
        "db_name": state_res["db_name"],
        "inserted": int(state_res["inserted"]),
        "updated": int(state_res["updated"]),
        "pinned": int(state_res["pinned"]),
        "session_index": int(index_res["count"]),
        "goals": int(goals_res["count"]),
        "rescued_copied": rescued[0],
        "rescued_skipped_existing": rescued[1],
        "rescued_skipped_links": rescued[2],
        "reconciliation": {
            "verified": reconcile_verified,
            "threads_before": int(state_before.get("target_threads", 0)),
            "threads_after": int(state_after.get("target_threads", 0)),
            "pinned_before": int(state_before.get("target_pinned", 0)),
            "pinned_after": int(state_after.get("target_pinned", 0)),
            "goals_before": int(goals_before.get("target_goals", 0)),
            "goals_after": int(goals_after.get("target_goals", 0)),
            "missing_ids_count": total_missing_ids,
            "missing_pinned_count": total_missing_pinned,
            "missing_goals_count": total_missing_goals,
        },
    }


def _format_sync_summary(
    mode: str,
    stats: dict[str, object],
    *,
    direction_label: str | None = None,
    include_rescue: bool = False,
) -> str:
    """Format a secret-free summary line containing explicit status, DB basenames, integer counts, and reconciliation metrics."""
    status = str(stats.get("status", SYNC_STATUS_SUCCESS))
    if mode == "DRY-RUN":
        tag = "DRY-RUN"
    elif status == SYNC_STATUS_FAILED:
        tag = "FAIL"
    elif status == SYNC_STATUS_PARTIAL:
        tag = "PARTIAL"
    else:
        tag = "OK"

    prefix = f"[{tag}] [{direction_label}]" if direction_label else f"[{tag}]"
    rec = dict(stats.get("reconciliation", {}))
    rec_label = "OK" if rec.get("verified", True) else "MISMATCH"
    line = (
        f"{prefix} status={status} | "
        f"session_index={stats['session_index']}({stats.get('index_status', SYNC_STATUS_SKIPPED)}) | "
        f"state_db={stats['db_name'] or 'N/A'}({stats.get('state_status', SYNC_STATUS_SKIPPED)}: "
        f"inserted={stats['inserted']}, updated={stats['updated']}, pinned={stats['pinned']}) | "
        f"goals={stats['goals']}({stats.get('goals_status', SYNC_STATUS_SKIPPED)}) | "
        f"reconcile={rec_label}("
        f"threads={rec.get('threads_before', 0)}->{rec.get('threads_after', 0)}, "
        f"pinned={rec.get('pinned_before', 0)}->{rec.get('pinned_after', 0)}, "
        f"goals={rec.get('goals_before', 0)}->{rec.get('goals_after', 0)}, "
        f"missing_ids={rec.get('missing_ids_count', 0)}, "
        f"missing_pinned={rec.get('missing_pinned_count', 0)}, "
        f"missing_goals={rec.get('missing_goals_count', 0)})"
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
        "--max-backups",
        type=int,
        default=DEFAULT_MAX_SYNC_BACKUPS,
        help=f"Maximum .sync-backup-* files to retain per SQLite DB when --backup-target is set (default: {DEFAULT_MAX_SYNC_BACKUPS}; 0=unlimited)",
    )
    parser.add_argument(
        "--rescue-shared-files",
        action="store_true",
        help="Copy missing regular files from real local sessions/archived_sessions/memories/memories_v2 directories into target (skipping existing symlinks/junctions)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail closed if any existing source SQLite DB cannot be read/synced or if post-sync reconciliation mismatches",
    )
    parser.add_argument(
        "--busy-timeout",
        type=float,
        default=None,
        help=f"SQLite busy timeout in seconds (default: {DEFAULT_BUSY_TIMEOUT_SEC}s; can also be set via CODEX_SYNC_BUSY_TIMEOUT_SEC)",
    )
    parser.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        help="Emit secret-free structured JSON summary instead of plain text",
    )
    parser.add_argument(
        "--compact-storage",
        action="store_true",
        help="Compact target SQLite WAL/free pages and prune excess rotated backups & temp files to bound disk/RAM usage",
    )
    parser.add_argument(
        "--fast",
        action="store_true",
        help="With --compact-storage: run fast non-blocking backup/tmp rotation + PASSIVE WAL checkpoint (skips slow VACUUM on huge DBs)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Inspect schemas and report what would be synced without writing any file",
    )
    args = parser.parse_args()
    if args.max_backups < 0:
        print("[FAIL] --max-backups must be >= 0.", file=sys.stderr)
        return 1
    if args.busy_timeout is not None and args.busy_timeout < 0:
        print("[FAIL] --busy-timeout must be >= 0.", file=sys.stderr)
        return 1

    prev_env_timeout = os.environ.get("CODEX_SYNC_BUSY_TIMEOUT_SEC")
    if args.busy_timeout is not None:
        os.environ["CODEX_SYNC_BUSY_TIMEOUT_SEC"] = str(args.busy_timeout)

    mode = "DRY-RUN" if args.dry_run else "OK"
    require_source_dbs = bool(args.strict or args.rescue_shared_files)
    try:
        # When rescuing back to GPT 1 (unidirectional --rescue-shared-files), preserve
        # target's existing model_provider instead of forcing "openai".
        fwd_force_openai = not args.rescue_shared_files or args.bidirectional
        rev_stats: dict[str, object] | None = None
        fwd_stats = _run_directional_sync(
            args.lane1,
            args.lane2,
            repo_path=args.repo,
            approval_mode=args.approval_mode,
            pinned_only=args.pinned_only,
            dry_run=args.dry_run,
            backup_target=args.backup_target,
            max_backups=args.max_backups,
            rescue_shared=args.rescue_shared_files,
            force_openai_provider=fwd_force_openai,
            require_source_dbs=require_source_dbs,
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
                max_backups=args.max_backups,
                rescue_shared=args.rescue_shared_files,
                force_openai_provider=False,
                require_source_dbs=require_source_dbs,
            )

        if args.compact_storage:
            fwd_stats["compaction"] = compact_codex_home_storage(
                args.lane2, max_backups=args.max_backups, dry_run=args.dry_run, fast=args.fast
            )
            if args.bidirectional and rev_stats is not None:
                rev_stats["compaction"] = compact_codex_home_storage(
                    args.lane1, max_backups=args.max_backups, dry_run=args.dry_run, fast=args.fast
                )

        if args.bidirectional and rev_stats is not None:
            overall_status = _aggregate_sync_status(
                [str(fwd_stats["status"]), str(rev_stats["status"])]
            )
            if args.json_output:
                print(
                    json.dumps(
                        {
                            "status": overall_status,
                            "dry_run": args.dry_run,
                            "forward": fwd_stats,
                            "reverse": rev_stats,
                        },
                        ensure_ascii=False,
                    )
                )
            else:
                # Print only status, basenames, and integer counts; never log thread content or secrets.
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
            overall_status = str(fwd_stats["status"])
            if args.json_output:
                print(
                    json.dumps(
                        {
                            "status": overall_status,
                            "dry_run": args.dry_run,
                            "forward": fwd_stats,
                        },
                        ensure_ascii=False,
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
    finally:
        if args.busy_timeout is not None:
            if prev_env_timeout is None:
                os.environ.pop("CODEX_SYNC_BUSY_TIMEOUT_SEC", None)
            else:
                os.environ["CODEX_SYNC_BUSY_TIMEOUT_SEC"] = prev_env_timeout

    if overall_status in (SYNC_STATUS_FAILED, SYNC_STATUS_PARTIAL):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
