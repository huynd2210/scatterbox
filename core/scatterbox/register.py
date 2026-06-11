"""Central register: SQLite (WAL) holding all metadata (PLAN.md §9).

Contains wrapped file keys but no secrets — useless without the vault.
Migrations are versioned scripts applied via PRAGMA user_version.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

from scatterbox.errors import ScatterboxError

_MIGRATIONS = [
    # v1 — initial schema
    """
    CREATE TABLE files (
        id         INTEGER PRIMARY KEY,
        vpath      TEXT NOT NULL UNIQUE,
        size       INTEGER NOT NULL,
        mtime      REAL NOT NULL,
        created_at REAL NOT NULL
    );

    CREATE TABLE manifests (
        id               INTEGER PRIMARY KEY,
        file_id          INTEGER NOT NULL UNIQUE REFERENCES files(id) ON DELETE CASCADE,
        scheme           TEXT NOT NULL DEFAULT 'replica',
        wrapped_file_key BLOB NOT NULL,
        chunk_size       INTEGER NOT NULL,
        replica_target   INTEGER NOT NULL
    );

    CREATE TABLE chunks (
        id          INTEGER PRIMARY KEY,
        manifest_id INTEGER NOT NULL REFERENCES manifests(id) ON DELETE CASCADE,
        seq         INTEGER NOT NULL,
        chunk_hash  TEXT NOT NULL,
        stored_size INTEGER NOT NULL,
        plain_size  INTEGER NOT NULL,
        compressed  INTEGER NOT NULL DEFAULT 0,
        UNIQUE (manifest_id, seq)
    );

    CREATE TABLE replicas (
        id            INTEGER PRIMARY KEY,
        chunk_id      INTEGER NOT NULL REFERENCES chunks(id) ON DELETE CASCADE,
        provider_id   INTEGER NOT NULL REFERENCES providers(id),
        remote_ref    TEXT NOT NULL,
        state         TEXT NOT NULL DEFAULT 'ok',
        last_verified REAL
    );
    CREATE INDEX idx_replicas_chunk ON replicas(chunk_id);

    CREATE TABLE providers (
        id         INTEGER PRIMARY KEY,
        name       TEXT NOT NULL UNIQUE,
        type       TEXT NOT NULL,
        config     TEXT NOT NULL,
        profile    TEXT NOT NULL DEFAULT '{}',
        created_at REAL NOT NULL
    );

    CREATE TABLE jobs (
        id         INTEGER PRIMARY KEY,
        kind       TEXT NOT NULL,
        payload    TEXT,
        state      TEXT NOT NULL DEFAULT 'pending',
        created_at REAL NOT NULL,
        updated_at REAL
    );
    """,
    # v2 — Phase 1 replica lifecycle: pending → stored → suspect → lost
    """
    UPDATE replicas SET state = 'stored' WHERE state = 'ok';
    UPDATE replicas SET state = 'suspect' WHERE state = 'missing';
    """,
]

# Replica lifecycle (TASKS.md §3). Same-state transitions are idempotent no-ops;
# 'lost' is terminal — repair creates new rows instead of resurrecting old ones.
_REPLICA_TRANSITIONS = {
    "pending": {"stored", "suspect", "lost"},
    "stored": {"suspect", "lost"},
    "suspect": {"stored", "lost"},
    "lost": set(),
}

# Reliability EMA (TASKS.md §3): successful verify nudges the score up
# slightly; a missed probe / corrupt chunk / 404 drags it down sharply.
RELIABILITY_ALPHA_UP = 0.05
RELIABILITY_ALPHA_DOWN = 0.30


class Register:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path))
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self._migrate()

    def _migrate(self) -> None:
        version = self.conn.execute("PRAGMA user_version").fetchone()[0]
        for i, script in enumerate(_MIGRATIONS[version:], start=version + 1):
            self.conn.executescript(script)
            self.conn.execute(f"PRAGMA user_version = {i}")
            self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    # -- providers ----------------------------------------------------------

    def add_provider(self, name: str, type_: str, config: dict) -> int:
        try:
            cur = self.conn.execute(
                "INSERT INTO providers (name, type, config, created_at) VALUES (?, ?, ?, ?)",
                (name, type_, json.dumps(config), time.time()),
            )
        except sqlite3.IntegrityError as exc:
            raise ScatterboxError(f"provider {name!r} already exists") from exc
        self.conn.commit()
        return cur.lastrowid

    def list_providers(self) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM providers ORDER BY id").fetchall()

    def get_provider(self, provider_id: int) -> sqlite3.Row:
        row = self.conn.execute(
            "SELECT * FROM providers WHERE id = ?", (provider_id,)
        ).fetchone()
        if row is None:
            raise ScatterboxError(f"no provider with id {provider_id}")
        return row

    def update_provider_config(self, provider_id: int, config: dict) -> None:
        with self.conn:
            self.conn.execute(
                "UPDATE providers SET config = ? WHERE id = ?",
                (json.dumps(config), provider_id),
            )

    def get_reliability(self, provider_id: int, *, prior: float) -> float:
        """Learned reliability score, or the profile prior if never observed."""
        stats = json.loads(self.get_provider(provider_id)["profile"] or "{}")
        score = stats.get("reliability_score")
        return prior if score is None else score

    def update_reliability(self, provider_id: int, ok: bool, *, prior: float) -> float:
        """EMA update from one scrub/read observation; returns the new score."""
        stats = json.loads(self.get_provider(provider_id)["profile"] or "{}")
        score = stats.get("reliability_score", prior)
        alpha = RELIABILITY_ALPHA_UP if ok else RELIABILITY_ALPHA_DOWN
        score = (1 - alpha) * score + alpha * (1.0 if ok else 0.0)
        stats["reliability_score"] = score
        with self.conn:
            self.conn.execute(
                "UPDATE providers SET profile = ? WHERE id = ?",
                (json.dumps(stats), provider_id),
            )
        return score

    # -- files / manifests ---------------------------------------------------

    def get_file(self, vpath: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM files WHERE vpath = ?", (vpath,)
        ).fetchone()

    def get_file_with_manifest(self, vpath: str) -> sqlite3.Row | None:
        return self.conn.execute(
            """
            SELECT f.id AS file_id, f.vpath, f.size, f.mtime,
                   m.id AS manifest_id, m.scheme, m.wrapped_file_key,
                   m.chunk_size, m.replica_target
            FROM files f JOIN manifests m ON m.file_id = f.id
            WHERE f.vpath = ?
            """,
            (vpath,),
        ).fetchone()

    def list_all_files(self) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT vpath, size FROM files ORDER BY vpath"
        ).fetchall()

    def insert_file_with_manifest(
        self,
        vpath: str,
        size: int,
        mtime: float,
        scheme: str,
        wrapped_file_key: bytes,
        chunk_size: int,
        replica_target: int,
        chunk_rows: list[tuple[int, str, int, int, bool, list[tuple[int, str]]]],
    ) -> int:
        """chunk_rows: (seq, chunk_hash, stored_size, plain_size, compressed,
        [(provider_id, remote_ref), ...]). One transaction."""
        with self.conn:
            cur = self.conn.execute(
                "INSERT INTO files (vpath, size, mtime, created_at) VALUES (?, ?, ?, ?)",
                (vpath, size, mtime, time.time()),
            )
            file_id = cur.lastrowid
            cur = self.conn.execute(
                """INSERT INTO manifests
                   (file_id, scheme, wrapped_file_key, chunk_size, replica_target)
                   VALUES (?, ?, ?, ?, ?)""",
                (file_id, scheme, wrapped_file_key, chunk_size, replica_target),
            )
            manifest_id = cur.lastrowid
            for seq, chunk_hash, stored_size, plain_size, compressed, refs in chunk_rows:
                cur = self.conn.execute(
                    """INSERT INTO chunks
                       (manifest_id, seq, chunk_hash, stored_size, plain_size, compressed)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (manifest_id, seq, chunk_hash, stored_size, plain_size, int(compressed)),
                )
                chunk_row_id = cur.lastrowid
                for provider_id, remote_ref in refs:
                    self.conn.execute(
                        """INSERT INTO replicas (chunk_id, provider_id, remote_ref, state)
                           VALUES (?, ?, ?, 'stored')""",
                        (chunk_row_id, provider_id, remote_ref),
                    )
        return file_id

    def add_replica(
        self, chunk_row_id: int, provider_id: int, remote_ref: str, state: str = "stored"
    ) -> int:
        with self.conn:
            cur = self.conn.execute(
                """INSERT INTO replicas (chunk_id, provider_id, remote_ref, state, last_verified)
                   VALUES (?, ?, ?, ?, ?)""",
                (chunk_row_id, provider_id, remote_ref, state, time.time()),
            )
        return cur.lastrowid

    def delete_file(self, file_id: int) -> None:
        with self.conn:
            self.conn.execute("DELETE FROM files WHERE id = ?", (file_id,))

    # -- chunks / replicas ----------------------------------------------------

    def get_chunks(self, manifest_id: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM chunks WHERE manifest_id = ? ORDER BY seq", (manifest_id,)
        ).fetchall()

    def get_replicas(self, chunk_row_id: int) -> list[sqlite3.Row]:
        """Healthiest replicas first."""
        return self.conn.execute(
            """SELECT * FROM replicas WHERE chunk_id = ?
               ORDER BY CASE state
                   WHEN 'stored' THEN 0 WHEN 'pending' THEN 1
                   WHEN 'suspect' THEN 2 ELSE 3 END, id""",
            (chunk_row_id,),
        ).fetchall()

    def replicas_for_file(self, file_id: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            """
            SELECT r.* FROM replicas r
            JOIN chunks c ON c.id = r.chunk_id
            JOIN manifests m ON m.id = c.manifest_id
            WHERE m.file_id = ?
            """,
            (file_id,),
        ).fetchall()

    def set_replica_state(self, replica_id: int, state: str) -> None:
        """Validated lifecycle transition (same-state is an idempotent no-op)."""
        if state not in _REPLICA_TRANSITIONS:
            raise ScatterboxError(f"unknown replica state {state!r}")
        row = self.conn.execute(
            "SELECT state FROM replicas WHERE id = ?", (replica_id,)
        ).fetchone()
        if row is None:
            raise ScatterboxError(f"no replica with id {replica_id}")
        current = row["state"]
        if state == current:
            return
        if state not in _REPLICA_TRANSITIONS[current]:
            raise ScatterboxError(
                f"invalid replica transition {current!r} -> {state!r}"
            )
        with self.conn:
            self.conn.execute(
                "UPDATE replicas SET state = ? WHERE id = ?", (state, replica_id)
            )

    def mark_replica_verified(self, replica_id: int) -> None:
        self.set_replica_state(replica_id, "stored")
        with self.conn:
            self.conn.execute(
                "UPDATE replicas SET last_verified = ? WHERE id = ?",
                (time.time(), replica_id),
            )

    # -- durability ------------------------------------------------------------

    def min_live_replicas(self, manifest_id: int) -> int:
        """Stored-replica count of the file's weakest chunk."""
        row = self.conn.execute(
            """
            SELECT MIN(cnt) AS min_live FROM (
                SELECT SUM(CASE WHEN r.state = 'stored' THEN 1 ELSE 0 END) AS cnt
                FROM chunks c LEFT JOIN replicas r ON r.chunk_id = c.id
                WHERE c.manifest_id = ?
                GROUP BY c.id
            )
            """,
            (manifest_id,),
        ).fetchone()
        return row["min_live"] if row["min_live"] is not None else 0

    def file_health(self, manifest_id: int, replica_target: int) -> str:
        """healthy / degraded / at-risk / lost, from the weakest chunk
        (PLAN.md §8 dots)."""
        return derive_health(self.min_live_replicas(manifest_id), replica_target)

    # -- scrubber --------------------------------------------------------------

    def replicas_for_scrub(self, limit: int | None = None) -> list[sqlite3.Row]:
        """Non-lost replicas with their chunk hash/size, oldest last_verified
        first (never-verified before everything else)."""
        sql = """
            SELECT r.*, c.chunk_hash, c.stored_size
            FROM replicas r JOIN chunks c ON c.id = r.chunk_id
            WHERE r.state != 'lost'
            ORDER BY (r.last_verified IS NOT NULL), r.last_verified, r.id
        """
        if limit is not None:
            return self.conn.execute(sql + " LIMIT ?", (limit,)).fetchall()
        return self.conn.execute(sql).fetchall()

    def chunks_below_floor(self) -> list[sqlite3.Row]:
        """Chunks whose stored-replica count is under the manifest's floor,
        weakest first."""
        return self.conn.execute(
            """
            SELECT c.id AS chunk_row_id, c.seq, c.chunk_hash, c.stored_size,
                   m.replica_target, f.vpath,
                   SUM(CASE WHEN r.state = 'stored' THEN 1 ELSE 0 END) AS live
            FROM chunks c
            JOIN manifests m ON m.id = c.manifest_id
            JOIN files f ON f.id = m.file_id
            LEFT JOIN replicas r ON r.chunk_id = c.id
            GROUP BY c.id
            HAVING live < m.replica_target
            ORDER BY live, c.id
            """
        ).fetchall()

    def replica_state_counts(self, manifest_id: int) -> dict[str, int]:
        rows = self.conn.execute(
            """
            SELECT r.state, COUNT(*) AS n
            FROM replicas r JOIN chunks c ON c.id = r.chunk_id
            WHERE c.manifest_id = ?
            GROUP BY r.state
            """,
            (manifest_id,),
        ).fetchall()
        return {row["state"]: row["n"] for row in rows}


def derive_health(min_live: int, replica_target: int) -> str:
    if min_live >= replica_target:
        return "healthy"
    if min_live == 0:
        return "lost"
    if min_live == 1:
        return "at-risk"
    return "degraded"
