"""Central register: SQLite (WAL) holding all metadata (PLAN.md §9).

This is "the crown jewel": it knows where every chunk of every file lives.
Lose it and the ciphertext scattered across providers is garbage. It holds
wrapped (encrypted) file keys but no secrets — useless without the vault.

How the tables relate (one row each, top to bottom):

    files      "/docs/report.pdf"            — the virtual path tree
      └─ manifests   how that file is stored — chunk size, wrapped key, floor
           └─ chunks      one per 8 MiB slice — BLAKE3 hash, sizes, seq order
                └─ replicas   one per copy of a chunk — which provider, what
                              ref, lifecycle state, when last seen alive
    providers  one per configured backend (type + JSON config + learned stats)
    jobs       background job queue (used from Phase 3 onwards)

SQLite specifics:
- WAL (write-ahead logging) journal mode lets readers keep reading while a
  write is in progress — needed later when the daemon and CLI share the DB.
- Migrations are plain SQL scripts applied in order; PRAGMA user_version
  records how many have run, so old databases upgrade automatically.
- row_factory = sqlite3.Row makes query results behave like dicts
  (row["vpath"]) instead of bare tuples.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

from scatterbox.errors import ScatterboxError

_MIGRATIONS = [
    # v1 — initial schema (Phase 0)
    """
    CREATE TABLE files (
        id         INTEGER PRIMARY KEY,
        vpath      TEXT NOT NULL UNIQUE,   -- virtual path, e.g. /docs/a.pdf
        size       INTEGER NOT NULL,       -- plaintext size in bytes
        mtime      REAL NOT NULL,          -- source file's modification time
        created_at REAL NOT NULL
    );

    CREATE TABLE manifests (
        id               INTEGER PRIMARY KEY,
        -- ON DELETE CASCADE: deleting a file row automatically deletes its
        -- manifest, which cascades to chunks, which cascades to replicas.
        file_id          INTEGER NOT NULL UNIQUE REFERENCES files(id) ON DELETE CASCADE,
        scheme           TEXT NOT NULL DEFAULT 'replica',  -- later: 'ec(k,n)'
        wrapped_file_key BLOB NOT NULL,    -- file key encrypted by master key
        chunk_size       INTEGER NOT NULL, -- plaintext bytes per chunk
        replica_target   INTEGER NOT NULL  -- the per-chunk replica floor
    );

    CREATE TABLE chunks (
        id          INTEGER PRIMARY KEY,
        manifest_id INTEGER NOT NULL REFERENCES manifests(id) ON DELETE CASCADE,
        seq         INTEGER NOT NULL,      -- position within the file (0, 1, 2…)
        chunk_hash  TEXT NOT NULL,         -- BLAKE3 of the stored ciphertext
        stored_size INTEGER NOT NULL,      -- bytes actually uploaded
        plain_size  INTEGER NOT NULL,      -- bytes after decrypt+decompress
        compressed  INTEGER NOT NULL DEFAULT 0,  -- was zstd worth it for this chunk
        UNIQUE (manifest_id, seq)
    );

    CREATE TABLE replicas (
        id            INTEGER PRIMARY KEY,
        chunk_id      INTEGER NOT NULL REFERENCES chunks(id) ON DELETE CASCADE,
        provider_id   INTEGER NOT NULL REFERENCES providers(id),
        remote_ref    TEXT NOT NULL,       -- provider's handle for the object
        state         TEXT NOT NULL DEFAULT 'ok',  -- lifecycle; see v2 below
        last_verified REAL                 -- unix time of last successful check
    );
    CREATE INDEX idx_replicas_chunk ON replicas(chunk_id);

    CREATE TABLE providers (
        id         INTEGER PRIMARY KEY,
        name       TEXT NOT NULL UNIQUE,   -- user-chosen, e.g. "my-gdrive"
        type       TEXT NOT NULL,          -- adapter type for create_provider()
        config     TEXT NOT NULL,          -- JSON: root/limits/etc, no secrets
        profile    TEXT NOT NULL DEFAULT '{}',  -- JSON: learned stats (reliability)
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
    # (renames Phase 0's ad-hoc states; new rows always set state explicitly,
    # so the old DEFAULT 'ok' in the v1 DDL is harmless leftover)
    """
    UPDATE replicas SET state = 'stored' WHERE state = 'ok';
    UPDATE replicas SET state = 'suspect' WHERE state = 'missing';
    """,
    # v3 — anti-colocation (Policy.min_spread): which disjoint provider group
    # each chunk belongs to, and the file's spread requirement, so repair can
    # keep honoring the guarantee long after the original placement.
    # Pre-existing files default to 1/0: no constraint, all chunks group 0.
    """
    ALTER TABLE manifests ADD COLUMN min_spread INTEGER NOT NULL DEFAULT 1;
    ALTER TABLE chunks ADD COLUMN spread_group INTEGER NOT NULL DEFAULT 0;
    """,
    # v4 — spread cap K: how many of the file's shard groups one provider
    # may hold (1 = disjoint groups, min_spread-1 = packed; PLAN.md §7).
    # Existing spread files were written with disjoint groups, hence DEFAULT 1.
    """
    ALTER TABLE manifests ADD COLUMN spread_cap INTEGER NOT NULL DEFAULT 1;
    """,
    # v5 — Phase 3 daemon: job outcome (result JSON or {"error": ...}).
    """
    ALTER TABLE jobs ADD COLUMN result TEXT;
    """,
    # v6 — Phase 5: erasure coding + per-folder policies.
    # ec_k/ec_n: ec(k,n) parameters (NULL = plain replication). For EC
    # manifests replica_target = n and each replicas row is one SHARE:
    # share_index says which, share_hash lets the scrubber verify it
    # without reconstructing the chunk. policies: folder vpath -> policy
    # JSON, resolved nearest-ancestor-first at put time (PLAN.md §7).
    """
    ALTER TABLE manifests ADD COLUMN ec_k INTEGER;
    ALTER TABLE manifests ADD COLUMN ec_n INTEGER;
    ALTER TABLE replicas ADD COLUMN share_index INTEGER;
    ALTER TABLE replicas ADD COLUMN share_hash TEXT;

    CREATE TABLE policies (
        vpath  TEXT NOT NULL UNIQUE,   -- folder ('/' = global default)
        policy TEXT NOT NULL           -- JSON, see placement.policy_to_dict
    );
    """,
]

# Replica lifecycle (TASKS.md §3). Same-state transitions are idempotent no-ops;
# 'lost' is terminal — repair creates new rows instead of resurrecting old ones.
#
#   pending  — placement decided, upload not yet confirmed
#   stored   — uploaded and verified at some point
#   suspect  — one failed observation (missed probe, fetch error, bad bytes)
#   lost     — gone for good (second strike, or definitive corruption)
_REPLICA_TRANSITIONS = {
    "pending": {"stored", "suspect", "lost"},
    "stored": {"suspect", "lost"},
    "suspect": {"stored", "lost"},  # a deep verify can clear suspicion
    "lost": set(),
}

# Reliability EMA (TASKS.md §3): successful verify nudges the score up
# slightly; a missed probe / corrupt chunk / 404 drags it down sharply.
# (EMA = exponential moving average: new = (1-a)*old + a*observation, where
# the observation is 1.0 for success, 0.0 for failure.)
RELIABILITY_ALPHA_UP = 0.05
RELIABILITY_ALPHA_DOWN = 0.30

# Upper bound for vpath range scans: sorts after every valid character, so
# [prefix, prefix + sentinel) covers exactly the subtree under prefix.
_VPATH_SENTINEL = chr(0x10FFFF)


class Register:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path))
        self.conn.row_factory = sqlite3.Row  # rows addressable by column name
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")  # off by default in SQLite!
        self._migrate()

    def _migrate(self) -> None:
        # user_version starts at 0; run every script we have beyond it.
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
            # the UNIQUE constraint on name fired
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

    def get_provider_by_name(self, name: str) -> sqlite3.Row:
        row = self.conn.execute(
            "SELECT * FROM providers WHERE name = ?", (name,)
        ).fetchone()
        if row is None:
            raise ScatterboxError(f"no provider named {name!r}")
        return row

    def replica_count_on_provider(self, provider_id: int) -> int:
        """How many non-lost replicas live on this provider (for the safety
        check before `provider remove`)."""
        return self.conn.execute(
            "SELECT COUNT(*) FROM replicas WHERE provider_id = ? AND state != 'lost'",
            (provider_id,),
        ).fetchone()[0]

    def delete_provider(self, provider_id: int) -> None:
        """Drop a provider and any replica rows pointing at it.

        The replica rows must go too (the FK would block the delete
        otherwise) — afterwards chunks_below_floor() reports the orphaned
        chunks, so `scrub --repair` re-replicates them elsewhere. Callers
        are responsible for warning the user first.
        """
        with self.conn:
            self.conn.execute(
                "DELETE FROM replicas WHERE provider_id = ?", (provider_id,)
            )
            self.conn.execute("DELETE FROM providers WHERE id = ?", (provider_id,))

    def update_provider_config(self, provider_id: int, config: dict) -> None:
        with self.conn:  # "with conn" = run inside a transaction, commit on exit
            self.conn.execute(
                "UPDATE providers SET config = ? WHERE id = ?",
                (json.dumps(config), provider_id),
            )

    def get_reliability(self, provider_id: int, *, prior: float) -> float:
        """Learned reliability score, or the profile prior if never observed.

        The score lives in the providers.profile JSON column; the prior comes
        from the adapter's ProviderProfile and is only the starting point.
        """
        stats = json.loads(self.get_provider(provider_id)["profile"] or "{}")
        score = stats.get("reliability_score")
        return prior if score is None else score

    def update_reliability(self, provider_id: int, ok: bool, *, prior: float) -> float:
        """EMA update from one scrub/read observation; returns the new score."""
        stats = json.loads(self.get_provider(provider_id)["profile"] or "{}")
        score = stats.get("reliability_score", prior)
        # Asymmetric: trust is gained slowly (alpha 0.05) and lost fast (0.30).
        alpha = RELIABILITY_ALPHA_UP if ok else RELIABILITY_ALPHA_DOWN
        score = (1 - alpha) * score + alpha * (1.0 if ok else 0.0)
        stats["reliability_score"] = score
        with self.conn:
            self.conn.execute(
                "UPDATE providers SET profile = ? WHERE id = ?",
                (json.dumps(stats), provider_id),
            )
        return score

    # -- folder policies (Phase 5, PLAN.md §7) --------------------------------

    def set_folder_policy(self, vpath: str, policy: dict) -> None:
        with self.conn:
            self.conn.execute(
                """INSERT INTO policies (vpath, policy) VALUES (?, ?)
                   ON CONFLICT(vpath) DO UPDATE SET policy = excluded.policy""",
                (vpath, json.dumps(policy)),
            )

    def delete_folder_policy(self, vpath: str) -> bool:
        with self.conn:
            cur = self.conn.execute("DELETE FROM policies WHERE vpath = ?", (vpath,))
        return cur.rowcount > 0

    def list_folder_policies(self) -> list[tuple[str, dict]]:
        return [
            (row["vpath"], json.loads(row["policy"]))
            for row in self.conn.execute("SELECT * FROM policies ORDER BY vpath")
        ]

    def folder_policy_for(self, vpath: str) -> tuple[str, dict] | None:
        """The policy governing a file path: its deepest ancestor folder
        with a policy set ('/' acts as the global default). Returns
        (folder, policy) or None. Policy rows are few — a Python scan
        beats SQL prefix gymnastics here."""
        best: tuple[str, dict] | None = None
        for folder, policy in self.list_folder_policies():
            prefix = "/" if folder == "/" else folder + "/"
            if vpath == folder or vpath.startswith(prefix):
                if best is None or len(folder) > len(best[0]):
                    best = (folder, policy)
        return best

    # -- files / manifests ---------------------------------------------------

    def get_file(self, vpath: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM files WHERE vpath = ?", (vpath,)
        ).fetchone()

    def get_file_with_manifest(self, vpath: str) -> sqlite3.Row | None:
        """File row joined with its manifest — everything the read path needs
        in one query."""
        return self.conn.execute(
            """
            SELECT f.id AS file_id, f.vpath, f.size, f.mtime,
                   m.id AS manifest_id, m.scheme, m.wrapped_file_key,
                   m.chunk_size, m.replica_target, m.min_spread,
                   m.ec_k, m.ec_n
            FROM files f JOIN manifests m ON m.file_id = f.id
            WHERE f.vpath = ?
            """,
            (vpath,),
        ).fetchone()

    def list_all_files(self) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT vpath, size FROM files ORDER BY vpath"
        ).fetchall()

    def list_children(self, vpath: str) -> tuple[list[str], list[sqlite3.Row]]:
        """Immediate children of a virtual directory: (subdir names, file rows).

        Two indexed range scans over files.vpath (the UNIQUE index), so a
        directory listing costs O(children) regardless of how many files the
        register holds — this is what keeps browsing <100 ms at 50k files
        (PLAN.md §12 Phase 3 gate). '\\uffff' sorts after every character
        that can appear in a normalized vpath, closing the range.
        """
        prefix = "/" if vpath == "/" else vpath + "/"
        plen = len(prefix)
        # Direct files: rows under the prefix whose remainder has no '/'.
        files = self.conn.execute(
            """
            SELECT vpath, size, mtime FROM files
            WHERE vpath >= ? AND vpath < ?
              AND instr(substr(vpath, ?), '/') = 0
            ORDER BY vpath
            """,
            (prefix, prefix + _VPATH_SENTINEL, plen + 1),
        ).fetchall()
        # First-level subdirectories: distinct text between the prefix and
        # the next '/'. Directories exist only implicitly (S3-style).
        dirs = [
            row[0]
            for row in self.conn.execute(
                """
                SELECT DISTINCT substr(vpath, ?, instr(substr(vpath, ?), '/') - 1)
                FROM files
                WHERE vpath >= ? AND vpath < ?
                  AND instr(substr(vpath, ?), '/') > 0
                ORDER BY 1
                """,
                (plen + 1, plen + 1, prefix, prefix + _VPATH_SENTINEL, plen + 1),
            )
        ]
        return dirs, files

    def move_file(self, file_id: int, new_vpath: str) -> None:
        try:
            with self.conn:
                self.conn.execute(
                    "UPDATE files SET vpath = ? WHERE id = ?", (new_vpath, file_id)
                )
        except sqlite3.IntegrityError as exc:
            raise ScatterboxError(f"{new_vpath} already exists") from exc

    def move_tree(self, old_prefix: str, new_prefix: str) -> int:
        """Rename every vpath under old_prefix/ to new_prefix/ in one
        transaction; returns the number of files moved."""
        try:
            with self.conn:
                cur = self.conn.execute(
                    """
                    UPDATE files SET vpath = ? || substr(vpath, ?)
                    WHERE vpath >= ? || '/' AND vpath < ? || '/' || ?
                    """,
                    (
                        new_prefix,
                        len(old_prefix) + 1,
                        old_prefix,
                        old_prefix,
                        _VPATH_SENTINEL,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise ScatterboxError(
                f"cannot move {old_prefix} to {new_prefix}: a target path already exists"
            ) from exc
        return cur.rowcount

    def insert_file_with_manifest(
        self,
        vpath: str,
        size: int,
        mtime: float,
        scheme: str,
        wrapped_file_key: bytes,
        chunk_size: int,
        replica_target: int,
        chunk_rows: list[
            tuple[int, str, int, int, bool, int, list[tuple[int, str, int | None, str | None]]]
        ],
        min_spread: int = 1,
        spread_cap: int = 1,
        ec_k: int | None = None,
        ec_n: int | None = None,
    ) -> int:
        """Record a fully-uploaded file: file + manifest + chunks + replicas.

        chunk_rows: (seq, chunk_hash, stored_size, plain_size, compressed,
        spread_group, [(provider_id, remote_ref, share_index, share_hash),
        ...]) — share fields are None for plain replicas. Runs as ONE
        transaction — either the whole file becomes visible in the register
        or none of it does; a crash mid-insert can never leave a
        half-recorded file.
        """
        with self.conn:
            cur = self.conn.execute(
                "INSERT INTO files (vpath, size, mtime, created_at) VALUES (?, ?, ?, ?)",
                (vpath, size, mtime, time.time()),
            )
            file_id = cur.lastrowid
            cur = self.conn.execute(
                """INSERT INTO manifests
                   (file_id, scheme, wrapped_file_key, chunk_size, replica_target,
                    min_spread, spread_cap, ec_k, ec_n)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (file_id, scheme, wrapped_file_key, chunk_size, replica_target,
                 min_spread, spread_cap, ec_k, ec_n),
            )
            manifest_id = cur.lastrowid
            for seq, chunk_hash, stored_size, plain_size, compressed, group, refs in chunk_rows:
                cur = self.conn.execute(
                    """INSERT INTO chunks
                       (manifest_id, seq, chunk_hash, stored_size, plain_size, compressed, spread_group)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (manifest_id, seq, chunk_hash, stored_size, plain_size, int(compressed), group),
                )
                chunk_row_id = cur.lastrowid
                for provider_id, remote_ref, share_index, share_hash in refs:
                    # uploads happen before this insert, so replicas are
                    # born 'stored', not 'pending'
                    self.conn.execute(
                        """INSERT INTO replicas
                           (chunk_id, provider_id, remote_ref, state, share_index, share_hash)
                           VALUES (?, ?, ?, 'stored', ?, ?)""",
                        (chunk_row_id, provider_id, remote_ref, share_index, share_hash),
                    )
        return file_id

    def add_replica(
        self,
        chunk_row_id: int,
        provider_id: int,
        remote_ref: str,
        state: str = "stored",
        share_index: int | None = None,
        share_hash: str | None = None,
    ) -> int:
        """Record one new copy of a chunk — or one EC share — (used by
        repair after re-uploading)."""
        with self.conn:
            cur = self.conn.execute(
                """INSERT INTO replicas
                   (chunk_id, provider_id, remote_ref, state, last_verified,
                    share_index, share_hash)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (chunk_row_id, provider_id, remote_ref, state, time.time(),
                 share_index, share_hash),
            )
        return cur.lastrowid

    def delete_file(self, file_id: int) -> None:
        # The ON DELETE CASCADEs take the manifest, chunks and replicas with it.
        with self.conn:
            self.conn.execute("DELETE FROM files WHERE id = ?", (file_id,))

    # -- chunks / replicas ----------------------------------------------------

    def get_chunks(self, manifest_id: int) -> list[sqlite3.Row]:
        # ORDER BY seq: the read path concatenates these in order.
        return self.conn.execute(
            "SELECT * FROM chunks WHERE manifest_id = ? ORDER BY seq", (manifest_id,)
        ).fetchall()

    def get_replicas(self, chunk_row_id: int) -> list[sqlite3.Row]:
        """Healthiest replicas first — the read path tries them in this order,
        so it normally never touches a suspect copy."""
        return self.conn.execute(
            """SELECT * FROM replicas WHERE chunk_id = ?
               ORDER BY CASE state
                   WHEN 'stored' THEN 0 WHEN 'pending' THEN 1
                   WHEN 'suspect' THEN 2 ELSE 3 END, id""",
            (chunk_row_id,),
        ).fetchall()

    def replicas_for_file(self, file_id: int) -> list[sqlite3.Row]:
        """Every replica of every chunk of a file (used by rm to delete them)."""
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
        """Validated lifecycle transition (same-state is an idempotent no-op).

        Centralizing the check here means no caller can accidentally e.g.
        resurrect a 'lost' replica — the state machine is enforced in one place.
        """
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
        """A successful observation: move to 'stored' and stamp last_verified
        (which pushes this replica to the back of the scrub queue)."""
        self.set_replica_state(replica_id, "stored")
        with self.conn:
            self.conn.execute(
                "UPDATE replicas SET last_verified = ? WHERE id = ?",
                (time.time(), replica_id),
            )

    # -- durability ------------------------------------------------------------

    def min_live_replicas(self, manifest_id: int) -> int:
        """Stored-replica count of the file's weakest chunk.

        A file is only as durable as its worst chunk — losing any single
        chunk loses the file. The inner SELECT counts 'stored' replicas per
        chunk (LEFT JOIN so a chunk with zero replicas still appears, as 0);
        the outer MIN takes the weakest.
        """
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

    def file_health(
        self, manifest_id: int, replica_target: int, ec_k: int | None = None
    ) -> str:
        """healthy / degraded / at-risk / lost, from the weakest chunk
        (PLAN.md §8 dots)."""
        return derive_health(self.min_live_replicas(manifest_id), replica_target, ec_k=ec_k)

    def count_files(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM files").fetchone()[0]

    def file_provider_summary(self, manifest_id: int) -> list[sqlite3.Row]:
        """Per-provider replica breakdown for one file — the "where is this?"
        detail panel (PLAN.md §11): provider name/type and how many of the
        file's replicas it holds in each state."""
        return self.conn.execute(
            """
            SELECT p.id AS provider_id, p.name, p.type, r.state, COUNT(*) AS n
            FROM replicas r
            JOIN chunks c ON c.id = r.chunk_id
            JOIN providers p ON p.id = r.provider_id
            WHERE c.manifest_id = ?
            GROUP BY p.id, r.state
            ORDER BY p.id
            """,
            (manifest_id,),
        ).fetchall()

    def durability_summary(self) -> tuple[int, int]:
        """(chunks at or above their replica floor, total chunks) — the
        global durability indicator (PLAN.md §11)."""
        row = self.conn.execute(
            """
            SELECT COUNT(*) AS total,
                   SUM(CASE WHEN live >= replica_target THEN 1 ELSE 0 END) AS ok
            FROM (
                SELECT m.replica_target,
                       SUM(CASE WHEN r.state = 'stored' THEN 1 ELSE 0 END) AS live
                FROM chunks c
                JOIN manifests m ON m.id = c.manifest_id
                LEFT JOIN replicas r ON r.chunk_id = c.id
                GROUP BY c.id
            )
            """
        ).fetchone()
        return (row["ok"] or 0, row["total"] or 0)

    # -- scrubber --------------------------------------------------------------

    def replicas_for_scrub(self, limit: int | None = None) -> list[sqlite3.Row]:
        """Non-lost replicas with their chunk hash/size, oldest last_verified
        first (never-verified before everything else).

        This ordering is what makes the scrub "rotating": each cycle checks
        the replicas that have gone longest without a health check, and
        verifying one pushes it to the back of the queue.
        (In SQLite, `x IS NOT NULL` is 0 for NULL and 1 otherwise, so NULLs —
        never verified — sort first.)
        """
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
        weakest first — repair's work list.

        GROUP BY chunk, count its 'stored' replicas, keep only the groups
        where that count is under replica_target (HAVING filters groups the
        way WHERE filters rows). vpath/seq ride along for error messages.
        """
        return self.conn.execute(
            """
            SELECT c.id AS chunk_row_id, c.seq, c.chunk_hash, c.stored_size,
                   c.manifest_id, c.spread_group, m.min_spread, m.spread_cap,
                   m.scheme, m.ec_k, m.ec_n,
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

    def spread_conflict_providers(
        self, manifest_id: int, spread_group: int, spread_cap: int
    ) -> list[int]:
        """Providers that must not receive a chunk of this spread group.

        The invariant (PLAN.md §7) is "at most spread_cap of the file's
        shard groups per provider". A provider already inside this group can
        take more of its chunks freely; a provider outside it is barred once
        it already holds spread_cap OTHER groups — accepting would push it
        over, and with cap = min_spread-1 that literally means completing a
        full copy. The guarantee has to survive years of scrub/repair
        cycles, not just the original placement. Suspect replicas count as
        held: a deep verify can rehabilitate them.
        """
        rows = self.conn.execute(
            """
            SELECT r.provider_id,
                   MAX(CASE WHEN c.spread_group = :g THEN 1 ELSE 0 END) AS in_group,
                   COUNT(DISTINCT CASE WHEN c.spread_group != :g
                                       THEN c.spread_group END) AS other_groups
            FROM replicas r JOIN chunks c ON c.id = r.chunk_id
            WHERE c.manifest_id = :m AND r.state != 'lost'
            GROUP BY r.provider_id
            HAVING in_group = 0 AND other_groups >= :cap
            """,
            {"m": manifest_id, "g": spread_group, "cap": spread_cap},
        ).fetchall()
        return [row["provider_id"] for row in rows]

    # -- jobs (daemon queue, Phase 3) -------------------------------------------
    # Lifecycle: pending -> running -> done | failed. The table is the
    # durable queue; progress percentages are transient and live in the
    # daemon's memory/WebSocket, not here.

    def add_job(self, kind: str, payload: dict) -> int:
        with self.conn:
            cur = self.conn.execute(
                "INSERT INTO jobs (kind, payload, state, created_at) VALUES (?, ?, 'pending', ?)",
                (kind, json.dumps(payload), time.time()),
            )
        return cur.lastrowid

    def claim_next_job(self) -> sqlite3.Row | None:
        """Atomically move the oldest pending job to running and return it.

        The UPDATE..RETURNING form is a single statement, so two workers can
        never claim the same job even on a shared database.
        """
        with self.conn:
            row = self.conn.execute(
                """
                UPDATE jobs SET state = 'running', updated_at = ?
                WHERE id = (
                    SELECT id FROM jobs WHERE state = 'pending'
                    ORDER BY id LIMIT 1
                )
                RETURNING *
                """,
                (time.time(),),
            ).fetchone()
        return row

    def finish_job(self, job_id: int, *, error: str | None = None, result: dict | None = None) -> None:
        """Mark a running job done (with an optional result) or failed (with
        the error message stored in the payload-adjacent result column)."""
        with self.conn:
            self.conn.execute(
                "UPDATE jobs SET state = ?, result = ?, updated_at = ? WHERE id = ?",
                (
                    "failed" if error is not None else "done",
                    json.dumps({"error": error} if error is not None else (result or {})),
                    time.time(),
                    job_id,
                ),
            )

    def get_job(self, job_id: int) -> sqlite3.Row:
        row = self.conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        if row is None:
            raise ScatterboxError(f"no job with id {job_id}")
        return row

    def list_jobs(self, limit: int = 100) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM jobs ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()

    def reset_orphaned_jobs(self) -> int:
        """Jobs left 'running' by a crashed daemon go back to pending at
        startup; returns how many were rescued."""
        with self.conn:
            cur = self.conn.execute(
                "UPDATE jobs SET state = 'pending', updated_at = ? WHERE state = 'running'",
                (time.time(),),
            )
        return cur.rowcount

    def replica_state_counts(self, manifest_id: int) -> dict[str, int]:
        """How many of a file's replicas are in each state (for `status`)."""
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


def derive_health(min_live: int, replica_target: int, *, ec_k: int | None = None) -> str:
    """Weakest-chunk replica/share count -> the health word shown to the user.

    Replication (default floor 3, PLAN.md §8's dots): 3+ -> healthy (●●●),
    2 -> degraded (●●○), 1 -> at-risk (●○○), 0 -> lost.

    Erasure coding ec(k,n): replica_target is n and the file dies below k
    shares — n -> healthy, k<s<n -> degraded, =k -> at-risk (one more loss
    is fatal), <k -> lost.
    """
    if min_live >= replica_target:
        return "healthy"
    if ec_k is not None:
        if min_live < ec_k:
            return "lost"
        return "at-risk" if min_live == ec_k else "degraded"
    if min_live == 0:
        return "lost"
    if min_live == 1:
        return "at-risk"
    return "degraded"
