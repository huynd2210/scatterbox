# Claude Code handover prompt — scatterbox Phase 0

Read `PLAN.md` in this folder fully before writing any code. It is the source of truth; §13 is the decisions log — do not revisit settled decisions.

## Task

Implement **Phase 0 only** (PLAN.md §12): core pipeline + CLI + LocalFS mock provider. Do not build the daemon, web UI, real provider adapters, scrubber, or placement engine yet — but respect the interfaces the plan defines so they slot in later.

## Scope

1. **Monorepo skeleton:** `core/` `daemon/` `cli/` `web/` (daemon/ and web/ as empty placeholders). Python 3.12+, managed with `uv`. Tests with pytest + hypothesis.
2. **SQLite register** (WAL mode): tables `files`, `manifests`, `chunks`, `replicas`, `providers`, `jobs` per PLAN.md §9. Migrations can be a simple versioned-script approach — nothing fancy.
3. **Pipeline** (PLAN.md §5): split into 8 MiB chunks (configurable, respects provider `max_object_bytes`) → zstd compress (skip when incompressible) → AES-256-GCM with random per-file key, per-chunk nonce → BLAKE3 hash of ciphertext = chunk_id. Manifest stores chunk list, wrapped file key, `scheme` field (only `replica` implemented).
4. **Key handling (minimal for Phase 0):** master key derived from passphrase via Argon2id; wraps per-file keys. Full secret-vault file format is Phase 2 — for now a stub module with the right interface.
5. **Provider interface** exactly as PLAN.md §6 (including the optional `transform: Transform | None` hook — define the Transform protocol, no implementations). One implementation: `LocalFSProvider` (stores chunks as files in a directory; configurable `max_object_bytes` and capacity for testing).
6. **CLI** (Typer): `scatterbox init`, `put <local> <vpath>`, `get <vpath> <local>`, `ls [vpath]`, `rm <vpath>`, `provider add/list` (LocalFS only). Replica target configurable via `put --replicas N` (default 3) across distinct LocalFS provider instances.
7. **Soft-block:** refuse files >10 GB unless `--force-large`.

## Verification gate (must pass before you stop)

- Round-trip property test (hypothesis): random files 0 B – 100 MiB → put → get → byte-identical.
- Edge cases: 0-byte file, file < 1 chunk, file = exact chunk multiple, file > many chunks.
- Corruption test: flip a byte in one stored replica → get detects it (hash mismatch), falls back to another replica, still restores byte-identical.
- Provider limit test: provider with `max_object_bytes = 1 MiB` → chunks sized to fit.
- Soft-block test: >10 GB refused without `--force-large` (use a sparse/mocked size, don't write 10 GB).
- All tests green via `uv run pytest`.

## Constraints

- Follow the repo's CLAUDE.md: simplicity first, no speculative abstraction, surgical changes.
- Libraries: `cryptography`, `blake3`, `zstandard`, `argon2-cffi`, `typer`. No others without need.
- Keep modules small; the pipeline must be usable as a library (the daemon will import it in Phase 3).
- When done, update PLAN.md §12 marking Phase 0 complete with a one-line note of any deviations.
