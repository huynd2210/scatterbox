# Distributed Free-Tier Cloud Storage — Architecture Plan

**Status:** Draft v2 · 2026-06-11
**Name:** `scatterbox`

## 1. Problem

Aggregate many free storage sources (Google Drive, OneDrive, MongoDB free tiers, and later unorthodox ones like Discord attachments or YouTube videos) into one virtual storage system with a normal file-explorer experience. Every backend is treated as **unreliable and hostile**: data may be exposed, throttled, corrupted, or deleted at any time.

## 2. Core principles

1. **Zero trust in providers.** Everything leaving the machine is encrypted client-side. Loss of any single provider must never lose data.
2. **Browsing never touches providers.** All metadata lives in a local index; the explorer reads only that. Provider I/O happens in background jobs. This is what makes the UI butter-smooth — it's an architecture property, not a language property.
3. **Metadata is the crown jewel.** Without the index, chunks scattered across 10 providers are garbage. The index itself must be redundantly backed up (encrypted) to the providers.
4. **Providers are not equal — and the user sees it.** Every provider has a capability/trust profile (speed, capacity, reliability) surfaced prominently in the UI and used by the placement engine.
5. **Simplicity first.** Replication before erasure coding; two real providers before ten; CLI before polish. Designs leave room for the fancy stuff without building it yet.

## 3. Stack decision

The "wait 10s while I browse" fear is solved by principle #2: the explorer queries a local SQLite index (sub-millisecond), never the network. Given that, language choice is about developer speed and the heavy paths:

| Concern | Python reality |
|---|---|
| Browse/index latency | SQLite via local API — fast in any language |
| Encryption throughput | `cryptography` (OpenSSL C bindings) does AES-GCM at GB/s |
| Hashing | `blake3` (Rust binding) — multi-GB/s |
| Erasure coding (later) | `zfec` (C) |
| File→video transform (later) | ffmpeg subprocess — language-agnostic anyway |
| Concurrency for parallel chunk transfers | `asyncio` + httpx; transfers are network-bound, not CPU-bound |
| Provider SDKs / OAuth | Best-in-class library support |
| Weakness | Packaging/distribution of the daemon (mitigate: `uv`, later PyInstaller) |

Go would deploy nicer and Rust would crunch faster, but neither bottleneck is real for the MVP, and Python halves the dev time. The CPU-heavy bits are already C/Rust under the hood.

**Chosen stack:**

- **Core engine + daemon:** Python 3.12+, FastAPI (local HTTP API), SQLite in WAL mode
- **CLI:** Typer, calling the same core library as the daemon (one code path)
- **Frontend:** React + Vite + TypeScript, virtualized file list (TanStack Virtual) so 100k-file folders scroll smoothly; talks to the daemon over HTTP + WebSocket (job progress)
- **Escape hatch:** if a hot loop ever shows up in profiling, rewrite that one piece as a Rust extension (PyO3). Don't pre-build this.

## 4. System architecture

```
┌────────────────────────────── user machine ──────────────────────────────┐
│  Web UI (React)         CLI (Typer)                                      │
│       │ HTTP/WS              │ direct import                             │
│       ▼                      ▼                                           │
│  ┌─────────────────────────────────────────────┐                         │
│  │ Daemon (FastAPI)                            │                         │
│  │  ├─ VFS API (ls/stat/mkdir/mv/rm)  ──────┐  │     ┌────────────────┐  │
│  │  ├─ Transfer API (upload/download jobs)  │  │ ◄──►│ SQLite index   │  │
│  │  ├─ Job queue + workers (async)          │  │     │ (WAL)          │  │
│  │  ├─ Placement engine (policy → providers)│  │     └────────────────┘  │
│  │  ├─ Pipeline: chunk→compress→encrypt→hash│  │                         │
│  │  ├─ Scrubber (health, verify, re-replicate) │                         │
│  │  └─ Provider registry                    │  │                         │
│  └──────────────┬───────────────────────────┘  │                         │
│                 ▼ adapter interface             │                         │
│   ┌─────────┬─────────┬─────────┬──────────────┴───┐                     │
│   │ GDrive  │OneDrive │ LocalFS │ (Discord, YouTube│                     │
│   │ adapter │ adapter │ (mock)  │  Mongo… later)   │                     │
│   └─────────┴─────────┴─────────┴──────────────────┘                     │
└───────────────────────────────────────────────────────────────────────────┘
```

## 5. Data pipeline

**Write path** (`put file.zip /docs/`):

1. Split into fixed-size chunks (default 8 MiB; per-provider max may force smaller). **Chunking is the sharding:** a 10 GB file naturally becomes many chunks spread across different providers — no single provider needs to hold the whole file. Files larger than **10 GB are soft-blocked** by default (warning + refusal); an advanced setting lifts the cap.
2. Optionally compress each chunk (zstd; skip if entropy high).
3. Encrypt each chunk: AES-256-GCM, random per-file key (FK), per-chunk nonce.
4. Hash ciphertext (BLAKE3) → chunk ID. Enables integrity checks and dedup.
5. Placement engine picks N target providers per the file's policy (default N=3, spread across distinct providers).
6. Workers upload replicas in parallel with retry/backoff; partial success is tracked, not hidden.
7. Write manifest (chunk list, FK wrapped by master key, replica locations) to the index. File is "durable" only when every chunk meets its replica target; UI shows the true state until then.

**Read path:** manifest from index → for each chunk, fetch from the healthiest+fastest replica → verify BLAKE3 → decrypt → reassemble. Failed replica ⇒ try next, mark replica suspect.

**Transform hook (YouTube/Discord-class providers):** the adapter interface includes an optional `transform` stage — a pluggable encoder/decoder pair applied between encryption and upload (e.g., bytes→video frames). The pipeline treats it as a black box with declared properties (size overhead ratio, encode/decode cost). Nothing else in the system needs to know how it works. Interface only for now; implementations later.

## 6. Provider abstraction

```python
class Provider(Protocol):
    async def put(self, chunk_id: str, data: bytes) -> RemoteRef
    async def get(self, ref: RemoteRef) -> bytes
    async def delete(self, ref: RemoteRef) -> None
    async def exists(self, ref: RemoteRef) -> bool          # cheap health probe
    async def quota(self) -> Quota                           # total/used bytes
    def profile(self) -> ProviderProfile
    transform: Transform | None                              # YouTube-class hook
```

**ProviderProfile** (static prior + learned stats):

| Field | Example: GDrive | Example: Discord | Example: YouTube |
|---|---|---|---|
| `latency_class` | hot | warm | glacial |
| `throughput_class` | high | low | very low (transform cost) |
| `max_object_bytes` | ~5 TB | 10 MB | ~large but encode-bound |
| `capacity_free` | 15 GB | "unlimited"-ish | "unlimited"-ish |
| `reliability_prior` | 0.9 | 0.5 | 0.3 |
| `exposure_risk` | low | high | high |
| `rate_limits` | yes | strict | strict |

`reliability_score` starts at the prior and is updated from scrubber observations (missed probes, corrupt chunks, deletions). These profiles drive both placement decisions and the UI badges (§10).

**Quota confidence:** not all providers can report free space honestly. Each provider instance tracks capacity with a confidence level — `exact` (API-reported, e.g. Drive), `estimated` (configured cap minus bytes we've stored), or `unknown` (Discord-class). The placement engine keeps a safety margin on non-exact providers and corrects estimates from observed failures (quota-exceeded errors shrink the estimate). The UI never pretends: "~3.2 GB left (estimated)" vs "3.2 GB left".

**Provider onboarding (user-driven):** providers are added by the user through a setup wizard — pick a provider type, complete its credential flow (OAuth for Drive/OneDrive, token/webhook for others), connection is tested, secrets land in the vault (§9), profile lands in the register. Each adapter type ships sane profile defaults (e.g. Drive: 15 GB, large objects; pastebin-class: tiny objects), but `max_object_bytes`, capacity, and tier are **user-configurable per provider instance** — the placement engine and chunking respect whatever is configured (chunks are sized down to fit a provider's max where needed).

## 7. Placement & policies

A **policy** is attached per-file (inherited from folder, defaulting from global settings):

- `replicas: int` (default 3)
- `allowed_tiers`: e.g. "hot only" for stuff you'll re-download often, "anything" for cold archives
- `pinned_providers` / `excluded_providers`
- `min_spread: int` (default 1) + `spread_mode`/`spread_cap` — anti-colocation, see below
- (later) `erasure: k_of_n` as an alternative to plain replication

Placement engine scores candidate providers: free capacity, reliability score, latency class vs policy, diversity (never two replicas on the same provider account). Starts as a simple weighted sort — no genius algorithm needed yet.

**Reliability-weighted replicas:** the replica count is a *per-chunk floor*, not a ceiling. If a chunk's best available homes are low-reliability providers, the placement engine adds extra replicas there to hit an effective durability target — e.g. a chunk on Drive+OneDrive gets 2 copies, while one forced onto two Discord-class providers gets 3–4.

**Anti-colocation (`min_spread`, `spread_mode`/`spread_cap`):** since providers are hostile, plain replication has a quiet downside: every replica provider holds a complete (encrypted) copy of the file. `min_spread: N` forbids that — the file's chunks are dealt round-robin across N shard groups, and no provider may hold more than K of those groups, so every provider misses at least one piece of the file. Two named modes for K, plus an explicit override:

- `disjoint` (default): K=1 — a provider holds at most ~1/N of the file; costs ~N×R usable providers.
- `packed`: K=N−1 — the weakest guarantee that still denies a full copy (a provider may hold up to (N−1)/N); cheapest at P ≥ ⌈N×R⁄(N−1)⌉ (e.g. spread 3 × 2 replicas fits on 3 providers via the rotation table S1:{P1,P2}, S2:{P2,P3}, S3:{P3,P1}).
- `spread_cap: K`: anywhere between, P ≥ max(R, ⌈N×R⁄K⌉).

Per-chunk replicas stay on distinct providers regardless (the diversity rule), so a provider death still costs each chunk at most one replica — but note the packed blast radius: one death can degrade up to N−1 groups at once. Files smaller than N chunks get their chunk size shrunk so they still split into N pieces. Selection is a load-balanced greedy (pinned > least groups held > score) which reaches the bound for interchangeable providers; heterogeneous quotas/pins may need more, and infeasibility tells the user to add providers or accept less spread. The guarantee survives repair: each chunk's group and the file's K are recorded in the register, and re-replication never pushes a provider past the cap. Default `min_spread` 1 — trusting a provider with full (encrypted) colocation is allowed unless the user opts in.

**Replication vs erasure coding:** start with full replicas (simple, debuggable, fine at MVP scale). The manifest schema includes a `scheme` field (`replica` | `ec(k,n)`) so erasure coding slots in later without migration pain.

## 8. Redundancy, health & repair

- **Scrubber** runs periodically: cheap `exists()` probes on a rotating sample, plus occasional full download+hash verification (budgeted, prefers hot providers).
- Chunk below replica target → re-replicate from a surviving copy onto a new provider.
- Provider failing repeatedly → reliability score decays → placement avoids it → UI shows it degraded; user can trigger "evacuate provider".
- All of this is visible: per-file health (●●● healthy / ●●○ degraded / ●○○ at risk), per-provider status page.

## 9. Central register + secret vault

The system's state is split into two portable artifacts, kept deliberately separate:

**Central register** — the SQLite DB. Knows *where everything is*: `files` (virtual path tree, policy, size, mtime), `manifests` (file → chunk list, wrapped file key, scheme), `chunks` (chunk_id, size, hash), `replicas` (chunk_id → provider, remote_ref, state, last_verified), `providers` (non-secret config, profile, stats), `jobs` (queue). Contains wrapped (encrypted) file keys but **no secrets** — useless without the vault.

**Secret vault** — a small, always-encrypted file (Argon2id from master passphrase → AES-256-GCM). Holds the master key and all provider credentials/OAuth tokens. Never written to disk unencrypted; never uploaded to providers as part of register snapshots unless the user explicitly includes it.

**Portability (first-class flow):**

- **Export button:** dumps the register (optionally encrypted with the master key) + the vault as two files.
- **Import:** on a new machine, point scatterbox at register + vault, enter passphrase → everything is back: file tree, chunk locations, provider access. No re-upload, no re-scan.
- **Automatic safety net:** after changes (debounced), an encrypted register snapshot is also uploaded to ≥2 of the most reliable providers. Recovery without the exported register: passphrase + vault (or re-auth one provider) → fetch snapshot → restore. The register is the crown jewel; without it, chunks scattered across 10 providers are garbage.

## 10. Security

- Master passphrase → Argon2id → master key (never stored; held in daemon memory while unlocked).
- Master key wraps per-file keys; per-file keys encrypt chunks (AES-256-GCM). Compromise of one manifest ≠ compromise of the archive.
- Providers see only ciphertext with random-looking names. Exposure of a Discord channel or public link leaks nothing but traffic-analysis-ish metadata (chunk sizes/timing).
- All credentials/OAuth tokens live only in the secret vault (§9), encrypted at rest.
- Local DB file: contains the virtual file tree in plaintext for fast search. Acceptable for MVP (it's the user's own machine); note as a hardening option later (SQLCipher).
- Honest caveat in docs/UI: this raises durability, it does not make free tiers a place for irreplaceable data.

## 11. User experience

- **Explorer:** normal folder tree + file list, drag-drop upload, download, rename, move, delete. Instant — all from the index. Virtualized rendering.
- **Truth, highly visible** (explicit requirement):
  - Per-file badges: storage tier (⚡hot / 🐌slow), health dots, replica count, "where is this?" detail panel listing providers.
  - Upload flow shows estimated retrieval speed for the chosen placement *before* committing ("this will land on YouTube-class storage; retrieval may take minutes").
  - Provider dashboard: capacity bars **with confidence labels** (exact / estimated / unknown — §6), reliability trend, status, per-provider evacuate button. Global "space left" is shown as a range, not a lie.
  - Global durability indicator: % of chunks at full replica target.
- **Transfers panel:** background job queue with progress (WebSocket), pause/retry.
- **Advanced settings** per upload/folder: replica count, tier constraints, provider pin/exclude. Defaults hide all of this.
- **Settings page:** provider setup wizard (add/edit/remove, per-instance limits), and Export/Import — one button exports register (+optional encryption) and vault for hopping machines (§9).

## 12. Roadmap

Each phase has a verification gate; don't advance until it passes.

**Phase 0 — Core pipeline + CLI (foundation)** ✅ **Complete (2026-06-11)**
Repo skeleton, SQLite schema, chunk→compress→encrypt→hash pipeline, manifest format, LocalFS mock provider, CLI `put/get/ls/rm`.
*Verify:* round-trip integrity test suite (byte-identical restore, 0-byte files, >chunk-size files, corrupted-chunk detection). Property test: random files survive the pipeline.
*Deviations:* none of substance — hypothesis property test runs with scaled-down chunk size (64 KiB) for speed, with a separate 100 MiB test at the default 8 MiB chunks; Phase 0 placement is a plain most-free-space sort (real engine is Phase 1 as planned).

**Phase 1 — Replication + repair (the "unreliable" promise)** ✅ **Complete (2026-06-11)**
Placement engine, N-replica writes across multiple mock providers, scrubber, re-replication. Mock providers gain failure injection (drop chunks, corrupt bytes, randomly 404, throttle).
*Verify:* chaos test — store 100 files across 4 mocks at N=3, kill one provider entirely + randomly delete 20% of another's chunks → scrubber heals, every file restores byte-identical.
*Deviations:* durability-chasing extra replicas are capped at floor+2 (per §7's "3–4 copies" example); repair's diversity rule bars only *live* copies, so a provider whose replica of a chunk is suspect can host the fresh copy (the stale row is superseded to `lost`) — necessary to meet the floor with 4 providers and two damaged; file health has an explicit fourth `lost` state beyond §8's three dots.

**Phase 2 — Real providers + vault** ✅ **Code complete (2026-06-11); real-credential gates pending**
Google Drive + OneDrive adapters (OAuth flow, rate-limit handling, resumable upload), secret vault (passphrase-encrypted credentials/master key), provider onboarding via CLI, per-instance configurable limits, quota tracking.
*Verify:* real round-trip on both; revoke a file in Drive manually → scrubber detects and re-replicates; set `max_object_bytes=1 MiB` on a provider → chunks respect it.
*Status:* offline gates green (max_object_bytes respected, 115+ tests, all adapter paths mock-transport tested). Still open, needs the user's OAuth apps: (1) real round-trips — onboard providers then run the env-gated tests (recipe in tests/test_real_providers.py docstring); (2) manual revoke-in-Drive → `scrub --repair` heals. Mark this line fully complete when both pass.

**Phase 3 — Daemon + Web explorer**
FastAPI daemon, job queue, React explorer with virtualized listing, transfers panel, badges/health UI, provider dashboard.
*Verify:* browse operations <100 ms on a 50k-file index; uploads never block the UI; health/tier badges reflect injected failures within one scrub cycle.

**Phase 4 — Portability + recovery**
Export/import of register + vault (UI button + CLI), automatic encrypted register snapshots to providers, restore-from-snapshot flow.
*Verify:* export on machine A, import on a clean environment → full access, byte-identical downloads. Separately: destroy the local register, recover from passphrase + provider snapshot.

**Phase 5 — Policies, erasure coding, exotic adapters**
Per-folder policies UI, `ec(k,n)` scheme, transform-stage implementations (Discord first — it's a normal adapter with small `max_object_bytes`; then the YouTube-class transform when you supply the method).
*Verify:* EC chaos test (lose n−k providers, restore); Discord round-trip.

## 13. Decisions log

1. ✅ Single user. Portability via register + vault export/import, not live multi-device sync.
2. ✅ Providers added by the user (setup wizard / CLI), credentials in the vault, per-instance size/capacity limits configurable.
3. ✅ Repo layout: monorepo `core/` `daemon/` `cli/` `web/`.
4. ✅ Name: `scatterbox`.
5. ✅ No dedup. Two identical files = two full copies; dedup is the user's job.
6. ✅ Files >10 GB soft-blocked by default; advanced setting lifts the cap. Sharding via chunking handles large files across providers.
7. ✅ Free-space reporting uses quota confidence levels (exact/estimated/unknown) — never presented as more precise than it is.
8. ✅ Anti-colocation is opt-in per file (`min_spread`, CLI `--spread N`): chunks split across N shard groups with a per-provider cap K so no provider holds a full ciphertext copy. Two modes — `disjoint` (K=1, strongest, default) and `packed` (K=N−1, cheapest: P ≥ ⌈NR⁄(N−1)⌉) — plus explicit `--spread-cap K`; infeasible spread tells the user to add providers or lower N/loosen K (added 2026-06-11, after Phase 2; packed model and provider-minimum formula by the user).
