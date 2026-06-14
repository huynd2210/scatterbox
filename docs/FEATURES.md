# scatterbox — feature reference

The complete map of what scatterbox does and how to drive it. The README is
the overview; PLAN.md is the design rationale; this is the reference.
Status: Phases 0–5 implemented (PLAN.md §12); Phase 2's real-credential
verification and the exotic adapters (Discord/YouTube/Mega/…) are the open
items.

---

## 1. Concepts

| Term | Meaning |
|---|---|
| **home** | The local state directory (`$SCATTERBOX_HOME`, default `~/.scatterbox`): `register.db` + `vault.json` + `tmp/` spool. |
| **register** | SQLite database (WAL). Knows where every chunk of every file lives. Metadata only — no secrets, no usable keys. "The crown jewel." |
| **vault** | Small always-encrypted file. Holds provider credentials/OAuth tokens and the register-snapshot locations, sealed under the master key. The initialization marker: a home is "set up" iff `vault.json` exists. |
| **master passphrase** | The one secret you keep. Argon2id-derives the master key; never stored anywhere. No recovery if lost. |
| **provider** | One storage backend instance (a Google Drive account, a local folder…). Assumed hostile: sees only ciphertext under random names. |
| **chunk** | A fixed-size slice of a file (default 8 MiB plaintext), independently compressed + encrypted + hashed. |
| **replica / share** | A stored copy of a chunk on one provider. Under `ec(k,n)` the rows are *shares* instead: n per chunk, any k reconstruct. |
| **policy** | Per-file placement rules (replicas, spread, scheme, tiers, pin/exclude), inheritable per folder. |
| **job** | A queued daemon operation that touches providers (upload / delete / scrub). Browsing never queues jobs. |

## 2. Architecture in one breath

CLI (Typer) and daemon (FastAPI) are thin shells over one library,
`core/scatterbox` — same functions, one code path (PLAN.md §4). The web
explorer (React + Vite) talks to the daemon over HTTP + WebSocket. Browsing
reads only the local register (two indexed range scans per directory —
<100 ms at 50k files); all provider I/O happens in background jobs.

```
web UI ──HTTP/WS──> daemon ──┐
CLI ────direct import────────┼──> core/scatterbox ──adapters──> providers
                             └──> register.db + vault.json
```

## 3. Setup — two equal paths

**Web:** `scatterbox daemon` on a fresh home serves a first-run wizard:

- *set up new* → choose master passphrase (creates the vault, unlocks) →
  add providers (form, including the OAuth browser flow) → explorer.
- *import existing* → drop a backup zip, vault + register files, or
  **vault.json alone** (recovers the register from provider snapshots, §10)
  → unlocked explorer with the restored archive.

**CLI:** `scatterbox init`, then `scatterbox provider add …`. The paths
interoperate: a web-initialized home is a normal home to the CLI and vice
versa.

## 4. Security model

```
passphrase ──Argon2id──> master key ──wraps──> per-file keys ──AES-256-GCM──> chunks
                              └──seals──> vault secrets (credentials, snapshot locations)
```

- Per-chunk encryption: fresh nonce per chunk, compression *before*
  encryption, BLAKE3 over ciphertext (so health checks never need keys).
- Compromise containment: one leaked manifest ≠ the archive; a stolen
  provider token exposes scope-limited ciphertext (revocable); a stolen
  vault+register is useless without the passphrase.
- The register stores vpaths in plaintext locally (fast search; hardening
  via SQLCipher is a noted future option). The daemon binds 127.0.0.1 and
  holds the master key in memory only between `unlock` and `lock`.
- Honest caveat: scatterbox raises free-tier durability; it is not a home
  for irreplaceable data.

## 5. Providers

**Built-in types:** `localfs` (a directory; doubles as the test backend),
`gdrive` (Drive v3, `drive.file` scope, visible `scatterbox/` folder,
resumable uploads), `onedrive` (Graph app folder, upload sessions with
320 KiB-aligned fragments), `dropbox` (app folder, single-request uploads,
fixed OAuth redirect port 8421 — Dropbox verifies redirect URIs exactly),
`pcloud` (visible `scatterbox/` folder, single multipart uploads + getfilelink
downloads, fixed redirect port 8422; a confidential client with a non-expiring
token and no refresh — region (US/EU) auto-detected at consent and pinned in
the token blob; errors arrive as HTTP-200 `result` codes, not status codes),
`koofr` (visible `scatterbox/` folder in the account's primary mount, single
multipart uploads, path-addressed objects; authenticates with a self-serve
app password over HTTP Basic — not OAuth — which is static, so a rejected one
is a re-auth rather than a refresh),
`oracle` (Oracle Cloud Object Storage via its S3 Compatibility API: objects
under a `scatterbox/` key prefix in a bucket, single-PUT uploads, key-addressed
objects; authenticates with a Customer Secret Key — an S3 access key/secret —
signed with AWS SigV4, not OAuth, static so a rejected key is a re-auth rather
than a refresh. The namespace + region + bucket are non-secret register config;
no free-space API, so quota is the configured cap if set ('estimated') else
'unknown'. The shared S3 core lives in `providers/_s3.py`).
`chaos` exists for tests only (failure injection: 404s, corruption,
latency, hard-kill).

**Onboarding:** web form or `scatterbox provider add NAME --type …`.
OAuth types run a loopback browser consent (PKCE); tokens and the Google
client secret land in the vault, never in the register. A failed add rolls
the stored secret back. Each provider gets a connection test before the
register row is written.

**Per-instance limits** (always respected): `max_object_bytes` (chunks are
sized down to fit) and `capacity_bytes` ("use at most this much of the
account"). `scatterbox provider set`, or at add time.

**Quota confidence:** `exact` (API-reported) / `estimated` (configured cap)
/ `unknown` (no idea). The placement engine demands 2× headroom on
non-exact numbers, and the UI labels every capacity bar with its
confidence — free space is never shown more precisely than it is known.

**Reliability:** each provider carries a learned score (EMA: slow to gain
trust at α=0.05, fast to lose it at α=0.30) seeded from the adapter's
prior. Reads and scrubs feed it; placement prefers reliable homes; the
dashboard shows it.

**Removal:** guarded — refuses while replicas live there; `--force` (or
the UI confirmation) drops them and points you at `scrub --repair`.

**Adding new backends:** one module + one `register_adapter()` call.
`providers/_template.py` is the documented skeleton (protocol, profile
priors for Discord/YouTube/Mega/Pastebin classes, vault rules, retry
discipline, transform hook for encode-as-video backends).

## 6. Storing and retrieving files

**Write path** (`put` / upload): split into chunks → zstd-compress each
(kept only if smaller) → AES-256-GCM encrypt (per-file key) → BLAKE3 hash →
upload to the placement targets concurrently → record everything in one
register transaction. Uploads happen *before* the register insert, so a
crash leaves at worst orphaned ciphertext, never a record of a missing
file. Files >10 GB are soft-blocked (`--force-large` lifts it).

**Read path** (`get` / download): per chunk, try replicas healthiest-first;
each must pass fetch + BLAKE3 + GCM tag + size checks. Failures mark the
replica suspect and ding reliability — reads double as health observations.
Output lands in a temp file and is atomically renamed only when complete.

## 7. Placement and durability

**Replication (default):** `replicas` is a per-chunk floor across distinct
providers (diversity is absolute: never two copies of a chunk on one
provider). Low-reliability targets attract extra copies until the combined
loss probability clears 1e-3, capped at floor+2. Candidates are scored by
reliability (0.5), free-capacity fraction (0.3), latency fit (0.2); pinned
providers always sort first; full/unreachable providers are filtered out.

**Anti-colocation (`--spread N`):** chunks are dealt round-robin across N
shard groups with a per-provider cap K on how many groups one provider may
hold — so nobody ever holds a full (ciphertext) copy. Modes:
`disjoint` (K=1, ≤1/N per provider, needs ~N×R providers) and
`packed` (K=N−1, the cheapest that still denies a full copy:
P ≥ ⌈N×R⁄(N−1)⌉ — e.g. spread 3 × 2 replicas fits on 3 providers), plus
explicit `--spread-cap K` (P ≥ max(R, ⌈N×R⁄K⌉)). Small files get their
chunk size shrunk so they still split into N pieces. The guarantee
survives repair: groups and K are recorded in the register and
re-replication never pushes a provider past the cap.

**Erasure coding (`--scheme ec --ec-k K --ec-n N`):** each encrypted chunk
becomes n zfec shares on n distinct providers; any k rebuild it. Costs
n/k× storage (vs n× for same-tolerance replication) and survives n−k
provider losses. Share objects are named `<chunk_hash>.<index>` and carry
individual hashes, so the scrubber verifies them without reconstruction
and repair regenerates exactly the missing indices from any k survivors.
`min_spread` is moot under EC — a share holder owns 1/k of nothing
decryptable.

## 8. Folder policies

Attach a policy to any folder; files stored beneath it inherit
automatically. Resolution: deepest ancestor folder wins (`/` acts as the
global default); explicit flags/form fields beat the folder policy *field
by field*. Identical behavior in the library, CLI, daemon, and UI.

Fields: `replicas`, `min_spread` + `spread_mode`/`spread_cap`,
`scheme` (`replica`/`ec`) + `ec_k`/`ec_n`, `allowed_tiers`,
`pinned`/`excluded` providers.

- CLI: `scatterbox policy set /cold --scheme ec --ec-k 3 --ec-n 5`,
  `policy show PATH` (effective + source), `policy list`, `policy unset`.
- UI: *policy* button on the files toolbar — shows the effective policy
  and where it came from ("set on this folder" / "inherited from /docs" /
  "defaults") with an editor; upload options default to "auto" (inherit).

## 9. Health, scrubbing, repair

**Replica lifecycle:** `pending → stored → suspect → lost`. Two-strike
rule: one failed observation raises suspicion, a second writes the replica
off; a hash mismatch on deep verify is definitive (straight to lost). Only
a deep verify rehabilitates a suspect — a passing `exists()` probe proves
presence, not integrity. `lost` is terminal; repair creates new rows.

**Scrubbing** (`scatterbox scrub`, or the dashboard buttons / scrub jobs):
rotating cheap pass (existence probes, oldest-verified first) and a deep
pass (`--full`, or byte-budgeted via `--deep-budget-bytes`) that downloads
and re-hashes. Every finding updates replica state and provider
reliability.

**Repair** (`--repair`): chunks below their floor get new copies — fetched
from any surviving verified replica (ciphertext only: repair never needs
the passphrase), placed with full diversity/spread/EC-cap rules. EC chunks
are reconstructed from k shares and only the missing indices are
regenerated. Unrepairable chunks are reported loudly, never skipped.

**Health words** (per file, derived from its weakest chunk):
replication — at/above floor `healthy ●●●`, 2 `degraded ●●○`,
1 `at-risk ●○○`, 0 `lost`; EC — n `healthy`, k<s<n `degraded`,
=k `at-risk` (one more loss is fatal), <k `lost`. Shown as dots in the
explorer, `scatterbox status`, and the per-file detail panel; the header
shows a global durability % (chunks at full target).

## 10. Backup, portability, disaster recovery

Register + vault + passphrase = the whole archive; chunks never move.

- **Export:** `scatterbox export DIR` (register snapshot, encrypted under
  the master key unless `--plain`, + vault copy) or the UI's *export
  backup* button (one zip). Snapshot format: `SBSNAP1` magic + nonce +
  AES-256-GCM(zstd(db)).
- **Import:** `scatterbox import REGISTER VAULT`, or the wizard's *import
  existing*. Validates the passphrase against the vault first and
  sanity-opens the register before installing anything — a failed import
  leaves the home untouched.
- **Automatic safety net:** the daemon uploads an encrypted register
  snapshot to the two most reliable providers ~20 s after changes settle
  (debounced; skipped while locked; previous generation deleted after the
  new one is safe). Locations are recorded *inside the vault*. CLI
  equivalent: `scatterbox snapshot`.
- **Disaster recovery:** vault.json + passphrase alone rebuild everything —
  `scatterbox restore --vault vault.json`, or hand the wizard just the
  vault file. The vault knows the snapshot locations and already holds the
  provider credentials.
- **Cold recovery (worst case — nothing local at all):** snapshots are v2
  (`SBSNAP2`) — they embed the non-secret Argon2id parameters and sit under
  a fixed, `find()`-discoverable name. So passphrase + re-authenticating
  ONE provider rebuilds everything: `scatterbox recover --type gdrive`,
  the wizard's *recover with passphrase*, or dropping a lone `.sbsnap`
  into the import form. The vault is recreated with the original salt
  (wrapped file keys keep unwrapping); the re-authed provider's tokens are
  adopted automatically and the rest are one `scatterbox provider reauth
  NAME` (or the *reauth* link on the provider card) each — register rows
  and replicas untouched.

## 11. Web explorer

`scatterbox daemon` → http://127.0.0.1:8420 (serves `web/dist`; `npm run
dev` in `web/` proxies to it during UI work).

- **files** — breadcrumbs; virtualized listing (smooth at 100k entries);
  drag-drop or button upload with inherit-by-default options; download,
  move/rename, delete; lazy per-row health dots (fetched only for visible
  rows); "where is this?" detail panel (per-provider replica breakdown,
  scheme, spread); folder policy editor.
- **transfers** — live job queue over WebSocket: per-chunk upload progress
  bars, scrub reports, failures with reasons.
- **providers** — capacity bars with confidence labels, learned
  reliability, latency class, replicas held; add/remove providers (with
  the OAuth flow); scrub / deep scrub / scrub+repair; export backup.
- Plus the unlock screen (locked daemon) and the first-run wizard (§3).

## 12. Daemon API

Local-only by default. `423 Locked` on crypto endpoints while locked.

| Endpoint | Purpose |
|---|---|
| `POST /api/init` | First-run: create + unlock the vault |
| `POST /api/import` | First-run: backup zip / vault+register / vault-only restore |
| `GET /api/export` | One zip: vault + encrypted register snapshot |
| `POST /api/unlock`, `POST /api/lock`, `GET /api/status` | Session + counters + durability % |
| `GET /api/files?path=` | Directory listing (index only) |
| `GET /api/file?path=` | Stat + health + provider breakdown |
| `POST /api/health` | Batch health for visible rows |
| `POST /api/move`, `DELETE /api/file?path=` | Move (sync, metadata); delete (job) |
| `POST /api/upload` | Multipart spool → job id (returns pre-provider-I/O) |
| `GET /api/download?path=` | Streamed reassembled file |
| `GET /api/jobs` | Job queue |
| `GET/POST /api/providers`, `DELETE /api/providers/{name}` | List/onboard/remove |
| `POST /api/recover`, `POST /api/providers/{name}/reauth` | Cold recovery; fresh OAuth consent for an existing provider |
| `GET /api/policies`, `GET/PUT/DELETE /api/policy` | Folder policies |
| `POST /api/scrub` | Enqueue scrub (deep/repair options) |
| `WS /ws` | Job lifecycle + progress, files-changed, snapshot events |

## 13. CLI reference

| Command | Purpose |
|---|---|
| `init` | Create register + vault (choose passphrase) |
| `put LOCAL VPATH [--replicas --spread --spread-mode --spread-cap --scheme --ec-k --ec-n --pin --exclude --force-large]` | Store a file (unset options inherit the folder policy) |
| `get VPATH LOCAL` | Restore byte-identically |
| `ls [VPATH]`, `status VPATH`, `mv SRC DST`, `rm VPATH` | Browse / health / move / delete |
| `scrub [--full --repair --probe-limit --deep-budget-bytes]` | Verify + heal |
| `provider add NAME --type localfs\|gdrive\|onedrive\|dropbox\|pcloud\|koofr\|oracle …` | Onboard (OAuth for cloud types; app password for koofr; S3 key/secret for oracle) |
| `provider list / set / remove [--force]` | Inspect / limits / remove |
| `policy set/show/list/unset` | Folder policies |
| `export DIR [--plain]` / `import REGISTER VAULT [--force]` | Backup / restore |
| `snapshot` / `restore [--vault FILE] [--force]` | Provider snapshot / vault-based disaster recovery |
| `recover --type T [--root R \| --client-id …] [--name N]` | COLD recovery: passphrase + one re-authed provider, nothing local |
| `provider reauth NAME [--client-id …]` | Fresh OAuth consent for an existing provider (tokens expired/revoked/recovered) |
| `daemon [--host --port]` | Serve the API + web explorer |

Environment: `SCATTERBOX_HOME` (state directory), `SCATTERBOX_PASSPHRASE`
(non-interactive passphrase for scripts/tests).

## 14. On-disk schema (migrations v1–v6)

`files` (vpath tree) → `manifests` (scheme, wrapped file key, chunk size,
replica target, spread + EC params) → `chunks` (seq, BLAKE3 hash, sizes,
compressed flag, spread group) → `replicas` (provider, remote ref,
lifecycle state, last_verified, share index/hash). Plus `providers`
(type + non-secret config + learned stats), `jobs` (daemon queue),
`policies` (folder → policy JSON). Migrations are plain SQL applied via
`PRAGMA user_version`; old databases upgrade automatically on open.

## 15. Testing

`uv run pytest -q` — fully offline (~180 tests, <1 min): adapters run
against `httpx.MockTransport` fakes of Drive/Graph; provider failure is
simulated by the chaos adapter. Notable gates: the Phase 1 chaos drill
(kill a provider + delete 20% of another → heal → byte-identical), the
50k-file <100 ms browse test, non-blocking-upload and
health-flip-in-one-scrub daemon tests, both portability gates, and the EC
chaos gate (lose n−k providers → restore → repair). Real-credential
round-trips are opt-in: see `tests/test_real_providers.py` for the recipe.
