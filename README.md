# scatterbox

Distributed free-tier cloud storage: aggregate many free storage sources
(Google Drive, OneDrive, and later more exotic backends) into one virtual
filesystem. Files are chunked, compressed, encrypted on your machine, and
scattered as replicas across providers — every backend is treated as
**unreliable and hostile**, and losing any single one never loses data.

```
put file.zip /docs/   →  chunk → zstd → AES-256-GCM → BLAKE3 → 3 providers
get /docs/file.zip    →  fetch healthiest replicas → verify → reassemble
scrub --repair        →  probe replicas, heal anything below its floor
```

**Honest caveat up front:** this raises durability of free-tier storage; it
does not make free tiers a place for irreplaceable data.

## How it works

- **Zero trust in providers.** Everything leaving the machine is ciphertext
  with random-looking names. Providers see chunk sizes and timing, nothing
  else. Per-file keys are wrapped by a master key derived from your
  passphrase (Argon2id); compromise of one manifest never exposes other
  files.
- **The local register is the source of truth.** A SQLite database knows
  where every chunk of every file lives; browsing never touches the network.
  It holds no secrets — credentials and wrapped keys live in a separate,
  always-encrypted **vault** (`vault.json`). Register + vault + passphrase
  are all you need to move to a new machine.
- **Replication with a reliability-weighted floor.** The placement engine
  spreads replicas across distinct providers, weighting free capacity,
  learned reliability, and latency class; chunks forced onto sketchy homes
  get extra copies. A scrubber probes replicas in rotation, demotes failures
  (stored → suspect → lost), and re-replicates anything below its floor.
- **Anti-colocation on demand.** By default each replica provider holds a
  full (encrypted) copy. `put --spread N` splits a file's chunks across N
  shard groups instead, so no single provider ever holds the whole file — a
  guarantee that survives repair. Two modes: `--spread-mode disjoint`
  (default; a provider gets at most 1/N of the file, costs ~N × replicas
  providers) and `--spread-mode packed` (cheapest: ⌈N×replicas⁄(N−1)⌉
  providers — spread 3 × 2 replicas fits on 3), with `--spread-cap K` for
  anywhere in between. Scatterbox tells you when you don't have enough
  providers.
- **Truth, highly visible.** `status` shows real per-file health (●●● /
  ●●○ / ●○○), `provider list` shows quota with confidence labels (exact /
  estimated / unknown) — free space is never presented as more precise than
  it is.

The full architecture (and the reasoning behind it) is in [PLAN.md](PLAN.md);
current work is tracked in [TASKS.md](TASKS.md).

## Status

| Phase | | |
|---|---|---|
| 0 | Core pipeline + CLI (chunk/encrypt/hash, localfs mock, put/get/ls/rm) | ✅ |
| 1 | Replication + repair (placement engine, scrubber, chaos-tested healing) | ✅ |
| 2 | Real providers + vault (Google Drive, OneDrive, OAuth, secret vault) | ✅ code complete — real-credential gates pending |
| 3 | Daemon + web explorer (FastAPI, React, virtualized listing) | ✅ |
| 4 | Portability + recovery (export/import, register snapshots to providers) | — |
| 5 | Policies, erasure coding, exotic adapters (Discord, transform stage) | — |

## Install

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```sh
git clone <this repo>
cd scatterbox
uv sync
uv run scatterbox --help
```

## Quickstart (local, no cloud accounts)

```sh
uv run scatterbox init                       # choose your master passphrase
uv run scatterbox provider add p0 --root D:/sb0
uv run scatterbox provider add p1 --root E:/sb1
uv run scatterbox provider add p2 --root F:/sb2

uv run scatterbox put report.pdf /docs/      # 3 replicas across p0/p1/p2
uv run scatterbox ls /docs
uv run scatterbox status /docs/report.pdf    # ●●● healthy 3/3
uv run scatterbox get /docs/report.pdf restored.pdf
uv run scatterbox scrub --repair             # verify + heal
```

`localfs` providers are real storage (point them at different disks/mounts)
but exist mainly to exercise the full pipeline; the interesting ones are
below.

## Web explorer

```sh
cd web && npm install && npm run build && cd ..
uv run scatterbox daemon          # http://127.0.0.1:8420
```

The daemon serves the built UI: unlock with your passphrase, then browse
(virtualized — 100k-file folders scroll fine), drag-drop upload with
replica/spread options, download, move, delete. Per-file health dots and a
"where is this?" provider panel; a live transfers tab (WebSocket job
progress); a provider dashboard with confidence-labelled capacity bars and
scrub buttons. Browsing reads only the local index — provider I/O happens
in background jobs, never in a request you're waiting on. The daemon binds
127.0.0.1 and holds the master key in memory only after an explicit unlock.

## Real providers

Each provider type needs a one-time (free) OAuth app registration — Google
and Microsoft don't let software talk to their APIs anonymously. Short
version (details: TASKS.md §7):

- **Google Drive:** create a project at console.cloud.google.com, enable the
  Drive API, configure the consent screen (add yourself as test user,
  publish for long-lived tokens), create a **Desktop app** OAuth client.
- **OneDrive:** register an app at entra.microsoft.com for **personal
  Microsoft accounts**, add `http://localhost` as a *Mobile and desktop*
  redirect URI. No client secret (public client + PKCE).

Then:

```sh
uv run scatterbox provider add gd --type gdrive     # prompts id/secret, opens browser
uv run scatterbox provider add od --type onedrive   # prompts id, opens browser
uv run scatterbox provider list                     # real quota, confidence-labelled
```

Tokens land in the encrypted vault, never in the register. Scopes are
minimal: scatterbox can only touch files it created (`drive.file` / the
OneDrive app folder) — never the rest of your account.

Per-instance limits are user-configurable and always respected:

```sh
uv run scatterbox provider set gd --max-object-bytes 1048576   # chunks shrink to fit
uv run scatterbox provider set od --capacity-bytes 5000000000  # use at most ~5 GB
uv run scatterbox provider remove gd                           # guarded if replicas live there
```

## Security model in one paragraph

Your passphrase → Argon2id → master key (never stored) → wraps random
per-file keys → AES-256-GCM per chunk, BLAKE3 over ciphertext (so health
checks never need keys). The vault holds provider credentials encrypted
under the master key; the register holds metadata only. A stolen provider
token exposes ciphertext at worst (and is revocable + scope-limited); a
stolen vault+register is useless without the passphrase. The passphrase is
the one secret that matters — there is no recovery from losing it.

## Development

```sh
uv run pytest -q                 # full offline suite (~30 s, no network)
uv run pytest tests/test_chaos_gate.py -q   # the Phase 1 disaster drill
```

Layout: `core/scatterbox/` (library: pipeline, placement, scrubber,
register, vault, providers), `cli/scatterbox_cli/` (thin Typer wrapper),
`daemon/scatterbox_daemon/` (FastAPI shell over the same library),
`web/` (React explorer; `npm run dev` proxies to a running daemon), and
`tests/`. Adapters are testable offline via injected
`httpx.MockTransport`s; real-credential round-trips are env-gated in
`tests/test_real_providers.py`.

Useful env vars: `SCATTERBOX_HOME` (default `~/.scatterbox`),
`SCATTERBOX_PASSPHRASE` (for scripts/tests; interactive prompt otherwise).
