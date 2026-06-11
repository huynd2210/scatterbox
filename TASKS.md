# TASKS.md — Phase 5: Policies + erasure coding (+ adapter registry)

**Status: ✅ complete (2026-06-11).** EC chaos gate automated (test_ec.py),
policies resolved identically across library/CLI/daemon/UI, registry +
template in place; verified live in the browser (EC folder policy →
optionless upload → ●●●●● "5/5 shares" → byte-identical download). 182+
tests green. See PLAN.md §12 Phase 5 for deviations.
Scope decision (user): NO exotic adapter implementations yet (Discord/
YouTube/Mega/Pastebin…) — but ship the plug-in seams so they bolt on later.
Phase 2's real-credential gates remain open (PLAN.md §12).

## 1. Erasure coding `ec(k,n)` (PLAN.md §7) ✅

- `core/scatterbox/ec.py`: thin zfec wrapper — split (pad → k blocks → n
  systematic shares), join (any k shares → original), regenerate (specific
  missing share indices). Dependency `zfec` (named in PLAN.md §3).
- Schema v6: `manifests.ec_k/ec_n`; `replicas.share_index/share_hash`
  (NULL for plain replicas). For EC manifests `replica_target = n`, rows
  are shares — health/floor queries keep working; `derive_health` learns
  the k threshold (≥n healthy, k<s<n degraded, =k at-risk, <k lost).
- Pipeline: per chunk, the encrypted object is split into n shares stored
  on n distinct providers (object name `<chunk_hash>.<share_index>`); read
  fetches any k verified shares (share_hash) and reconstructs, then checks
  the chunk hash + GCM tag as usual. Scrub deep-verifies shares by
  share_hash; repair fetches k shares, regenerates exactly the missing
  indices, places them on providers holding no live share of the chunk.
- `min_spread` is ignored for EC files (a share holder owns 1/k of nothing
  decryptable — anti-colocation is built in).

*Verify (phase gate):* EC chaos test — files at ec(3,5) across 5 providers,
kill 2 (n−k) → every file restores byte-identical; with spare providers,
scrub+repair regenerates the missing shares and health returns to healthy.

## 2. Per-folder policies (PLAN.md §7/§11) ✅

- Schema v6: `policies(vpath UNIQUE, policy JSON)` — folder → policy
  (replicas, spread, scheme incl. ec(k,n), tiers, pin/exclude).
- Resolution: deepest ancestor folder wins; explicit arguments override
  per field. `put_file` with no policy resolves from the register.
- CLI: `scatterbox policy set|show|list|unset`; put gains `--scheme`,
  `--ec-k`, `--ec-n` overrides.
- Daemon: GET /api/policies, GET/PUT/DELETE /api/policy (effective policy
  + its source folder); upload form fields become optional → inherit.
- UI: policy panel on the files toolbar for the current folder (shows the
  effective policy and where it came from, set/clear); upload options
  default to "inherit".

*Verify:* resolution unit tests (nearest ancestor, overrides win); upload
into a folder with an ec policy produces an EC manifest; CLI + API CRUD.

## 3. Adapter registry (future Discord/YouTube/Mega/Pastebin…) ✅

- `providers/__init__.py` becomes a registry: `AdapterSpec(factory,
  requires_secrets, oauth_module)` + `register_adapter()`; create_provider,
  requires_secrets, and onboarding's OAuth-type list all read from it —
  adding a backend touches exactly one new module + one register call.
- `providers/_template.py`: a fully-commented skeleton adapter (the
  Provider protocol, profile guidance with the PLAN.md §6 priors for
  Discord/YouTube-class backends, transform-stage hook, onboarding notes).

*Verify:* a test registers a toy adapter and round-trips through
create_provider + the CLI/daemon type validation messages.

## 4. Wrap-up ✅

PLAN.md §12 Phase 5 marked (deviation: transform implementations deferred
by user decision) + decision log #9; README; full suite + web build green.
