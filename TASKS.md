# TASKS.md — Phase 1: Replication + repair

**Status: ✅ complete (2026-06-11).** All six tasks done, all verify gates green (72 tests, ~30 s; chaos gate ~20 s). See PLAN.md §12 Phase 1 for the deviations note.

Read `PLAN.md` first (§7 placement, §8 scrubber, §12 Phase 1). Phase 0 is complete — build on `core/scatterbox/`, don't restructure it. Work the tasks in order; each has its own verify gate.

## 1. Failure-injecting mock provider ✅

Extend or wrap `LocalFSProvider` into a `ChaosProvider` for tests: configurable failure modes — drop stored chunks (silent delete), corrupt random bytes, return 404 on `get`/`exists` with probability p, artificial latency/throttle, hard-kill (all operations fail). Deterministic via seed.

*Verify:* unit tests per failure mode; seeded runs reproduce identically.

## 2. Placement engine ✅

`core/scatterbox/placement.py`. Input: chunk size, policy (replica floor, tier constraints, pin/exclude), provider registry with profiles + quotas. Output: target provider list. Rules from PLAN.md §7:

- Weighted sort: free capacity, reliability score, latency class vs policy.
- Diversity: never two replicas of one chunk on the same provider instance.
- **Reliability-weighted floor:** replica count is a per-chunk floor; low-reliability targets get extra copies to hit an effective durability target (simple formula is fine, e.g. combined loss probability under a threshold — document it).
- **Quota safety margin** on `estimated`/`unknown` confidence providers.

Replace the Phase 0 most-free-space sort with this; CLI `put` goes through it.

*Verify:* unit tests — diversity is never violated; a Discord-class profile (reliability_prior 0.5) receives more replicas than a Drive-class one for the same policy; full provider is skipped; pinned/excluded respected.

## 3. Replica state tracking + reliability scores ✅

- `replicas.state`: `pending → stored → suspect → lost` transitions, `last_verified` timestamps.
- Per-provider reliability score in the register: starts at `reliability_prior`, updated from observations (successful verify ↑ slightly, missed probe / corrupt chunk / 404 ↓ sharply). Simple exponential moving average — no Bayesian machinery.
- A file's durability state derives from its chunks: healthy / degraded / at-risk (PLAN.md §8 dots).

*Verify:* unit tests for state transitions and score updates; `scatterbox status <vpath>` CLI shows per-file health.

## 4. Scrubber ✅

`core/scatterbox/scrubber.py`, runnable via CLI (`scatterbox scrub [--full]`), designed so the Phase 3 daemon can schedule it.

- Rotating cheap pass: `exists()` probes over a sample of replicas (oldest `last_verified` first).
- Budgeted deep pass (`--full` or sampled): download + BLAKE3 verify.
- Findings update replica states and reliability scores (task 3).

*Verify:* inject failures via ChaosProvider → one scrub cycle marks the right replicas suspect/lost and decays the right provider's score.

## 5. Repair (re-replication) ✅

When a chunk is below its effective replica floor: fetch from a surviving verified replica, place a new copy via the placement engine (diversity respected), update register. Triggered at the end of a scrub cycle (`scatterbox scrub --repair` or automatic flag).

*Verify:* delete replicas down to one copy → scrub+repair restores the floor on different providers; unrepairable chunks (zero surviving replicas) are reported loudly, not silently skipped.

## 6. Chaos gate (phase exit criterion — PLAN.md §12) ✅

Integration test: store 100 files (mixed sizes, hypothesis-seeded) across 4 mock providers at floor 3 → hard-kill one provider entirely + randomly delete 20% of another's chunks → run scrub+repair → every file restores byte-identical, and every chunk is back at its floor on live providers.

*Verify:* test green in CI-time (keep it under ~2 min: small chunk size is fine); plus the full Phase 0 suite still green (no regressions).

## Constraints

- Follow CLAUDE.md: simplicity first, surgical changes, no speculative abstraction.
- No new dependencies expected; ask before adding any.
- Scrubber/placement must be pure-library (no daemon assumptions) — CLI is the only entry point for now.
- When done: update PLAN.md §12 marking Phase 1 complete with a one-line deviations note, and update this file's checkboxes/status.
