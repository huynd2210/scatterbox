# TASKS.md — Phase 4: Portability + recovery

**Status: ✅ complete (2026-06-11).** Both PLAN gates automated (157 tests)
and exercised live: CLI export → web-wizard import restored a home
byte-identically; auto-snapshot + vault-only recovery rebuilt a destroyed
register. See PLAN.md §12 Phase 4 for deviations.
(Phase 2's real-credential gates remain open, tracked in PLAN.md §12.)

Read `PLAN.md` first (§9 register+vault portability, §12 Phase 4). The
register is the crown jewel; these tasks make it survivable: export/import
for deliberate moves, automatic provider snapshots for disasters.

## 1. Core portability (`core/scatterbox/portability.py`) ✅

- **Snapshot format:** consistent register bytes via the SQLite backup API →
  zstd → AES-256-GCM under the master key (`SBSNAP1` magic + nonce + ct,
  AAD-bound). Plain (unencrypted) export also allowed per PLAN.md §9.
- **export_archive:** register snapshot (encrypted or plain) + vault copy.
- **import_archive:** validate the vault against the passphrase FIRST, then
  accept either snapshot or raw SQLite register bytes, sanity-open the
  result (migrations + file count) before finalizing. Refuses an
  initialized home unless forced.
- **snapshot_to_providers:** encrypt → upload to the ≥2 most reliable
  providers → store the locations (provider type/config/ref) in the vault
  under `register-snapshot`, then best-effort delete the previous
  snapshot's objects. The vault is what makes recovery possible: it already
  holds the credentials, now also where the snapshot lives.
- **restore_register_from_snapshot:** vault + passphrase only → fetch from
  any stored location → decrypt → validate → install.

*Verify (the two PLAN gates):* export on A, import into a clean home →
byte-identical downloads; destroy register.db, restore from passphrase +
provider snapshot → byte-identical downloads.

## 2. CLI ✅

`scatterbox export <dir> [--plain]`, `scatterbox import <register> <vault>
[--force]`, `scatterbox snapshot`, `scatterbox restore --vault <file>`.

## 3. Daemon + automatic safety net ✅

- `GET /api/export` (unlocked): one zip — vault.json + encrypted register
  snapshot.
- `POST /api/import` (uninitialized only): multipart; accepts the export
  zip, or vault+register files, or vault alone (→ provider-snapshot
  restore). Detects parts by content, not filename. Unlocks on success so
  the wizard drops straight into the explorer. The daemon's open register
  connection is closed around the file swap and reopened.
- **Debounced auto-snapshot:** mutating jobs (upload/delete/scrub) and
  move/rm mark the state dirty; a background task snapshots to providers
  ~20 s after changes settle (skipped while locked), reported over /ws.

*Verify:* API tests — export zip round-trips through import on a fresh
home; vault-only restore works; auto-snapshot fires after an upload
(debounce shortened via monkeypatch).

## 4. Web UI ✅

- First-run screen becomes a choice: **set up new** (existing wizard) or
  **import backup** (drop the export zip — or vault.json + register file,
  or vault.json alone for provider-snapshot recovery — plus passphrase).
- **export backup** button on the providers tab.

*Verify:* `npm run build` clean; wizard choice + import path exercised
against a live daemon.

## 5. Wrap-up ✅

PLAN.md §12 Phase 4 marked with deviations; README portability section;
full suite green (157 passed) + web build clean.
