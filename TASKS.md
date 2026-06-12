# TASKS.md — Cold recovery: find()-based, passphrase-only (PLAN.md §9)

**Status: ✅ complete (2026-06-12).** Reverses the Phase 4 deviation:
recovery without even the vault file — passphrase + re-auth one provider.
Gate verified twice: automated (test_cold_recovery.py wipes vault+register
and restores byte-identically through the salt round-trip) and live (wiped
home → wizard "recover with passphrase" → explorer, replica + EC files
byte-identical). 193 tests green; web build clean.
(Phase 2's real-credential gates remain open, PLAN.md §12.)

## 1. Snapshot format v2 (the enabler)

The master key = Argon2id(passphrase, salt) and the salt lives in
vault.json — so today a snapshot alone is undecryptable. v2 embeds the KDF
parameters (explicitly non-secret: salt + work factors) in the blob:

    SBSNAP2\n || u16 len || kdf json || nonce || AES-256-GCM(zstd(db), AAD-v2)

decrypt accepts v1 and v2 (vault path unchanged); v1 blobs in cold recovery
get a clear "predates cold recovery, needs the vault file" error. The Vault
object now carries its kdf params so every snapshot/export writes v2.

## 2. `find()` on adapters + fixed snapshot name

- Optional adapter method `find(name) -> RemoteRef | None` (documented in
  base/_template; recovery getattr-guards so custom adapters may omit it):
  localfs = path probe, chaos = gated passthrough, gdrive = files.list by
  name (newest first), onedrive = direct approot path lookup.
- Snapshots now use the fixed name `scatterbox-register-snapshot` (instead
  of per-generation UUIDs) so they are discoverable cold. Writes stay safe:
  localfs is an atomic replace, OneDrive replaces atomically on session
  commit, Drive creates duplicates which the existing old-generation
  cleanup deletes — with a new guard that never deletes a location whose
  ref equals the freshly written one.

## 3. Core recovery flow (`portability`)

- `find_snapshot(provider)`, `recover_register_cold(home, passphrase,
  provider)`: find → decrypt via embedded KDF → validate → install
  register.db → recreate vault.json with the SAME salt (so the register's
  wrapped file keys still unwrap) → return the unlocked Vault.
- `adopt_recovered_credentials(...)`: store the re-authed token blob under
  the restored register row's existing secret name, so that provider works
  immediately; other OAuth providers need `provider reauth`.
- `vault.MemorySecretStore`: dict-backed store for the pre-vault window.

## 4. Re-auth (completes the story)

`onboarding.reauth_provider`: run the OAuth flow for an EXISTING provider
row and write the secret under its existing name — no register changes, no
replica loss. CLI `provider reauth NAME`, daemon
`POST /api/providers/{name}/reauth`, and a reauth action on provider cards.

## 5. Entry points

- CLI: `scatterbox recover --type localfs|gdrive|onedrive [--root R]
  [--client-id …] [--name N]` (cold); existing `restore` keeps the
  vault-based path.
- Daemon: `POST /api/recover` (uninitialized homes only); `/api/import`
  additionally accepts a lone v2 snapshot (no vault) — restores, recreates
  the vault, flags providers needing reauth.
- Wizard: third first-run choice — "recover with passphrase".

## 6. Verify

Core: cold-recovery gate — wipe the ENTIRE home (vault + register), recover
from passphrase + one localfs root → byte-identical downloads (proves the
salt round-trip). OAuth flavor with a mock-transport provider + credential
adoption. v1-blob error path. find() unit tests per adapter incl. Drive
duplicate handling. Reauth via CLI + API. Wizard recover + snapshot-only
import via API. Full suite green; docs (PLAN §9/§12 deviation, FEATURES
§10/§12/§13, README) updated.
