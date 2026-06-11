# TASKS.md — Phase 2: Real providers + vault

**Status: code complete (2026-06-11) — tasks 1–6 done, offline suite green
(115 tests). Task 7's real-credential gates (round-trip on real Drive/
OneDrive, manual revoke-and-heal) need the user's OAuth client apps and
accounts; see task 7 for how to run them.**

Read `PLAN.md` first (§6 providers, §9 vault, §12 Phase 2). Phases 0–1 are
complete — build on `core/scatterbox/`, don't restructure it. Work the tasks
in order; each has its own verify gate.

## 1. Vault v2 — encrypted secrets store ✅

Extend `core/scatterbox/vault.py`: a `secrets` section in the vault file — a
JSON map encrypted as one AES-256-GCM blob under the master key. The unlocked
`Vault` implements `get_secret/set_secret/delete_secret` (JSON values),
persisting atomically on every write. v1 vault files (no secrets section)
unlock fine and upgrade to v2 on first write. A `SecretStore` protocol so
adapters/tests don't depend on the Vault class.

*Verify:* unit tests — secrets round-trip across lock/unlock; v1 file
upgrades; vault file never contains plaintext secrets; wrong passphrase still
rejected.

## 2. OAuth foundation ✅

`core/scatterbox/oauth.py`:

- **Loopback flow (sync, CLI-driven):** authorization-code + PKCE against a
  local `127.0.0.1:<random port>` redirect; opens the browser, catches the
  code, exchanges it for tokens. Works for Google (client_id + client_secret)
  and Microsoft (public client, id only).
- **TokenManager (async):** hands out a valid access token, refreshing via
  the refresh-token grant when expired (60 s skew); persists rotated refresh
  tokens back to the SecretStore (Microsoft rotates them).

New dependency: `httpx` (pre-approved — PLAN.md §3 names it in the stack).

*Verify:* unit tests with mocked transports — PKCE challenge is S256; expired
token triggers exactly one refresh; rotated refresh token is persisted.

## 3. Google Drive adapter ✅

`core/scatterbox/providers/gdrive.py`, type `"gdrive"`. Scope
`drive.file`; objects live in a visible `scatterbox/` folder (created lazily,
folder id cached in config) so the user can manually delete files — required
by the phase verify gate. Resumable upload (`uploadType=resumable`), download
via `alt=media`, `exists` via metadata fetch (trashed ⇒ missing), exact quota
from `about.storageQuota`. 429/403-rate-limit/5xx → exponential backoff +
`Retry-After`; 401 → one token refresh + retry.

*Verify:* offline tests via injected MockTransport for every operation +
retry/refresh paths; env-gated real round-trip test.

## 4. OneDrive adapter ✅

`core/scatterbox/providers/onedrive.py`, type `"onedrive"`. Microsoft Graph,
app folder (`special/approot`), scope `Files.ReadWrite.AppFolder
offline_access`. Small objects via simple PUT; >4 MiB via upload session with
320 KiB-aligned fragments. Same retry/refresh discipline as gdrive. Exact
quota from `/me/drive`.

*Verify:* same shape as task 3, plus fragment alignment unit test.

## 5. Secrets threading ✅

`create_provider(type_, config, secrets=None)`; `load_providers(register,
secrets=None)`; `secrets` param on `get_file`, `remove_file`, `scrub`.
`providers.requires_secrets(type_)` tells the CLI whether a command must
unlock the vault (rm/scrub/provider-list unlock only when a registered
provider needs it; put/get already unlock for the master key).

*Verify:* full Phase 0/1 suite still green (localfs/chaos need no secrets);
unit test that a gdrive row without an unlocked vault fails loudly.

## 6. CLI onboarding + per-instance limits ✅

`scatterbox provider add <name> --type gdrive|onedrive|localfs`: prompts for
the OAuth client app credentials, runs the loopback flow, tests the
connection (`quota()`), stores tokens + client_secret in the vault
(`provider:<name>`), non-secret config in the register. `provider remove`
(refuses while the provider still holds live replicas, `--force` overrides);
`provider set <name>` for per-instance `--max-object-bytes` /
`--capacity-bytes`. Limits respected by chunking/placement (existing
machinery).

*Verify:* CLI tests with a stubbed OAuth flow; `provider set
--max-object-bytes 1MiB` → next put produces chunks that fit (phase gate).

## 7. Phase gate (PLAN.md §12) — ⏳ awaiting real credentials

- [ ] Real round-trip on both providers. Onboard each
  (`scatterbox provider add gd --type gdrive`, `... add od --type
  onedrive`), then run the env-gated tests (`SCATTERBOX_TEST_GDRIVE=gd`
  etc. — see tests/test_real_providers.py for the full recipe).
- [ ] Manually revoke a file in Drive (delete a chunk from the scatterbox/
  folder) → `scatterbox scrub --repair` detects and re-replicates.
- [x] `max_object_bytes = 1 MiB` on a provider → chunks respect it
  (test_provider_onboarding.py::test_max_object_bytes_limit_shrinks_chunks).
- [x] Full suite green, no regressions (115 passed).

## Constraints

- Follow CLAUDE.md: simplicity first, surgical changes, no speculative
  abstraction.
- New deps: `httpx` only.
- Adapters must be testable offline (injectable transport) — the default
  suite never touches the network.
- When done: update PLAN.md §12 marking Phase 2 complete with a one-line
  deviations note, and update this file's checkboxes/status.
