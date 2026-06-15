"""Provider onboarding/removal — shared by the CLI and the daemon's setup
wizard (PLAN.md §4: one code path; §6: user-driven onboarding).

The interactive parts stay with the caller (CLI prompts, web forms); what
lives here is the sequence that must be identical in both: credential flow →
secret into the vault → connection test → row into the register, with
rollback if anything fails after the secret was stored.

onboard_oauth_provider is synchronous on purpose: it drives the blocking
loopback browser flow and is called either directly from the CLI or via
asyncio.to_thread from the daemon.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from scatterbox import oauth
from scatterbox.errors import ScatterboxError
from scatterbox.providers import ADAPTERS, Quota, create_provider
from scatterbox.register import Register
from scatterbox.vault import Vault


def oauth_types() -> dict[str, object]:
    """type -> module with AUTH_URL/TOKEN_URL/SCOPES, from the adapter
    registry — a newly registered OAuth backend onboards with zero changes
    here."""
    return {
        type_: spec.oauth_module
        for type_, spec in ADAPTERS.items()
        if spec.oauth_module is not None
    }


def _ensure_name_free(register: Register, name: str) -> None:
    """Fail on a duplicate provider name BEFORE any credential flow runs."""
    try:
        register.get_provider_by_name(name)
    except ScatterboxError:
        return
    raise ScatterboxError(f"provider {name!r} already exists")


def _limits(max_object_bytes: int | None, capacity_bytes: int | None) -> dict:
    """The per-instance limit config keys, omitting unset ones."""
    config: dict = {}
    if max_object_bytes is not None:
        config["max_object_bytes"] = max_object_bytes
    if capacity_bytes is not None:
        config["capacity_bytes"] = capacity_bytes
    return config


def add_localfs_provider(
    register: Register,
    name: str,
    *,
    root: str | Path,
    max_object_bytes: int | None = None,
    capacity_bytes: int | None = None,
) -> dict:
    """Register a localfs provider; returns its config."""
    _ensure_name_free(register, name)
    config = {"root": str(Path(root).resolve()), **_limits(max_object_bytes, capacity_bytes)}
    create_provider("localfs", config)  # validates config, creates the root dir
    register.add_provider(name, "localfs", config)
    return config


def onboard_oauth_provider(
    register: Register,
    vault: Vault,
    name: str,
    type_: str,
    *,
    client_id: str,
    client_secret: str | None = None,
    max_object_bytes: int | None = None,
    capacity_bytes: int | None = None,
    open_browser: bool = True,
) -> Quota:
    """Full gdrive/onedrive onboarding: browser consent → tokens into the
    vault → connection test → register row. Returns the tested quota.

    Blocks until the user finishes (or abandons) the browser consent —
    callers in async contexts run this in a thread.
    """
    _ensure_name_free(register, name)
    blob = acquire_oauth_blob(
        type_,
        client_id=client_id,
        client_secret=client_secret,
        open_browser=open_browser,
    )
    return _store_test_register(
        register, vault, name, type_, blob,
        max_object_bytes=max_object_bytes, capacity_bytes=capacity_bytes,
    )


def onboard_secret_provider(
    register: Register,
    vault: Vault,
    name: str,
    type_: str,
    *,
    blob: dict,
    extra_config: dict | None = None,
    max_object_bytes: int | None = None,
    capacity_bytes: int | None = None,
) -> Quota:
    """Onboard a secret-requiring backend whose credential is NOT acquired
    through the OAuth loopback flow (Koofr's app password, an S3 access
    key/secret): the caller builds the credential blob with whatever prompt
    that backend needs, and this stores it → connection-tests → registers the
    row, with the same rollback as the OAuth path. Returns the tested quota.

    extra_config carries non-secret register config the adapter needs but does
    not discover at runtime (an S3 backend's account id / namespace / region /
    bucket / endpoint); it is merged into the register row, never the vault."""
    _ensure_name_free(register, name)
    return _store_test_register(
        register, vault, name, type_, blob, extra_config=extra_config,
        max_object_bytes=max_object_bytes, capacity_bytes=capacity_bytes,
    )


def _store_test_register(
    register: Register,
    vault: Vault,
    name: str,
    type_: str,
    blob: dict,
    *,
    extra_config: dict | None = None,
    max_object_bytes: int | None,
    capacity_bytes: int | None,
) -> Quota:
    """Shared onboarding tail: credential into the vault → live connection
    test → register row, rolling the secret back if anything fails after it
    was stored. Used by both the OAuth and app-password onboarding paths.
    extra_config (non-secret, e.g. an S3 bucket/account/namespace) is merged into
    the register row alongside the secret reference."""
    secret_name = f"provider:{name}"
    vault.set_secret(secret_name, blob)
    config = {
        "secret": secret_name,
        **(extra_config or {}),
        **_limits(max_object_bytes, capacity_bytes),
    }
    try:
        instance = create_provider(type_, config, vault)
        quota = asyncio.run(instance.quota())  # connection test
        if hasattr(instance, "prepare"):  # gdrive/pcloud/koofr: create scatterbox/ now
            asyncio.run(instance.prepare())
            config.update(instance.learned_config())
        register.add_provider(name, type_, config)
    except ScatterboxError:
        vault.delete_secret(secret_name)  # don't strand credentials for a failed add
        raise
    return quota


def acquire_oauth_blob(
    type_: str,
    *,
    client_id: str,
    client_secret: str | None = None,
    open_browser: bool = True,
) -> dict:
    """Run the browser consent flow for an OAuth backend type and return
    the token blob — without touching register or vault. Cold recovery uses
    this before any vault exists."""
    modules = oauth_types()
    if type_ not in modules:
        raise ScatterboxError(f"unknown OAuth provider type {type_!r}")
    mod = modules[type_]
    return oauth.run_loopback_flow(
        auth_url=mod.AUTH_URL,
        token_url=mod.TOKEN_URL,
        client_id=client_id,
        scopes=mod.SCOPES,
        client_secret=client_secret,
        extra_auth_params=getattr(mod, "EXTRA_AUTH_PARAMS", None),
        fixed_port=getattr(mod, "REDIRECT_PORT", None),
        open_browser=open_browser,
        # pCloud-class backends declare these; the others take the defaults
        # (refresh token required, single fixed token endpoint).
        require_refresh_token=getattr(mod, "REQUIRE_REFRESH_TOKEN", True),
        token_url_resolver=getattr(mod, "resolve_token_url", None),
    )


def reauth_provider(
    register: Register,
    vault: Vault,
    name: str,
    *,
    client_id: str | None = None,
    client_secret: str | None = None,
    open_browser: bool = True,
) -> Quota:
    """Re-run the OAuth consent for an EXISTING provider row and store the
    fresh tokens under its existing secret name — no register changes, no
    replica loss. The fix for expired/revoked tokens and for providers left
    credential-less by a recovery.

    Client app credentials are reused from the previous token blob when
    still present in the vault; otherwise the caller must supply them.
    Returns the post-reauth quota (the connection test).
    """
    row = register.get_provider_by_name(name)
    if row["type"] not in oauth_types():
        raise ScatterboxError(
            f"provider {name!r} ({row['type']}) does not use OAuth — nothing to reauth"
        )
    config = json.loads(row["config"])
    secret_name = config.get("secret") or f"provider:{name}"
    if client_id is None and vault.has_secret(secret_name):
        previous = vault.get_secret(secret_name)
        client_id = previous.get("client_id")
        client_secret = client_secret or previous.get("client_secret")
    if not client_id:
        raise ScatterboxError(
            "no previous client credentials to reuse — pass the OAuth client id"
        )
    blob = acquire_oauth_blob(
        row["type"],
        client_id=client_id,
        client_secret=client_secret,
        open_browser=open_browser,
    )
    vault.set_secret(secret_name, blob)
    instance = create_provider(row["type"], config, vault)
    return asyncio.run(instance.quota())  # connection test with the new tokens


def update_provider_secret(
    register: Register, vault: Vault, name: str, blob: dict
) -> Quota:
    """Replace the stored credential of an EXISTING secret-backed provider and
    connection-test it — the reauth path for non-OAuth backends (a Koofr app
    password that was revoked/regenerated, or one left missing by a cold
    recovery). Keeps the register row and every replica; returns the tested
    quota."""
    row = register.get_provider_by_name(name)
    config = json.loads(row["config"])
    secret_name = config.get("secret")
    if secret_name is None:
        raise ScatterboxError(f"provider {name!r} ({row['type']}) keeps no credentials")
    vault.set_secret(secret_name, blob)
    instance = create_provider(row["type"], config, vault)
    return asyncio.run(instance.quota())  # connection test with the new credential


def pending_reauth(register: Register, vault: Vault) -> list[str]:
    """Provider names whose credentials are missing from the vault — the
    post-recovery to-do list."""
    out = []
    for row in register.list_providers():
        secret_name = json.loads(row["config"]).get("secret")
        if secret_name is not None and not vault.has_secret(secret_name):
            out.append(row["name"])
    return out


def remove_provider(
    register: Register,
    name: str,
    *,
    vault: Vault | None = None,
    force: bool = False,
) -> int:
    """Remove a provider and its vault credentials; returns how many
    replica rows were dropped with it (0 unless force).

    Refuses while replicas still live there unless force — and the caller
    should then tell the user to run scrub --repair.
    """
    row = register.get_provider_by_name(name)
    count = register.replica_count_on_provider(row["id"])
    if count and not force:
        raise ScatterboxError(
            f"provider {name!r} still holds {count} replica(s); "
            "re-replicate first or force removal (then run a repair scrub "
            "to heal the affected files)"
        )
    secret_name = json.loads(row["config"]).get("secret")
    if secret_name is not None:
        if vault is None:
            raise ScatterboxError(
                f"removing {name!r} requires the unlocked vault (its "
                "credentials must be deleted too)"
            )
        vault.delete_secret(secret_name)
    register.delete_provider(row["id"])
    return count
