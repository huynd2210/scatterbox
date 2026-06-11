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
from scatterbox.providers import Quota, create_provider, gdrive, onedrive
from scatterbox.register import Register
from scatterbox.vault import Vault

# OAuth endpoint/scope knowledge lives in the adapter modules.
OAUTH_MODULES = {"gdrive": gdrive, "onedrive": onedrive}


def _ensure_name_free(register: Register, name: str) -> None:
    try:
        register.get_provider_by_name(name)
    except ScatterboxError:
        return
    raise ScatterboxError(f"provider {name!r} already exists")


def _limits(max_object_bytes: int | None, capacity_bytes: int | None) -> dict:
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
    if type_ not in OAUTH_MODULES:
        raise ScatterboxError(f"unknown OAuth provider type {type_!r}")
    _ensure_name_free(register, name)
    mod = OAUTH_MODULES[type_]
    blob = oauth.run_loopback_flow(
        auth_url=mod.AUTH_URL,
        token_url=mod.TOKEN_URL,
        client_id=client_id,
        scopes=mod.SCOPES,
        client_secret=client_secret,
        extra_auth_params=getattr(mod, "EXTRA_AUTH_PARAMS", None),
        open_browser=open_browser,
    )
    secret_name = f"provider:{name}"
    vault.set_secret(secret_name, blob)
    config = {"secret": secret_name, **_limits(max_object_bytes, capacity_bytes)}
    try:
        instance = create_provider(type_, config, vault)
        quota = asyncio.run(instance.quota())  # connection test
        if type_ == "gdrive":
            asyncio.run(instance.prepare())  # create the scatterbox/ folder now
            config.update(instance.learned_config())
        register.add_provider(name, type_, config)
    except ScatterboxError:
        vault.delete_secret(secret_name)  # don't strand tokens for a failed add
        raise
    return quota


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
