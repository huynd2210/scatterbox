"""Provider abstraction and adapter factory.

This package exposes the Provider interface plus the adapters that exist so
far. The register stores each provider instance as (type, JSON config);
create_provider turns such a row back into a live adapter object.

Real providers (gdrive, onedrive) keep their credentials in the vault, not
in the register config — so instantiating one needs an unlocked SecretStore.
requires_secrets() lets callers (the CLI) know whether the vault must be
unlocked before touching a given provider type.
"""

from __future__ import annotations

from scatterbox.errors import ScatterboxError
from scatterbox.providers.base import (
    Provider,
    ProviderProfile,
    Quota,
    RemoteRef,
    Transform,
)
from scatterbox.providers.chaos import ChaosProvider
from scatterbox.providers.gdrive import GDriveProvider
from scatterbox.providers.localfs import LocalFSProvider
from scatterbox.providers.onedrive import OneDriveProvider
from scatterbox.vault import SecretStore

__all__ = [
    "Provider",
    "ProviderProfile",
    "Quota",
    "RemoteRef",
    "Transform",
    "LocalFSProvider",
    "ChaosProvider",
    "GDriveProvider",
    "OneDriveProvider",
    "create_provider",
    "requires_secrets",
    "SECRET_TYPES",
]

# Provider types whose credentials live in the vault.
SECRET_TYPES = frozenset({"gdrive", "onedrive"})


def requires_secrets(type_: str) -> bool:
    return type_ in SECRET_TYPES


def create_provider(
    type_: str, config: dict, secrets: SecretStore | None = None
) -> Provider:
    """Instantiate a provider adapter from its register row (type + JSON
    config). Secret-requiring types additionally need the unlocked vault."""
    if type_ == "localfs":
        return LocalFSProvider(
            root=config["root"],
            max_object_bytes=config.get("max_object_bytes"),
            capacity_bytes=config.get("capacity_bytes"),
        )
    if type_ == "chaos":  # failure-injecting localfs wrapper, tests only
        inner = LocalFSProvider(
            root=config["root"],
            max_object_bytes=config.get("max_object_bytes"),
            capacity_bytes=config.get("capacity_bytes"),
        )
        return ChaosProvider(
            inner,
            seed=config.get("seed", 0),
            p_not_found=config.get("p_not_found", 0.0),
            p_corrupt=config.get("p_corrupt", 0.0),
            latency_s=config.get("latency_s", 0.0),
            # "killed" lives in the config so a hard-kill survives across
            # instantiations — every part of the system that re-creates the
            # provider from the register sees it dead.
            killed=config.get("killed", False),
            reliability_prior=config.get("reliability_prior"),
            latency_class=config.get("latency_class"),
        )
    if type_ in SECRET_TYPES:
        if secrets is None:
            raise ScatterboxError(
                f"provider type {type_!r} stores credentials in the vault — "
                "unlock it first (passphrase required)"
            )
        if type_ == "gdrive":
            return GDriveProvider(
                secrets=secrets,
                secret_name=config["secret"],
                folder_id=config.get("folder_id"),
                max_object_bytes=config.get("max_object_bytes"),
                capacity_bytes=config.get("capacity_bytes"),
            )
        return OneDriveProvider(
            secrets=secrets,
            secret_name=config["secret"],
            max_object_bytes=config.get("max_object_bytes"),
            capacity_bytes=config.get("capacity_bytes"),
        )
    raise ScatterboxError(f"unknown provider type: {type_!r}")
