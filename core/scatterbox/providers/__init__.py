"""Provider abstraction and adapter factory.

This package exposes the Provider interface plus the adapters that exist so
far. The register stores each provider instance as (type, JSON config);
create_provider turns such a row back into a live adapter object. Phase 2
adds real types here ("gdrive", "onedrive", ...).
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
from scatterbox.providers.localfs import LocalFSProvider

__all__ = [
    "Provider",
    "ProviderProfile",
    "Quota",
    "RemoteRef",
    "Transform",
    "LocalFSProvider",
    "ChaosProvider",
    "create_provider",
]


def create_provider(type_: str, config: dict) -> Provider:
    """Instantiate a provider adapter from its register row (type + JSON config)."""
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
    raise ScatterboxError(f"unknown provider type: {type_!r}")
