"""Provider abstraction and adapter registry.

The register stores each provider instance as (type, JSON config);
create_provider turns such a row back into a live adapter object via the
ADAPTERS registry. Adding a backend (Discord, YouTube-class, Mega,
Pastebin, …) means writing one module that implements the Provider
protocol (start from providers/_template.py) and registering it here with
register_adapter() — the factory, the CLI, the daemon's onboarding, and
the vault plumbing all read from the same registry.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from types import ModuleType

from scatterbox.errors import ScatterboxError
from scatterbox.providers.base import (
    Provider,
    ProviderProfile,
    Quota,
    RemoteRef,
    Transform,
)
from scatterbox.providers.chaos import ChaosProvider
from scatterbox.providers.dropbox import DropboxProvider
from scatterbox.providers.gdrive import GDriveProvider
from scatterbox.providers.koofr import KoofrProvider
from scatterbox.providers.localfs import LocalFSProvider
from scatterbox.providers.onedrive import OneDriveProvider
from scatterbox.providers.oracle import OracleProvider
from scatterbox.providers.pcloud import PCloudProvider
from scatterbox.providers.r2 import R2Provider
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
    "DropboxProvider",
    "PCloudProvider",
    "KoofrProvider",
    "R2Provider",
    "OracleProvider",
    "AdapterSpec",
    "ADAPTERS",
    "register_adapter",
    "create_provider",
    "requires_secrets",
    "known_types",
]


@dataclass(frozen=True)
class AdapterSpec:
    """Everything the rest of the system needs to know about one backend
    type, in one place."""

    # (config, secrets) -> live adapter. secrets is the unlocked vault, or
    # None for credential-free types.
    factory: Callable[[dict, SecretStore | None], Provider]
    # Credentials live in the vault -> instantiating needs it unlocked, and
    # onboarding must store secrets there.
    requires_secrets: bool = False
    # Module exposing AUTH_URL / TOKEN_URL / SCOPES (and optionally
    # EXTRA_AUTH_PARAMS) — set for backends onboarded via the OAuth
    # loopback flow; None for token/path/webhook-configured ones.
    oauth_module: ModuleType | None = None
    # Shown by CLI/daemon when listing what can be added; tests-only types
    # (chaos) keep it False.
    user_addable: bool = True


# The factories below turn a register row's JSON config into a live
# adapter — the only place config keys are interpreted per type.
def _localfs_factory(config: dict, secrets: SecretStore | None) -> Provider:
    return LocalFSProvider(
        root=config["root"],
        max_object_bytes=config.get("max_object_bytes"),
        capacity_bytes=config.get("capacity_bytes"),
    )


def _chaos_factory(config: dict, secrets: SecretStore | None) -> Provider:
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


def _gdrive_factory(config: dict, secrets: SecretStore | None) -> Provider:
    return GDriveProvider(
        secrets=secrets,
        secret_name=config["secret"],
        folder_id=config.get("folder_id"),
        max_object_bytes=config.get("max_object_bytes"),
        capacity_bytes=config.get("capacity_bytes"),
    )


def _onedrive_factory(config: dict, secrets: SecretStore | None) -> Provider:
    return OneDriveProvider(
        secrets=secrets,
        secret_name=config["secret"],
        max_object_bytes=config.get("max_object_bytes"),
        capacity_bytes=config.get("capacity_bytes"),
    )


def _dropbox_factory(config: dict, secrets: SecretStore | None) -> Provider:
    return DropboxProvider(
        secrets=secrets,
        secret_name=config["secret"],
        max_object_bytes=config.get("max_object_bytes"),
        capacity_bytes=config.get("capacity_bytes"),
    )


def _pcloud_factory(config: dict, secrets: SecretStore | None) -> Provider:
    return PCloudProvider(
        secrets=secrets,
        secret_name=config["secret"],
        folder_id=config.get("folder_id"),
        api_base=config.get("api_base"),
        max_object_bytes=config.get("max_object_bytes"),
        capacity_bytes=config.get("capacity_bytes"),
    )


def _koofr_factory(config: dict, secrets: SecretStore | None) -> Provider:
    return KoofrProvider(
        secrets=secrets,
        secret_name=config["secret"],
        mount_id=config.get("mount_id"),
        base_url=config.get("base_url"),
        max_object_bytes=config.get("max_object_bytes"),
        capacity_bytes=config.get("capacity_bytes"),
    )


def _r2_factory(config: dict, secrets: SecretStore | None) -> Provider:
    return R2Provider(
        secrets=secrets,
        secret_name=config["secret"],
        account_id=config["account_id"],
        bucket=config["bucket"],
        endpoint=config.get("endpoint"),
        max_object_bytes=config.get("max_object_bytes"),
        capacity_bytes=config.get("capacity_bytes"),
    )


def _oracle_factory(config: dict, secrets: SecretStore | None) -> Provider:
    return OracleProvider(
        secrets=secrets,
        secret_name=config["secret"],
        namespace=config["namespace"],
        region=config["region"],
        bucket=config["bucket"],
        endpoint=config.get("endpoint"),
        max_object_bytes=config.get("max_object_bytes"),
        capacity_bytes=config.get("capacity_bytes"),
    )


def _oauth_module(name: str) -> ModuleType:
    # local import keeps module load order simple (gdrive/onedrive import
    # from this package's submodules, not from this __init__)
    from scatterbox.providers import dropbox as dropbox_mod
    from scatterbox.providers import gdrive as gdrive_mod
    from scatterbox.providers import onedrive as onedrive_mod
    from scatterbox.providers import pcloud as pcloud_mod

    return {
        "gdrive": gdrive_mod,
        "onedrive": onedrive_mod,
        "dropbox": dropbox_mod,
        "pcloud": pcloud_mod,
    }[name]


ADAPTERS: dict[str, AdapterSpec] = {
    "localfs": AdapterSpec(factory=_localfs_factory),
    "chaos": AdapterSpec(factory=_chaos_factory, user_addable=False),  # tests only
    "gdrive": AdapterSpec(
        factory=_gdrive_factory,
        requires_secrets=True,
        oauth_module=_oauth_module("gdrive"),
    ),
    "onedrive": AdapterSpec(
        factory=_onedrive_factory,
        requires_secrets=True,
        oauth_module=_oauth_module("onedrive"),
    ),
    "dropbox": AdapterSpec(
        factory=_dropbox_factory,
        requires_secrets=True,
        oauth_module=_oauth_module("dropbox"),
    ),
    "pcloud": AdapterSpec(
        factory=_pcloud_factory,
        requires_secrets=True,
        oauth_module=_oauth_module("pcloud"),
    ),
    # Koofr keeps credentials in the vault (an app password) but is NOT an
    # OAuth backend — no oauth_module, so it onboards via the app-password
    # prompt path, not the loopback consent flow.
    "koofr": AdapterSpec(
        factory=_koofr_factory,
        requires_secrets=True,
    ),
    # Cloudflare R2 keeps an S3 access-key/secret pair in the vault and is NOT
    # OAuth — no oauth_module, so it onboards via the S3-credential prompt path.
    # The non-secret account id + bucket live in the register config.
    "r2": AdapterSpec(
        factory=_r2_factory,
        requires_secrets=True,
    ),
    # Oracle Cloud Object Storage (S3 Compatibility API) keeps an S3 access-key/
    # secret pair in the vault and is NOT OAuth — no oauth_module, so it onboards
    # via the S3-credential prompt path. The non-secret namespace, region, and
    # bucket live in the register config.
    "oracle": AdapterSpec(
        factory=_oracle_factory,
        requires_secrets=True,
    ),
    # Future backends slot in here (see providers/_template.py):
    #   "discord":  small max_object_bytes (~10 MB), reliability_prior 0.5,
    #               exposure_risk high, token-configured
    #   "youtube":  Transform-stage adapter (bytes -> video), glacial
    #   "mega" / "pastebin" / ...: register_adapter("mega", AdapterSpec(...))
}


def register_adapter(type_: str, spec: AdapterSpec) -> None:
    """Plug in a new backend type (also handy for tests)."""
    if type_ in ADAPTERS:
        raise ScatterboxError(f"adapter type {type_!r} is already registered")
    ADAPTERS[type_] = spec


def known_types(*, user_addable_only: bool = True) -> list[str]:
    return sorted(
        t for t, spec in ADAPTERS.items() if spec.user_addable or not user_addable_only
    )


def requires_secrets(type_: str) -> bool:
    spec = ADAPTERS.get(type_)
    return spec.requires_secrets if spec else False


def create_provider(
    type_: str, config: dict, secrets: SecretStore | None = None
) -> Provider:
    """Instantiate a provider adapter from its register row (type + JSON
    config). Secret-requiring types additionally need the unlocked vault."""
    spec = ADAPTERS.get(type_)
    if spec is None:
        raise ScatterboxError(
            f"unknown provider type: {type_!r} (known: {', '.join(known_types())})"
        )
    if spec.requires_secrets and secrets is None:
        raise ScatterboxError(
            f"provider type {type_!r} stores credentials in the vault — "
            "unlock it first (passphrase required)"
        )
    return spec.factory(config, secrets)
