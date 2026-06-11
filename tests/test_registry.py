"""Adapter registry (Phase 5 §3): future backends (Discord/YouTube/Mega/
Pastebin…) plug in with one module + one register_adapter call."""

import asyncio

import pytest

from scatterbox.errors import ScatterboxError
from scatterbox.providers import (
    ADAPTERS,
    AdapterSpec,
    LocalFSProvider,
    create_provider,
    known_types,
    requires_secrets,
)


@pytest.fixture
def toy_adapter(tmp_path):
    """Register a throwaway backend type for the duration of one test."""

    def factory(config, secrets):
        # a "new backend" that happens to be a localfs under the hood —
        # what matters is that the registry routed us here
        return LocalFSProvider(root=config["base"])

    ADAPTERS["toyfs"] = AdapterSpec(factory=factory)
    yield "toyfs"
    del ADAPTERS["toyfs"]


def test_registered_adapter_round_trips(toy_adapter, tmp_path):
    provider = create_provider("toyfs", {"base": str(tmp_path / "toy")})
    ref = asyncio.run(provider.put("abcd1234", b"opaque ciphertext"))
    assert asyncio.run(provider.get(ref)) == b"opaque ciphertext"
    assert "toyfs" in known_types()
    assert not requires_secrets("toyfs")


def test_register_adapter_rejects_duplicates():
    from scatterbox.providers import register_adapter

    with pytest.raises(ScatterboxError, match="already registered"):
        register_adapter("localfs", AdapterSpec(factory=lambda c, s: None))


def test_unknown_type_lists_known_types():
    with pytest.raises(ScatterboxError, match="known: .*gdrive.*localfs.*onedrive"):
        create_provider("dropbox", {})


def test_builtin_registry_shape():
    assert known_types() == ["gdrive", "localfs", "onedrive"]  # chaos hidden
    assert "chaos" in known_types(user_addable_only=False)
    assert requires_secrets("gdrive") and requires_secrets("onedrive")
    assert not requires_secrets("localfs")
    # OAuth-onboarded types expose their endpoints via the registry
    from scatterbox.onboarding import oauth_types

    assert set(oauth_types()) == {"gdrive", "onedrive"}
    assert oauth_types()["gdrive"].AUTH_URL.startswith("https://accounts.google.com")
