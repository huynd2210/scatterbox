"""Real-provider round-trips (TASKS.md Phase 2 §7) — OPT-IN, skipped by
default: the normal suite never touches the network.

To run, onboard a provider into a dedicated scatterbox home first:

    set SCATTERBOX_HOME=...   (a home with 'scatterbox init' done and the
                               provider added via 'scatterbox provider add')
    set SCATTERBOX_PASSPHRASE=...
    set SCATTERBOX_TEST_GDRIVE=gd      (the provider's registered name)
    set SCATTERBOX_TEST_ONEDRIVE=od
    set SCATTERBOX_TEST_DROPBOX=db
    set SCATTERBOX_TEST_PCLOUD=pc
    set SCATTERBOX_TEST_KOOFR=kf
    set SCATTERBOX_TEST_TIGRIS=tg
    uv run pytest tests/test_real_providers.py -v

Each test stores a small file pinned to that single provider (replicas=1),
restores it byte-identically, checks exists/scrub bookkeeping, and removes it.
"""

import asyncio
import os
from pathlib import Path

import pytest

from scatterbox import pipeline, scrubber, vault
from scatterbox.placement import Policy
from scatterbox.register import Register


def _home() -> Path:
    return Path(os.environ.get("SCATTERBOX_HOME", str(Path.home() / ".scatterbox")))


def _roundtrip(provider_name: str, tmp_path: Path) -> None:
    passphrase = os.environ.get("SCATTERBOX_PASSPHRASE")
    assert passphrase, "SCATTERBOX_PASSPHRASE must be set for real-provider tests"
    v = vault.unlock_vault(_home() / "vault.json", passphrase)
    register = Register(_home() / "register.db")
    vpath = "/scatterbox-selftest/roundtrip.bin"
    src = tmp_path / "src.bin"
    data = os.urandom(150_000)
    src.write_bytes(data)
    # exclude every other provider: durability-chasing extras must not leak
    # this test's chunks onto backends it isn't about
    others = frozenset(
        row["name"] for row in register.list_providers() if row["name"] != provider_name
    )
    try:
        asyncio.run(
            pipeline.put_file(
                register,
                v.master_key,
                src,
                vpath,
                policy=Policy(replicas=1, pinned=frozenset({provider_name}), excluded=others),
                secrets=v,
            )
        )
        dst = tmp_path / "dst.bin"
        asyncio.run(pipeline.get_file(register, v.master_key, vpath, dst, secrets=v))
        assert dst.read_bytes() == data

        report = asyncio.run(scrubber.scrub(register, secrets=v))
        assert report.probed >= 1 and report.marked_lost == 0
    finally:
        if register.get_file(vpath) is not None:
            asyncio.run(pipeline.remove_file(register, vpath, secrets=v))
        register.close()


@pytest.mark.skipif(
    not os.environ.get("SCATTERBOX_TEST_GDRIVE"),
    reason="set SCATTERBOX_TEST_GDRIVE=<provider name> to run against Google Drive",
)
def test_gdrive_real_roundtrip(tmp_path):
    _roundtrip(os.environ["SCATTERBOX_TEST_GDRIVE"], tmp_path)


@pytest.mark.skipif(
    not os.environ.get("SCATTERBOX_TEST_ONEDRIVE"),
    reason="set SCATTERBOX_TEST_ONEDRIVE=<provider name> to run against OneDrive",
)
def test_onedrive_real_roundtrip(tmp_path):
    _roundtrip(os.environ["SCATTERBOX_TEST_ONEDRIVE"], tmp_path)


@pytest.mark.skipif(
    not os.environ.get("SCATTERBOX_TEST_DROPBOX"),
    reason="set SCATTERBOX_TEST_DROPBOX=<provider name> to run against Dropbox",
)
def test_dropbox_real_roundtrip(tmp_path):
    _roundtrip(os.environ["SCATTERBOX_TEST_DROPBOX"], tmp_path)


@pytest.mark.skipif(
    not os.environ.get("SCATTERBOX_TEST_PCLOUD"),
    reason="set SCATTERBOX_TEST_PCLOUD=<provider name> to run against pCloud",
)
def test_pcloud_real_roundtrip(tmp_path):
    _roundtrip(os.environ["SCATTERBOX_TEST_PCLOUD"], tmp_path)


@pytest.mark.skipif(
    not os.environ.get("SCATTERBOX_TEST_KOOFR"),
    reason="set SCATTERBOX_TEST_KOOFR=<provider name> to run against Koofr",
)
def test_koofr_real_roundtrip(tmp_path):
    _roundtrip(os.environ["SCATTERBOX_TEST_KOOFR"], tmp_path)


@pytest.mark.skipif(
    not os.environ.get("SCATTERBOX_TEST_TIGRIS"),
    reason="set SCATTERBOX_TEST_TIGRIS=<provider name> to run against Tigris",
)
def test_tigris_real_roundtrip(tmp_path):
    _roundtrip(os.environ["SCATTERBOX_TEST_TIGRIS"], tmp_path)
