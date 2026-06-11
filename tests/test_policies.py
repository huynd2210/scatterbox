"""Per-folder policies (Phase 5, PLAN.md §7): nearest ancestor wins,
explicit arguments beat it field by field, and every entry point — library,
CLI, daemon upload — resolves the same way."""

import os

import pytest
from typer.testing import CliRunner

from conftest import add_localfs_providers, put
from scatterbox import pipeline
from scatterbox.placement import Policy, merge_policy, policy_from_dict, policy_to_dict


def test_policy_dict_roundtrip():
    policy = Policy(
        replicas=4,
        min_spread=2,
        spread_mode="packed",
        scheme="ec",
        ec_k=2,
        ec_n=4,
        pinned=frozenset({"a"}),
        excluded=frozenset({"b"}),
    )
    assert policy_from_dict(policy_to_dict(policy)) == policy
    # defaults serialize to an empty dict (future default changes apply)
    assert policy_to_dict(Policy()) == {}
    assert policy_from_dict({}) == Policy()


def test_nearest_ancestor_wins(register):
    register.set_folder_policy("/", policy_to_dict(Policy(replicas=2)))
    register.set_folder_policy("/docs", policy_to_dict(Policy(replicas=4)))
    register.set_folder_policy("/docs/cold", policy_to_dict(Policy(scheme="ec")))

    assert pipeline.resolve_policy(register, "/other/x.bin").replicas == 2
    assert pipeline.resolve_policy(register, "/docs/x.bin").replicas == 4
    assert pipeline.resolve_policy(register, "/docs/colder/x.bin").replicas == 4
    assert pipeline.resolve_policy(register, "/docs/cold/x.bin").scheme == "ec"
    # exact-prefix trap: /docsx is NOT under /docs
    assert pipeline.resolve_policy(register, "/docsx/y.bin").replicas == 2

    register.delete_folder_policy("/docs")
    assert pipeline.resolve_policy(register, "/docs/x.bin").replicas == 2


def test_explicit_overrides_beat_folder_policy():
    base = Policy(replicas=4, scheme="ec")
    merged = merge_policy(base, replicas=2, scheme=None)
    assert merged.replicas == 2 and merged.scheme == "ec"


def test_put_inherits_folder_policy(register, tmp_path):
    add_localfs_providers(register, tmp_path, 5)
    register.set_folder_policy(
        "/archive", policy_to_dict(Policy(scheme="ec", ec_k=3, ec_n=5))
    )
    register.set_folder_policy("/hot", policy_to_dict(Policy(replicas=2)))

    src = tmp_path / "f.bin"
    src.write_bytes(os.urandom(50_000))

    result = put(register, src, "/archive/f.bin")  # no policy passed
    assert result.scheme == "ec" and result.replicas == 5

    result = put(register, src, "/hot/f.bin")
    assert result.scheme == "replica" and result.replicas == 2

    # per-call override still wins
    result = put(register, src, "/hot/g.bin", replicas=3)
    assert result.replicas == 3


def test_cli_policy_commands(tmp_path, monkeypatch):
    from scatterbox_cli.main import app

    runner = CliRunner()
    monkeypatch.setenv("SCATTERBOX_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("SCATTERBOX_PASSPHRASE", "pw")
    assert runner.invoke(app, ["init"]).exit_code == 0
    for i in range(5):
        assert (
            runner.invoke(
                app, ["provider", "add", f"p{i}", "--root", str(tmp_path / f"p{i}")]
            ).exit_code
            == 0
        )

    result = runner.invoke(
        app, ["policy", "set", "/cold", "--scheme", "ec", "--ec-k", "3", "--ec-n", "5"]
    )
    assert result.exit_code == 0 and "ec(3,5)" in result.output
    assert runner.invoke(app, ["policy", "set", "/x"]).exit_code == 1  # nothing to set
    assert (
        runner.invoke(app, ["policy", "set", "/x", "--scheme", "ec", "--ec-k", "5", "--ec-n", "3"]).exit_code
        == 1
    )  # invalid params

    result = runner.invoke(app, ["policy", "show", "/cold/deep/file.bin"])
    assert "ec(3,5)" in result.output and "from /cold" in result.output
    result = runner.invoke(app, ["policy", "list"])
    assert "/cold" in result.output

    # an upload under /cold inherits EC without flags
    src = tmp_path / "f.bin"
    src.write_bytes(os.urandom(20_000))
    result = runner.invoke(app, ["put", str(src), "/cold/"])
    assert result.exit_code == 0, result.output
    assert "ec(3,5) shares" in result.output
    result = runner.invoke(app, ["status", "/cold/f.bin"])
    assert "ec(3,5)" in result.output and "healthy" in result.output

    assert runner.invoke(app, ["policy", "unset", "/cold"]).exit_code == 0
    assert runner.invoke(app, ["policy", "unset", "/cold"]).exit_code == 1
    result = runner.invoke(app, ["policy", "show", "/cold"])
    assert "defaults" in result.output


def test_daemon_policy_endpoints_and_inherit(tmp_path):
    from fastapi.testclient import TestClient

    from scatterbox import vault
    from scatterbox.register import Register
    from scatterbox_daemon import create_app

    home = tmp_path / "home"
    home.mkdir()
    reg = Register(home / "register.db")
    for i in range(5):
        reg.add_provider(f"p{i}", "localfs", {"root": str(tmp_path / f"prov{i}")})
    reg.close()
    vault.create_vault(home / "vault.json", "pw", time_cost=1, memory_cost=8 * 1024, parallelism=1)

    with TestClient(create_app(home)) as client:
        assert client.post("/api/unlock", json={"passphrase": "pw"}).status_code == 200

        resp = client.put(
            "/api/policy", json={"path": "/cold", "scheme": "ec", "ec_k": 3, "ec_n": 5}
        )
        assert resp.status_code == 200, resp.text
        # invalid combinations are clean 400s
        assert (
            client.put("/api/policy", json={"path": "/x", "scheme": "ec", "ec_k": 9, "ec_n": 3}).status_code
            == 400
        )

        eff = client.get("/api/policy", params={"path": "/cold/sub/file.bin"}).json()
        assert eff["effective"]["scheme"] == "ec" and eff["source"] == "/cold"
        assert eff["explicit"] is None  # asked about a sub-path, not /cold itself
        assert client.get("/api/policies").json() == [
            {"path": "/cold", "policy": {"scheme": "ec"}}
        ]

        # upload with no options inherits the folder's EC policy
        import time as time_mod

        resp = client.post(
            "/api/upload",
            files={"file": ("f.bin", os.urandom(30_000))},
            data={"path": "/cold/"},
        )
        assert resp.status_code == 200
        job_id = resp.json()["job_id"]
        deadline = time_mod.time() + 15
        while time_mod.time() < deadline:
            job = next(j for j in client.get("/api/jobs").json() if j["id"] == job_id)
            if job["state"] in ("done", "failed"):
                break
            time_mod.sleep(0.05)
        assert job["state"] == "done", job
        assert job["result"]["scheme"] == "ec"

        detail = client.get("/api/file", params={"path": "/cold/f.bin"}).json()
        assert detail["scheme"] == "ec" and detail["ec_k"] == 3
        assert detail["replica_target"] == 5 and detail["health"] == "healthy"

        assert client.delete("/api/policy", params={"path": "/cold"}).status_code == 200
        assert client.delete("/api/policy", params={"path": "/cold"}).status_code == 404
