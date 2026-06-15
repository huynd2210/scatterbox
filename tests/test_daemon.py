"""Daemon API tests (TASKS.md Phase 3 §2) — including two phase gates:
uploads never block (job-based, returns pre-I/O) and health badges reflect
injected failures within one scrub cycle."""

import json
import time

import pytest
from fastapi.testclient import TestClient

from scatterbox import vault
from scatterbox.register import Register
from scatterbox_daemon import create_app

PASS = "correct horse battery staple"


@pytest.fixture
def home(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    reg = Register(home / "register.db")
    for i in range(3):
        reg.add_provider(f"p{i}", "localfs", {"root": str(tmp_path / f"prov{i}")})
    reg.close()
    # cheap KDF so unlock doesn't dominate the test suite
    vault.create_vault(
        home / "vault.json", PASS, time_cost=1, memory_cost=8 * 1024, parallelism=1
    )
    return home


@pytest.fixture
def client(home):
    with TestClient(create_app(home)) as c:
        yield c


def unlock(client):
    resp = client.post("/api/unlock", json={"passphrase": PASS})
    assert resp.status_code == 200


def wait_job(client, job_id, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        job = next(j for j in client.get("/api/jobs").json() if j["id"] == job_id)
        if job["state"] in ("done", "failed"):
            return job
        time.sleep(0.05)
    raise AssertionError(f"job {job_id} did not finish")


def test_lock_unlock_flow(client):
    assert client.get("/api/status").json()["locked"] is True
    assert client.post("/api/unlock", json={"passphrase": "wrong"}).status_code == 401
    unlock(client)
    assert client.get("/api/status").json()["locked"] is False
    client.post("/api/lock")
    assert client.get("/api/status").json()["locked"] is True


def test_upload_requires_unlock(client):
    resp = client.post(
        "/api/upload", files={"file": ("a.bin", b"data")}, data={"path": "/"}
    )
    assert resp.status_code == 423


def test_upload_download_roundtrip(client):
    unlock(client)
    data = b"the quick brown fox" * 5000
    resp = client.post(
        "/api/upload", files={"file": ("fox.bin", data)}, data={"path": "/docs/"}
    )
    assert resp.status_code == 200
    job = wait_job(client, resp.json()["job_id"])
    assert job["state"] == "done", job
    assert job["result"]["vpath"] == "/docs/fox.bin"

    listing = client.get("/api/files", params={"path": "/docs"}).json()
    assert [f["name"] for f in listing["files"]] == ["fox.bin"]

    dl = client.get("/api/download", params={"path": "/docs/fox.bin"})
    assert dl.status_code == 200
    assert dl.content == data

    # duplicate upload is rejected up front, not at job time
    resp = client.post(
        "/api/upload", files={"file": ("fox.bin", b"x")}, data={"path": "/docs/"}
    )
    assert resp.status_code == 409


def test_upload_returns_before_provider_io(home, tmp_path):
    """Phase gate: the upload request must not wait for providers. Providers
    here sleep 1 s per operation; the endpoint must return well before that."""
    reg = Register(home / "register.db")
    for row in reg.list_providers():
        config = json.loads(row["config"])
        reg.update_provider_config(row["id"], {**config, "latency_s": 1.0})
        reg.conn.execute("UPDATE providers SET type = 'chaos' WHERE id = ?", (row["id"],))
        reg.conn.commit()
    reg.close()
    with TestClient(create_app(home)) as client:
        unlock(client)
        start = time.perf_counter()
        resp = client.post(
            "/api/upload", files={"file": ("slow.bin", b"y" * 100_000)}, data={"path": "/"}
        )
        elapsed = time.perf_counter() - start
        assert resp.status_code == 200
        assert elapsed < 0.9, f"upload endpoint blocked for {elapsed:.2f}s"
        job = wait_job(client, resp.json()["job_id"])
        assert job["state"] == "done"


def test_move_and_delete(client):
    unlock(client)
    resp = client.post(
        "/api/upload", files={"file": ("a.bin", b"abc" * 1000)}, data={"path": "/"}
    )
    wait_job(client, resp.json()["job_id"])

    assert client.post("/api/move", json={"src": "/a.bin", "dst": "/b.bin"}).status_code == 200
    names = [f["name"] for f in client.get("/api/files", params={"path": "/"}).json()["files"]]
    assert names == ["b.bin"]

    resp = client.delete("/api/file", params={"path": "/b.bin"})
    assert resp.status_code == 200
    job = wait_job(client, resp.json()["job_id"])
    assert job["state"] == "done"
    assert client.get("/api/files", params={"path": "/"}).json()["files"] == []
    assert client.delete("/api/file", params={"path": "/b.bin"}).status_code == 404


def test_file_detail_shows_providers_and_health(client):
    unlock(client)
    resp = client.post(
        "/api/upload", files={"file": ("d.bin", b"detail" * 2000)}, data={"path": "/"}
    )
    wait_job(client, resp.json()["job_id"])
    detail = client.get("/api/file", params={"path": "/d.bin"}).json()
    assert detail["health"] == "healthy"
    assert detail["min_live"] == 3 and detail["replica_target"] == 3
    assert len(detail["providers"]) == 3
    assert all(p["states"].get("stored", 0) >= 1 for p in detail["providers"])


def test_health_flips_within_one_scrub_cycle(home, tmp_path):
    """Phase gate: injected failure -> badge change after a single scrub."""
    with TestClient(create_app(home)) as client:
        unlock(client)
        resp = client.post(
            "/api/upload", files={"file": ("h.bin", b"health" * 3000)}, data={"path": "/"}
        )
        assert wait_job(client, resp.json()["job_id"])["state"] == "done"
        health = client.post("/api/health", json={"paths": ["/h.bin"]}).json()
        assert health["/h.bin"]["health"] == "healthy"

    # hard-kill one provider (config-level, like a dead account)
    reg = Register(home / "register.db")
    row = reg.list_providers()[0]
    config = json.loads(row["config"])
    reg.update_provider_config(row["id"], {**config, "killed": True})
    reg.conn.execute("UPDATE providers SET type = 'chaos' WHERE id = ?", (row["id"],))
    reg.conn.commit()
    reg.close()

    with TestClient(create_app(home)) as client:
        unlock(client)
        job_id = client.post("/api/scrub", json={}).json()["job_id"]
        report = wait_job(client, job_id)
        assert report["state"] == "done"
        assert report["result"]["marked_suspect"] >= 1
        health = client.post("/api/health", json={"paths": ["/h.bin"]}).json()
        assert health["/h.bin"]["health"] == "degraded"
        assert health["/h.bin"]["min_live"] == 2


def test_websocket_streams_job_lifecycle(client):
    unlock(client)
    with client.websocket_connect("/ws") as ws:
        resp = client.post(
            "/api/upload", files={"file": ("w.bin", b"ws" * 5000)}, data={"path": "/"}
        )
        job_id = resp.json()["job_id"]
        states = []
        deadline = time.time() + 15
        while time.time() < deadline:
            msg = ws.receive_json()
            if msg.get("type") == "job" and msg.get("id") == job_id:
                states.append(msg["state"])
                if msg["state"] in ("done", "failed"):
                    break
        assert states[0] == "running" and states[-1] == "done"


def test_providers_endpoint_reports_quota_confidence(client):
    providers = client.get("/api/providers").json()
    assert len(providers) == 3
    for p in providers:
        assert p["quota"]["confidence"] == "unknown"  # localfs without cap
        assert p["reliability"] == pytest.approx(0.99)
        assert p["error"] is None


def test_web_first_run_setup(tmp_path, monkeypatch):
    """The whole CLI-free path: empty home -> /api/init -> providers via
    API -> upload round-trip. (TASKS/PLAN: setup wizard, 2 setup paths.)"""
    home = tmp_path / "fresh"
    home.mkdir()
    with TestClient(create_app(home)) as client:
        status = client.get("/api/status").json()
        assert status["initialized"] is False and status["locked"] is True

        # empty passphrase rejected; then init unlocks immediately
        assert client.post("/api/init", json={"passphrase": ""}).status_code == 400
        assert client.post("/api/init", json={"passphrase": PASS}).status_code == 200
        status = client.get("/api/status").json()
        assert status["initialized"] is True and status["locked"] is False
        # second init refused — it would orphan everything already encrypted
        assert client.post("/api/init", json={"passphrase": "x"}).status_code == 409

        for i in range(3):
            resp = client.post(
                "/api/providers",
                json={"name": f"p{i}", "type": "localfs", "root": str(tmp_path / f"prov{i}")},
            )
            assert resp.status_code == 200, resp.text
        # duplicate name and missing root are clean 400s
        assert (
            client.post(
                "/api/providers",
                json={"name": "p0", "type": "localfs", "root": str(tmp_path / "x")},
            ).status_code
            == 400
        )
        assert (
            client.post("/api/providers", json={"name": "q", "type": "localfs"}).status_code
            == 400
        )

        data = b"wizard" * 4000
        resp = client.post(
            "/api/upload", files={"file": ("w.bin", data)}, data={"path": "/"}
        )
        assert wait_job(client, resp.json()["job_id"])["state"] == "done"
        assert client.get("/api/download", params={"path": "/w.bin"}).content == data

        # remove: guarded while replicas live there, force drops + reports
        assert client.delete("/api/providers/p0").status_code == 409
        resp = client.delete("/api/providers/p0", params={"force": True})
        assert resp.status_code == 200
        assert resp.json()["replicas_dropped"] >= 1
        assert len(client.get("/api/providers").json()) == 2

    # the CLI sees the web-initialized home as a normal one (two paths, one
    # result): its init refuses, its commands work against the same vault
    monkeypatch.setenv("SCATTERBOX_HOME", str(home))
    monkeypatch.setenv("SCATTERBOX_PASSPHRASE", PASS)
    from typer.testing import CliRunner

    from scatterbox_cli.main import app as cli_app

    runner = CliRunner()
    assert runner.invoke(cli_app, ["init"]).exit_code == 1
    listing = runner.invoke(cli_app, ["ls", "/"])
    assert listing.exit_code == 0 and "w.bin" in listing.output


def test_oauth_provider_add_via_api(client, monkeypatch):
    """The endpoint threads the shared onboarding flow; OAuth itself is
    covered by test_oauth/test_provider_onboarding."""
    from scatterbox import onboarding

    calls = {}

    def fake_onboard(register, v, name, type_, **kwargs):
        calls.update({"name": name, "type": type_, **kwargs})
        register.add_provider(name, type_, {"secret": f"provider:{name}"})

    monkeypatch.setattr(onboarding, "onboard_oauth_provider", fake_onboard)
    # locked: refused before any browser opens
    resp = client.post(
        "/api/providers", json={"name": "gd", "type": "gdrive", "client_id": "cid"}
    )
    assert resp.status_code == 423 and calls == {}

    unlock(client)
    resp = client.post(
        "/api/providers",
        json={"name": "gd", "type": "gdrive", "client_id": "cid", "client_secret": "shh"},
    )
    assert resp.status_code == 200, resp.text
    assert calls["name"] == "gd" and calls["client_id"] == "cid"
    assert calls["client_secret"] == "shh"
    assert any(p["name"] == "gd" for p in client.get("/api/providers").json())


def test_koofr_provider_add_via_api(client, monkeypatch):
    """Koofr is secret-backed but not OAuth: the endpoint takes an email +
    app password, hands the shared flow a Basic credential blob, no browser."""
    import base64

    from scatterbox import onboarding

    calls = {}

    def fake_onboard(register, v, name, type_, **kwargs):
        calls.update({"name": name, "type": type_, **kwargs})
        register.add_provider(name, type_, {"secret": f"provider:{name}"})

    monkeypatch.setattr(onboarding, "onboard_secret_provider", fake_onboard)
    # locked: refused before any credential is used
    resp = client.post(
        "/api/providers",
        json={"name": "kf", "type": "koofr", "email": "a@k.test", "app_password": "pw"},
    )
    assert resp.status_code == 423 and calls == {}

    unlock(client)
    # missing app password is rejected up front
    assert (
        client.post("/api/providers", json={"name": "kf", "type": "koofr", "email": "a@k.test"}).status_code
        == 400
    )

    resp = client.post(
        "/api/providers",
        json={"name": "kf", "type": "koofr", "email": "a@k.test", "app_password": "pw"},
    )
    assert resp.status_code == 200, resp.text
    assert calls["name"] == "kf" and calls["type"] == "koofr"
    # the app password reached the flow as a precomputed Basic credential
    assert base64.b64decode(calls["blob"]["access_token"]).decode() == "a@k.test:pw"
    assert any(p["name"] == "kf" for p in client.get("/api/providers").json())


def test_r2_provider_add_via_api(client, monkeypatch):
    """Cloudflare R2 is secret-backed but not OAuth: the endpoint takes an S3
    access key/secret plus the (non-secret) account id + bucket, and hands the
    shared flow the key blob and bucket extra_config, no browser."""
    from scatterbox import onboarding

    calls = {}

    def fake_onboard(register, v, name, type_, **kwargs):
        calls.update({"name": name, "type": type_, **kwargs})
        register.add_provider(name, type_, {"secret": f"provider:{name}"})

    monkeypatch.setattr(onboarding, "onboard_secret_provider", fake_onboard)
    full = {
        "name": "r2",
        "type": "r2",
        "account_id": "acct",
        "bucket": "buck",
        "access_key_id": "AKID",
        "secret_access_key": "SEC",
    }
    # locked: refused before any credential is used
    assert client.post("/api/providers", json=full).status_code == 423 and calls == {}

    unlock(client)
    # missing keys rejected up front (account/bucket present, no key/secret)
    assert (
        client.post(
            "/api/providers", json={"name": "r2", "type": "r2", "account_id": "acct", "bucket": "buck"}
        ).status_code
        == 400
    )

    resp = client.post("/api/providers", json=full)
    assert resp.status_code == 200, resp.text
    assert calls["name"] == "r2" and calls["type"] == "r2"
    # key/secret reached the flow as the vault blob; account/bucket as register config
    assert calls["blob"] == {"access_key_id": "AKID", "secret_access_key": "SEC"}
    assert calls["extra_config"] == {"account_id": "acct", "bucket": "buck"}
    assert any(p["name"] == "r2" for p in client.get("/api/providers").json())


def test_oracle_provider_add_via_api(client, monkeypatch):
    """Oracle Object Storage is secret-backed but not OAuth: the endpoint takes
    an S3 access key/secret plus the (non-secret) namespace/region/bucket, and
    hands the shared flow the key blob and bucket extra_config, no browser."""
    from scatterbox import onboarding

    calls = {}

    def fake_onboard(register, v, name, type_, **kwargs):
        calls.update({"name": name, "type": type_, **kwargs})
        register.add_provider(name, type_, {"secret": f"provider:{name}"})

    monkeypatch.setattr(onboarding, "onboard_secret_provider", fake_onboard)
    full = {
        "name": "or",
        "type": "oracle",
        "namespace": "myns",
        "region": "us-ashburn-1",
        "bucket": "buck",
        "access_key_id": "AKID",
        "secret_access_key": "SEC",
    }
    # locked: refused before any credential is used
    assert client.post("/api/providers", json=full).status_code == 423 and calls == {}

    unlock(client)
    # missing keys rejected up front (location present, no key/secret)
    assert (
        client.post(
            "/api/providers",
            json={"name": "or", "type": "oracle", "namespace": "myns", "region": "us-ashburn-1", "bucket": "buck"},
        ).status_code
        == 400
    )

    resp = client.post("/api/providers", json=full)
    assert resp.status_code == 200, resp.text
    assert calls["name"] == "or" and calls["type"] == "oracle"
    assert calls["blob"] == {"access_key_id": "AKID", "secret_access_key": "SEC"}
    assert calls["extra_config"] == {
        "namespace": "myns",
        "region": "us-ashburn-1",
        "bucket": "buck",
    }
    assert any(p["name"] == "or" for p in client.get("/api/providers").json())


def test_export_zip_and_import_on_fresh_home(client, home, tmp_path):
    """Phase 4 via the API: export one zip, import it into a clean home,
    download byte-identical."""
    assert client.get("/api/export").status_code == 423  # locked: no key, no zip
    unlock(client)
    data = b"take me with you" * 3000
    resp = client.post(
        "/api/upload", files={"file": ("keep.bin", data)}, data={"path": "/docs/"}
    )
    assert wait_job(client, resp.json()["job_id"])["state"] == "done"

    resp = client.get("/api/export")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/zip"
    backup = resp.content

    home_b = tmp_path / "home_b"
    home_b.mkdir()
    with TestClient(create_app(home_b)) as client_b:
        assert client_b.get("/api/status").json()["initialized"] is False
        # wrong passphrase is a clean 401, home stays uninitialized
        resp = client_b.post(
            "/api/import",
            files={"files": ("backup.zip", backup)},
            data={"passphrase": "wrong"},
        )
        assert resp.status_code == 401
        assert client_b.get("/api/status").json()["initialized"] is False

        resp = client_b.post(
            "/api/import",
            files={"files": ("backup.zip", backup)},
            data={"passphrase": PASS},
        )
        assert resp.status_code == 200, resp.text
        assert resp.json() == {
            "files": 1,
            "restored_from": "files",
            "pending_reauth": [],  # localfs providers keep no credentials
        }
        # imported AND unlocked — straight into the explorer
        status = client_b.get("/api/status").json()
        assert status["initialized"] is True and status["locked"] is False
        listing = client_b.get("/api/files", params={"path": "/docs"}).json()
        assert [f["name"] for f in listing["files"]] == ["keep.bin"]
        assert client_b.get("/api/download", params={"path": "/docs/keep.bin"}).content == data


def test_auto_snapshot_then_vault_only_recovery(home, tmp_path, monkeypatch):
    """The safety net end to end: a mutation triggers a debounced snapshot;
    later, vault.json + passphrase alone rebuild a working home."""
    from scatterbox import portability, vault as vault_mod
    from scatterbox_daemon import worker

    monkeypatch.setattr(worker, "SNAPSHOT_DEBOUNCE_S", 0.05)
    data = b"survives the apocalypse" * 2000
    with TestClient(create_app(home)) as client:
        unlock(client)
        resp = client.post(
            "/api/upload", files={"file": ("a.bin", data)}, data={"path": "/"}
        )
        assert wait_job(client, resp.json()["job_id"])["state"] == "done"
        # the debounced snapshotter persists locations into the vault file
        deadline = time.time() + 10
        while time.time() < deadline:
            v = vault_mod.unlock_vault(home / "vault.json", PASS)
            if v.has_secret(portability.SNAPSHOT_SECRET):
                break
            time.sleep(0.1)
        else:
            raise AssertionError("auto-snapshot never happened")

    # new machine: nothing but the vault file and the passphrase
    home_c = tmp_path / "home_c"
    home_c.mkdir()
    with TestClient(create_app(home_c)) as client_c:
        resp = client_c.post(
            "/api/import",
            files={"files": ("vault.json", (home / "vault.json").read_bytes())},
            data={"passphrase": PASS},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["files"] == 1 and body["restored_from"].startswith("p")
        assert client_c.get("/api/download", params={"path": "/a.bin"}).content == data


def test_status_counts(client):
    unlock(client)
    resp = client.post(
        "/api/upload", files={"file": ("s.bin", b"status" * 1000)}, data={"path": "/"}
    )
    wait_job(client, resp.json()["job_id"])
    status = client.get("/api/status").json()
    assert status["files"] == 1
    assert status["providers"] == 3
    assert status["chunks_total"] >= 1
    assert status["chunks_at_floor"] == status["chunks_total"]
