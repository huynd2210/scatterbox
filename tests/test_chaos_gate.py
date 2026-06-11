"""Phase 1 exit criterion (PLAN.md §12): 100 files across 4 mock providers at
floor 3 survive losing one provider entirely plus 20% of another's chunks —
scrub+repair heals everything, every file restores byte-identical.

File sizes are a seeded random mix (edge cases pinned), small chunk size
keeps this in CI-time.
"""

import asyncio
import json
import random

from scatterbox import scrubber
from scatterbox.providers import ChaosProvider, LocalFSProvider

from conftest import add_chaos_providers, get, put

CHUNK = 2048
SEED = 0xC4A05
N_FILES = 100


def test_chaos_gate(tmp_path, register):
    rng = random.Random(SEED)
    pids = add_chaos_providers(register, tmp_path, n=4)

    # -- store 100 files, mixed sizes (edge cases + seeded random) -------------
    sizes = [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 3 * CHUNK]
    sizes += [rng.randrange(0, 4 * CHUNK) for _ in range(N_FILES - len(sizes))]
    files = {}
    for i, size in enumerate(sizes):
        data = rng.randbytes(size)
        src = tmp_path / "src.bin"
        src.write_bytes(data)
        vpath = f"/docs/f{i:03d}.bin"
        put(register, src, vpath, chunk_size=CHUNK)
        files[vpath] = data
    assert len(files) == N_FILES

    # -- inject disaster --------------------------------------------------------
    killed = pids[0]
    config = json.loads(register.get_provider(killed)["config"])
    register.update_provider_config(killed, {**config, "killed": True})

    lossy_config = json.loads(register.get_provider(pids[1])["config"])
    lossy = ChaosProvider(LocalFSProvider(lossy_config["root"]), seed=SEED)
    dropped = lossy.drop_chunks(0.2)
    assert dropped

    # -- heal --------------------------------------------------------------------
    report = asyncio.run(scrubber.scrub(register, repair=True))
    assert not report.unrepairable
    assert report.marked_suspect > 0
    assert report.repaired > 0

    # every chunk is back at its floor, exclusively on live providers
    assert register.chunks_below_floor() == []
    short = register.conn.execute(
        """
        SELECT COUNT(*) AS n FROM (
            SELECT c.id,
                   SUM(CASE WHEN r.state = 'stored' THEN 1 ELSE 0 END) AS live
            FROM chunks c LEFT JOIN replicas r ON r.chunk_id = c.id
            GROUP BY c.id HAVING live < 3
        )
        """
    ).fetchone()["n"]
    assert short == 0
    on_dead = register.conn.execute(
        "SELECT COUNT(*) AS n FROM replicas WHERE state = 'stored' AND provider_id = ?",
        (killed,),
    ).fetchone()["n"]
    assert on_dead == 0
    assert register.get_reliability(killed, prior=0.99) < 0.5

    # -- every file restores byte-identical --------------------------------------
    for vpath, data in files.items():
        dst = tmp_path / "dst.bin"
        get(register, vpath, dst)
        assert dst.read_bytes() == data, f"{vpath} not byte-identical"
