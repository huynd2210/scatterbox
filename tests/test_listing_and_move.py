"""Phase 3 core support: indexed directory listing and metadata move
(TASKS.md §1), including the <100 ms browse gate at 50k files."""

import time

import pytest

from conftest import add_localfs_providers, get, put
from scatterbox import pipeline
from scatterbox.errors import ScatterboxError, VPathExistsError, VPathNotFoundError


def seed(register, paths):
    """Insert bare file rows (listing/move read only the files table)."""
    with register.conn:
        register.conn.executemany(
            "INSERT INTO files (vpath, size, mtime, created_at) VALUES (?, 1, 0, 0)",
            [(p,) for p in paths],
        )


def test_list_children_shape(register):
    seed(register, [
        "/a.txt", "/docs/b.txt", "/docs/c.txt", "/docs/deep/d.txt", "/music/e.mp3",
    ])
    dirs, files = register.list_children("/")
    assert dirs == ["docs", "music"]
    assert [f["vpath"] for f in files] == ["/a.txt"]
    dirs, files = register.list_children("/docs")
    assert dirs == ["deep"]
    assert [f["vpath"] for f in files] == ["/docs/b.txt", "/docs/c.txt"]
    assert register.list_children("/nope") == ([], [])


def test_list_dir_uses_index_and_errors_on_missing(register):
    seed(register, ["/docs/a.txt"])
    dirs, files = pipeline.list_dir(register, "/")
    assert dirs == ["docs"] and files == []
    with pytest.raises(VPathNotFoundError):
        pipeline.list_dir(register, "/missing")


def test_listing_50k_files_under_100ms(register):
    """PLAN.md §12 Phase 3 gate: browse operations <100 ms on a 50k index."""
    paths = [f"/dir{i // 500:03d}/file{i:05d}.bin" for i in range(50_000)]
    seed(register, paths)
    register.list_children("/")  # warm sqlite caches once

    start = time.perf_counter()
    dirs, files = register.list_children("/")
    root_ms = (time.perf_counter() - start) * 1000
    assert len(dirs) == 100 and files == []

    start = time.perf_counter()
    dirs, files = register.list_children("/dir042")
    nested_ms = (time.perf_counter() - start) * 1000
    assert len(files) == 500 and dirs == []

    assert root_ms < 100, f"root listing took {root_ms:.1f} ms"
    assert nested_ms < 100, f"nested listing took {nested_ms:.1f} ms"


def test_move_file_and_into_directory(register):
    seed(register, ["/a.txt", "/docs/b.txt"])
    assert pipeline.move_path(register, "/a.txt", "/renamed.txt") == 1
    assert register.get_file("/renamed.txt") is not None
    # trailing slash = move INTO
    assert pipeline.move_path(register, "/renamed.txt", "/docs/") == 1
    assert register.get_file("/docs/renamed.txt") is not None
    # moving onto an existing directory also means INTO
    seed(register, ["/c.txt"])
    pipeline.move_path(register, "/c.txt", "/docs")
    assert register.get_file("/docs/c.txt") is not None


def test_move_tree(register):
    seed(register, ["/old/a.txt", "/old/sub/b.txt", "/other.txt"])
    assert pipeline.move_path(register, "/old", "/new") == 2
    assert register.get_file("/new/a.txt") is not None
    assert register.get_file("/new/sub/b.txt") is not None
    assert register.list_children("/old") == ([], [])


def test_move_guards(register):
    seed(register, ["/a.txt", "/b.txt", "/dir/c.txt"])
    with pytest.raises(VPathExistsError):
        pipeline.move_path(register, "/a.txt", "/b.txt")
    with pytest.raises(ScatterboxError, match="into itself"):
        pipeline.move_path(register, "/dir", "/dir/sub")
    with pytest.raises(VPathNotFoundError):
        pipeline.move_path(register, "/ghost", "/elsewhere")
    with pytest.raises(ScatterboxError, match="root"):
        pipeline.move_path(register, "/", "/x")


def test_moved_file_still_restores(register, tmp_path):
    """A move is metadata-only — the chunks stay put and the file still
    reassembles after renaming."""
    add_localfs_providers(register, tmp_path, 3)
    src = tmp_path / "f.bin"
    data = b"payload" * 10_000
    src.write_bytes(data)
    put(register, src, "/f.bin")
    pipeline.move_path(register, "/f.bin", "/archive/renamed.bin")
    dst = tmp_path / "out.bin"
    get(register, "/archive/renamed.bin", dst)
    assert dst.read_bytes() == data
