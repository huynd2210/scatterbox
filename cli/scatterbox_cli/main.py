"""scatterbox CLI entry point.

Home directory: $SCATTERBOX_HOME or ~/.scatterbox (register.db + vault.json).
Passphrase: $SCATTERBOX_PASSPHRASE or interactive prompt.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Annotated, NoReturn, Optional

import typer

from scatterbox import pipeline, scrubber, vault
from scatterbox.errors import ScatterboxError
from scatterbox.placement import Policy
from scatterbox.providers import create_provider
from scatterbox.register import Register

app = typer.Typer(
    help="scatterbox - distributed free-tier cloud storage.",
    no_args_is_help=True,
    pretty_exceptions_show_locals=False,
)
provider_app = typer.Typer(help="Manage storage providers.", no_args_is_help=True)
app.add_typer(provider_app, name="provider")


def _home() -> Path:
    return Path(os.environ.get("SCATTERBOX_HOME", str(Path.home() / ".scatterbox")))


def _fail(message: str) -> NoReturn:
    typer.secho(f"error: {message}", fg=typer.colors.RED, err=True)
    raise typer.Exit(code=1)


def _open_register() -> Register:
    db = _home() / "register.db"
    if not db.is_file():
        _fail(f"not initialized at {_home()}; run 'scatterbox init' first")
    return Register(db)


def _passphrase(confirm: bool = False) -> str:
    env = os.environ.get("SCATTERBOX_PASSPHRASE")
    if env:
        return env
    return typer.prompt("Passphrase", hide_input=True, confirmation_prompt=confirm)


def _master_key() -> bytes:
    try:
        return vault.unlock_vault(_home() / "vault.json", _passphrase()).master_key
    except ScatterboxError as exc:
        _fail(str(exc))


def _human(n: int) -> str:
    size = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024 or unit == "TiB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    raise AssertionError


@app.command()
def init() -> None:
    """Create the register and vault in the scatterbox home directory."""
    home = _home()
    if (home / "register.db").exists() or (home / "vault.json").exists():
        _fail(f"already initialized at {home}")
    passphrase = _passphrase(confirm=True)
    home.mkdir(parents=True, exist_ok=True)
    Register(home / "register.db").close()
    vault.create_vault(home / "vault.json", passphrase)
    typer.echo(f"initialized scatterbox at {home}")


@app.command()
def put(
    local: Annotated[
        Path, typer.Argument(exists=True, dir_okay=False, readable=True)
    ],
    vpath: Annotated[str, typer.Argument(help="Target virtual path; trailing / means directory.")],
    replicas: Annotated[int, typer.Option(min=1, help="Replica floor across distinct providers.")] = pipeline.DEFAULT_REPLICAS,
    pin: Annotated[Optional[list[str]], typer.Option(help="Provider name to always include (repeatable).")] = None,
    exclude: Annotated[Optional[list[str]], typer.Option(help="Provider name to never use (repeatable).")] = None,
    force_large: Annotated[bool, typer.Option("--force-large", help="Lift the 10 GB soft cap.")] = False,
) -> None:
    """Store a local file at a virtual path."""
    register = _open_register()
    master_key = _master_key()
    policy = Policy(
        replicas=replicas,
        pinned=frozenset(pin or ()),
        excluded=frozenset(exclude or ()),
    )
    try:
        result = asyncio.run(
            pipeline.put_file(
                register,
                master_key,
                local,
                vpath,
                policy=policy,
                force_large=force_large,
            )
        )
    except ScatterboxError as exc:
        _fail(str(exc))
    finally:
        register.close()
    typer.echo(
        f"stored {result.vpath} ({_human(result.size)}, "
        f"{result.chunk_count} chunk(s) x {result.replicas} replicas)"
    )


@app.command()
def get(
    vpath: Annotated[str, typer.Argument()],
    local: Annotated[Path, typer.Argument(dir_okay=False)],
) -> None:
    """Restore a virtual path to a local file."""
    register = _open_register()
    master_key = _master_key()
    try:
        asyncio.run(pipeline.get_file(register, master_key, vpath, local))
    except ScatterboxError as exc:
        _fail(str(exc))
    finally:
        register.close()
    typer.echo(f"restored {vpath} -> {local}")


@app.command()
def ls(vpath: Annotated[str, typer.Argument()] = "/") -> None:
    """List a virtual directory (or a single file)."""
    register = _open_register()
    try:
        dirs, files = pipeline.list_dir(register, vpath)
    except ScatterboxError as exc:
        _fail(str(exc))
    finally:
        register.close()
    for d in dirs:
        typer.echo(f"{d}/")
    for name, size in files:
        typer.echo(f"{name}\t{_human(size)}")


@app.command()
def status(vpath: Annotated[str, typer.Argument()]) -> None:
    """Show a file's durability state (healthy / degraded / at-risk / lost)."""
    register = _open_register()
    try:
        st = pipeline.file_status(register, vpath)
    except ScatterboxError as exc:
        _fail(str(exc))
    finally:
        register.close()
    dots = "●" * min(st.min_live, st.replica_target) + "○" * max(
        st.replica_target - st.min_live, 0
    )
    states = ", ".join(f"{n} {state}" for state, n in sorted(st.replica_states.items()))
    typer.echo(
        f"{st.vpath}  {dots} {st.health}  "
        f"weakest chunk {st.min_live}/{st.replica_target} replicas stored  "
        f"({st.chunk_count} chunk(s); replicas: {states})"
    )


@app.command()
def rm(vpath: Annotated[str, typer.Argument()]) -> None:
    """Delete a virtual path and its replicas."""
    register = _open_register()
    try:
        asyncio.run(pipeline.remove_file(register, vpath))
    except ScatterboxError as exc:
        _fail(str(exc))
    finally:
        register.close()
    typer.echo(f"removed {vpath}")


@app.command()
def scrub(
    full: Annotated[bool, typer.Option("--full", help="Download + hash-verify every replica instead of cheap existence probes.")] = False,
    repair: Annotated[bool, typer.Option("--repair", help="Re-replicate below-floor chunks after the scrub.")] = False,
    probe_limit: Annotated[Optional[int], typer.Option(min=1, help="Probe at most N replicas (oldest-verified first).")] = None,
    deep_budget_bytes: Annotated[Optional[int], typer.Option(min=1, help="Byte budget for deep verification; the rest get cheap probes.")] = None,
) -> None:
    """Verify replica health; optionally repair below-floor chunks."""
    register = _open_register()
    try:
        report = asyncio.run(
            scrubber.scrub(
                register,
                deep=full or deep_budget_bytes is not None,
                probe_limit=probe_limit,
                deep_budget_bytes=deep_budget_bytes,
                repair=repair,
            )
        )
    except ScatterboxError as exc:
        _fail(str(exc))
    finally:
        register.close()
    typer.echo(
        f"scrubbed {report.probed} replica(s): {report.confirmed} probe-ok, "
        f"{report.deep_verified} deep-verified, {report.marked_suspect} suspect, "
        f"{report.marked_lost} lost"
        + (f"; repaired {report.repaired} replica(s)" if repair else "")
    )
    if report.unrepairable:
        for line in report.unrepairable:
            typer.secho(f"UNREPAIRABLE: {line}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)


@provider_app.command("add")
def provider_add(
    name: Annotated[str, typer.Argument()],
    type_: Annotated[str, typer.Option("--type")] = "localfs",
    root: Annotated[Optional[Path], typer.Option(help="Directory for localfs storage.")] = None,
    max_object_bytes: Annotated[Optional[int], typer.Option(min=1)] = None,
    capacity_bytes: Annotated[Optional[int], typer.Option(min=1)] = None,
) -> None:
    """Register a provider instance (Phase 0: localfs only)."""
    if type_ != "localfs":
        _fail(f"unsupported provider type {type_!r} (Phase 0 supports: localfs)")
    if root is None:
        _fail("--root is required for localfs providers")
    register = _open_register()
    try:
        config = {"root": str(root.resolve())}
        if max_object_bytes is not None:
            config["max_object_bytes"] = max_object_bytes
        if capacity_bytes is not None:
            config["capacity_bytes"] = capacity_bytes
        create_provider(type_, config)  # validates config and creates the root dir
        register.add_provider(name, type_, config)
    except ScatterboxError as exc:
        _fail(str(exc))
    finally:
        register.close()
    typer.echo(f"added provider {name} ({type_} at {root})")


@provider_app.command("list")
def provider_list() -> None:
    """List registered providers with quota (confidence-labelled)."""
    register = _open_register()
    try:
        rows = register.list_providers()
        if not rows:
            typer.echo("no providers; add one with 'scatterbox provider add'")
            return
        for row in rows:
            config = json.loads(row["config"])
            quota = asyncio.run(create_provider(row["type"], config).quota())
            if quota.total_bytes is None:
                space = f"{_human(quota.used_bytes)} used, total unknown"
            else:
                free = quota.total_bytes - quota.used_bytes
                space = f"{_human(free)} free of {_human(quota.total_bytes)} ({quota.confidence})"
            limit = config.get("max_object_bytes")
            limit_s = f", max object {_human(limit)}" if limit else ""
            typer.echo(f"{row['id']}  {row['name']}  {row['type']}  {space}{limit_s}")
    finally:
        register.close()


if __name__ == "__main__":
    app()
