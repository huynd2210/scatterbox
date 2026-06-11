"""scatterbox CLI entry point.

A thin Typer wrapper around the core library: every command opens the
register, calls one pipeline/scrubber function, prints the result, and turns
ScatterboxError into a red one-line error (exit code 1). No storage logic
lives here — if a command seems to "do" something, the implementation is in
core/scatterbox.

Home directory: $SCATTERBOX_HOME or ~/.scatterbox (register.db + vault.json).
Passphrase: $SCATTERBOX_PASSPHRASE or interactive prompt (the env var exists
for tests and scripts; the prompt is the normal path).
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Annotated, NoReturn, Optional

import typer

from scatterbox import oauth, pipeline, scrubber, vault
from scatterbox.errors import ScatterboxError
from scatterbox.placement import Policy
from scatterbox.providers import create_provider, gdrive, onedrive, requires_secrets
from scatterbox.register import Register

app = typer.Typer(
    help="scatterbox - distributed free-tier cloud storage.",
    no_args_is_help=True,
    pretty_exceptions_show_locals=False,  # never dump locals — may hold keys
)
# Sub-app gives the nested command style: `scatterbox provider add ...`
provider_app = typer.Typer(help="Manage storage providers.", no_args_is_help=True)
app.add_typer(provider_app, name="provider")


def _home() -> Path:
    return Path(os.environ.get("SCATTERBOX_HOME", str(Path.home() / ".scatterbox")))


def _fail(message: str) -> NoReturn:
    """Print a red error to stderr and exit 1 (no traceback for known errors)."""
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


def _unlock() -> vault.Vault:
    """Prompt for the passphrase and unlock the vault. Needed by commands
    that encrypt/decrypt (master key) or touch a provider whose credentials
    live in the vault (gdrive/onedrive tokens)."""
    try:
        return vault.unlock_vault(_home() / "vault.json", _passphrase())
    except ScatterboxError as exc:
        _fail(str(exc))


def _vault_if_needed(register: Register) -> vault.Vault | None:
    """Unlock the vault only when some registered provider keeps credentials
    there — pure-localfs setups never get a passphrase prompt for rm/scrub."""
    if any(requires_secrets(row["type"]) for row in register.list_providers()):
        return _unlock()
    return None


def _human(n: int) -> str:
    """Bytes -> '1.5 MiB'-style display string."""
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
    spread: Annotated[int, typer.Option(min=1, help="Split chunks across N provider shard groups so no single provider ever holds the whole file.")] = 1,
    spread_mode: Annotated[str, typer.Option(help="disjoint: a provider holds at most 1 group (max 1/N of the file, needs ~N x replicas providers); packed: up to N-1 groups (cheapest, needs ~ceil(N x replicas/(N-1)) providers).")] = "disjoint",
    spread_cap: Annotated[Optional[int], typer.Option(min=1, help="Explicit max shard groups per provider (1..N-1); overrides --spread-mode.")] = None,
    pin: Annotated[Optional[list[str]], typer.Option(help="Provider name to always include (repeatable).")] = None,
    exclude: Annotated[Optional[list[str]], typer.Option(help="Provider name to never use (repeatable).")] = None,
    force_large: Annotated[bool, typer.Option("--force-large", help="Lift the 10 GB soft cap.")] = False,
) -> None:
    """Store a local file at a virtual path."""
    register = _open_register()
    v = _unlock()
    policy = Policy(
        replicas=replicas,
        pinned=frozenset(pin or ()),
        excluded=frozenset(exclude or ()),
        min_spread=spread,
        spread_mode=spread_mode,
        spread_cap=spread_cap,
    )
    try:
        result = asyncio.run(
            pipeline.put_file(
                register,
                v.master_key,
                local,
                vpath,
                policy=policy,
                force_large=force_large,
                secrets=v,
            )
        )
    except ScatterboxError as exc:
        _fail(str(exc))
    finally:
        register.close()
    typer.echo(
        f"stored {result.vpath} ({_human(result.size)}, "
        f"{result.chunk_count} chunk(s) x {result.replicas} replicas"
        + (
            f", split across {result.spread} provider shard groups"
            if result.spread > 1
            else ""
        )
        + ")"
    )


@app.command()
def get(
    vpath: Annotated[str, typer.Argument()],
    local: Annotated[Path, typer.Argument(dir_okay=False)],
) -> None:
    """Restore a virtual path to a local file."""
    register = _open_register()
    v = _unlock()
    try:
        asyncio.run(pipeline.get_file(register, v.master_key, vpath, local, secrets=v))
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
    # PLAN.md §8's dot display: ●●○ = weakest chunk has 2 of 3 replicas alive
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
        asyncio.run(pipeline.remove_file(register, vpath, secrets=_vault_if_needed(register)))
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
                # giving a byte budget implies you want deep verification
                deep=full or deep_budget_bytes is not None,
                probe_limit=probe_limit,
                deep_budget_bytes=deep_budget_bytes,
                repair=repair,
                secrets=_vault_if_needed(register),
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


# OAuth endpoint/scope knowledge lives in the adapter modules; the CLI only
# needs to know which module backs which type.
_OAUTH_TYPES = {"gdrive": gdrive, "onedrive": onedrive}


def _onboard_oauth(
    register: Register,
    name: str,
    type_: str,
    config: dict,
    client_id: str | None,
    open_browser: bool,
) -> None:
    """Interactive credential flow for gdrive/onedrive: browser consent →
    tokens into the vault → connection test → row into the register."""
    mod = _OAUTH_TYPES[type_]
    v = _unlock()
    if client_id is None:
        typer.echo(
            f"You need your own OAuth client app for {type_} "
            "(Google Cloud Console / Microsoft Entra portal)."
        )
        client_id = typer.prompt("OAuth client id")
    client_secret = None
    if type_ == "gdrive":
        # Google installed apps are issued a client secret (not actually
        # confidential, but required at the token endpoint). Microsoft
        # public clients have none.
        client_secret = typer.prompt("OAuth client secret", hide_input=True)

    blob = oauth.run_loopback_flow(
        auth_url=mod.AUTH_URL,
        token_url=mod.TOKEN_URL,
        client_id=client_id,
        scopes=mod.SCOPES,
        client_secret=client_secret,
        extra_auth_params=getattr(mod, "EXTRA_AUTH_PARAMS", None),
        open_browser=open_browser,
    )
    secret_name = f"provider:{name}"
    v.set_secret(secret_name, blob)
    config["secret"] = secret_name
    try:
        instance = create_provider(type_, config, v)
        quota = asyncio.run(instance.quota())  # connection test
        if type_ == "gdrive":
            asyncio.run(instance.prepare())  # create the scatterbox/ folder now
            config.update(instance.learned_config())
        register.add_provider(name, type_, config)
    except ScatterboxError:
        v.delete_secret(secret_name)  # don't strand tokens for a failed add
        raise
    free = "" if quota.total_bytes is None else (
        f", {_human(quota.total_bytes - quota.used_bytes)} free"
    )
    typer.echo(f"added provider {name} ({type_}{free})")


@provider_app.command("add")
def provider_add(
    name: Annotated[str, typer.Argument()],
    type_: Annotated[str, typer.Option("--type", help="localfs | gdrive | onedrive")] = "localfs",
    root: Annotated[Optional[Path], typer.Option(help="Directory for localfs storage.")] = None,
    max_object_bytes: Annotated[Optional[int], typer.Option(min=1)] = None,
    capacity_bytes: Annotated[Optional[int], typer.Option(min=1, help="Cap how much of the account scatterbox may use.")] = None,
    client_id: Annotated[Optional[str], typer.Option(help="OAuth client id (gdrive/onedrive); prompted if omitted.")] = None,
    no_browser: Annotated[bool, typer.Option("--no-browser", help="Print the consent URL instead of opening a browser.")] = False,
) -> None:
    """Register a provider instance, running its credential flow if needed."""
    register = _open_register()
    try:
        # Fail on a duplicate name before any OAuth dance.
        try:
            register.get_provider_by_name(name)
        except ScatterboxError:
            pass
        else:
            _fail(f"provider {name!r} already exists")
        config: dict = {}
        if max_object_bytes is not None:
            config["max_object_bytes"] = max_object_bytes
        if capacity_bytes is not None:
            config["capacity_bytes"] = capacity_bytes
        if type_ == "localfs":
            if root is None:
                _fail("--root is required for localfs providers")
            config["root"] = str(root.resolve())
            create_provider(type_, config)  # validates config, creates the root dir
            register.add_provider(name, type_, config)
            typer.echo(f"added provider {name} (localfs at {root})")
        elif type_ in _OAUTH_TYPES:
            _onboard_oauth(register, name, type_, config, client_id, not no_browser)
        else:
            _fail(f"unsupported provider type {type_!r} (localfs, gdrive, onedrive)")
    except ScatterboxError as exc:
        _fail(str(exc))
    finally:
        register.close()


@provider_app.command("remove")
def provider_remove(
    name: Annotated[str, typer.Argument()],
    force: Annotated[bool, typer.Option("--force", help="Remove even if replicas still live there.")] = False,
) -> None:
    """Remove a provider (and its vault credentials)."""
    register = _open_register()
    try:
        row = register.get_provider_by_name(name)
        count = register.replica_count_on_provider(row["id"])
        if count and not force:
            _fail(
                f"provider {name!r} still holds {count} replica(s); "
                "re-replicate first or pass --force (then run "
                "'scatterbox scrub --repair' to heal the affected files)"
            )
        secret_name = json.loads(row["config"]).get("secret")
        if secret_name is not None:
            _unlock().delete_secret(secret_name)
        register.delete_provider(row["id"])
    except ScatterboxError as exc:
        _fail(str(exc))
    finally:
        register.close()
    typer.echo(f"removed provider {name}")
    if count:
        typer.secho(
            f"warning: {count} replica(s) were dropped with it — run "
            "'scatterbox scrub --repair'",
            fg=typer.colors.YELLOW,
            err=True,
        )


@provider_app.command("set")
def provider_set(
    name: Annotated[str, typer.Argument()],
    max_object_bytes: Annotated[Optional[int], typer.Option(min=0, help="Per-object size cap; 0 clears it.")] = None,
    capacity_bytes: Annotated[Optional[int], typer.Option(min=0, help="Account usage cap; 0 clears it.")] = None,
) -> None:
    """Change a provider instance's configurable limits (PLAN.md §6)."""
    if max_object_bytes is None and capacity_bytes is None:
        _fail("nothing to change: pass --max-object-bytes and/or --capacity-bytes")
    register = _open_register()
    try:
        row = register.get_provider_by_name(name)
        config = json.loads(row["config"])
        for key, value in (
            ("max_object_bytes", max_object_bytes),
            ("capacity_bytes", capacity_bytes),
        ):
            if value == 0:
                config.pop(key, None)
            elif value is not None:
                config[key] = value
        register.update_provider_config(row["id"], config)
    except ScatterboxError as exc:
        _fail(str(exc))
    finally:
        register.close()
    typer.echo(f"updated provider {name}")


@provider_app.command("list")
def provider_list() -> None:
    """List registered providers with quota (confidence-labelled)."""
    register = _open_register()
    try:
        rows = register.list_providers()
        if not rows:
            typer.echo("no providers; add one with 'scatterbox provider add'")
            return
        secrets = _vault_if_needed(register)
        for row in rows:
            config = json.loads(row["config"])
            quota = asyncio.run(create_provider(row["type"], config, secrets).quota())
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
