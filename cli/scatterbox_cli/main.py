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

from scatterbox import ec, onboarding, pipeline, portability, scrubber, vault
from scatterbox.errors import ScatterboxError
from scatterbox.placement import Policy, merge_policy, policy_from_dict, policy_to_dict
from scatterbox.providers import create_provider, known_types, requires_secrets
from scatterbox.register import Register

app = typer.Typer(
    help="scatterbox - distributed free-tier cloud storage.",
    no_args_is_help=True,
    pretty_exceptions_show_locals=False,  # never dump locals — may hold keys
)
# Sub-apps give the nested command style: `scatterbox provider add ...`
provider_app = typer.Typer(help="Manage storage providers.", no_args_is_help=True)
app.add_typer(provider_app, name="provider")
policy_app = typer.Typer(help="Per-folder placement policies (PLAN.md §7).", no_args_is_help=True)
app.add_typer(policy_app, name="policy")


def _home() -> Path:
    """The scatterbox state directory ($SCATTERBOX_HOME or ~/.scatterbox)."""
    return Path(os.environ.get("SCATTERBOX_HOME", str(Path.home() / ".scatterbox")))


def _fail(message: str) -> NoReturn:
    """Print a red error to stderr and exit 1 (no traceback for known errors)."""
    typer.secho(f"error: {message}", fg=typer.colors.RED, err=True)
    raise typer.Exit(code=1)


def _open_register() -> Register:
    """Open the register or fail with init guidance; caller closes it."""
    db = _home() / "register.db"
    if not db.is_file():
        _fail(f"not initialized at {_home()}; run 'scatterbox init' first")
    return Register(db)


def _passphrase(confirm: bool = False) -> str:
    """Passphrase from $SCATTERBOX_PASSPHRASE (scripts/tests) or a hidden
    interactive prompt."""
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
    # The vault is the initialization marker — a bare register.db may have
    # been created by a daemon started before setup; that's fine to adopt.
    if (home / "vault.json").exists():
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
    replicas: Annotated[Optional[int], typer.Option(min=1, help="Replica floor across distinct providers (default: folder policy, else 3).")] = None,
    spread: Annotated[Optional[int], typer.Option(min=1, help="Split chunks across N provider shard groups so no single provider ever holds the whole file.")] = None,
    spread_mode: Annotated[Optional[str], typer.Option(help="disjoint: a provider holds at most 1 group (max 1/N of the file, needs ~N x replicas providers); packed: up to N-1 groups (cheapest, needs ~ceil(N x replicas/(N-1)) providers).")] = None,
    spread_cap: Annotated[Optional[int], typer.Option(min=1, help="Explicit max shard groups per provider (1..N-1); overrides --spread-mode.")] = None,
    scheme: Annotated[Optional[str], typer.Option(help="replica | ec (erasure coding: chunks become n shares, any k rebuild).")] = None,
    ec_k: Annotated[Optional[int], typer.Option(min=1, help="EC data shares k.")] = None,
    ec_n: Annotated[Optional[int], typer.Option(min=2, help="EC total shares n.")] = None,
    pin: Annotated[Optional[list[str]], typer.Option(help="Provider name to always include (repeatable).")] = None,
    exclude: Annotated[Optional[list[str]], typer.Option(help="Provider name to never use (repeatable).")] = None,
    force_large: Annotated[bool, typer.Option("--force-large", help="Lift the 10 GB soft cap.")] = False,
) -> None:
    """Store a local file at a virtual path.

    Unspecified options inherit from the deepest folder policy covering the
    target path ('scatterbox policy set'); explicit flags win field by field.
    """
    register = _open_register()
    v = _unlock()
    target = pipeline.normalize_vpath(vpath, basename=local.name)
    policy = merge_policy(
        pipeline.resolve_policy(register, target),
        replicas=replicas,
        min_spread=spread,
        spread_mode=spread_mode,
        spread_cap=spread_cap,
        scheme=scheme,
        ec_k=ec_k,
        ec_n=ec_n,
        pinned=frozenset(pin) if pin else None,
        excluded=frozenset(exclude) if exclude else None,
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
    stored_as = (
        f"ec({policy.ec_k},{policy.ec_n}) shares"
        if result.scheme == "ec"
        else f"{result.replicas} replicas"
    )
    typer.echo(
        f"stored {result.vpath} ({_human(result.size)}, "
        f"{result.chunk_count} chunk(s) x {stored_as}"
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
    unit = f"ec({st.ec_k},{st.replica_target}) shares" if st.scheme == "ec" else "replicas"
    typer.echo(
        f"{st.vpath}  {dots} {st.health}  "
        f"weakest chunk {st.min_live}/{st.replica_target} {unit} stored  "
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


def _onboard_oauth(
    register: Register,
    name: str,
    type_: str,
    client_id: str | None,
    open_browser: bool,
    max_object_bytes: int | None,
    capacity_bytes: int | None,
) -> None:
    """CLI front-end for OAuth onboarding: prompts here, shared flow in
    scatterbox.onboarding (same code path as the web setup wizard)."""
    v = _unlock()
    if client_id is None:
        typer.echo(
            f"You need your own OAuth client app for {type_} "
            "(Google Cloud Console / Microsoft Entra portal / Dropbox or "
            "pCloud App Console)."
        )
        client_id = typer.prompt("OAuth client id")
    client_secret = None
    if type_ in ("gdrive", "pcloud"):
        # Confidential clients: a client secret is required at the token
        # endpoint (Google installed apps and pCloud both issue one).
        # Microsoft and Dropbox public clients have none.
        client_secret = typer.prompt("OAuth client secret", hide_input=True)

    quota = onboarding.onboard_oauth_provider(
        register,
        v,
        name,
        type_,
        client_id=client_id,
        client_secret=client_secret,
        max_object_bytes=max_object_bytes,
        capacity_bytes=capacity_bytes,
        open_browser=open_browser,
    )
    free = "" if quota.total_bytes is None else (
        f", {_human(quota.total_bytes - quota.used_bytes)} free"
    )
    typer.echo(f"added provider {name} ({type_}{free})")


def _prompt_koofr_blob() -> dict:
    """Prompt for Koofr's app-password credentials and build the vault blob.

    Koofr authenticates with an application-specific password (self-serve in
    the Koofr web app: Preferences -> Password -> App passwords) sent as HTTP
    Basic — there is no OAuth consent flow. Reused by add/reauth/recover."""
    from scatterbox.providers.koofr import credential_blob

    typer.echo(
        "Koofr uses an application-specific password (generate one under "
        "Preferences -> Password -> App passwords in the Koofr web app)."
    )
    email = typer.prompt("Koofr account email")
    app_password = typer.prompt("Koofr app password", hide_input=True)
    return credential_blob(email, app_password)


def _onboard_koofr(
    register: Register,
    name: str,
    max_object_bytes: int | None,
    capacity_bytes: int | None,
) -> None:
    """CLI front-end for Koofr (app-password) onboarding: prompt here, shared
    store/test/register flow in scatterbox.onboarding."""
    v = _unlock()
    quota = onboarding.onboard_secret_provider(
        register,
        v,
        name,
        "koofr",
        blob=_prompt_koofr_blob(),
        max_object_bytes=max_object_bytes,
        capacity_bytes=capacity_bytes,
    )
    free = "" if quota.total_bytes is None else (
        f", {_human(quota.total_bytes - quota.used_bytes)} free"
    )
    typer.echo(f"added provider {name} (koofr{free})")


def _prompt_mega_blob() -> dict:
    """Prompt for MEGA account credentials and build the vault blob.

    MEGA has no OAuth and no scoped/app-password option — it authenticates with
    the account email + password, which is what gets stored (encrypted) in the
    vault. Reused by add/reauth/recover."""
    from scatterbox.providers.mega import credential_blob

    typer.echo(
        "MEGA uses your account email + password (it has no app-password or "
        "OAuth option). The password is stored in the encrypted vault and "
        "grants full account access; scatterbox confines itself to a "
        "scatterbox/ folder."
    )
    email = typer.prompt("MEGA account email")
    password = typer.prompt("MEGA password", hide_input=True)
    return credential_blob(email, password)


def _onboard_mega(
    register: Register,
    name: str,
    max_object_bytes: int | None,
    capacity_bytes: int | None,
) -> None:
    """CLI front-end for MEGA (email+password) onboarding: prompt here, shared
    store/test/register flow in scatterbox.onboarding."""
    v = _unlock()
    quota = onboarding.onboard_secret_provider(
        register,
        v,
        name,
        "mega",
        blob=_prompt_mega_blob(),
        max_object_bytes=max_object_bytes,
        capacity_bytes=capacity_bytes,
    )
    free = "" if quota.total_bytes is None else (
        f", {_human(quota.total_bytes - quota.used_bytes)} free"
    )
    typer.echo(f"added provider {name} (mega{free})")


def _prompt_r2_blob() -> dict:
    """Prompt for Cloudflare R2's S3 access key pair and build the vault blob.

    R2 has no OAuth: you create an R2 API token in the Cloudflare dashboard,
    which yields an S3-style Access Key ID + Secret Access Key. Only the
    key/secret are secret (stored in the vault); the account id and bucket are
    prompted separately as non-secret config. Reused by add/reauth/recover."""
    from scatterbox.providers.r2 import credential_blob

    typer.echo(
        "Cloudflare R2 uses an S3 API token (dashboard -> R2 -> Manage R2 API "
        "Tokens). Paste the token's Access Key ID and Secret Access Key."
    )
    access_key_id = typer.prompt("R2 Access Key ID")
    secret_access_key = typer.prompt("R2 Secret Access Key", hide_input=True)
    return credential_blob(access_key_id, secret_access_key)


def _prompt_r2_location() -> dict:
    """Prompt for R2's non-secret config (Cloudflare account id + bucket) — the
    register config that, together with the key/secret, locates the bucket.
    Reused by add and cold recovery."""
    account_id = typer.prompt("Cloudflare account id")
    bucket = typer.prompt("R2 bucket name")
    return {"account_id": account_id, "bucket": bucket}


def _onboard_r2(
    register: Register,
    name: str,
    max_object_bytes: int | None,
    capacity_bytes: int | None,
) -> None:
    """CLI front-end for Cloudflare R2 (S3 access key) onboarding: prompt here,
    shared store/test/register flow in scatterbox.onboarding."""
    location = _prompt_r2_location()
    blob = _prompt_r2_blob()
    v = _unlock()
    quota = onboarding.onboard_secret_provider(
        register,
        v,
        name,
        "r2",
        blob=blob,
        extra_config=location,
        max_object_bytes=max_object_bytes,
        capacity_bytes=capacity_bytes,
    )
    free = "" if quota.total_bytes is None else (
        f", {_human(quota.total_bytes - quota.used_bytes)} free"
    )
    typer.echo(f"added provider {name} (r2{free})")


def _prompt_oracle_blob() -> dict:
    """Prompt for Oracle's Customer Secret Key (an S3 access key pair) and build
    the vault blob.

    Oracle's S3 Compatibility API has no OAuth: you generate a Customer Secret
    Key under your OCI user settings, which yields an Access Key ID + Secret
    Access Key. Only the key/secret are secret (stored in the vault); namespace,
    region, and bucket are prompted separately as non-secret config. Reused by
    add/reauth/recover."""
    from scatterbox.providers.oracle import credential_blob

    typer.echo(
        "Oracle Object Storage uses a Customer Secret Key (OCI console -> your "
        "profile -> Customer Secret Keys). Paste its Access Key and Secret Key."
    )
    access_key_id = typer.prompt("Oracle Access Key")
    secret_access_key = typer.prompt("Oracle Secret Key", hide_input=True)
    return credential_blob(access_key_id, secret_access_key)


def _prompt_oracle_location() -> dict:
    """Prompt for Oracle's non-secret config (object-storage namespace, region,
    bucket) — the register config that, with the key/secret, locates the bucket.
    Reused by add and cold recovery."""
    namespace = typer.prompt("Oracle object-storage namespace")
    region = typer.prompt("Oracle region (e.g. us-ashburn-1)")
    bucket = typer.prompt("Oracle bucket name")
    return {"namespace": namespace, "region": region, "bucket": bucket}


def _onboard_oracle(
    register: Register,
    name: str,
    max_object_bytes: int | None,
    capacity_bytes: int | None,
) -> None:
    """CLI front-end for Oracle Object Storage (S3 access key) onboarding: prompt
    here, shared store/test/register flow in scatterbox.onboarding."""
    location = _prompt_oracle_location()
    blob = _prompt_oracle_blob()
    v = _unlock()
    quota = onboarding.onboard_secret_provider(
        register,
        v,
        name,
        "oracle",
        blob=blob,
        extra_config=location,
        max_object_bytes=max_object_bytes,
        capacity_bytes=capacity_bytes,
    )
    free = "" if quota.total_bytes is None else (
        f", {_human(quota.total_bytes - quota.used_bytes)} free"
    )
    typer.echo(f"added provider {name} (oracle{free})")


def _prompt_tigris_blob() -> dict:
    """Prompt for Tigris's S3 access key pair and build the vault blob.

    Tigris has no OAuth: you create an access key in the Tigris dashboard, which
    yields an Access Key ID + Secret Access Key. Only the key/secret are secret
    (stored in the vault); the bucket is prompted separately as non-secret
    config (the endpoint is fixed). Reused by add/reauth/recover."""
    from scatterbox.providers.tigris import credential_blob

    typer.echo(
        "Tigris uses an S3 access key (storage.new -> your bucket -> Access "
        "Keys). Paste its Access Key ID and Secret Access Key."
    )
    access_key_id = typer.prompt("Tigris Access Key ID")
    secret_access_key = typer.prompt("Tigris Secret Access Key", hide_input=True)
    return credential_blob(access_key_id, secret_access_key)


def _prompt_tigris_location() -> dict:
    """Prompt for Tigris's non-secret config (the globally-unique bucket name)
    — the only register config it needs (the endpoint is fixed). Reused by add
    and cold recovery."""
    bucket = typer.prompt("Tigris bucket name")
    return {"bucket": bucket}


def _onboard_tigris(
    register: Register,
    name: str,
    max_object_bytes: int | None,
    capacity_bytes: int | None,
) -> None:
    """CLI front-end for Tigris (S3 access key) onboarding: prompt here, shared
    store/test/register flow in scatterbox.onboarding."""
    location = _prompt_tigris_location()
    blob = _prompt_tigris_blob()
    v = _unlock()
    quota = onboarding.onboard_secret_provider(
        register,
        v,
        name,
        "tigris",
        blob=blob,
        extra_config=location,
        max_object_bytes=max_object_bytes,
        capacity_bytes=capacity_bytes,
    )
    free = "" if quota.total_bytes is None else (
        f", {_human(quota.total_bytes - quota.used_bytes)} free"
    )
    typer.echo(f"added provider {name} (tigris{free})")


def _prompt_vercel_blob_blob() -> dict:
    """Prompt for a Vercel Blob read-write token and build the vault blob.

    Vercel Blob has no OAuth: you copy a Read-Write Token from the Vercel
    dashboard (Storage -> your Blob store -> Tokens, the BLOB_READ_WRITE_TOKEN
    value). It is a static bearer credential, stored in the vault. Reused by
    add/reauth/recover."""
    from scatterbox.providers.vercel_blob import credential_blob

    typer.echo(
        "Vercel Blob uses a Read-Write Token (Vercel dashboard -> Storage -> "
        "your Blob store -> the BLOB_READ_WRITE_TOKEN value)."
    )
    token = typer.prompt("Vercel Blob read-write token", hide_input=True)
    return credential_blob(token)


def _onboard_vercel_blob(
    register: Register,
    name: str,
    max_object_bytes: int | None,
    capacity_bytes: int | None,
) -> None:
    """CLI front-end for Vercel Blob (read-write token) onboarding: prompt here,
    shared store/test/register flow in scatterbox.onboarding."""
    v = _unlock()
    quota = onboarding.onboard_secret_provider(
        register,
        v,
        name,
        "vercel_blob",
        blob=_prompt_vercel_blob_blob(),
        max_object_bytes=max_object_bytes,
        capacity_bytes=capacity_bytes,
    )
    free = "" if quota.total_bytes is None else (
        f", {_human(quota.total_bytes - quota.used_bytes)} free"
    )
    typer.echo(f"added provider {name} (vercel_blob{free})")


@provider_app.command("add")
def provider_add(
    name: Annotated[str, typer.Argument()],
    type_: Annotated[str, typer.Option("--type", help="localfs | gdrive | onedrive | dropbox | pcloud | koofr | r2 | oracle | tigris | vercel_blob | mega")] = "localfs",
    root: Annotated[Optional[Path], typer.Option(help="Directory for localfs storage.")] = None,
    max_object_bytes: Annotated[Optional[int], typer.Option(min=1)] = None,
    capacity_bytes: Annotated[Optional[int], typer.Option(min=1, help="Cap how much of the account scatterbox may use.")] = None,
    client_id: Annotated[Optional[str], typer.Option(help="OAuth client id (cloud types); prompted if omitted.")] = None,
    no_browser: Annotated[bool, typer.Option("--no-browser", help="Print the consent URL instead of opening a browser.")] = False,
) -> None:
    """Register a provider instance, running its credential flow if needed."""
    register = _open_register()
    try:
        if type_ == "localfs":
            if root is None:
                _fail("--root is required for localfs providers")
            onboarding.add_localfs_provider(
                register,
                name,
                root=root,
                max_object_bytes=max_object_bytes,
                capacity_bytes=capacity_bytes,
            )
            typer.echo(f"added provider {name} (localfs at {root})")
        elif type_ in onboarding.oauth_types():
            # Fail on a duplicate name before any OAuth dance.
            try:
                register.get_provider_by_name(name)
            except ScatterboxError:
                pass
            else:
                _fail(f"provider {name!r} already exists")
            _onboard_oauth(
                register, name, type_, client_id, not no_browser,
                max_object_bytes, capacity_bytes,
            )
        elif type_ == "koofr":
            # Secret-backed but not OAuth: its own app-password prompt, no
            # browser consent. Fail on a duplicate name before prompting.
            try:
                register.get_provider_by_name(name)
            except ScatterboxError:
                pass
            else:
                _fail(f"provider {name!r} already exists")
            _onboard_koofr(register, name, max_object_bytes, capacity_bytes)
        elif type_ == "mega":
            # Secret-backed but not OAuth: email+password prompt, no browser
            # consent. Fail on a duplicate name before prompting.
            try:
                register.get_provider_by_name(name)
            except ScatterboxError:
                pass
            else:
                _fail(f"provider {name!r} already exists")
            _onboard_mega(register, name, max_object_bytes, capacity_bytes)
        elif type_ == "r2":
            # S3 access-key backend (not OAuth): its own credential prompt, no
            # browser consent. Fail on a duplicate name before prompting.
            try:
                register.get_provider_by_name(name)
            except ScatterboxError:
                pass
            else:
                _fail(f"provider {name!r} already exists")
            _onboard_r2(register, name, max_object_bytes, capacity_bytes)
        elif type_ == "oracle":
            # S3 access-key backend (not OAuth): its own credential prompt, no
            # browser consent. Fail on a duplicate name before prompting.
            try:
                register.get_provider_by_name(name)
            except ScatterboxError:
                pass
            else:
                _fail(f"provider {name!r} already exists")
            _onboard_oracle(register, name, max_object_bytes, capacity_bytes)
        elif type_ == "tigris":
            # S3 access-key backend (not OAuth): its own credential prompt, no
            # browser consent. Fail on a duplicate name before prompting.
            try:
                register.get_provider_by_name(name)
            except ScatterboxError:
                pass
            else:
                _fail(f"provider {name!r} already exists")
            _onboard_tigris(register, name, max_object_bytes, capacity_bytes)
        elif type_ == "vercel_blob":
            # Token backend (not OAuth): a single read-write token prompt, no
            # browser consent. Fail on a duplicate name before prompting.
            try:
                register.get_provider_by_name(name)
            except ScatterboxError:
                pass
            else:
                _fail(f"provider {name!r} already exists")
            _onboard_vercel_blob(register, name, max_object_bytes, capacity_bytes)
        else:
            _fail(f"unsupported provider type {type_!r} ({', '.join(known_types())})")
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
        needs_vault = json.loads(row["config"]).get("secret") is not None
        count = onboarding.remove_provider(
            register, name, vault=_unlock() if needs_vault else None, force=force
        )
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


@provider_app.command("reauth")
def provider_reauth(
    name: Annotated[str, typer.Argument()],
    client_id: Annotated[Optional[str], typer.Option(help="OAuth client id; reused from the previous tokens if omitted.")] = None,
    client_secret: Annotated[Optional[str], typer.Option(help="OAuth client secret (gdrive/pcloud).")] = None,
    no_browser: Annotated[bool, typer.Option("--no-browser")] = False,
) -> None:
    """Re-run the consent/credential flow for an existing provider (expired/
    revoked tokens, a regenerated Koofr app password, or credentials missing
    after a cold recovery). Keeps the register row and every replica."""
    register = _open_register()
    try:
        v = _unlock()
        ptype = register.get_provider_by_name(name)["type"]
        secret_reauth_prompts = {
            "koofr": _prompt_koofr_blob,
            "r2": _prompt_r2_blob,
            "oracle": _prompt_oracle_blob,
            "tigris": _prompt_tigris_blob,
            "vercel_blob": _prompt_vercel_blob_blob,
            "mega": _prompt_mega_blob,
        }
        if ptype in secret_reauth_prompts:
            # Secret backends (no browser): re-prompt for just the credential —
            # the register row's non-secret config (bucket/account…) is unchanged.
            quota = onboarding.update_provider_secret(
                register, v, name, secret_reauth_prompts[ptype]()
            )
        else:
            quota = onboarding.reauth_provider(
                register,
                v,
                name,
                client_id=client_id,
                client_secret=client_secret,
                open_browser=not no_browser,
            )
    except ScatterboxError as exc:
        _fail(str(exc))
    finally:
        register.close()
    free = "" if quota.total_bytes is None else (
        f" ({_human(quota.total_bytes - quota.used_bytes)} free)"
    )
    typer.echo(f"re-authenticated provider {name}{free}")


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


def _policy_words(policy: Policy) -> str:
    """One human-readable line summarizing a policy (for policy show/list)."""
    parts = []
    if policy.scheme == "ec":
        parts.append(f"ec({policy.ec_k},{policy.ec_n})")
    else:
        parts.append(f"{policy.replicas} replicas")
        if policy.min_spread > 1:
            cap = policy.resolved_spread_cap()
            parts.append(f"spread {policy.min_spread} (cap {cap})")
    if policy.pinned:
        parts.append(f"pin {','.join(sorted(policy.pinned))}")
    if policy.excluded:
        parts.append(f"exclude {','.join(sorted(policy.excluded))}")
    return ", ".join(parts)


@policy_app.command("set")
def policy_set(
    folder: Annotated[str, typer.Argument(help="Folder path ('/' = global default).")],
    replicas: Annotated[Optional[int], typer.Option(min=1)] = None,
    spread: Annotated[Optional[int], typer.Option(min=1)] = None,
    spread_mode: Annotated[Optional[str], typer.Option()] = None,
    spread_cap: Annotated[Optional[int], typer.Option(min=1)] = None,
    scheme: Annotated[Optional[str], typer.Option(help="replica | ec")] = None,
    ec_k: Annotated[Optional[int], typer.Option(min=1)] = None,
    ec_n: Annotated[Optional[int], typer.Option(min=2)] = None,
    pin: Annotated[Optional[list[str]], typer.Option()] = None,
    exclude: Annotated[Optional[list[str]], typer.Option()] = None,
) -> None:
    """Attach a placement policy to a folder; files stored under it inherit
    these settings (deepest folder wins, explicit put flags beat both)."""
    register = _open_register()
    try:
        vpath = pipeline.normalize_vpath(folder)
        policy = merge_policy(
            Policy(),
            replicas=replicas,
            min_spread=spread,
            spread_mode=spread_mode,
            spread_cap=spread_cap,
            scheme=scheme,
            ec_k=ec_k,
            ec_n=ec_n,
            pinned=frozenset(pin) if pin else None,
            excluded=frozenset(exclude) if exclude else None,
        )
        if policy == Policy():
            _fail("nothing to set: pass at least one policy option")
        if policy.scheme == "ec":
            ec.validate_params(policy.ec_k, policy.ec_n)
        if policy.min_spread > 1:
            policy.resolved_spread_cap()  # validates mode/cap combination
        register.set_folder_policy(vpath, policy_to_dict(policy))
    except ScatterboxError as exc:
        _fail(str(exc))
    finally:
        register.close()
    typer.echo(f"policy for {vpath}: {_policy_words(policy)}")


@policy_app.command("show")
def policy_show(path: Annotated[str, typer.Argument()] = "/") -> None:
    """Show the effective policy for a path and where it comes from."""
    register = _open_register()
    try:
        vpath = pipeline.normalize_vpath(path)
        found = register.folder_policy_for(vpath)
    except ScatterboxError as exc:
        _fail(str(exc))
    finally:
        register.close()
    if found is None:
        typer.echo(f"{vpath}: defaults ({_policy_words(Policy())})")
    else:
        folder, data = found
        typer.echo(f"{vpath}: {_policy_words(policy_from_dict(data))}  (from {folder})")


@policy_app.command("list")
def policy_list() -> None:
    """List every folder policy."""
    register = _open_register()
    try:
        rows = register.list_folder_policies()
    finally:
        register.close()
    if not rows:
        typer.echo("no folder policies; defaults apply everywhere")
    for folder, data in rows:
        typer.echo(f"{folder}  {_policy_words(policy_from_dict(data))}")


@policy_app.command("unset")
def policy_unset(folder: Annotated[str, typer.Argument()]) -> None:
    """Remove a folder's policy (its subtree falls back to the parent's)."""
    register = _open_register()
    try:
        removed = register.delete_folder_policy(pipeline.normalize_vpath(folder))
    finally:
        register.close()
    if not removed:
        _fail(f"no policy set on {folder}")
    typer.echo(f"removed policy on {folder}")


@app.command()
def export(
    dest: Annotated[Path, typer.Argument(help="Directory for the two backup files.")],
    plain: Annotated[bool, typer.Option("--plain", help="Write the register as plain SQLite instead of encrypting it.")] = False,
) -> None:
    """Export the register + vault for moving to another machine (PLAN.md §9)."""
    register = _open_register()
    try:
        v = None if plain else _unlock()
        reg_path, vault_path = portability.export_archive(
            register,
            _home() / "vault.json",
            dest,
            master_key=v.master_key if v else None,
            kdf=v.kdf if v else None,
        )
    except ScatterboxError as exc:
        _fail(str(exc))
    finally:
        register.close()
    typer.echo(f"exported {reg_path} and {vault_path}")
    typer.echo("both files + your passphrase = your archive on any machine")


@app.command("import")
def import_cmd(
    register_file: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    vault_file: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    force: Annotated[bool, typer.Option("--force", help="Overwrite an already-initialized home.")] = False,
) -> None:
    """Restore an exported register + vault into the scatterbox home."""
    try:
        _, files = portability.import_archive(
            _home(),
            vault_bytes=vault_file.read_bytes(),
            register_blob=register_file.read_bytes(),
            passphrase=_passphrase(),
            force=force,
        )
    except ScatterboxError as exc:
        _fail(str(exc))
    typer.echo(f"imported archive with {files} file(s) into {_home()}")


@app.command()
def snapshot() -> None:
    """Upload an encrypted register snapshot to the most reliable providers."""
    register = _open_register()
    try:
        names = asyncio.run(
            portability.snapshot_to_providers(register, _unlock())
        )
    except ScatterboxError as exc:
        _fail(str(exc))
    finally:
        register.close()
    typer.echo(f"register snapshot stored on: {', '.join(names)}")


@app.command()
def restore(
    vault_file: Annotated[Optional[Path], typer.Option("--vault", exists=True, dir_okay=False, help="Vault file to install first (when the home is empty).")] = None,
    force: Annotated[bool, typer.Option("--force", help="Overwrite an existing register.db.")] = False,
) -> None:
    """Disaster recovery: rebuild the register from a provider snapshot
    using only the vault + passphrase."""
    home = _home()
    if vault_file is not None:
        home.mkdir(parents=True, exist_ok=True)
        if (home / "vault.json").exists() and not force:
            _fail(f"{home / 'vault.json'} already exists (use --force to replace)")
        (home / "vault.json").write_bytes(vault_file.read_bytes())
    try:
        v = vault.unlock_vault(home / "vault.json", _passphrase())
        files, provider = asyncio.run(
            portability.restore_register_from_snapshot(home, v, force=force)
        )
    except ScatterboxError as exc:
        _fail(str(exc))
    typer.echo(f"restored register with {files} file(s) from provider {provider!r}")


@app.command()
def recover(
    type_: Annotated[str, typer.Option("--type", help="Provider type holding a snapshot: localfs | gdrive | onedrive | dropbox | pcloud | koofr | r2 | oracle | tigris | vercel_blob | mega.")],
    root: Annotated[Optional[Path], typer.Option(help="The localfs provider's directory.")] = None,
    client_id: Annotated[Optional[str], typer.Option(help="OAuth client id (cloud types); prompted if omitted.")] = None,
    name: Annotated[Optional[str], typer.Option(help="Provider name in the recovered register (needed when several share the type).")] = None,
    no_browser: Annotated[bool, typer.Option("--no-browser")] = False,
    force: Annotated[bool, typer.Option("--force", help="Overwrite an existing home.")] = False,
) -> None:
    """COLD disaster recovery: rebuild everything from your passphrase plus
    one re-authenticated provider — no vault file, no register, no exports.

    Finds the register snapshot on the provider by its well-known name,
    decrypts it with your passphrase, recreates the vault, and adopts the
    re-authenticated credentials. Other OAuth providers then need
    'scatterbox provider reauth'.
    """
    passphrase = _passphrase()
    blob: dict | None = None
    try:
        if type_ == "localfs":
            if root is None:
                _fail("--root is required for localfs recovery")
            provider = create_provider("localfs", {"root": str(root.resolve())})
        elif type_ in onboarding.oauth_types():
            if client_id is None:
                client_id = typer.prompt("OAuth client id")
            client_secret = (
                typer.prompt("OAuth client secret", hide_input=True)
                if type_ in ("gdrive", "pcloud")
                else None
            )
            blob = onboarding.acquire_oauth_blob(
                type_,
                client_id=client_id,
                client_secret=client_secret,
                open_browser=not no_browser,
            )
            provider = create_provider(
                type_, {"secret": "recovery"}, vault.MemorySecretStore(recovery=blob)
            )
        elif type_ == "koofr":
            # App-password backend: prompt for the credential instead of the
            # OAuth dance, then recover and adopt it like the OAuth types.
            blob = _prompt_koofr_blob()
            provider = create_provider(
                "koofr", {"secret": "recovery"}, vault.MemorySecretStore(recovery=blob)
            )
        elif type_ == "mega":
            # Email+password backend: prompt for the credential, then recover
            # and adopt it like the OAuth types.
            blob = _prompt_mega_blob()
            provider = create_provider(
                "mega", {"secret": "recovery"}, vault.MemorySecretStore(recovery=blob)
            )
        elif type_ == "r2":
            # S3 access-key backend: prompt for account id + bucket (to locate
            # the snapshot) and the key/secret, then recover and adopt.
            location = _prompt_r2_location()
            blob = _prompt_r2_blob()
            provider = create_provider(
                "r2", {"secret": "recovery", **location},
                vault.MemorySecretStore(recovery=blob),
            )
        elif type_ == "oracle":
            # S3 access-key backend: prompt for namespace/region/bucket (to
            # locate the snapshot) and the key/secret, then recover and adopt.
            location = _prompt_oracle_location()
            blob = _prompt_oracle_blob()
            provider = create_provider(
                "oracle", {"secret": "recovery", **location},
                vault.MemorySecretStore(recovery=blob),
            )
        elif type_ == "tigris":
            # S3 access-key backend: prompt for the bucket (to locate the
            # snapshot) and the key/secret, then recover and adopt.
            location = _prompt_tigris_location()
            blob = _prompt_tigris_blob()
            provider = create_provider(
                "tigris", {"secret": "recovery", **location},
                vault.MemorySecretStore(recovery=blob),
            )
        elif type_ == "vercel_blob":
            # Token backend: prompt for the read-write token, then recover and
            # adopt it like the OAuth types.
            blob = _prompt_vercel_blob_blob()
            provider = create_provider(
                "vercel_blob", {"secret": "recovery"},
                vault.MemorySecretStore(recovery=blob),
            )
        else:
            _fail(f"unsupported provider type {type_!r} ({', '.join(known_types())})")

        v, files = asyncio.run(
            portability.recover_register_cold(_home(), passphrase, provider, force=force)
        )
        register = Register(_home() / "register.db")
        try:
            if blob is not None:
                adopted = portability.adopt_recovered_credentials(
                    register, v, type_, blob, name=name
                )
                typer.echo(f"adopted credentials for provider {adopted!r}")
            pending = onboarding.pending_reauth(register, v)
        finally:
            register.close()
    except ScatterboxError as exc:
        _fail(str(exc))
    typer.echo(f"recovered register with {files} file(s) into {_home()}")
    if pending:
        typer.secho(
            "providers still needing credentials: "
            + ", ".join(pending)
            + "  — run 'scatterbox provider reauth <name>' for each",
            fg=typer.colors.YELLOW,
        )


@app.command()
def mv(
    src: Annotated[str, typer.Argument()],
    dst: Annotated[str, typer.Argument(help="Target path; trailing / means move into.")],
) -> None:
    """Move/rename a virtual file or directory (metadata only — no provider I/O)."""
    register = _open_register()
    try:
        moved = pipeline.move_path(register, src, dst)
    except ScatterboxError as exc:
        _fail(str(exc))
    finally:
        register.close()
    typer.echo(f"moved {moved} file(s)")


@app.command()
def daemon(
    host: Annotated[str, typer.Option(help="Bind address; keep it loopback unless you know why not.")] = "127.0.0.1",
    port: Annotated[int, typer.Option()] = 8420,
) -> None:
    """Run the scatterbox daemon (HTTP API + web explorer)."""
    import uvicorn

    from scatterbox_daemon import create_app

    typer.echo(f"scatterbox daemon on http://{host}:{port} (home: {_home()})")
    if not (_home() / "vault.json").is_file():
        typer.echo("not set up yet — open the URL above to run the setup wizard")
    uvicorn.run(create_app(_home()), host=host, port=port, log_level="warning")


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
