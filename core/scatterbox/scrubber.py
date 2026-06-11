"""Scrubber: health verification + repair (PLAN.md §8).

Pure library — no daemon assumptions. The CLI (`scatterbox scrub`) drives it
now; the Phase 3 daemon schedules the same functions later.

- Cheap pass: exists() probes, oldest last_verified first (never-verified
  replicas before everything else). A passing probe refreshes last_verified
  on a stored replica but does NOT rehabilitate a suspect one — only a deep
  verify clears suspicion.
- Deep pass: download + BLAKE3 verify against chunk_hash. With a byte
  budget, replicas past the budget fall back to cheap probes.
- Findings drive the replica lifecycle (stored → suspect → lost; a hash
  mismatch is definitive and goes straight to lost) and the provider
  reliability EMA.
- Repair: chunks whose stored-replica count is under the manifest floor get
  new copies — ciphertext is fetched from a surviving replica (verified by
  hash, so no master key is needed), placed via the placement engine on
  providers not already holding a live copy of the chunk. Chunks with no
  fetchable replica are reported loudly in ScrubReport.unrepairable, never
  silently skipped.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from blake3 import blake3

from scatterbox import placement
from scatterbox.errors import NotEnoughProvidersError
from scatterbox.pipeline import ProviderHandle, load_providers
from scatterbox.placement import Policy
from scatterbox.providers import RemoteRef
from scatterbox.register import Register
from scatterbox.vault import SecretStore


@dataclass
class ScrubReport:
    """Tally of one scrub/repair run — what the CLI prints at the end."""

    probed: int = 0  # replicas examined (cheap or deep)
    confirmed: int = 0  # cheap probes that passed
    deep_verified: int = 0  # downloads that hashed clean
    marked_suspect: int = 0
    marked_lost: int = 0
    repaired: int = 0  # new replicas created by repair
    unrepairable: list[str] = field(default_factory=list)


def _demote(register: Register, replica, report: ScrubReport) -> None:
    """One failed observation: stored/pending → suspect, suspect → lost.

    Two-strike rule: a single failure might be a transient outage, so it
    only raises suspicion; failing again while already suspect is the
    second strike, and the replica is written off.
    """
    if replica["state"] in ("stored", "pending"):
        register.set_replica_state(replica["id"], "suspect")
        report.marked_suspect += 1
    elif replica["state"] == "suspect":
        register.set_replica_state(replica["id"], "lost")
        report.marked_lost += 1


async def _probe(register: Register, handle: ProviderHandle, replica, report) -> None:
    """Cheap check: ask the provider if the object exists, without downloading."""
    try:
        ok = await handle.instance.exists(RemoteRef(replica["remote_ref"]))
    except Exception:
        ok = False  # an unreachable provider counts as a failed observation
    if ok:
        report.confirmed += 1
        # Note the condition: a *suspect* replica is NOT rehabilitated here.
        # exists() proves an object with that name is there, not that its
        # bytes are intact — only a deep verify can clear suspicion.
        if replica["state"] in ("stored", "pending"):
            register.mark_replica_verified(replica["id"])
    else:
        _demote(register, replica, report)
    register.update_reliability(handle.id, ok, prior=handle.reliability)


async def _deep_verify(register: Register, handle, replica, report) -> None:
    """Expensive check: download the object and hash it against the register."""
    try:
        obj = await handle.instance.get(RemoteRef(replica["remote_ref"]))
    except Exception:
        _demote(register, replica, report)
        register.update_reliability(handle.id, False, prior=handle.reliability)
        return
    if blake3(obj).hexdigest() != replica["chunk_hash"]:
        # definitive corruption — no second chances
        register.set_replica_state(replica["id"], "lost")
        report.marked_lost += 1
        register.update_reliability(handle.id, False, prior=handle.reliability)
        return
    register.mark_replica_verified(replica["id"])
    report.deep_verified += 1
    register.update_reliability(handle.id, True, prior=handle.reliability)


async def scrub(
    register: Register,
    *,
    deep: bool = False,
    probe_limit: int | None = None,
    deep_budget_bytes: int | None = None,
    repair: bool = False,
    secrets: SecretStore | None = None,
) -> ScrubReport:
    """One scrub cycle. deep=False: cheap probes only. deep=True: download +
    verify until deep_budget_bytes is spent (None = no budget), cheap probes
    for the rest. repair=True: re-replicate below-floor chunks afterwards.
    `secrets` (the unlocked vault) is needed only when a registered provider
    keeps credentials there — scrubbing itself never needs the master key."""
    handles = {h.id: h for h in load_providers(register, secrets)}
    report = ScrubReport()
    spent = 0  # download bytes used so far against deep_budget_bytes
    # replicas_for_scrub yields oldest-verified first, so each cycle attends
    # to whatever has gone longest unchecked (the "rotating" scrub).
    for replica in register.replicas_for_scrub(limit=probe_limit):
        handle = handles[replica["provider_id"]]
        report.probed += 1
        if deep and (
            deep_budget_bytes is None
            or spent + replica["stored_size"] <= deep_budget_bytes
        ):
            spent += replica["stored_size"]
            await _deep_verify(register, handle, replica, report)
        else:
            # not in deep mode, or this replica would blow the byte budget —
            # fall back to the cheap existence probe
            await _probe(register, handle, replica, report)
    if repair:
        await repair_chunks(register, report, secrets=secrets)
    return report


async def repair_chunks(
    register: Register,
    report: ScrubReport | None = None,
    *,
    secrets: SecretStore | None = None,
) -> ScrubReport:
    """Bring every chunk back to its replica floor (TASKS.md §5).

    For each below-floor chunk: fetch its ciphertext from any surviving
    replica, ask the placement engine for new homes, upload. Works entirely
    on ciphertext — repair never needs the passphrase, so a daemon can run
    it unattended.
    """
    report = report if report is not None else ScrubReport()
    handles = load_providers(register, secrets)
    by_id = {h.id: h for h in handles}

    for chunk in register.chunks_below_floor():
        label = f"{chunk['vpath']} chunk {chunk['seq']}"
        replicas = register.get_replicas(chunk["chunk_row_id"])
        # fetch the ciphertext from a surviving replica, healthiest first;
        # the hash check makes any source as good as a verified one
        obj = None
        for replica in replicas:
            if replica["state"] == "lost":
                continue
            try:
                data = await by_id[replica["provider_id"]].instance.get(
                    RemoteRef(replica["remote_ref"])
                )
            except Exception:
                continue
            if blake3(data).hexdigest() == chunk["chunk_hash"]:
                obj = data
                break
        if obj is None:
            report.unrepairable.append(f"{label}: no surviving replica verified")
            continue

        # diversity bars providers with a *live* copy; a provider holding only
        # a suspect (likely gone) replica is a valid new home — the stale row
        # is superseded (-> lost) once the fresh copy lands
        existing = [
            (r["provider_id"], by_id[r["provider_id"]].reliability)
            for r in replicas
            if r["state"] == "stored"
        ]
        exclude_ids = {r["provider_id"] for r in replicas if r["state"] == "pending"}
        # Anti-colocation must survive repair: a provider already at the
        # file's spread cap (groups-per-provider limit) can never receive a
        # chunk from a new group, or it would creep toward a complete copy
        # over repair cycles.
        if chunk["min_spread"] > 1:
            exclude_ids.update(
                register.spread_conflict_providers(
                    chunk["manifest_id"], chunk["spread_group"], chunk["spread_cap"]
                )
            )
        try:
            targets = await placement.select_targets(
                handles,
                Policy(replicas=chunk["replica_target"]),
                chunk["stored_size"],
                existing=existing,
                exclude_ids=list(exclude_ids),
            )
        except NotEnoughProvidersError as exc:
            report.unrepairable.append(f"{label}: {exc}")
            continue
        for target in targets:
            try:
                ref = await target.instance.put(chunk["chunk_hash"], obj)
            except Exception as exc:
                report.unrepairable.append(
                    f"{label}: upload to {target.name} failed: {exc}"
                )
                continue
            register.add_replica(chunk["chunk_row_id"], target.id, ref.value)
            report.repaired += 1
            # The fresh copy supersedes any suspect row this provider held
            # for the same chunk — retire the old row so it can't be counted.
            for stale in replicas:
                if stale["provider_id"] == target.id and stale["state"] == "suspect":
                    register.set_replica_state(stale["id"], "lost")
    return report
