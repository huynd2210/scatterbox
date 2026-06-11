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


@dataclass
class ScrubReport:
    probed: int = 0  # replicas examined (cheap or deep)
    confirmed: int = 0  # cheap probes that passed
    deep_verified: int = 0  # downloads that hashed clean
    marked_suspect: int = 0
    marked_lost: int = 0
    repaired: int = 0  # new replicas created by repair
    unrepairable: list[str] = field(default_factory=list)


def _demote(register: Register, replica, report: ScrubReport) -> None:
    """One failed observation: stored/pending → suspect, suspect → lost."""
    if replica["state"] in ("stored", "pending"):
        register.set_replica_state(replica["id"], "suspect")
        report.marked_suspect += 1
    elif replica["state"] == "suspect":
        register.set_replica_state(replica["id"], "lost")
        report.marked_lost += 1


async def _probe(register: Register, handle: ProviderHandle, replica, report) -> None:
    try:
        ok = await handle.instance.exists(RemoteRef(replica["remote_ref"]))
    except Exception:
        ok = False
    if ok:
        report.confirmed += 1
        if replica["state"] in ("stored", "pending"):
            register.mark_replica_verified(replica["id"])
    else:
        _demote(register, replica, report)
    register.update_reliability(handle.id, ok, prior=handle.reliability)


async def _deep_verify(register: Register, handle, replica, report) -> None:
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
) -> ScrubReport:
    """One scrub cycle. deep=False: cheap probes only. deep=True: download +
    verify until deep_budget_bytes is spent (None = no budget), cheap probes
    for the rest. repair=True: re-replicate below-floor chunks afterwards."""
    handles = {h.id: h for h in load_providers(register)}
    report = ScrubReport()
    spent = 0
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
            await _probe(register, handle, replica, report)
    if repair:
        await repair_chunks(register, report)
    return report


async def repair_chunks(
    register: Register, report: ScrubReport | None = None
) -> ScrubReport:
    """Bring every chunk back to its replica floor (TASKS.md §5)."""
    report = report if report is not None else ScrubReport()
    handles = load_providers(register)
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
        pending_ids = [r["provider_id"] for r in replicas if r["state"] == "pending"]
        try:
            targets = await placement.select_targets(
                handles,
                Policy(replicas=chunk["replica_target"]),
                chunk["stored_size"],
                existing=existing,
                exclude_ids=pending_ids,
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
            for stale in replicas:
                if stale["provider_id"] == target.id and stale["state"] == "suspect":
                    register.set_replica_state(stale["id"], "lost")
    return report
