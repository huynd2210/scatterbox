"""Placement engine (PLAN.md §7): pick target providers for a chunk's replicas.

Filtering: excluded providers, disallowed tiers, providers already holding a
replica (diversity), dead providers (quota() raised), and providers without
room for the chunk. Quota confidence below `exact` gets a safety margin —
the provider must have QUOTA_SAFETY_MARGIN x the chunk's stored size free
(unknown-capacity providers are assumed to have room).

Ranking: weighted sort over reliability, free-capacity fraction, and latency
class; pinned providers always sort first.

Reliability-weighted floor: policy.replicas is a per-chunk *floor*. After the
floor is met, targets keep being added while the combined loss probability
of all replicas — prod(1 - reliability_i) over existing + chosen — exceeds
MAX_CHUNK_LOSS_PROB, until candidates run out or the total replica count
reaches floor + MAX_EXTRA_REPLICAS (PLAN.md §7: a chunk forced onto
Discord-class homes gets 3-4 copies, not every provider in the fleet).
Three replicas at reliability 0.9 hit the default target (0.1^3 = 1e-3);
lower-reliability homes get extra copies. The floor is hard
(NotEnoughProvidersError if unmet); the durability target is best-effort.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass, field

from scatterbox.errors import NotEnoughProvidersError

MAX_CHUNK_LOSS_PROB = 1e-3  # target: ≤0.1% chance all replicas of a chunk die
MAX_EXTRA_REPLICAS = 2  # durability-chasing copies allowed beyond the floor
QUOTA_SAFETY_MARGIN = 2.0  # required headroom factor on non-exact quotas

# Ranking weights: how much each factor matters when scoring a candidate.
# Reliability dominates; capacity keeps providers from filling up unevenly;
# latency is a tiebreaker preference for fast homes.
_WEIGHT_RELIABILITY = 0.5
_WEIGHT_CAPACITY = 0.3
_WEIGHT_LATENCY = 0.2
_LATENCY_FIT = {"hot": 1.0, "warm": 0.6, "glacial": 0.2}  # latency class -> score


@dataclass(frozen=True)
class Policy:
    """Per-file placement policy (PLAN.md §7)."""

    replicas: int = 3  # per-chunk floor across distinct providers
    allowed_tiers: frozenset[str] | None = None  # latency classes; None = any
    pinned: frozenset[str] = field(default_factory=frozenset)  # provider names
    excluded: frozenset[str] = field(default_factory=frozenset)


@dataclass
class _Candidate:
    """A provider that survived filtering, waiting to be scored and ranked."""

    handle: object  # pipeline.ProviderHandle (avoid circular import)
    free: float  # free bytes; math.inf when capacity is unknown
    pinned: bool
    latency_class: str
    score: float = 0.0


async def select_targets(
    handles: Sequence,
    policy: Policy,
    stored_chunk_size: int,
    *,
    existing: Sequence[tuple[int, float]] = (),
    exclude_ids: Sequence[int] = (),
) -> list:
    """Choose providers for new replicas of one chunk.

    handles: ProviderHandles (id, name, instance, reliability).
    existing: (provider_id, reliability) of replicas the chunk already has
    alive — their providers are excluded (diversity) and their reliability
    counts toward the durability target. exclude_ids: further provider ids
    to avoid (e.g. holders of suspect replicas). Returns only the *new*
    targets.
    """
    # -- filtering: drop providers that can't or shouldn't hold this chunk --
    skip_ids = {pid for pid, _ in existing} | set(exclude_ids)
    candidates: list[_Candidate] = []
    for handle in handles:
        if handle.name in policy.excluded or handle.id in skip_ids:
            continue
        profile = handle.instance.profile()
        if (
            policy.allowed_tiers is not None
            and profile.latency_class not in policy.allowed_tiers
        ):
            continue
        try:
            quota = await handle.instance.quota()
        except Exception:
            continue  # provider unreachable/dead — never a placement target
        free = (
            math.inf
            if quota.total_bytes is None
            else quota.total_bytes - quota.used_bytes
        )
        # A provider that only *estimates* its free space must show 2x the
        # chunk size free — don't trust a fuzzy number down to the last byte.
        required = stored_chunk_size * (
            1.0 if quota.confidence == "exact" else QUOTA_SAFETY_MARGIN
        )
        if free < required:
            continue
        candidates.append(
            _Candidate(
                handle=handle,
                free=free,
                pinned=handle.name in policy.pinned,
                latency_class=profile.latency_class,
            )
        )

    # -- ranking: score the survivors and sort best-first --
    # Free space is normalized against the roomiest candidate so the capacity
    # term is a 0..1 fraction like the others; unknown capacity counts as 1.0.
    max_free = max((c.free for c in candidates if math.isfinite(c.free)), default=0.0)
    for c in candidates:
        capacity_frac = 1.0 if not math.isfinite(c.free) or not max_free else c.free / max_free
        c.score = (
            _WEIGHT_RELIABILITY * c.handle.reliability
            + _WEIGHT_CAPACITY * capacity_frac
            + _WEIGHT_LATENCY * _LATENCY_FIT.get(c.latency_class, 0.0)
        )
    # Sort: pinned first, then highest score, then id as a stable tiebreaker.
    candidates.sort(key=lambda c: (not c.pinned, -c.score, c.handle.id))

    # -- selection: walk the ranked list, taking providers until satisfied --
    # `loss` is the probability that EVERY replica dies: the product of each
    # provider's individual failure probability (1 - reliability). Each chosen
    # provider multiplies it down; we stop once it's small enough.
    floor_needed = max(policy.replicas - len(existing), 0)
    cap = policy.replicas + MAX_EXTRA_REPLICAS - len(existing)
    loss = math.prod(1.0 - r for _, r in existing)
    chosen: list[_Candidate] = []
    for cand in candidates:
        if len(chosen) >= cap:
            break  # hard ceiling — don't spray copies across the whole fleet
        # The (1 + 1e-9) fudge keeps float rounding from demanding one extra
        # replica when loss is exactly at the target.
        if len(chosen) >= floor_needed and loss <= MAX_CHUNK_LOSS_PROB * (1 + 1e-9):
            break  # floor met AND durability target met — done
        chosen.append(cand)
        loss *= 1.0 - cand.handle.reliability

    if len(chosen) < floor_needed:
        raise NotEnoughProvidersError(
            f"need {floor_needed} more distinct usable providers for "
            f"{policy.replicas} replicas, found {len(chosen)} "
            "— add providers, free space, or lower the replica floor"
        )
    return [c.handle for c in chosen]
