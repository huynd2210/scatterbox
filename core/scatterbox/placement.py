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
from dataclasses import dataclass, field, replace

from scatterbox.errors import NotEnoughProvidersError, ScatterboxError

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
    # Anti-colocation (PLAN.md §7): split the file's chunks into min_spread
    # shard groups and limit how many of those groups any one provider may
    # touch, so no provider ever holds a complete copy of the file — even as
    # ciphertext. min_spread=1 = no constraint (every replica provider holds
    # the whole file). How many groups one provider may hold:
    #   spread_mode="disjoint"  -> 1 group   (≤1/N of the file; needs ~N×R
    #                                          providers)
    #   spread_mode="packed"    -> N-1 groups (no full copy, cheapest:
    #                                          needs ~⌈N×R/(N-1)⌉ providers)
    #   spread_cap=K            -> exactly K  (explicit; overrides the mode)
    min_spread: int = 1
    spread_mode: str = "disjoint"
    spread_cap: int | None = None
    # Storage scheme (PLAN.md §7): plain replication or erasure coding.
    # With "ec", each chunk becomes ec_n shares of which any ec_k rebuild
    # it; replicas/min_spread are ignored (n distinct providers, and a
    # share holder owns 1/k of undecryptable ciphertext anyway).
    scheme: str = "replica"  # replica | ec
    ec_k: int = 3
    ec_n: int = 5

    def resolved_spread_cap(self) -> int:
        """The effective max number of shard groups per provider (K)."""
        if self.min_spread <= 1:
            return 1
        if self.spread_mode not in ("disjoint", "packed"):
            raise ScatterboxError(
                f"unknown spread mode {self.spread_mode!r} (disjoint | packed)"
            )
        cap = self.spread_cap
        if cap is None:
            cap = 1 if self.spread_mode == "disjoint" else self.min_spread - 1
        if not 1 <= cap <= self.min_spread - 1:
            raise ScatterboxError(
                f"spread cap must be between 1 and min_spread-1 "
                f"({self.min_spread - 1}), got {cap} — a provider holding all "
                f"{self.min_spread} groups would hold the whole file"
            )
        return cap


def policy_to_dict(policy: Policy) -> dict:
    """JSON-ready form for the register's policies table — only fields
    that differ from the defaults, so stored policies stay readable and
    future defaults apply to old rows."""
    default = Policy()
    out: dict = {}
    for field_name in (
        "replicas", "min_spread", "spread_mode", "spread_cap",
        "scheme", "ec_k", "ec_n",
    ):
        value = getattr(policy, field_name)
        if value != getattr(default, field_name):
            out[field_name] = value
    if policy.allowed_tiers is not None:
        out["allowed_tiers"] = sorted(policy.allowed_tiers)
    if policy.pinned:
        out["pinned"] = sorted(policy.pinned)
    if policy.excluded:
        out["excluded"] = sorted(policy.excluded)
    return out


def policy_from_dict(data: dict) -> Policy:
    kwargs: dict = {k: v for k, v in data.items() if k in (
        "replicas", "min_spread", "spread_mode", "spread_cap",
        "scheme", "ec_k", "ec_n",
    )}
    if data.get("allowed_tiers") is not None:
        kwargs["allowed_tiers"] = frozenset(data["allowed_tiers"])
    if data.get("pinned"):
        kwargs["pinned"] = frozenset(data["pinned"])
    if data.get("excluded"):
        kwargs["excluded"] = frozenset(data["excluded"])
    return Policy(**kwargs)


def merge_policy(base: Policy, **overrides) -> Policy:
    """base with every non-None override applied — how explicit CLI flags /
    upload-form fields beat the folder policy field by field."""
    changes = {k: v for k, v in overrides.items() if v is not None}
    return replace(base, **changes) if changes else base


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
    spread_load: dict[int, int] | None = None,
) -> list:
    """Choose providers for new replicas of one chunk.

    handles: ProviderHandles (id, name, instance, reliability).
    existing: (provider_id, reliability) of replicas the chunk already has
    alive — their providers are excluded (diversity) and their reliability
    counts toward the durability target. exclude_ids: further provider ids
    to avoid (e.g. holders of suspect replicas). spread_load: shard-group
    counts from select_spread_groups — lightly-loaded providers are
    preferred ahead of score, which is what lets a packed spread placement
    actually reach its theoretical provider minimum instead of cornering
    itself (the top-scored providers would otherwise win every group and
    hit their cap before the last one). Returns only the *new* targets.
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
    # Sort: pinned first, then least spread-load (see docstring), then
    # highest score, then id as a stable tiebreaker.
    load = spread_load or {}
    candidates.sort(
        key=lambda c: (not c.pinned, load.get(c.handle.id, 0), -c.score, c.handle.id)
    )

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


async def select_spread_groups(
    handles: Sequence,
    policy: Policy,
    stored_chunk_size: int,
) -> list[list]:
    """Provider groups for anti-colocation (Policy.min_spread / spread_cap).

    The file's chunks are dealt round-robin across min_spread shard groups
    (chunk seq % min_spread); each group gets its own target set meeting the
    replica floor, and no provider may appear in more than K =
    resolved_spread_cap() groups — so every provider misses at least one
    group, i.e. nobody ever holds a complete copy of the file.

    Provider cost is K-dependent: each group needs `replicas` distinct
    providers and a provider offers at most K group slots, so roughly
    max(replicas, ceil(min_spread x replicas / K)) usable providers are
    needed — min_spread x replicas for disjoint (K=1), down to
    ceil(min_spread x replicas / (min_spread-1)) for packed. Selection is a
    load-balanced greedy: it achieves that bound for interchangeable
    providers, but heterogeneous quotas/pins may need more — failure is
    loud either way.
    """
    n = max(policy.min_spread, 1)
    if n == 1:
        return [await select_targets(handles, policy, stored_chunk_size)]
    cap = policy.resolved_spread_cap()
    groups: list[list] = []
    load: dict[int, int] = {}  # provider id -> shard groups held so far
    for _ in range(n):
        at_cap = [pid for pid, count in load.items() if count >= cap]
        try:
            targets = await select_targets(
                handles,
                policy,
                stored_chunk_size,
                exclude_ids=at_cap,
                spread_load=load,
            )
        except NotEnoughProvidersError as exc:
            needed = max(policy.replicas, math.ceil(n * policy.replicas / cap))
            raise NotEnoughProvidersError(
                f"cannot spread the file across {n} provider groups with at "
                f"most {cap} group(s) per provider (~{needed} usable "
                f"providers needed): {exc}. Add providers, or accept less "
                "spread by lowering --spread or using --spread-mode packed"
            ) from exc
        groups.append(targets)
        for t in targets:
            load[t.id] = load.get(t.id, 0) + 1
    return groups
