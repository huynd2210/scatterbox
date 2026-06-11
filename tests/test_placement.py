"""Placement engine rules: diversity, reliability-weighted floor, quota
safety margin, pin/exclude, tier constraints (PLAN.md §7)."""

import asyncio
import itertools

import pytest

from scatterbox.errors import NotEnoughProvidersError
from scatterbox.pipeline import ProviderHandle
from scatterbox.placement import Policy, select_targets
from scatterbox.providers.base import ProviderProfile, Quota

_ids = itertools.count(1)

CHUNK = 1024


class FakeProvider:
    """Stub provider: only profile() and quota() matter to placement."""

    def __init__(
        self,
        reliability_prior=0.9,
        latency_class="hot",
        free=10**9,
        total=10**9,
        confidence="exact",
        dead=False,
    ):
        self._profile = ProviderProfile(
            latency_class=latency_class,
            throughput_class="high",
            max_object_bytes=None,
            reliability_prior=reliability_prior,
            exposure_risk="low",
            rate_limited=False,
        )
        self._quota = (
            None
            if total is None
            else Quota(total, total - free, confidence)
        )
        if total is None:
            self._quota = Quota(None, 0, "unknown")
        self.dead = dead

    def profile(self):
        return self._profile

    async def quota(self):
        if self.dead:
            raise ConnectionError("provider unreachable")
        return self._quota


def handle(name, **kwargs) -> ProviderHandle:
    provider = FakeProvider(**kwargs)
    return ProviderHandle(
        next(_ids), name, provider, provider.profile().reliability_prior
    )


def select(handles, policy=Policy(), size=CHUNK, existing=()):
    return asyncio.run(
        select_targets(handles, policy, size, existing=existing)
    )


def drive_fleet(n, prefix="drive"):
    return [handle(f"{prefix}{i}", reliability_prior=0.9) for i in range(n)]


def test_diversity_never_two_replicas_on_one_provider():
    handles = drive_fleet(6)
    targets = select(handles, Policy(replicas=3))
    assert len(targets) == len({t.id for t in targets}) == 3


def test_low_reliability_gets_more_replicas_than_drive_class():
    # same policy, floor 3: drive-class (0.9) stops at the floor,
    # discord-class (0.5) gets extra copies chasing the durability target
    drive_targets = select(drive_fleet(8), Policy(replicas=3))
    discord = [handle(f"d{i}", reliability_prior=0.5) for i in range(8)]
    discord_targets = select(discord, Policy(replicas=3))
    assert len(drive_targets) == 3
    assert len(discord_targets) > 3


def test_durability_is_best_effort_when_candidates_run_out():
    discord = [handle(f"d{i}", reliability_prior=0.5) for i in range(4)]
    assert len(select(discord, Policy(replicas=3))) == 4  # all it can do


def test_full_provider_is_skipped():
    handles = drive_fleet(3) + [handle("full", free=10)]
    targets = select(handles, Policy(replicas=3), size=CHUNK)
    assert "full" not in {t.name for t in targets}
    assert len(targets) == 3


def test_quota_safety_margin_on_estimated_confidence():
    # 1.5x chunk free: enough at exact confidence, not at estimated
    snug_exact = handle("exact", free=CHUNK * 3 // 2, confidence="exact")
    snug_est = handle("est", free=CHUNK * 3 // 2, confidence="estimated")
    assert select([snug_exact] + drive_fleet(2), Policy(replicas=3))
    with pytest.raises(NotEnoughProvidersError):
        select([snug_est] + drive_fleet(2), Policy(replicas=3))


def test_unknown_capacity_is_usable():
    handles = drive_fleet(2) + [handle("mystery", total=None)]
    assert len(select(handles, Policy(replicas=3))) == 3


def test_dead_provider_is_skipped():
    handles = drive_fleet(3) + [handle("dead", dead=True)]
    targets = select(handles, Policy(replicas=3))
    assert "dead" not in {t.name for t in targets}
    with pytest.raises(NotEnoughProvidersError):
        select(drive_fleet(2) + [handle("dead2", dead=True)], Policy(replicas=3))


def test_pinned_provider_is_always_chosen():
    # low-reliability, low-capacity pin would never win the weighted sort
    pin = handle("slowpin", reliability_prior=0.5, latency_class="glacial", free=10**6)
    handles = drive_fleet(5) + [pin]
    targets = select(handles, Policy(replicas=3, pinned=frozenset({"slowpin"})))
    assert "slowpin" in {t.name for t in targets}


def test_excluded_provider_is_never_chosen():
    handles = drive_fleet(4)
    name = handles[0].name
    targets = select(handles, Policy(replicas=3, excluded=frozenset({name})))
    assert name not in {t.name for t in targets}
    with pytest.raises(NotEnoughProvidersError):
        select(drive_fleet(3), Policy(replicas=3, excluded=frozenset({"drive0"})))


def test_tier_constraint_filters_candidates():
    hot = drive_fleet(3)
    cold = [handle(f"cold{i}", latency_class="glacial") for i in range(3)]
    targets = select(hot + cold, Policy(replicas=3, allowed_tiers=frozenset({"hot"})))
    assert all(t.name.startswith("drive") for t in targets)


def test_existing_replicas_respected_for_repair():
    handles = drive_fleet(5)
    existing = [(handles[0].id, 0.9), (handles[1].id, 0.9)]
    targets = select(handles, Policy(replicas=3), existing=existing)
    # one new replica needed, never on a provider that already has one
    assert len(targets) == 1
    assert targets[0].id not in {pid for pid, _ in existing}


def test_weighted_sort_reliability_decides_at_equal_capacity():
    shaky = handle("shaky", reliability_prior=0.6)
    solids = [handle(f"solid{i}", reliability_prior=0.95) for i in range(3)]
    targets = select([shaky] + solids, Policy(replicas=3))
    assert "shaky" not in {t.name for t in targets}


def test_weighted_sort_capacity_decides_at_equal_reliability():
    frees = {"roomy": 10**9, "mid": 8 * 10**8, "snug": 6 * 10**8, "tight": 10**7}
    handles = [
        handle(name, reliability_prior=0.95, free=free, total=10**9)
        for name, free in frees.items()
    ]
    targets = select(handles, Policy(replicas=3))
    assert {t.name for t in targets} == {"roomy", "mid", "snug"}
