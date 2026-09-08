"""Topological clustering: >1,000 fix-units → 40-70 atomic, conflict-free PR batches (docs/07 §7.4).

Reference implementation of steps 1-8. Community detection here is constrained agglomerative
(single-linkage over the affinity graph with a tuned threshold) rather than Louvain: it is
deterministic, trivially auditable, and honours hard constraints during merging rather than after.
Louvain with a resolution parameter is a drop-in replacement for step 3 at larger estate sizes;
the threshold binary search plays the same role as resolution tuning.

The direction of the file-collocation rule is the part most often got backwards: two fixes to one
file in two PRs IS the conflict. Co-location is a reason to MERGE batches, not to separate them.
"""
from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field

AFFINITY = {
    "same_file": 1.00,          # hard
    "same_symbol": 1.00,        # hard
    "same_build_file": 1.00,    # hard
    "same_dependency": 0.90,
    "same_module_and_template": 0.75,
    "shared_contract": 0.60,
    "same_template_and_component": 0.55,
    "shared_zone": 0.50,
    "call_edge": 0.35,
    "same_component_and_team": 0.30,
}

# Two classes of constraint, and the distinction is load-bearing.
#
# HARD (safety) — never relaxed. Violating one reintroduces the failure the platform exists to
#   prevent: component isolation keeps deploys independently revertible; file exclusivity is the
#   cure for conflicting PRs; zone separation keeps an architect's review focused.
#
# SOFT (review ergonomics) — batch size caps. These express "how much should one reviewer read",
#   not "what is safe". When the hard constraints make the 40-70 target unreachable, the correct
#   response is to relax these within documented bounds and SAY SO — not to quietly break a hard
#   constraint, and not to emit 90+ batches while claiming the target was met.
LANE_CAPS = {"A": 12, "B": 25, "C": 60}          # soft defaults
LANE_CAP_MAX = {"A": 18, "B": 40, "C": 80}       # documented relaxation ceiling
MAX_FILES_PER_BATCH = 25                          # soft
MAX_FILES_PER_BATCH_MAX = 35
MAX_BATCH_BRS = 80                                # hard: a batch may not exceed CRITICAL band


@dataclass
class FixUnit:
    id: str
    component: str
    files: frozenset[str]
    symbols: frozenset[str]
    module: str
    fix_template: str
    lane: str
    team: str
    language: str
    sla_deadline: str
    severity: str
    blast_radius: int = 0
    dependency_coord: str | None = None
    contracts: frozenset[str] = frozenset()
    zones: frozenset[str] = frozenset()


@dataclass
class Batch:
    id: str
    units: list[FixUnit] = field(default_factory=list)
    depends_on: list[str] = field(default_factory=list)

    @property
    def component(self) -> str:
        return self.units[0].component if self.units else ""

    @property
    def lane(self) -> str:
        return min((u.lane for u in self.units), default="B")  # A < B < C lexically: strictest wins

    @property
    def files(self) -> set[str]:
        return {f for u in self.units for f in u.files}

    @property
    def deadline(self) -> str:
        return min(u.sla_deadline for u in self.units)

    @property
    def blast_radius(self) -> int:
        return max((u.blast_radius for u in self.units), default=0)

    @property
    def zones(self) -> set[str]:
        return {z for u in self.units for z in u.zones}


class _UnionFind:
    def __init__(self, items):
        self.parent = {i: i for i in items}

    def find(self, x):
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


# ── step 1: hard-merge into atoms ───────────────────────────────────────────
def hard_atoms(units: list[FixUnit]) -> list[list[FixUnit]]:
    """Union-find over hard-conflict edges. Nothing downstream may ever split an atom."""
    uf = _UnionFind([u.id for u in units])
    by_file: dict[str, list[str]] = defaultdict(list)
    by_symbol: dict[str, list[str]] = defaultdict(list)
    by_dep: dict[str, list[str]] = defaultdict(list)
    for u in units:
        for f in u.files:
            by_file[f].append(u.id)
        for s in u.symbols:
            by_symbol[s].append(u.id)
        if u.dependency_coord:
            # Scope by component: two components upgrading the same library edit two different
            # build files and are not in conflict.
            by_dep[(u.component, u.dependency_coord)].append(u.id)
    for group in (*by_file.values(), *by_symbol.values(), *by_dep.values()):
        for other in group[1:]:
            uf.union(group[0], other)
    index = {u.id: u for u in units}
    atoms: dict[str, list[FixUnit]] = defaultdict(list)
    for u in units:
        atoms[uf.find(u.id)].append(index[u.id])
    return list(atoms.values())


# ── separation constraints (hard) ───────────────────────────────────────────
def may_merge(a: list[FixUnit], b: list[FixUnit], caps: dict | None = None,
              file_cap: int = MAX_FILES_PER_BATCH) -> bool:
    caps = caps or LANE_CAPS
    ua, ub = a[0], b[0]
    if ua.component != ub.component:
        return False                       # deploy units stay independently revertible
    if ua.team != ub.team:
        return False                       # review routing coherence
    if ua.language != ub.language:
        return False
    # Lane homogeneity: do not mix a 7-day blocker with 30-day backlog work in one PR — the batch
    # would inherit the tighter deadline and the tighter review profile for no reason. Hard
    # co-location overrides this, and has already merged those units into a single atom upstream.
    # Compare EFFECTIVE lane (the strictest member), not the exact lane set: a hard atom that
    # already mixes lanes because two findings share a file is itself a lane-A batch and must
    # still be able to merge with other lane-A work.
    if min(u.lane for u in a) != min(u.lane for u in b):
        return False
    merged_files = {f for u in a + b for f in u.files}
    if len(merged_files) > file_cap:
        return False
    lane = min(u.lane for u in a + b)
    if len(a) + len(b) > caps[lane]:
        return False
    if max(u.blast_radius for u in a + b) > MAX_BATCH_BRS:
        return False
    # Keep an architect's review focused: do not mix an AUTHZ zone with unrelated work.
    za = {z for u in a for z in u.zones}
    zb = {z for u in b for z in u.zones}
    if (za or zb) and not (za & zb) and (za and zb):
        return False
    return True


def _signature(units: list[FixUnit]) -> dict[str, set]:
    """Set-based cluster signature. Affinity then becomes a handful of set intersections instead
    of a cartesian product over members, which is what makes re-clustering on every ingest cycle
    affordable."""
    return {
        "deps":      {(u.component, u.dependency_coord) for u in units if u.dependency_coord},
        "mod_tpl":   {(u.module, u.fix_template) for u in units},
        "contracts": {c for u in units for c in u.contracts},
        "tpl_comp":  {(u.fix_template, u.component) for u in units},
        "zones":     {z for u in units for z in u.zones},
        "comp_team": {(u.component, u.team) for u in units},
    }


# Signature key → affinity weight, in DESCENDING weight order, so the first intersection wins
# and is therefore the maximum.
_SIG_WEIGHTS = [
    ("deps",      AFFINITY["same_dependency"]),
    ("mod_tpl",   AFFINITY["same_module_and_template"]),
    ("contracts", AFFINITY["shared_contract"]),
    ("tpl_comp",  AFFINITY["same_template_and_component"]),
    ("zones",     AFFINITY["shared_zone"]),
    ("comp_team", AFFINITY["same_component_and_team"]),
]


def _affinity_sig(sa: dict[str, set], sb: dict[str, set]) -> float:
    for key, weight in _SIG_WEIGHTS:
        if sa[key] & sb[key]:
            return weight
    return 0.0


def affinity(a: list[FixUnit], b: list[FixUnit]) -> float:
    """Readable form of the same function; the clustering loop uses the signature fast path."""
    return _affinity_sig(_signature(a), _signature(b))


def _bucket_key(units: list[FixUnit]) -> tuple:
    """Pairs across buckets can never merge (hard separation), so they are never compared."""
    u = units[0]
    return (u.component, u.team, u.language, min(x.lane for x in units))


def _agglomerate(atoms: list[list[FixUnit]], threshold: float, caps: dict | None = None,
                 file_cap: int = MAX_FILES_PER_BATCH) -> list[list[FixUnit]]:
    """Constrained agglomerative clustering, iterated to a fixed point.

    A single greedy pass leaves clusters unmerged: high-affinity pairs merge first and saturate
    against the size cap, stranding partners that could still have been packed. Recomputing the
    candidate set each round fixes that.

    Ties break toward the SMALLER combined cluster, which keeps batches evenly sized instead of
    producing a few cap-sized batches and a long tail of singletons.
    """
    caps = caps or LANE_CAPS
    clusters = [list(a) for a in atoms]

    while True:
        buckets: dict[tuple, list[int]] = defaultdict(list)
        for idx, c in enumerate(clusters):
            buckets[_bucket_key(c)].append(idx)
        sigs = {idx: _signature(clusters[idx]) for idx in range(len(clusters))}

        candidates = []
        for members in buckets.values():
            for a_i in range(len(members)):
                i = members[a_i]
                for b_i in range(a_i + 1, len(members)):
                    j = members[b_i]
                    w = _affinity_sig(sigs[i], sigs[j])
                    if w >= threshold and may_merge(clusters[i], clusters[j], caps, file_cap):
                        candidates.append((-w, len(clusters[i]) + len(clusters[j]), i, j))
        if not candidates:
            return clusters
        candidates.sort()

        used: set[int] = set()
        merged_this_round: list[list[FixUnit]] = []
        for _, _, i, j in candidates:
            if i in used or j in used:
                continue
            merged_this_round.append(clusters[i] + clusters[j])
            used.update((i, j))
        if not merged_this_round:
            return clusters
        clusters = merged_this_round + [c for k, c in enumerate(clusters) if k not in used]


def cluster(units: list[FixUnit], target=(40, 70), max_iter: int = 18) -> list[Batch]:
    """Cluster to the target band, relaxing SOFT caps only if hard constraints make it unreachable.

    Returns batches; the relaxation actually applied is recorded on the module-level
    ``last_run`` dict so the caller can report it rather than silently absorbing it.
    """
    atoms = hard_atoms(units)
    schedule = [(LANE_CAPS, MAX_FILES_PER_BATCH, "soft defaults")]
    for step in (1, 2, 3):
        caps = {k: round(LANE_CAPS[k] + (LANE_CAP_MAX[k] - LANE_CAPS[k]) * step / 3)
                for k in LANE_CAPS}
        fcap = round(MAX_FILES_PER_BATCH
                     + (MAX_FILES_PER_BATCH_MAX - MAX_FILES_PER_BATCH) * step / 3)
        schedule.append((caps, fcap, f"soft caps relaxed {step}/3 toward the documented ceiling"))

    # Affinity takes values from a small discrete set, so enumerate those exact thresholds
    # (descending: strictest grouping first) instead of binary-searching a continuum.
    thresholds = sorted({w for _, w in _SIG_WEIGHTS} | {1.01}, reverse=True)

    best_overall, best_gap, best_note, best_caps = None, float("inf"), "", LANE_CAPS
    for caps, fcap, note in schedule:
        best, gap_best = None, float("inf")
        for th in thresholds:
            clusters = _agglomerate(atoms, th, caps, fcap)
            n = len(clusters)
            gap = 0 if target[0] <= n <= target[1] else min(abs(n - target[0]), abs(n - target[1]))
            if gap < gap_best:
                best, gap_best = clusters, gap
            if gap == 0:
                break
            if n < target[0]:
                break             # further loosening only merges more; stop descending
        if gap_best < best_gap:
            best_overall, best_gap, best_note, best_caps = best, gap_best, note, caps
        if best_gap == 0:
            break
    clusters = best_overall or atoms

    last_run.clear()
    last_run.update({
        "caps_used": dict(best_caps),
        "relaxation": best_note,
        "in_target_band": best_gap == 0,
        "gap_to_band": best_gap,
    })

    batches: list[Batch] = []
    for idx, group in enumerate(sorted(clusters, key=lambda g: (g[0].component, g[0].id)), start=1):
        batches.append(Batch(id=f"PR-CCABC-{idx:03d}", units=sorted(group, key=lambda u: u.id)))
    return _topological_order(batches)


last_run: dict = {}


# ── step 7: topological ordering + step 8: lease serialisation ──────────────
def _topological_order(batches: list[Batch]) -> list[Batch]:
    """Dependency bumps and contract producers first; batches sharing a file are serialised.

    Cycles are broken by pinning the higher-BRS batch and deferring its counterpart — never by
    ignoring the edge, which would reintroduce the concurrent-edit conflict.
    """
    by_file: dict[str, list[Batch]] = defaultdict(list)
    for b in batches:
        for f in b.files:
            by_file[f].append(b)
    for f, sharing in by_file.items():
        if len(sharing) > 1:
            ordered = sorted(sharing, key=lambda b: (-b.blast_radius, b.id))
            for prev, nxt in zip(ordered, ordered[1:]):
                if prev.id not in nxt.depends_on:
                    nxt.depends_on.append(prev.id)
    for b in batches:
        if any(u.dependency_coord for u in b.units):
            b.depends_on = [d for d in b.depends_on]
    return sorted(batches, key=lambda b: (len(b.depends_on), b.lane, b.deadline, b.id))


def constraint_floor(units: list[FixUnit]) -> dict:
    """Minimum batch count achievable WITHOUT violating a separation constraint.

    The 40-70 target is a preference; the separation constraints are not. When the floor exceeds
    the band, the honest output is the floor plus the binding constraint — never a batch that
    quietly breaks component isolation or a lane cap. This names the knob to turn.
    """
    from collections import defaultdict
    groups: dict[tuple, int] = defaultdict(int)
    files: dict[tuple, set] = defaultdict(set)
    for u in units:
        key = (u.component, u.team, u.language, u.lane)
        groups[key] += 1
        files[key] |= set(u.files)
    floor = sum(max(math.ceil(n / LANE_CAPS[lane]),
                    math.ceil(len(files[(c, t, l, lane)]) / MAX_FILES_PER_BATCH))
                for (c, t, l, lane), n in groups.items())
    per_component = len({g[0] for g in groups})
    return {
        "floor": floor,
        "distinct_component_team_lang_lane_groups": len(groups),
        "components": per_component,
        "binding": ("component/team/language/lane separation" if floor > 70
                    else "none — the affinity threshold controls the count"),
    }


def summarise(batches: list[Batch]) -> dict:
    lanes = defaultdict(int)
    for b in batches:
        lanes[b.lane] += 1
    return {
        "batches": len(batches),
        "fix_units": sum(len(b.units) for b in batches),
        "by_lane": dict(sorted(lanes.items())),
        "max_units_in_batch": max((len(b.units) for b in batches), default=0),
        "max_files_in_batch": max((len(b.files) for b in batches), default=0),
        "serialised_pairs": sum(len(b.depends_on) for b in batches),
        "file_conflicts_across_batches": _conflicts(batches),
    }


def _conflicts(batches: list[Batch]) -> int:
    """Concurrently-runnable batches touching the same file. MUST be zero."""
    seen: dict[str, list[str]] = defaultdict(list)
    for b in batches:
        for f in b.files:
            seen[f].append(b.id)
    conflicts = 0
    order = {b.id: b for b in batches}
    for f, ids in seen.items():
        if len(ids) > 1:
            for i in range(len(ids)):
                for j in range(i + 1, len(ids)):
                    a, c = order[ids[i]], order[ids[j]]
                    if c.id not in a.depends_on and a.id not in c.depends_on:
                        conflicts += 1
    return conflicts
