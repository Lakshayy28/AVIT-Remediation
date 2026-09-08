"""Blast Radius Score, 0-100 (docs/07 §7.5).

BRS estimates SYSTEMIC REGRESSION RISK IF THIS CHANGE IS WRONG. It is deliberately not
vulnerability severity and not fix difficulty; those are separate axes and conflating them
produces bad routing. The score is always emitted with its factor decomposition, because a
number a reviewer cannot interrogate is a number a reviewer will learn to ignore.
"""
from __future__ import annotations

from dataclasses import dataclass, field

WEIGHTS = {
    "centrality":          0.16,
    "consumers":           0.14,
    "zone_proximity":      0.16,
    "contract_exposure":   0.12,
    "txn_concurrency":     0.09,
    "test_net_inverse":    0.11,
    "change_failure":      0.08,
    "runtime_criticality": 0.07,
    "data_sensitivity":    0.04,
    "cross_component":     0.03,
}

ZONE_CLASS_WEIGHT = {
    "AUTHN": 1.0, "AUTHZ": 1.0, "CRYPTO": 1.0,
    "TXN": 0.9, "IDEMPOTENCY": 0.9, "CONCURRENCY": 0.9,
    "CONTRACT": 0.7, "RATE_LIMIT": 0.7, "PII_PCI": 0.7, "CACHE": 0.7,
}

BANDS = [(0, 24, "LOW"), (25, 49, "MEDIUM"), (50, 74, "HIGH"), (75, 100, "CRITICAL")]

DEFAULT_ROUTING = {
    "LOW": "MERGE_AUTONOMOUS_ELIGIBLE",
    "MEDIUM": "PEER_REVIEW",
    "HIGH": "SECURITY_ARCHITECT",
    "CRITICAL": "HUMAN_FIX",
}


@dataclass
class BlastRadius:
    score: int
    band: str
    factors: dict[str, float] = field(default_factory=dict)
    contributions: dict[str, float] = field(default_factory=dict)
    overrides: list[str] = field(default_factory=list)
    zones_touched: list[str] = field(default_factory=list)
    routing_floor: str = ""
    whole_symbol_forbid: bool = False

    def explain(self) -> str:
        lines = [f"BRS {self.score}  {self.band}"]
        for k, v in sorted(self.contributions.items(), key=lambda kv: -kv[1]):
            lines.append(f"  {k:<20} {self.factors[k]:.2f} x{WEIGHTS[k]:.2f} = {v:.3f}")
        lines.append(f"  {'':<20} {'':>4}       Σ = {sum(self.contributions.values()):.3f}")
        for o in self.overrides:
            lines.append(f"  override: {o}")
        return "\n".join(lines)


def _clamp01(x: float) -> float:
    return max(0.0, min(1.0, x))


def zone_proximity(graph, symbols: list[str], zones: dict) -> tuple[float, list[str]]:
    """1.0 inside a zone; 0.6 at distance 1; 0.3 at distance 2; 0 beyond. Weighted by zone class."""
    best, touched = 0.0, []
    for zid, zone in zones.items():
        members = set(zone["symbols"])
        w = ZONE_CLASS_WEIGHT.get(zone["class"], 0.7)
        if members & set(symbols):
            touched.append(zid)
            best = max(best, 1.0 * w)
            continue
        neighbours: set[str] = set()
        for s in symbols:
            neighbours |= graph.callers(s, depth=1)
            neighbours |= {e.dst for e in graph.out_edges(s, {"CALLS"})}
        if members & neighbours:
            best = max(best, 0.6 * w)
            continue
        far: set[str] = set()
        for s in symbols:
            far |= graph.callers(s, depth=2)
        if members & far:
            best = max(best, 0.3 * w)
    return best, touched


def compute(graph, change: dict, zones: dict, pagerank: dict | None = None) -> BlastRadius:
    """change: {symbols, contracts, contract_consumers, coverage, mutation_score,
                incidents_365d, traffic_percentile, data_class, components, degraded_adapters,
                touches_legacy_monolith, contract_breaking}"""
    symbols = change["symbols"]
    pr = pagerank if pagerank is not None else graph.pagerank()

    centrality = max((graph.percentile_rank(pr, s) for s in symbols), default=0.0)
    consumers = set()
    for s in symbols:
        consumers |= graph.downstream_components(s)
    consumer_f = _clamp01(len(consumers) / 8.0)

    zone_f, touched = zone_proximity(graph, symbols, zones)

    contract_consumers = change.get("contract_consumers", 0)
    contract_f = _clamp01(contract_consumers / 5.0) if change.get("contracts") else 0.0

    zone_classes = {zones[z]["class"] for z in touched}
    if {"TXN", "CONCURRENCY", "IDEMPOTENCY"} & zone_classes:
        txn_f = 1.0
    elif change.get("calls_into_txn"):
        txn_f = 0.5
    else:
        txn_f = 0.0

    coverage = change.get("coverage", 0.5)
    mutation = change.get("mutation_score", 0.5)
    test_net_inverse = _clamp01(1.0 - (0.6 * coverage + 0.4 * mutation))

    change_failure = _clamp01(change.get("incidents_365d", 0) / 3.0)
    runtime_crit = _clamp01(change.get("traffic_percentile", 0.5))
    data_sens = {"NONE": 0.0, "INTERNAL": 0.5, "PII": 1.0, "PCI": 1.0, "FINANCIAL": 1.0}.get(
        change.get("data_class", "NONE"), 0.0)
    cross_comp = _clamp01((len(change.get("components", [])) - 1) / 3.0)

    factors = {
        "centrality": centrality,
        "consumers": consumer_f,
        "zone_proximity": zone_f,
        "contract_exposure": contract_f,
        "txn_concurrency": txn_f,
        "test_net_inverse": test_net_inverse,
        "change_failure": change_failure,
        "runtime_criticality": runtime_crit,
        "data_sensitivity": data_sens,
        "cross_component": cross_comp,
    }
    contributions = {k: v * WEIGHTS[k] for k, v in factors.items()}
    score = round(100 * sum(contributions.values()))

    # ── hard overrides: floors, not additions ───────────────────────────────
    overrides: list[str] = []
    routing_floor = ""

    if {"AUTHN", "AUTHZ", "CRYPTO"} & zone_classes:
        if score < 60:
            overrides.append("AUTHZ/AUTHN/CRYPTO zone floor 60")
        score = max(score, 60)
        routing_floor = "SECURITY_ARCHITECT"
    # A FORBID_MODIFY zone blocks delegation entirely only when it is whole-symbol.
    # A facet-scoped zone (forbidden_edits present) forbids specific edits, not all edits,
    # so the symbol stays delegable and the facet is enforced by the semantic-diff detectors.
    whole_symbol_forbid = [z for z in touched
                           if zones[z].get("enforcement") == "FORBID_MODIFY"
                           and not zones[z].get("forbidden_edits")]
    if whole_symbol_forbid:
        overrides.append(f"whole-symbol FORBID_MODIFY zone touched {whole_symbol_forbid} "
                         "— ineligible for agent delegation")
        routing_floor = "HUMAN_FIX"
    elif any(zones[z].get("enforcement") == "FORBID_MODIFY" for z in touched):
        overrides.append("facet-scoped FORBID_MODIFY zone in surface — facets enforced at G2")
    if change.get("contract_breaking"):
        if score < 70:
            overrides.append("breaking contract change floor 70")
        score = max(score, 70)
    if change.get("touches_legacy_monolith"):
        if score < 45:
            overrides.append("legacy monolith floor 45")
        score = max(score, 45)
    if change.get("degraded_adapters"):
        overrides.append("degraded adapter capability +15 uncertainty penalty")
        score += 15
    if mutation < 0.4:
        if score < 50:
            overrides.append("mutation score < 0.4 floor 50")
        score = max(score, 50)

    score = max(0, min(100, score))
    band = next(b for lo, hi, b in BANDS if lo <= score <= hi)
    return BlastRadius(score, band, factors, contributions, overrides, touched,
                       routing_floor or DEFAULT_ROUTING[band], bool(whole_symbol_forbid))
