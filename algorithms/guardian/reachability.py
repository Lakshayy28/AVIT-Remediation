"""Tiered reachability and verified-false-positive elimination (docs/03 §3.2-3.3).

Design rule that governs every branch below: UNKNOWN RESOLVES TO REACHABLE, never to safe.
The platform's credibility does not survive auto-closing one real critical.
"""
from __future__ import annotations

from dataclasses import dataclass, field

CONFIDENCE_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}

# Severity ceiling for automatic closure, per finding class. Deliberately conservative:
# CRITICAL semantic findings are NEVER auto-closed regardless of confidence — they become
# FP_PROPOSED for one-click analyst confirmation.
AUTO_CLOSE_CEILING = {
    "SEMANTIC_LOGIC": "MEDIUM",
    "TAINT_FLOW": "HIGH",
    "DEPENDENCY_CVE": "HIGH",
    "INFRA_DRIFT": "HIGH",
}
SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass
class TierResult:
    tier: str
    result: str
    confidence: str = "HIGH"
    detail: str = ""
    query: str = ""
    query_result: str = ""


@dataclass
class ReachabilityVerdict:
    verdict: str
    confidence: str
    tiers: list[TierResult] = field(default_factory=list)
    ingress_paths: list[list[str]] = field(default_factory=list)
    premises: list[dict] = field(default_factory=list)
    reason: str = ""

    def as_evidence(self, finding_id: str, snapshot: str, ruleset: str) -> dict:
        return {
            "finding": finding_id,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "graph_snapshot_id": snapshot,
            "ruleset_version": ruleset,
            "tiers": [t.__dict__ for t in self.tiers],
            "ingress_paths": self.ingress_paths,
            "premises": self.premises,
            "ttl_days": 90 if self.verdict == "VERIFIED_FALSE_POSITIVE" else None,
            "reverification": "AUTOMATIC_ON_PREMISE_CHANGE_OR_TTL",
        }


def evaluate(finding: dict, graph, deployment: dict, runtime: dict,
             sanitisers: dict | None = None) -> ReachabilityVerdict:
    """Evaluate T0-T4 for one finding. Cheapest tier first; lowest tier confidence caps the whole."""
    sanitisers = sanitisers or {}
    symbol = finding["symbol"]
    tiers: list[TierResult] = []
    premises: list[dict] = []

    # ── T0 provenance & existence ───────────────────────────────────────────
    if symbol not in graph.nodes:
        tiers.append(TierResult("T0", "SYMBOL_DELETED", detail="symbol absent at HEAD"))
        premises.append({"kind": "NO_CALLER", "symbol": symbol})
        return ReachabilityVerdict("VERIFIED_FALSE_POSITIVE", "HIGH", tiers, premises=premises,
                                   reason="code no longer exists")
    tiers.append(TierResult("T0", "EXISTS", detail="symbol present at HEAD"))

    # ── T1 static reachability from framework-modelled ingress ──────────────
    paths = graph.paths_to(symbol)
    if not paths:
        tiers.append(TierResult("T1", "NO_PATH", confidence="HIGH",
                                query=f"paths_to({symbol})", query_result="0 rows"))
        premises.append({"kind": "NO_CALLER", "symbol": symbol})
    else:
        min_conf = max(graph.path_confidence(p) for p in paths)
        # A path resting on a HEURISTIC seam cannot support a HIGH-confidence conclusion.
        t1_conf = "HIGH" if min_conf >= 0.85 else ("MEDIUM" if min_conf >= 0.6 else "LOW")
        tiers.append(TierResult("T1", "REACHABLE", confidence=t1_conf,
                                query=f"paths_to({symbol})", query_result=f"{len(paths)} rows",
                                detail=f"weakest seam confidence {min_conf:.2f}"))

    # ── T2 configuration / contract reachability ────────────────────────────
    dep = deployment.get(symbol, {})
    if dep.get("deployed") is False:
        tiers.append(TierResult("T2", "NOT_DEPLOYED", detail=dep.get("detail", "")))
        premises.append({"kind": "CONFIG_FALSE", "key": dep.get("flag", "?"),
                         "envs": dep.get("envs", [])})
    else:
        tiers.append(TierResult("T2", "DEPLOYED", detail=dep.get("detail", "route registered in all envs")))

    # ── T3 runtime evidence ─────────────────────────────────────────────────
    rt = runtime.get(symbol)
    if rt is None:
        # Absence of telemetry is not evidence of absence of execution. Skip, do not assume.
        tiers.append(TierResult("T3", "NO_TELEMETRY", confidence="LOW",
                                detail="no runtime coverage for this component; tier skipped"))
    elif rt.get("executions", 0) == 0:
        tiers.append(TierResult("T3", "NEVER_EXECUTED", detail=f"window {rt.get('window_days', 90)}d"))
        premises.append({"kind": "NEVER_EXECUTED", "symbol": symbol})
    else:
        tiers.append(TierResult("T3", "EXECUTED", detail=f"{rt['executions']:,} executions/day"))

    # ── T4 exploitability constraints ───────────────────────────────────────
    san = sanitisers.get(symbol)
    if san and san.get("effective_on_all_paths"):
        tiers.append(TierResult("T4", "FULLY_SANITISED", detail=san.get("detail", "")))
        premises.append({"kind": "SANITISED", "symbol": symbol})
    else:
        tiers.append(TierResult("T4", "NOT_SANITISED",
                                detail=san.get("detail", "no effective sanitiser on path") if san else
                                "no effective sanitiser on path"))

    # ── composition ─────────────────────────────────────────────────────────
    results = {t.tier: t for t in tiers}
    reachable = (
        results["T1"].result == "REACHABLE"
        and results["T2"].result != "NOT_DEPLOYED"
        and results["T4"].result != "FULLY_SANITISED"
    )
    applicable = [t for t in tiers if t.result != "NO_TELEMETRY"]
    confidence = min((t.confidence for t in applicable), key=lambda c: CONFIDENCE_ORDER[c])

    if reachable:
        return ReachabilityVerdict("REACHABLE", confidence, tiers,
                                   ingress_paths=paths, premises=premises,
                                   reason="live ingress path with no effective mitigation")

    cls = finding.get("class", "TAINT_FLOW")
    severity = finding.get("severity", "HIGH")
    ceiling = AUTO_CLOSE_CEILING.get(cls, "HIGH")
    within_ceiling = SEVERITY_ORDER[severity] <= SEVERITY_ORDER[ceiling]

    if confidence == "HIGH" and within_ceiling:
        return ReachabilityVerdict("VERIFIED_FALSE_POSITIVE", confidence, tiers,
                                   premises=premises, reason="unreachable with high confidence")
    if confidence == "HIGH":
        return ReachabilityVerdict("FP_PROPOSED", confidence, tiers, premises=premises,
                                   reason=f"unreachable, but {severity} {cls} exceeds the auto-close "
                                          f"ceiling ({ceiling}); analyst confirmation required")
    if confidence == "MEDIUM":
        return ReachabilityVerdict("FP_PROPOSED", confidence, tiers, premises=premises,
                                   reason="unreachable at medium confidence; analyst confirmation required")
    return ReachabilityVerdict("REACHABLE_ASSUMED", confidence, tiers, premises=premises,
                               reason="insufficient confidence to conclude unreachable — unknown is unsafe")


def premise_invalidated(premise: dict, change: dict) -> bool:
    """Premise-drift watch: what turns a cached VFP verdict back into an open finding.

    A VFP is not a permanent verdict. It is a cached verdict with invalidation.
    """
    kind = premise["kind"]
    if kind == "NO_CALLER" and change.get("type") == "CALLER_ADDED":
        return change.get("target") == premise.get("symbol")
    if kind == "CONFIG_FALSE" and change.get("type") == "CONFIG_CHANGED":
        return change.get("key") == premise.get("key") and change.get("value") is True
    if kind == "NO_ROUTE" and change.get("type") == "ROUTE_ADDED":
        return change.get("pattern", "").startswith(premise.get("pattern", "\0").rstrip("*"))
    if kind == "NEVER_EXECUTED" and change.get("type") == "EXECUTION_OBSERVED":
        return change.get("symbol") == premise.get("symbol")
    if kind == "SANITISED" and change.get("type") == "SANITISER_REMOVED":
        return change.get("symbol") == premise.get("symbol")
    return False
