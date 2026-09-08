#!/usr/bin/env python3
"""Assertions over the behaviours the Guardian-AVIT design actually depends on.

These are the properties that, if they silently regressed, would turn the platform into a
rubber stamp. Treat this file the way policy/anti-cheat-rules.yaml describes the red-team suite:
gates are software, and software regresses.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import fixtures as fx
from guardian import blast_radius, clustering, gate, reachability, semantic_diff

PASS, FAIL = "\033[32m✓\033[0m", "\033[31m✗\033[0m"
results: list[tuple[bool, str]] = []


def check(cond: bool, label: str) -> None:
    results.append((bool(cond), label))
    print(f"  {PASS if cond else FAIL} {label}")


def main() -> int:
    graph = fx.build_graph()
    print("\nreachability")
    v = {f["id"]: reachability.evaluate(f, graph, fx.DEPLOYMENT, fx.RUNTIME) for f in fx.FINDINGS}
    check(v["MYT-88231"].verdict == "REACHABLE", "live BOLA is REACHABLE")
    check(v["CX-441950"].verdict == "VERIFIED_FALSE_POSITIVE", "dead legacy path auto-closes as VFP")
    check(v["MYT-88999"].verdict == "FP_PROPOSED",
          "unreachable CRITICAL semantic finding is NEVER auto-closed (ceiling holds)")
    check(any(t.result == "NO_TELEMETRY" for t in v["MYT-88999"].tiers),
          "absent telemetry skips T3 rather than assuming never-executed")
    ev = v["CX-441950"].as_evidence("CX-441950", "snap", "rules")
    check(any(reachability.premise_invalidated(p, {"type": "CONFIG_CHANGED",
                                                   "key": "legacy.theme.enabled", "value": True})
              for p in ev["premises"]), "flipping the config premise re-opens the VFP")
    check(not any(reachability.premise_invalidated(p, {"type": "ROUTE_ADDED", "pattern": "/other/**"})
                  for p in ev["premises"]), "an unrelated change does not re-open the VFP")

    print("\nblast radius")
    br = blast_radius.compute(graph, fx.CHANGE_SURFACE, fx.ZONES)
    check(br.score == 68 and br.band == "HIGH", f"BRS is 68/HIGH (got {br.score}/{br.band})")
    check(br.routing_floor == "SECURITY_ARCHITECT", "AUTHZ zone forces a security-architect floor")
    check(not br.whole_symbol_forbid,
          "facet-scoped FORBID_MODIFY does not make the symbol undelegable")
    check(abs(sum(br.contributions.values()) * 100 - 68.1) < 1.0, "factor decomposition sums to the score")

    print("\nclustering")
    backlog = fx.synthetic_backlog()
    batches = clustering.cluster(backlog)
    s = clustering.summarise(batches)
    check(s["file_conflicts_across_batches"] == 0,
          "no two concurrently-runnable batches touch the same file")
    check(s["fix_units"] == len(backlog), "every fix-unit lands in exactly one batch")
    check(all(len({u.component for u in b.units}) == 1 for b in batches),
          "component isolation is never violated")
    check(all(len({u.team for u in b.units}) == 1 for b in batches), "team isolation is never violated")
    caps = clustering.last_run["caps_used"]
    check(all(len(b.units) <= caps[b.lane] for b in batches), "no batch exceeds the lane cap in force")
    check(clustering.last_run["in_target_band"] is False and clustering.last_run["gap_to_band"] > 0,
          "an unreachable target band is reported, not manufactured")

    print("\nsemantic diff — flawed patch")
    ctx = fx.context_for("flawed")
    findings, _ = semantic_diff.run(fx.FLAWED_PATCH_FACTS, ctx)
    fired = {f.detector for f in findings}
    for det, why in [
        ("AC-AUTHZ-03", "locking out required principal classes"),
        ("AC-AUTHZ-04", "controller-only enforcement leaving other ingress unprotected"),
        ("AC-ERR-04", "catch block neutralising the patch's own security check"),
        ("AC-CON-02", "DTO field removed with live consumers"),
        ("AC-CAP-01", "capability removal"),
        ("AC-NFR-02", "transaction boundary widened"),
        ("AC-SUP-01", "scanner suppression"),
        ("AC-TST-03", "characterization test disabled"),
        ("AC-TST-01", "characterization suite hash mismatch"),
        ("AC-CAP-03", "live path severed rather than fixed"),
    ]:
        check(det in fired, f"{det} fires on {why}")
    check(all(f.severity == "BLOCKER" for f in findings), "every flawed-patch finding is a BLOCKER")
    check(len(findings) == len({(f.detector, f.location) for f in findings}),
          "findings are deduplicated by (detector, location)")

    print("\nsemantic diff — compliant patch")
    findings2, positives = semantic_diff.run(fx.COMPLIANT_PATCH_FACTS, fx.context_for("compliant"))
    check(not findings2, "the compliant patch fires zero detectors")
    check(len(positives) == 6, "positive facts are recorded for the reviewer")

    print("\ncharacterization")
    bad = gate.characterization_outcome(fx.RECORDED, fx.OBSERVED_FLAWED, fx.EXPECTED_DELTA)
    check(not bad["passed"], "the flawed patch fails G3")
    check("happyPath.owner.getStatement" in [u["case_id"] for u in bad["unlisted_changes"]],
          "customer lockout is caught as an unlisted change")
    check("negAuth.ledgerReadAll.batch" in [u["case_id"] for u in bad["unlisted_changes"]],
          "batch-service lockout is caught as an unlisted change")
    check("negAuth.otherTenant.controller" in bad["expected_delta_unmet"],
          "unmet_expected_delta catches a fix that never took effect")
    good = gate.characterization_outcome(fx.RECORDED, fx.OBSERVED_COMPLIANT, fx.EXPECTED_DELTA)
    check(good["passed"] and len(good["expected_delta_met"]) == 6,
          "the compliant patch changes exactly the six declared cases and nothing else")

    print("\ntriage matrix")
    risk_hi = {"blast_radius": 68, "zones_touched": ["HIZ-CCABC-0031"], "zone_classes": {"AUTHZ"},
               "forbid_modify_touched": False}
    ok_gates = [gate.GateResult("G0", "x", "PASS", [], 1)]
    sem = {"contracts_touched": 1, "contract_breaking": False, "consumer_owners": []}
    own = {"codeowners": ["@t"]}
    check(gate.decide(ok_gates, risk_hi, {"mutation_score": 0.78}, {"invariant_risk": []},
                      2, "PATCH_SUBMITTED", sem, own).decision == "SECURITY_ARCHITECT",
          "a clean patch touching an AUTHZ zone still requires a security architect")
    risk_lo = {"blast_radius": 14, "zones_touched": [], "zone_classes": set(),
               "forbid_modify_touched": False}
    sem0 = {"contracts_touched": 0, "contract_breaking": False}
    check(gate.decide(ok_gates, risk_lo, {"mutation_score": 0.71}, {"invariant_risk": []},
                      1, "PATCH_SUBMITTED", sem0, own).decision == "MERGE_AUTONOMOUS",
          "all eight autonomy conditions met ⇒ autonomous merge")
    check(gate.decide(ok_gates, risk_lo, {"mutation_score": 0.71}, {"invariant_risk": []},
                      2, "PATCH_SUBMITTED", sem0, own).decision == "PEER_REVIEW",
          "attempt 2 alone removes autonomy")
    check(gate.decide(ok_gates, risk_lo, {"mutation_score": 0.41}, {"invariant_risk": []},
                      1, "PATCH_SUBMITTED", sem0, own).decision == "PEER_REVIEW",
          "a weak mutation score alone removes autonomy")
    check(gate.decide(ok_gates, risk_lo, {"mutation_score": 0.71}, {"invariant_risk": ["x"]},
                      1, "PATCH_SUBMITTED", sem0, own).decision == "PEER_REVIEW",
          "an oracle invariant-risk note can only raise the tier, never lower it")
    check(gate.decide(ok_gates, risk_lo, {"mutation_score": 0.9}, {"invariant_risk": []},
                      1, "BLOCKED", sem0, own).decision == "HUMAN_FIX",
          "an agent BLOCKED report routes to a human")
    fail_gate = [gate.GateResult("G2", "x", "FAIL",
                                 [{"check_id": "AC-SUP-01", "status": "FAIL", "severity": "BLOCKER",
                                   "message": "m"}], 1)]
    check(gate.decide(fail_gate, risk_lo, {"mutation_score": 0.9}, {"invariant_risk": []},
                      1, "PATCH_SUBMITTED", sem0, own).decision == "REJECT_AND_REISSUE",
          "a blocker on attempt 1 reissues the contract")
    check(gate.decide(fail_gate, risk_lo, {"mutation_score": 0.9}, {"invariant_risk": []},
                      2, "PATCH_SUBMITTED", sem0, own).decision == "HUMAN_FIX",
          "a blocker on attempt 2 stands the agent down (no unbounded iteration)")

    failed = [lbl for ok, lbl in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    if failed:
        print("FAILED:")
        for lbl in failed:
            print("  -", lbl)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
