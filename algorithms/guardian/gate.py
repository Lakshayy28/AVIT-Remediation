"""Gate pipeline outcome composition and the triage matrix (docs/09 §9.3-9.4).

Mirrors policy/gating-matrix.rego. The Python form exists so the routing logic is testable
without an OPA runtime; the Rego form is what runs in production.

Two properties of the matrix are deliberate and worth preserving in any port:
  * MERGE_AUTONOMOUS requires a conjunction of eight conditions. Autonomy is the narrow exception.
  * attempt == 1 is one of them. A patch that needed a second try has already demonstrated the
    agent misjudged the problem once.
"""
from __future__ import annotations

from dataclasses import dataclass, field

BLOCKER, REVIEW, INFO = "BLOCKER", "REVIEW", "INFO"


@dataclass
class GateResult:
    gate: str
    name: str
    status: str                      # PASS | FAIL | SKIPPED | ERROR
    checks: list = field(default_factory=list)
    duration_ms: int = 0

    @property
    def blockers(self) -> list:
        return [c for c in self.checks if c.get("status") == "FAIL" and c.get("severity") == BLOCKER]


@dataclass
class Verdict:
    decision: str
    rationale: str
    matched_rule: str
    blocker_count: int = 0
    gates_failed: list[str] = field(default_factory=list)
    attempts_remaining: int = 0
    required_reviewers: list[str] = field(default_factory=list)


def characterization_outcome(recorded: dict, observed: dict, expected_delta: dict) -> dict:
    """G3. Equality check with a declared exception set.

    Both halves matter:
      * an unlisted change is collateral damage;
      * an UNMET declared change means the fix did not actually land — the highest-value
        anti-cheat check in the system, and one a plain regression suite cannot express.
    """
    declared = {c["case_id"]: c for c in expected_delta.get("cases", [])}
    unlisted, met, unmet = [], [], []
    for case_id, rec in recorded.items():
        obs = observed.get(case_id)
        changed = obs != rec
        if case_id in declared:
            if obs == declared[case_id]["after"]:
                met.append(case_id)
            else:
                unmet.append(case_id)
        elif changed:
            unlisted.append({"case_id": case_id, "recorded": rec, "observed": obs})
    for case_id in declared:
        if case_id not in recorded:
            unmet.append(case_id)
    return {
        "total_cases": len(recorded),
        "identical": sum(1 for k, v in recorded.items() if observed.get(k) == v),
        "changed": sum(1 for k, v in recorded.items() if observed.get(k) != v),
        "expected_delta_met": met,
        "expected_delta_unmet": sorted(set(unmet)),
        "unlisted_changes": unlisted,
        "passed": not unlisted and not unmet,
    }


def decide(gates: list[GateResult], risk: dict, characterization: dict, oracle: dict,
           attempt: int, agent_outcome: str, semantic: dict, ownership: dict,
           adapter_degraded: bool = False) -> Verdict:
    blockers = [c for g in gates for c in g.blockers]
    failed = [g.gate for g in gates if g.status == "FAIL"]
    zones = risk.get("zones_touched", [])
    zone_classes = set(risk.get("zone_classes", []))
    brs = risk.get("blast_radius", 100)

    # ── rejection paths ─────────────────────────────────────────────────────
    if agent_outcome == "BLOCKED":
        return Verdict("HUMAN_FIX",
                       "Agent emitted BLOCKED with a report. Recorded as a successful agent outcome; "
                       "the work routes to a human with the full evidence bundle.",
                       "triage.agent_blocked", 0, failed, 0)
    if blockers and attempt < 2:
        return Verdict("REJECT_AND_REISSUE",
                       f"{len(blockers)} BLOCKER finding(s) across {', '.join(failed)}.",
                       "triage.blocker_and_attempts_remaining", len(blockers), failed, 2 - attempt)
    if blockers:
        return Verdict("HUMAN_FIX",
                       f"{len(blockers)} BLOCKER finding(s) after the final permitted attempt. "
                       "Agent stands down; unbounded iteration against a gate is adversarial search.",
                       "triage.blocker_attempts_exhausted", len(blockers), failed, 0)

    reviewers = list(ownership.get("codeowners", []))

    # ── escalation paths ────────────────────────────────────────────────────
    if risk.get("forbid_modify_touched"):
        return Verdict("SECURITY_ARCHITECT",
                       "A FORBID_MODIFY zone was reachable by the agent — the contract was mis-scoped. "
                       "Escalating and flagging a contract-scoping defect.",
                       "triage.forbid_modify_zone", 0, failed, 2 - attempt,
                       reviewers + ["@ccabc/appsec"])
    if {"AUTHN", "AUTHZ", "CRYPTO"} & zone_classes:
        return Verdict("SECURITY_ARCHITECT",
                       f"Change touches {sorted({'AUTHN','AUTHZ','CRYPTO'} & zone_classes)} zone(s) "
                       f"{zones}. All gates passed; the remaining question is a policy judgement.",
                       "triage.security_zone", 0, failed, 2 - attempt, reviewers + ["@ccabc/appsec"])
    if semantic.get("contract_breaking"):
        return Verdict("SECURITY_ARCHITECT",
                       "Breaking contract change; consumer owners must sign off.",
                       "triage.contract_breaking", 0, failed, 2 - attempt,
                       reviewers + ["@ccabc/appsec"] + semantic.get("consumer_owners", []))
    if brs >= 75:
        return Verdict("HUMAN_FIX",
                       f"Blast radius {brs} (CRITICAL) should not have been delegated — contract policy defect.",
                       "triage.brs_critical", 0, failed, 2 - attempt, reviewers)
    if brs >= 50:
        return Verdict("SECURITY_ARCHITECT", f"Blast radius {brs} (HIGH).",
                       "triage.brs_high", 0, failed, 2 - attempt, reviewers + ["@ccabc/appsec"])
    if brs >= 25:
        return Verdict("PEER_REVIEW", f"Blast radius {brs} (MEDIUM).",
                       "triage.brs_medium", 0, failed, 2 - attempt, reviewers)

    # ── autonomous merge: a conjunction of eight conditions ─────────────────
    conditions = {
        "no_blockers": not blockers,
        "brs_below_25": brs < 25,
        "no_zone_touched": not zones,
        "no_contract_touched": semantic.get("contracts_touched", 0) == 0,
        "mutation_score_ok": characterization.get("mutation_score", 0) >= 0.6,
        "no_oracle_invariant_risk": not oracle.get("invariant_risk"),
        "first_attempt": attempt == 1,
        "adapters_not_degraded": not adapter_degraded,
    }
    if all(conditions.values()):
        return Verdict("MERGE_AUTONOMOUS",
                       "All eight autonomy conditions satisfied: low blast radius, no invariant zone, "
                       "no contract surface, adequate mutation score, first attempt, full adapter capability.",
                       "triage.autonomous", 0, failed, 2 - attempt, [])
    unmet = [k for k, v in conditions.items() if not v]
    return Verdict("PEER_REVIEW",
                   f"Autonomy conditions unmet: {unmet}.", "triage.default",
                   0, failed, 2 - attempt, reviewers)


def structured_rejection(findings: list, guidance: str) -> dict:
    """Feedback shaped like the contract, so attempt 2 is a constrained repair rather than a fresh guess."""
    return {
        "blockers": [
            {"detector": f.detector, "location": f.location, "why": f.message,
             "invariant": f.invariant_violated, "exemplar": f.exemplar,
             "runtime_evidence": f.runtime_evidence}
            for f in findings if f.severity == BLOCKER
        ],
        "guidance": guidance,
        "surface_unchanged": True,
    }
