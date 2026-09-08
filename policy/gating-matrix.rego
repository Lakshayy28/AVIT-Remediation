# Guardian-AVIT — deterministic triage policy
# Evaluated ONLY after all gates have run. Any BLOCKER short-circuits before the routing rules.
# First matching rule wins; rules are ordered by descending precedence.
package guardian.triage

import rego.v1

default decision := "PEER_REVIEW"

# ── Rejection paths (evaluated first) ────────────────────────────────────────
decision := "REJECT_AND_REISSUE" if {
    count(blockers) > 0
    input.attempt < 2
}

decision := "HUMAN_FIX" if {
    count(blockers) > 0
    input.attempt >= 2
}

# An accurate BLOCKED report is a successful agent outcome, not a failure.
decision := "HUMAN_FIX" if {
    input.patch.agent_outcome == "BLOCKED"
}

# ── Escalation paths ─────────────────────────────────────────────────────────
# A FORBID_MODIFY zone was reachable by the agent at all ⇒ the contract was mis-scoped.
decision := "SECURITY_ARCHITECT" if {
    count(blockers) == 0
    some z in input.risk.zones_touched
    zone_enforcement[z] == "FORBID_MODIFY"
}

decision := "SECURITY_ARCHITECT" if {
    count(blockers) == 0
    some z in input.risk.zones_touched
    zone_class[z] in {"AUTHN", "AUTHZ", "CRYPTO"}
}

decision := "SECURITY_ARCHITECT" if {
    count(blockers) == 0
    input.semantic_diff.contract_breaking == true
}

# BRS >= 75 should never have been delegated; treat reaching here as a policy defect.
decision := "HUMAN_FIX" if {
    count(blockers) == 0
    input.risk.blast_radius >= 75
}

decision := "SECURITY_ARCHITECT" if {
    count(blockers) == 0
    input.risk.blast_radius >= 50
    input.risk.blast_radius < 75
}

decision := "PEER_REVIEW" if {
    count(blockers) == 0
    input.risk.blast_radius >= 25
    input.risk.blast_radius < 50
}

# ── Autonomous merge: a conjunction of eight conditions ──────────────────────
# Autonomy is the narrow exception, not the default. Expected to cover ~30% of volume,
# almost entirely dependency bumps and templated single-file fixes.
decision := "MERGE_AUTONOMOUS" if {
    count(blockers) == 0
    input.risk.blast_radius < 25
    count(input.risk.zones_touched) == 0
    input.semantic_diff.contracts_touched == 0
    input.characterization.mutation_score >= 0.6
    count(input.oracle_review.invariant_risk) == 0
    input.attempt == 1
    not input.adapter_capabilities_degraded
}

# ── Helpers ──────────────────────────────────────────────────────────────────
blockers contains f if {
    some g in input.gates
    some c in g.checks
    c.status == "FAIL"
    c.severity == "BLOCKER"
    f := c.check_id
}

zone_enforcement[z] := e if { some z, e in data.invariants.enforcement }
zone_class[z] := c if { some z, c in data.invariants.class }

# ── Required reviewers ───────────────────────────────────────────────────────
required_reviewers contains "@ccabc/appsec" if { decision == "SECURITY_ARCHITECT" }
required_reviewers contains r if {
    decision in {"PEER_REVIEW", "SECURITY_ARCHITECT"}
    some r in input.ownership.codeowners
}

# Consumer owners must sign off on any contract change, even a non-breaking one.
required_reviewers contains r if {
    input.semantic_diff.contracts_touched > 0
    some r in input.contract_consumer_owners
}
