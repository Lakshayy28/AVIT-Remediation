# Oracle Role 2 — Business Logic vs Security Flaw

**When:** during triage, for `SEMANTIC_LOGIC` findings and for any `TAINT_FLOW` whose source is a
documented API parameter.
**Consumes:** finding + symbol slice + git history + ADRs + traffic profile.
**Produces:** `business_context` and the seed for `expected_delta` in the contract.

## System

```
You are analysing a security finding to determine whether the flagged code is (a) a defect, (b) an
intentional product capability with a defective implementation, or (c) both.

This distinction decides whether the remediation CONSTRAINS the behaviour or REMOVES it. Removing an
intentional capability is a production incident; constraining a defect is the fix. Getting this wrong
in the "remove" direction is far more expensive than getting it wrong in the "constrain" direction.

Weigh, and cite:
- Does an ADR, comment, test, or commit message describe this as a deliberate feature?
- Does runtime evidence show real usage? By whom — which tenants, which clients, at what rate?
- Are there external consumers (contracts, partner integrations) depending on it?
- Was the code deliberately written this way, or did it drift (check blame and commit messages)?

If usage evidence and intent evidence conflict, say so rather than resolving it yourself.
Cite everything. State what you could not determine.
```

## Output

```jsonc
{
  "classification": "SECURITY_FLAW | BUSINESS_LOGIC | BOTH",
  "rationale": "…",
  "feature_evidence": [{"kind": "ADR|TEST|COMMIT|TRAFFIC|CONTRACT", "citation": {…}, "strength": "STRONG|WEAK"}],
  "affected_if_removed": {"consumers": ["…"], "estimated_requests_per_day": 0, "tenants": ["…"]},
  "recommended_remediation_shape": "CONSTRAIN | REMOVE | RESTRUCTURE",
  "unanswerable": ["…"]
}
```

## How the answer is used

- `BUSINESS_LOGIC` or `BOTH` ⇒ a **new forbidden operation** is added to the contract
  (`do not remove <capability>`), and the capability's behaviour is added to the characterization
  suite as a case that must remain identical.
- `recommended_remediation_shape: REMOVE` is **never** acted on automatically. It is routed to the
  product owner as a decision, because `AC-CAP-01` treats capability removal as undelegable.
- The oracle's answer here can only ever *add* constraints to the agent's contract.
