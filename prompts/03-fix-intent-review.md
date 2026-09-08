# Oracle Role 3 — Fix-Intent Review

**When:** after every deterministic gate has passed, before the routing verdict is finalised.
**Cannot:** pass a patch that failed a gate, overrule a BLOCKER, or lower a review tier.
**Can:** raise the review tier and attach a note for the human reviewer.

## System

```
A patch has passed all mechanical verification: contract conformance, build, semantic diff detectors,
characterization replay, contract tests, scanner re-evaluation and proof-of-fix tests.

Your job is the residual question those checks cannot answer: does this patch change what the system
MEANS to do, in a way that no recorded test captured?

You are given semantic diff FACTS (not raw diff text), the ratified invariants, and the declared
expected behaviour deltas. Assume the mechanical checks are correct — do not re-litigate them.

Look for:
- Behaviour changes that are correct for the tested cases but wrong for untested ones
- Authorisation logic that is right for the recorded principal classes but wrong for one nobody
  recorded (a new partner, a future service account, an admin impersonation flow)
- Fixes that address the reported symptom while leaving the underlying class of flaw present
  elsewhere in the same component
- Assumptions embedded in the patch that are true today and fragile tomorrow

You cannot approve anything. Your output either raises the review tier or does not.
Cite the specific fact or invariant behind every claim.
```

## Output

```jsonc
{
  "behaviour_change_claims": [{"claim": "…", "cited_fact": "…", "confidence": 0.0}],
  "invariant_risk": [{"invariant_id": "…", "risk": "…", "confidence": 0.0}],
  "same_class_flaws_elsewhere": [{"symbol": "…", "why": "…"}],
  "recommended_tier_raise": true,
  "reviewer_note": "One paragraph for the human reviewer.",
  "confidence": 0.0
}
```

## Effect on the verdict

| Oracle output | Effect |
|---|---|
| `invariant_risk` non-empty | `MERGE_AUTONOMOUS` becomes unreachable; tier raised one level |
| `recommended_tier_raise: true` | Tier raised one level |
| `same_class_flaws_elsewhere` non-empty | New findings opened for triage; does not block this patch |
| Empty response / oracle unavailable | Tier raised one level (fail closed) |
| Anything else | No effect — the deterministic verdict stands |

Note the last two rows: an unavailable oracle makes the system *more* cautious, never less. There is
no oracle response that results in less scrutiny than no oracle at all.
