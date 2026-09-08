# Reference implementations

Stdlib-only Python (3.10+). No external dependencies, no network, no I/O beyond stdout.
These are executable specifications of the decision logic in `docs/`, not a production system.

```bash
python3 algorithms/demo.py      # full end-to-end reference run
python3 algorithms/selftest.py  # assertions over the behaviours the design depends on
```

| Module | Implements | Doc |
|---|---|---|
| `guardian/usg.py` | Universal Symbol Graph: ingress→sink traversal with per-seam confidence, reverse reachability, PageRank | [04](../docs/04-architectural-intelligence.md) |
| `guardian/reachability.py` | T0–T4 tiers, verdict composition, auto-close ceilings, VFP premises, premise-drift invalidation | [03](../docs/03-ingestion-triage.md) |
| `guardian/blast_radius.py` | 10-factor BRS with decomposition, hard override floors, facet-scoped zone handling | [07](../docs/07-clustering-blast-radius.md) |
| `guardian/clustering.py` | Hard atoms, affinity graph, constrained agglomeration to a fixed point, θ search, soft-cap escalation, constraint floor, topological ordering | [07](../docs/07-clustering-blast-radius.md) |
| `guardian/semantic_diff.py` | 8 detector families over language-neutral PatchFacts, deduplicated by (detector, location) | [09](../docs/09-gating-semantic-diff.md) |
| `guardian/gate.py` | Characterization equality with declared deltas, triage matrix, structured rejection | [09](../docs/09-gating-semantic-diff.md) |
| `fixtures.py` | App CCABC topology, invariant zones, both walkthrough patches, synthetic backlog | [10](../docs/10-walkthrough.md) |

## What the reference run demonstrates

1. **Reachability triage** — a genuine VFP auto-closed with an evidence bundle and an armed
   premise-drift watch; a `CRITICAL` unreachable finding held at `FP_PROPOSED` because it exceeds
   the auto-close ceiling; an untelemetried component's T3 tier skipped rather than assumed.
2. **Blast radius 68 / HIGH** with full factor decomposition and the AUTHZ floor.
3. **Clustering** of 1,190 fix-units with zero concurrent file conflicts — and an honest report
   that the 40–70 band was missed by 7 under the hard constraints.
4. **The flawed patch** rejected by 15 semantic-diff findings plus characterization failures,
   including `unmet_expected_delta` — the check proving the fix never actually took effect.
5. **The compliant patch** passing every gate and *still* routing to a security architect.
6. **Autonomy granted** only when all eight conditions hold; the same change on attempt 2 does not
   qualify.

## Caveats

The fixture graph is a 13-node toy, so `centrality` saturates at 1.00 where a production graph
would yield a spread. The synthetic backlog is deliberately fragmented across 18 components to
exercise the constraint floor; a real backlog concentrates more heavily and clusters more easily.
