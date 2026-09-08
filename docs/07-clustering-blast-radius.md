# 07 — Topological Clustering, Blast Radius & Effort Scoring

Reference implementations: [`algorithms/guardian/clustering.py`](../algorithms/guardian/clustering.py),
[`algorithms/guardian/blast_radius.py`](../algorithms/guardian/blast_radius.py).

## 7.1 The problem

~1,190 post-triage fix-units must become **40–70 atomic, non-conflicting pull requests**. "Atomic"
means the batch is independently mergeable, independently revertible, and independently verifiable.
"Non-conflicting" means no two open batches may edit the same file, and no batch may invalidate
another's verification.

Getting this wrong in either direction is expensive:

- **Too granular** (1 PR per finding): 1,190 PRs, guaranteed merge conflicts, 1,190 gate runs
  (build+test cost dominates everything), review fatigue, and the exact "conflicting PR cascade"
  failure mode the platform exists to eliminate.
- **Too coarse** (10 mega-PRs): unreviewable, un-revertible, one bad hunk blocks 200 good fixes, and
  blast radius becomes the union of everything.

## 7.2 Fix-unit canonicalisation

Before clustering, each fix-unit is reduced to a comparable shape:

```python
FixUnit = {
  "id": "FU-CCABC-2211",
  "component": "account-service",
  "files": {"…/AccountStatementController.java", "…/StatementThemeResolver.java"},
  "symbols": {"…#getStatement().", "…#fetchTheme()."},
  "module": "account-service:statement",
  "fix_template": "AUTHZ_OBJECT_OWNERSHIP_CHECK",   # canonical remediation pattern
  "dependency_coord": None,                          # set for SCA fix-units
  "contracts": {"openapi:account-service:v3#getStatement"},
  "zones": {"HIZ-CCABC-0031"},
  "sla_deadline": "2026-09-15T00:00:00Z",
  "severity": "CRITICAL",
  "owning_team": "payments-core",
  "language": "java",
}
```

## 7.3 Conflict & affinity graph

Build a weighted undirected graph over fix-units. Two distinct kinds of edge, and conflating them is
the classic mistake:

**Hard conflict edges (must-serialise, never co-batch-forbidden — see below):**

```
same_file(a, b)          → a and b MUST be in the same batch, or in strictly serialised batches
same_symbol(a, b)        → same batch (splitting guarantees a merge conflict)
same_build_file(a, b)    → same batch or serialised (pom.xml, package.json, .csproj)
```

Note the direction: file co-location is a reason to **merge** batches, not to separate them. Two fixes
to one file in two PRs is the conflict; one PR is the cure.

**Affinity weights (should-co-batch, soft):**

| Signal | Weight | Rationale |
|---|---|---|
| Same file | 1.00 (hard) | Mechanical conflict avoidance |
| Same symbol | 1.00 (hard) | Same |
| Same module + same fix template | 0.75 | Agent solves once, applies N times; review is one pattern |
| Same fix template, same component | 0.55 | Reviewer amortisation |
| Same dependency coordinate | 0.90 | One version bump closes N CVEs |
| Shared contract artefact | 0.60 | One contract revision, one consumer-test run |
| Shared invariant zone | 0.50 | One proof-test set, one architect review |
| Same component + same owning team | 0.30 | Review routing coherence |
| Direct call edge between symbols | 0.35 | Coupled semantics |

**Separation constraints.** These fall into two classes, and the distinction is load-bearing.

*Hard (safety) — never relaxed, for any reason, including to hit the batch-count target:*

```
different component              → never co-batch (deploy units must stay independently revertible)
different owning team            → never co-batch (review routing)
different language runtime       → never co-batch
different effective SLA lane     → never co-batch (a batch inherits its strictest member's lane;
                                   hard co-location overrides this and is resolved upstream by
                                   merging those units into a single atom)
whole-symbol FORBID_MODIFY zone  → never in an agent batch at all
mixed AUTHZ zone + unrelated work→ split (keep architect review focused)
batch_blast_radius > 80          → must split
```

*Soft (review ergonomics) — relaxable within a documented ceiling, and any relaxation is reported:*

```
fix_units_in_batch > lane_cap    Lane A 12 (→18), Lane B 25 (→40), Lane C 60 (→80)
files_in_batch > 25              (→35)
```

Soft caps answer "how much should one reviewer read", not "what is safe". When the hard
constraints make the 40–70 band unreachable, the clusterer relaxes soft caps toward the ceiling and
then **reports the residual gap and the binding constraint** — it does not silently emit 90 batches
while claiming the target was met, and it does not break component isolation to make a number look
right. See `constraint_floor()` in the reference implementation.

## 7.4 Clustering algorithm

```
INPUT   F = fix-units (post-triage), G_usg, invariant registry, lane config
OUTPUT  B = batches, with a topological merge order

1. HARD-MERGE       union-find over hard-conflict edges (same file / symbol / build file)
                    → conflict-free "atoms". Nothing may ever split an atom.
2. AFFINITY GRAPH   nodes = atoms; edges = Σ affinity weights, subject to separation constraints
                    (an edge violating any separation constraint is deleted, not down-weighted)
3. COMMUNITY DETECT constrained agglomeration: repeatedly merge the highest-affinity pair that
                    violates no constraint, iterating to a fixed point. Ties break toward the
                    SMALLER combined cluster, which keeps batches evenly sized instead of producing
                    a few cap-sized batches and a long tail of singletons.
                    (Louvain with a resolution parameter is a drop-in alternative at larger estate
                    sizes; the threshold search below plays the same role as resolution tuning.
                    A single greedy pass is NOT sufficient — high-affinity pairs saturate against
                    the size cap and strand partners that could still have been packed.)
4. θ-TUNING         binary search the affinity threshold θ over [0, 1] until 40 ≤ |B| ≤ 70.
                    If unreachable, escalate the SOFT caps in three steps toward their ceiling and
                    retry; if still unreachable, return the best result with the gap and the
                    binding constraint reported.
5. CONSTRAINT CHECK constraints are enforced during merging, not repaired afterwards
6. LANE ASSIGN      batch.sla = min(member deadlines); batch.tier = max(member risk tiers)
                    batch.lane = lane_of(strictest member)
7. TOPO ORDER       DAG over batches:
                      contract producer  →  contract consumer
                      shared library     →  dependents
                      dependency bump    →  code that must compile against it
                    Cycles are broken by pinning the highest-BRS batch first and
                    deferring its counterpart to the next cycle (never by ignoring the edge).
8. LEASE PLAN       assign file/symbol write leases; batches sharing a lease are serialised
                    into a merge train rather than run concurrently
```

**Complexity.** Union-find `O(n·α(n))`. Agglomeration is `O(r · Σ_b |b|²)` where the sum is over
*separation buckets* `(component, team, language, lane)` — pairs across buckets can never merge, so
they are never compared, and this is the difference between a quadratic over 1,200 atoms and a
quadratic over ~40 each. Affinity is evaluated on precomputed set signatures rather than a
cartesian product over members. θ is enumerated over the 6 discrete affinity weights rather than
binary-searched, and cap escalation adds ≤4 passes. **Measured: 0.44 s for 1,190 fix-units**, which
matters because clustering is re-run on every ingest cycle as the backlog shifts.

**Observed on the reference fixture** (`python3 algorithms/demo.py`, 1,190 synthetic fix-units
Pareto-distributed over the 18 components): hard-constraint floor 66 batches; result **77 batches**
with soft caps at their ceiling, zero concurrent file conflicts, lane split A 24 / B 45 / C 8. The
band is missed by 7 and the clusterer says so. The binding constraint is per-component-per-lane
fragmentation: 18 components × up to 3 lanes each sets a hard floor no threshold can go below. The
levers a platform owner has are named explicitly — raise the lane caps, accept the batch count, or
reduce component fragmentation. This is the intended behaviour: **a target the algorithm cannot
reach honestly is reported, not manufactured.**

**Re-clustering stability.** Batches already dispatched to an agent are frozen; re-clustering only
re-partitions the undispatched remainder. Without this, a nightly re-cluster would churn in-flight work
and invalidate contracts mid-execution.

## 7.5 Blast Radius Score (0–100)

`BRS` estimates **systemic regression risk if this change is wrong** — not the severity of the
vulnerability, and not the difficulty of the fix. Those are separate axes (§7.6) and conflating them
produces bad routing.

```
BRS = round( 100 · Σ wᵢ · normᵢ )   , clamped to [0,100], then hard-override rules applied
```

| # | Factor | Weight | Normalisation |
|---|---|---|---|
| 1 | **Graph centrality** — PageRank of touched symbols in the USG | 0.16 | percentile rank within component estate |
| 2 | **Downstream consumers** — distinct components reachable via reverse edges | 0.14 | `min(1, consumers/8)` |
| 3 | **Invariant-zone proximity** — inside zone = 1.0; distance 1 = 0.6; 2 = 0.3; ≥3 = 0 | 0.16 | max over touched zones, weighted by zone class (`AUTHN`/`AUTHZ`/`CRYPTO` ×1.0, `TXN`/`IDEMPOTENCY` ×0.9, others ×0.7) |
| 4 | **Contract exposure** — public API / DTO / proto / Avro / DB schema touched | 0.12 | `min(1, (consumers_of_contract)/5)`; 0 if no contract touched |
| 5 | **Transaction / concurrency involvement** | 0.09 | 1.0 if inside a `TXN`/`CONCURRENCY` zone, 0.5 if calls into one |
| 6 | **Test safety net (inverse)** — line+branch coverage and mutation score of the change surface | 0.11 | `1 − (0.6·coverage + 0.4·mutation_score)` |
| 7 | **Change-failure history** — prior incidents/reverts on these files (365d) | 0.08 | `min(1, incidents/3)` |
| 8 | **Runtime criticality** — endpoint traffic × component tier × business criticality | 0.07 | percentile |
| 9 | **Data sensitivity** — PII/PCI/financial classification of touched fields/tables | 0.04 | class → {0, 0.5, 1.0} |
| 10 | **Cross-component span** — number of distinct components in the change surface | 0.03 | `min(1, (n−1)/3)` |

**Hard overrides (applied after the weighted sum — floors, not additions):**

```
touches AUTHN/AUTHZ/CRYPTO zone      → BRS = max(BRS, 60)   and review_tier ≥ SECURITY_ARCHITECT
touches FORBID_MODIFY zone           → ineligible for agent delegation entirely
breaking contract change detected    → BRS = max(BRS, 70)
touches legacy monolith core         → BRS = max(BRS, 45)
adapter capability degraded (§6.5)   → BRS += 15 uncertainty penalty
mutation score < 0.4 on surface      → BRS = max(BRS, 50)
```

**Bands → default routing:**

| Band | BRS | Default disposition |
|---|---|---|
| LOW | 0–24 | Autonomous merge eligible (if all gates pass and no zone touched) |
| MEDIUM | 25–49 | Standard peer review (CODEOWNERS) |
| HIGH | 50–74 | Security architect review + full gate suite incl. G7 NFR |
| CRITICAL | 75–100 | Human-led remediation; agent may produce analysis and a draft PoC branch only |

The score is always emitted **with its factor decomposition**, because a number a reviewer cannot
interrogate is a number a reviewer will learn to ignore:

```
BRS 68  HIGH
  centrality        0.71 ×0.16 = 0.114
  consumers (3)     0.38 ×0.14 = 0.053
  zone proximity    1.00 ×0.16 = 0.160   ← inside HIZ-CCABC-0031 (AUTHZ)
  contract exposure 0.60 ×0.12 = 0.072   ← openapi v3, 2 consumers + 1 pact
  txn/concurrency   0.50 ×0.09 = 0.045
  test net (inv)    0.44 ×0.11 = 0.048
  change failure    0.33 ×0.08 = 0.027
  runtime crit      0.82 ×0.07 = 0.057
  data sensitivity  1.00 ×0.04 = 0.040
  cross-component   0.33 ×0.03 = 0.010
                             Σ = 0.626 → 63
  override: AUTHZ zone floor 60 (not binding), monolith-adjacent +5 → 68
```

## 7.6 Effort and agent-difficulty tiers

Separate axis, separate model. Effort predicts **whether the agent will succeed**, and is used to set
budgets, pick the number of permitted iterations, and decide whether to even try.

```
E = f( files_touched, languages_touched, cross_component, contract_change_required,
       new_test_scaffolding_required, surface_LOC, cyclomatic_complexity,
       historical_agent_success_rate(fix_template, component, language) )
```

| Tier | Profile | Agent budget | Policy |
|---|---|---|---|
| **T1 trivial** | Single-file, templated, no contract change (e.g. dependency bump, add missing annotation) | 15 min, 1 iteration | Autonomous-eligible |
| **T2 routine** | Single component, ≤5 files, known template | 45 min, 2 iterations | Standard |
| **T3 complex** | Multi-file, invariant-adjacent, new tests needed | 90 min, 3 iterations | Full gate suite |
| **T4 architectural** | Cross-component, contract change, or novel pattern | 120 min, 3 iterations | Human-designed approach; agent implements a human-authored plan |
| **T5 ineligible** | `FORBID_MODIFY` zone, uncharacterisable legacy, or historical success rate < 20% | — | Human-only; platform provides analysis + evidence bundle |

`historical_agent_success_rate` is the term that makes this adaptive: the platform records, per
`(fix_template, component, language)`, the fraction of contracts that reached merge without a gate
rejection. Templates that agents reliably fail get promoted to T4/T5 automatically rather than burning
capacity on repeated rejections. This is the feedback loop that keeps the platform from repeatedly
throwing an agent at problems it structurally cannot solve.

## 7.7 Regression test selection

Per [04 §4.3](04-architectural-intelligence.md), the test set is computed by graph query. The batch's
verification plan enumerates it explicitly so the reviewer can see what was and was not run:

```yaml
verification_plan:
  batch: PR-CCABC-017
  characterization:
    - AccountStatementCharacterizationTest        # 42 golden cases, hash-pinned
  unit:
    - account-service: [AccountStatementServiceTest, StatementThemeResolverTest, AccountAccessPolicyTest]
  integration:
    - account-service: [AccountStatementIT, PartnerThemeIT]
    - core-ledger:     [LedgerStatementDaoIT]      # via WRITES edge on LEDGER.ACCOUNT_STATEMENT
  contract:
    - pact-verify: web-bff@v3 (consumer) vs account-service (provider)
    - openapi-diff: account-v3.yaml (must be non-breaking)
    - avro-compat:  StatementRequested v4 (BACKWARD_TRANSITIVE)
  zone_proof:
    - HIZ-CCABC-0031: negativeAuthMatrix
  e2e:
    - playwright: journeys/statement-download.spec.ts (web-portal micro-frontend)
  nfr:
    - k6: statement_read_p95 < 300ms @ 200rps; txn span count must not increase
  security_reverify:
    - mythos:    MYT-88231 must resolve
    - checkmarx: CX-441902 must resolve; zero new ≥ MEDIUM
    - blackduck: no new CVE, no license class change
  estimated_wall_clock: 34m
```
