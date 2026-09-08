# 02 — Pipeline Trade-off: Unified vs Bifurcated

**Directive Question A.** Should AI-discovered vulnerabilities (Mythos 5, 7-day SLA, semantic/business
logic context) run through an isolated dedicated pipeline, or should all scanner inputs feed a unified
ingestion and clustering engine with tiered priority execution?

## 2.1 Recommendation

> **Unify the spine. Bifurcate the lanes.**
>
> One normaliser, one symbol resolver, one Universal Symbol Graph, one correlation engine, one
> semantic-diff engine, one gate pipeline, one evidence store.
> **Separate** schedulers, WIP limits, agent capacity pools, reasoning depth, and default gate
> strictness per finding class.

Concretely: a Mythos BOLA finding and a Checkmarx SSRF finding are the *same kind of object* the moment
they are resolved to a symbol coordinate. What legitimately differs between them is not the plumbing —
it is **how much reasoning they deserve, how fast they must move, and how suspicious the gate should be
of the resulting patch.** Those are configuration on a shared path, not a second path.

## 2.2 The decision framed properly

The instinct to bifurcate is really three separate anxieties wearing one coat. Separating them
dissolves most of the argument:

| Anxiety | Is it real? | Does it require a separate pipeline? |
|---|---|---|
| "The 7-day SLA will be starved by 2,000 low-priority findings" | **Real** | **No.** This is a scheduling problem — priority lanes, reserved capacity, WIP limits. |
| "Semantic findings need much deeper context than a CVE bump" | **Real** | **No.** This is a per-class reasoning-depth policy on a shared engine. |
| "A noisy SCA batch job could break Mythos processing" | **Real** | **No.** This is a fault-isolation problem — separate consumer groups, bulkheads, per-lane rate limits. |
| "Correlating across scanners is valuable" | **Real** | **Yes — and it requires the opposite of bifurcation.** |

Only the fourth is an actual *architectural* driver, and it points to unification.

## 2.3 The case for unification: the collision case is the expensive case

The scenario the directive raises — a BlackDuck SCA upgrade, a Checkmarx taint path, and a Mythos BOLA
finding all touching the exact same service method — is not an edge case. In a Spring Boot service it
is the *normal* state of a controller method that handles money.

With **bifurcated pipelines**, that method receives:

```
Pipeline A (Mythos)      → Devin contract #1 → PR-A  edits AccountStatementController#getStatement
Pipeline B (traditional) → Devin contract #2 → PR-B  edits AccountStatementController#getStatement
Pipeline B (traditional) → Devin contract #3 → PR-C  bumps spring-web in the same pom.xml
```

Three agents, three worktrees, no shared knowledge, three merge conflicts, and — worse — **three
mutually invalidating gate runs**. PR-A passes its characterization suite against `main`; PR-B passes
against `main`; both merge; the composite behaviour was never tested. This is precisely the
"uncoordinated conflicting PRs and regression cascades" failure the platform exists to prevent. A
bifurcated architecture *institutionalises* it.

With the **unified spine**, the correlation engine collapses those three findings into one fix-unit
(or, for the dependency bump, an explicitly *sequenced* sibling batch holding a lease on the same
build file), producing one contract, one agent run, one characterization lock, one gate run, one PR.

Second-order wins that only exist when the spine is shared:

- **Cross-scanner evidence fusion.** A Checkmarx taint path is a *hypothesis about dataflow*; Mythos's
  semantic model is a *hypothesis about intent*; runtime traces are *observation*. Fusing all three
  raises reachability confidence far above what any single lane could justify, which is what makes
  aggressive VFP auto-closure defensible at all.
- **False-positive learning transfers.** "This sanitiser is effective" learned in the SAST lane
  suppresses noise in the Mythos lane, and vice versa.
- **One anti-cheat catalogue.** Agent workarounds are agent behaviours, not finding-class behaviours.
  Devin swallowing an exception looks identical whether it was chasing a BOLA or a taint path. A split
  architecture maintains two detector catalogues that drift apart, and the weaker one becomes the
  attack surface.
- **One audit story.** Regulators and internal audit ask "show me every autonomous change to
  App CCABC and its evidence." One evidence store answers that; two answer it twice, inconsistently.

## 2.4 The case for bifurcation, taken seriously

These are the genuine costs of unification, and the mitigation each one gets:

| Cost of unifying | Why it bites | Mitigation in this design |
|---|---|---|
| **Head-of-line blocking**: a 900-finding Checkmarx batch ingests ahead of a critical Mythos finding | 7-day SLA is a hard blocker; queueing behind bulk work is unacceptable | Lane-partitioned Kafka topics + weighted-fair scheduling; **Lane A holds a reserved 40% of agent capacity and 100% priority pre-emption on the graph query pool**. Bulk lanes run with strict WIP caps. |
| **Coupled deploys**: a bug in the SCA adapter blocks Mythos processing | Shared code = shared blast radius | Adapters are independently deployed sidecars behind a versioned `ScanBatch` interface; only the *normalised* path is shared, and it is the most stable, most tested component. Per-lane consumer groups and circuit breakers. |
| **Lowest-common-denominator modelling**: forcing a container IaC drift and a business-logic bypass into one schema | Real risk of a mushy schema that serves neither | The Canonical Vulnerability Record has a **small mandatory core + typed `class_payload` discriminated union** (`SEMANTIC_LOGIC`, `TAINT_FLOW`, `DEPENDENCY_CVE`, `INFRA_DRIFT`). Shared where genuinely shared; typed where genuinely different. See [schemas/canonical-vulnerability.schema.json](../schemas/canonical-vulnerability.schema.json). |
| **Reasoning cost blowout**: running the deep Copilot oracle on 800 CVE bumps is wasteful and slow | Oracle calls are the expensive step | Reasoning depth is a **policy keyed on `class_payload.type` and blast radius**, not on pipeline identity. `DEPENDENCY_CVE` with BRS < 25 skips the oracle entirely; `SEMANTIC_LOGIC` always invokes it. |
| **Different SLA clocks in one workflow** | A batch mixing 7d and 30d items has an ambiguous deadline | Deterministic rule: **a batch inherits the strictest SLA and the highest risk tier of its members.** Co-location on a symbol dominates SLA convenience — splitting a batch to preserve a comfortable deadline re-introduces the conflict problem. |

## 2.5 What "tiered execution" actually looks like

```
                    ┌──────────────── SHARED SPINE ─────────────────┐
 Mythos ─┐          │ Adapters → Normalise → Symbol resolve →       │
 Cx     ─┤          │ Fingerprint → Reachability → Correlate        │
 BD     ─┤ ───────► │                                               │ ──┐
 Prisma ─┘          │ (one USG, one contract registry, one IR)      │   │
                    └───────────────────────────────────────────────┘   │
                                                                        ▼
                            ┌──────────────── LANE SPLIT ────────────────────┐
                            │                                                │
              LANE A (7d, semantic)          LANE B (30d, traditional)   LANE C (dep/IaC trains)
              ─────────────────────          ────────────────────────    ─────────────────────
  oracle      always (full payload)          on BRS≥40 or contract touch  never (template fixes)
  capacity    40% reserved, pre-emptive      45%                          15%
  WIP cap     12 concurrent contracts        25                           6 (serialised per build file)
  char. suite mandatory + negative-auth      mandatory                    smoke + contract tests only
              matrix + event snapshots
  gates       G0–G8 (all)                    G0–G6, G7 if HIZ             G0,G1,G4,G5,G8
  autonomy    never autonomous if HIZ        autonomous if BRS<25         autonomous if BRS<25 and
              touched                                                     no major-version bump
  batch size  ≤12 fix-units (tight review)   ≤25                          ≤60 (mechanical)
                            │                                                │
                            └────────────► SHARED GATE + MERGE ◄─────────────┘
                              semantic diff · G-pipeline · policy · merge trains · evidence
```

The lanes differ in **policy values**, not in code paths. That is the whole recommendation in one
sentence.

## 2.6 Falsification criteria

State up front what would make this recommendation wrong, so the decision is reviewable rather than
dogmatic. Revisit unification if any of the following becomes true:

1. **Cross-scanner symbol collision rate < 5%.** If Mythos and traditional findings essentially never
   touch the same symbols, the correlation benefit evaporates and the coupling cost dominates.
   *Measure this in Phase 0 before building the correlation engine* — it is a one-week analysis over
   existing scan exports, and it is the single most decision-relevant number in this document.
2. **Lane A p95 time-to-contract exceeds 24h due to shared-resource contention** after fair-scheduling
   tuning. That would mean the bulkheads are insufficient and physical separation is required.
3. **Regulatory requirement for physical isolation** of AI-discovered findings (some regimes require
   segregated processing/retention for AI-generated security intelligence).
4. **The `class_payload` union grows past ~6 variants with < 30% shared core fields** — the schema is
   telling you the domains genuinely diverged.

## 2.7 Decision record

```
ADR-001  Unified ingestion/correlation spine with lane-bifurcated execution
Status   Accepted (design)
Context  3,000+ AVITs/cycle across 4 scanners, two SLA classes, 18+ components,
         agent-authored fixes, documented conflicting-PR failure mode.
Decision Single normalisation → symbol resolution → reachability → correlation → clustering path.
         Lane-scoped scheduling, capacity, reasoning depth and gate profiles.
         Batches inherit strictest SLA and highest risk tier of members.
Drivers  Cross-scanner collision on shared symbols is the dominant source of agent-induced
         regression; a split pipeline cannot see the collision and therefore cannot prevent it.
Rejected (a) Fully isolated Mythos pipeline — loses correlation exactly where it matters most,
             duplicates the anti-cheat catalogue, doubles the audit surface.
         (b) Fully unified including scheduling — head-of-line blocking violates the 7-day blocker.
Review   Re-evaluate on any falsification criterion in §2.6; mandatory review at Phase 2 exit.
```
