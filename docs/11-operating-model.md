# 11 — Operating Model, Rollout & Failure Modes

## 11.1 Phased rollout

Build the observation layers before the action layers. A platform that starts by dispatching agents
has no baseline against which to judge whether it is helping.

| Phase | Duration | Scope | Exit criteria |
|---|---|---|---|
| **P0 — Measure** | 3–4 wks | Ingestion + normalisation + symbol resolution only. No graph, no agents. Compute the cross-scanner symbol collision rate ([02 §2.6](02-pipeline-tradeoff.md) falsification criterion #1). | Collision rate measured; ADR-001 confirmed or revised. Fingerprint stability ≥ 95% across two consecutive scans. |
| **P1 — See** | 6–8 wks | USG for 3 pilot components (one Spring Boot, one Node BFF, one legacy monolith). Reachability T0–T2. VFP as *proposals* only, analyst-confirmed. | ≥ 90% analyst agreement with FP proposals over 200 samples. Graph seam resolution validated against traces. |
| **P2 — Judge** | 6–8 wks | Invariant registry, oracle integration, blast radius, clustering. Still no agent dispatch — outputs reviewed by humans doing the fixes manually. | Architects agree with BRS band on ≥ 85% of a sample. Batch plan accepted by component owners. |
| **P3 — Act (shadow)** | 8 wks | Agents dispatched under contracts; patches gated but **never merged** — humans fix in parallel and the two are compared. | Gate catches ≥ 95% of injected defects (red-team suite). No gate false-positive rate > 10%. |
| **P4 — Act (bounded)** | ongoing | Autonomous merge enabled **only** for BRS < 25, no-zone, no-contract fix-units in 2 pilot components. Everything else routes to review. | 30 consecutive autonomous merges with zero post-merge reverts before widening scope. |
| **P5 — Scale** | ongoing | Widen component coverage one at a time; each new component requires an adapter capability declaration and a characterization feasibility assessment. | Per-component gates. |

The red-team suite in P3 is essential and easy to skip: a library of **deliberately flawed patches**
(the Step-4 patch from the walkthrough is specimen #1) replayed against the gate pipeline on every
detector change. Gates are software; software regresses; a gate that silently stops detecting
`AC-ERR-04` is worse than no gate because it carries the platform's endorsement.

## 11.2 Human roles

| Role | Owns | Touches |
|---|---|---|
| **Security Architect** | Invariant ratification; `AUTHN`/`AUTHZ`/`CRYPTO` reviews; risk acceptance | ~20% of batches |
| **Component Owner (CODEOWNERS)** | Peer review of `MEDIUM` band; characterization feasibility for their component | ~45% of batches |
| **AppSec Analyst** | VFP proposals below auto-close threshold; SLA risk register; scanner tuning | Triage queue |
| **Platform SRE** | Graph freshness, adapter health, sandbox capacity, gate wall-clock | Platform |
| **Product Owner** | Capability-removal decisions (`AC-CAP-01`), partner-contract questions from `unanswerable` | Rare, high-stakes |

The design target is that a human's attention is only requested with a **complete evidence bundle and
a narrow, well-posed question**. "Review this PR" is a bad ask; "is `owner-tenant OR LEDGER_READ_ALL`
the correct policy — everything else is verified unchanged" is a good one.

## 11.3 Platform SLOs and the metrics that matter

| Metric | Target | Why it is the one to watch |
|---|---|---|
| **Post-merge revert rate on autonomous merges** | < 0.5% | The single number that determines whether autonomy is expanded or withdrawn |
| **Escaped-defect rate** (regression found in prod that gates should have caught) | 0 for HIZ-touching; < 1% overall | Each occurrence produces a new detector and a red-team specimen |
| **VFP reopen rate** (auto-closed findings later shown reachable) | < 2% | Directly measures whether reachability confidence thresholds are honest |
| Gate false-positive rate (blocked patches later confirmed correct) | < 10% | Above this, engineers route around the platform |
| Lane A p95 time-to-merge | < 5 days | 7-day SLA with margin |
| Agent contract success rate (merged or accurately BLOCKED) | > 70% | Below this, contracts are under-specified, not agents under-capable |
| Human review minutes per merged fix | decreasing | The actual value proposition |
| Findings closed per human-hour | increasing | — |

Explicitly **not** a target: *number of findings auto-closed* or *percentage of fixes automated*.
Optimising those produces exactly the behaviour the platform exists to prevent — a system rewarded for
closing findings will find a way to close findings.

## 11.4 Platform failure modes

| Failure | Detection | Response |
|---|---|---|
| Graph staleness → wrong reachability, wrong blast radius | Every verdict records `graph_snapshot_id`; freshness alarm at > 6h behind `main` | Gate verdicts computed against a stale snapshot are invalidated and re-run |
| Adapter drift (scanner changes export format) | Schema validation on every batch; row-level quarantine | Halt the batch, alert; never partially ingest a mis-mapped batch |
| Characterization suite rots (flaky golden cases) | Flake detection on repeated runs pre-dispatch | Quarantine flaky cases *before* issuing a contract; a flaky oracle produces both false rejections and false confidence |
| Detector regression | Red-team suite on every policy change (CI for the gates themselves) | Block policy deploy |
| Oracle unavailable / degraded | Timeout + `ORACLE_UNAVAILABLE` | Escalate tier; never proceed with reduced scrutiny |
| Agent adversarial iteration against gates | Attempt cap = 2; patterns of near-miss patches flagged | `HUMAN_FIX`; review whether a gate is being probed |
| Lease deadlock across batches | Lease timeout + topological cycle detection at plan time | Break cycle by BRS priority, defer counterpart to the next cycle |
| **Platform becomes a rubber stamp** | Autonomous-merge share climbing while review minutes fall to zero | Quarterly audit: sample merged autonomous changes and re-review manually. If the sample finds defects, autonomy scope contracts automatically |

The last row is the governance failure mode that matters most, and it is cultural rather than
technical: a control layer that always says yes is indistinguishable from no control layer. The
sampling audit is the mechanism that keeps the platform's own claims falsifiable.

## 11.5 Cost model sketch

Dominant costs, in order:

1. **Gate compute** — builds and tests dominate everything else. Mitigations: cheapest-first gate
   ordering (G0/G2 reject most bad patches in < 1 min), aggressive build caching, test-impact
   selection rather than full-suite runs, ephemeral environments pooled per component.
2. **Graph indexing** — nightly full + per-merge incremental. Scales with LOC, not with findings.
3. **Agent execution** — bounded per contract by budget; the attempt cap of 2 puts a hard ceiling on
   the worst case.
4. **Oracle calls** — lane- and BRS-gated, cached on `payload_sha256`. Lane C never calls.

The economics work because the expensive resources (agent time, gate compute, human review) are all
allocated by the same deterministic risk model rather than uniformly across 3,000 findings.

## 11.6 Open questions carried into implementation

Stated as risks rather than resolved, because pretending otherwise would misrepresent the design's
maturity:

1. **Characterization feasibility on the legacy monolith is unproven.** If neither traffic replay nor
   generated tests reach an acceptable mutation score, those components are `ANALYSIS_ONLY` and the
   automation benefit is limited to triage, correlation and routing. This should be spiked in P1, not
   discovered in P4.
2. **Copilot Chat endpoint capabilities vary by enterprise entitlement.** The `ReasoningOracle`
   abstraction limits the blast radius of that uncertainty, but the payload size limits and rate
   limits of the specific available surface must be measured before Lane A capacity is sized.
3. **Cross-scanner symbol collision rate is assumed, not measured.** It is the load-bearing assumption
   under ADR-001 and is cheap to measure — P0 exists to settle it.
4. **Ownership of the invariant registry** is an organisational question. If security architecture
   cannot sustain the ratification throughput, the registry becomes the bottleneck for the whole
   platform, and the phased rollout should be paced to their capacity rather than to engineering's.
