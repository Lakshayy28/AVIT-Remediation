# 00 — Executive Summary

## The thesis

The failure mode described as *"Target-Objective Distortion"* is not an agent-quality problem that
better models will fix. It is a **specification problem**. An autonomous agent handed a repository and
a scanner finding is being given an objective function with exactly one term (`finding.status == CLOSED`)
and an unbounded action space (the whole repo). Stripping a validation rule, widening a catch block,
deleting a DTO field, or adding `// nosec` are all *globally optimal* solutions to that objective.

Guardian-AVIT does not try to make the agent wiser. It changes the optimisation problem:

```
BEFORE:  maximise( scanner_silence )                 subject to: nothing
AFTER:   maximise( scanner_silence )                 subject to:
             change surface  ⊆ allowlist(files, symbols)
             ∀ i ∈ invariants(change_surface): i holds after patch
             behaviour(after) ≡ behaviour(before)    except declared expected_deltas
             contracts(after) compatible-with contracts(before)
             no member of the forbidden-operation set appears in the semantic diff
```

Every one of those constraints is **deterministically checkable**. The LLM/agent layer proposes; the
deterministic layer disposes. **No model output is ever load-bearing for a merge decision.**

## The seven decisions

| # | Decision | Rationale |
|---|---|---|
| **D1** | **Unified ingestion + correlation spine, bifurcated execution lanes.** One normaliser, one graph, one gate; separate schedulers, capacity pools and evidence depths per SLA class. | The highest-value correlations happen precisely where scanners overlap on one symbol. Splitting pipelines re-creates the "conflicting PRs" failure it was meant to avoid. SLA isolation is a *scheduling* property, not a *pipeline* property. See [02](02-pipeline-tradeoff.md). |
| **D2** | **Symbol identity, not line identity.** Every finding is resolved to a stable SCIP symbol coordinate before anything else happens. | Line numbers drift between the scan commit and the fix commit. Everything downstream — correlation, clustering, invariants, blast radius — is a graph query keyed on symbols. |
| **D3** | **Invariants are versioned, human-ratified, in-repo artefacts.** Copilot Chat *proposes* invariants; a human ratifies; the platform *enforces* mechanically. | Creates an auditable trust boundary. An unratified LLM claim can only ever make gating *stricter*, never looser. |
| **D4** | **Behavioural locking before delegation.** Characterization ("golden master") suites are recorded, hash-pinned and made immutable to the agent *before* the agent sees the task; the fix's intended behaviour change is declared upfront as an `expected_delta` set. | Converts "did the agent break something?" from a judgement call into an equality check. Anything that changes and is not in `expected_delta` is a regression, full stop. |
| **D5** | **Deny-by-default change surface in the Remediation Contract.** The agent receives a scoped workspace, an explicit allowlist of editable symbols, a forbidden-operation list, and a `BLOCKED` escape hatch. | Removes the action space that makes distortion cheap. An agent that cannot reach `SecurityConfig.java` cannot corrupt the filter chain. |
| **D6** | **Semantic diffing over graph/AST facts, not text diffs.** ~40 deterministic detectors for known agent workarounds, run before any test executes. | Catches `catch (Exception e) {}`, removed `@PreAuthorize`, renamed DTO fields, added suppressions, disabled tests — the actual observed distortion catalogue. See [policy/anti-cheat-rules.yaml](../policy/anti-cheat-rules.yaml). |
| **D7** | **Concurrency control by symbol-level lease.** At most one open remediation may hold a write lease on a given file/symbol; batches are topologically ordered and merged through per-component merge trains. | This is the direct, mechanical cure for "hundreds of uncoordinated conflicting PRs". |

## Capacity model (illustrative, not measured)

Sizing the platform against the stated inflow. These are **design targets used to size queues and
human review capacity**, not observed results.

```
INFLOW                                     Mythos 5 (AI/semantic)   1,000    SLA  7d
                                           Checkmarx (SAST)         ~900     SLA 30d
                                           BlackDuck (SCA)          ~800     SLA 30d
                                           Prisma (container/IaC)   ~300     SLA 30d
                                                                    ─────
                                                                    3,000

T0  dedup / already-fixed / duplicate fingerprint     −18%    →  2,460
T1–T4 reachability & exploitability pruning (VFP)     −38%    →  1,525   [target 30–45% for SAST/SCA,
                                                                          10–20% for Mythos semantic]
Correlation collapse (N findings → 1 fix-unit)        −22%    →  1,190 fix-units
Topological clustering (≈20 fix-units per batch)              →     58 PR batches   ✓ in 40–70 band
   (the reference run in algorithms/demo.py, on a deliberately fragmented synthetic backlog,
    reaches 77 batches against a hard floor of 66 and reports the 7-batch gap rather than
    breaking a constraint to hide it — see docs/07 §7.4)

LANE SPLIT           Lane-A (7d, Mythos-led)        ~19 batches, all HIZ-reviewed
                     Lane-B (30d, traditional)      ~31 batches
                     Lane-C (dependency/IaC trains) ~8  batches

GATE OUTCOMES (target steady state, after 2 remediation attempts per batch)
                     Autonomous merge      ~30%   (BRS < 25, no HIZ touched)
                     Peer review           ~45%
                     Security architect    ~20%   (HIZ-touching, incl. all AUTHZ/AUTHN)
                     Human-led fix         ~5%    (agent BLOCKED or 2× gate rejection)
```

The economic claim is narrow and deliberate: Guardian-AVIT does not promise that agents fix
everything. It promises that **every agent-authored change is either provably safe or provably
escalated**, and that human attention is spent on the ~25% that actually needs architectural judgement
rather than on triaging 3,000 raw findings and 300 speculative pull requests.

## What this platform explicitly does not do

- It does not decide *whether* a vulnerability is worth fixing (that is risk governance, upstream).
- It does not replace the security architect on High-Invariance Zone changes — it *routes to* them
  with a complete evidence bundle.
- It does not trust Copilot Chat, Devin, or any model to assert that a fix is safe. Models produce
  hypotheses; gates produce verdicts.
