# Guardian-AVIT

**An autonomous supervisory and deterministic gating platform for agentic vulnerability remediation.**

Guardian-AVIT is an architectural control layer that sits between vulnerability detection telemetry
(Mythos 5, Checkmarx, BlackDuck, Prisma Cloud) and autonomous coding agents (Devin, GitHub Copilot
coding agent). It exists because of one structural fact:

> **A coding agent optimises the objective you give it. If the objective is "make the scanner
> stop reporting this", the cheapest satisfying strategy is almost never the correct fix.**

Guardian-AVIT replaces the implicit objective *"silence the finding"* with an explicit, machine-checkable
objective: *"resolve the finding **while** provably preserving a named set of behavioural invariants,
inside a named change surface, evidenced by a named set of tests."*

App footprint under governance: **App ID `CCABC`**, 18+ polyglot components (Java EE / .NET Framework
monolith cores, Spring Boot / Kotlin / .NET Core microservices, Node.js + Python BFF/edge, React &
Angular micro-frontends, Spring Batch / Quartz workers).

---

## Read in this order

| # | Document | What it answers |
|---|---|---|
| 00 | [Executive Summary](docs/00-executive-summary.md) | The thesis, the seven design decisions, capacity model |
| 01 | [End-to-End Architecture](docs/01-architecture.md) | Component diagram, planes, data stores, runtime topology |
| 02 | [Pipeline Trade-off: Unified vs Bifurcated](docs/02-pipeline-tradeoff.md) | **Question A.** Recommendation + the analysis behind it |
| 03 | [Ingestion, Triage & False-Positive Elimination](docs/03-ingestion-triage.md) | Normalisation, reachability tiers, VFP evidence, SLA partitioning |
| 04 | [Architectural Intelligence & Invariant Indexing](docs/04-architectural-intelligence.md) | The Universal Symbol Graph, High-Invariance Zones |
| 05 | [Copilot Chat as a Reasoning Oracle](docs/05-copilot-chat-oracle.md) | **Question B.** Payloads, grounding, output contracts, trust boundary |
| 06 | [Polyglot & Language-Agnostic Governance](docs/06-polyglot-governance.md) | **Question C.** SCIP identity, adapter contract, degradation policy |
| 07 | [Clustering, Blast Radius & Effort](docs/07-clustering-blast-radius.md) | 1,000+ AVITs → 40–70 conflict-free PRs; BRS 0–100 |
| 08 | [Bounded Agent Delegation](docs/08-bounded-delegation.md) | The Remediation Contract; behavioural locking |
| 09 | [Deterministic Gating & Semantic Diffing](docs/09-gating-semantic-diff.md) | Anti-cheat catalogue, G0–G8 pipeline, triage matrix |
| 10 | [Concrete Walkthrough: BOLA + SSRF](docs/10-walkthrough.md) | End-to-end trace with real code, flawed fix, rejection, compliant fix |
| 11 | [Operating Model & Rollout](docs/11-operating-model.md) | Phasing, SLOs, failure modes, human roles |

## Machine-readable artefacts

```
schemas/     JSON Schema for the three core interfaces (+ worked examples)
policy/      Invariant tagging rules, anti-cheat detector catalogue, gating matrix (OPA-shaped)
prompts/     Structured Copilot Chat oracle prompts with grounding constraints
algorithms/  Runnable reference implementations (stdlib-only Python)
adapters/    Scanner normalisation adapter contract
```

## Run the reference implementation

The algorithms are not pseudocode — they execute against a fixture modelling the `CCABC` footprint
and the walkthrough scenario.

```bash
python3 algorithms/demo.py      # end-to-end reference run (~1s)
python3 algorithms/selftest.py  # 43 assertions over the behaviours the design depends on
```

The demo runs: reachability triage and VFP closure → correlation → blast-radius scoring →
topological clustering of 1,190 fix-units → semantic diff of the flawed patch → gate verdict →
semantic diff of the compliant patch → gate verdict → the autonomy boundary.

Every number reported in the docs that the code can compute — BRS 68, the detector set that fires
on the flawed patch, the characterization outcome, each triage verdict — is produced by these
modules, not transcribed. Where the reference run disagrees with an illustrative figure in the
docs (notably the batch count), the docs say so and explain why.
