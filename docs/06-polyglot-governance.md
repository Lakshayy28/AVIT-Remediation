# 06 — Polyglot & Language-Agnostic Governance

**Directive Question C.** How does the platform maintain uniform semantic visibility, call-graph
tracking and invariant enforcement across Java, Kotlin, C#, TypeScript, Python and frontend JavaScript?

## 6.1 Principle: one identity scheme, one fact model, N adapters

The mistake to avoid is a governance core that "understands Java" with bolt-ons for everything else —
the bolt-ons become second-class, their gates weaken, and the weakest-governed language becomes where
regressions ship. Guardian inverts this: **the core understands nothing about any language.** It
consumes two normalised streams:

1. **Symbols and edges** → the Universal Symbol Graph.
2. **Patch facts** → the semantic diff engine.

Everything language-specific lives behind the `LanguageAdapter` interface. The core's detectors,
scoring, clustering and gates operate exclusively on the normalised model.

```
     Java   Kotlin   C#    TypeScript   Python   JS/JSX
       │      │      │         │          │        │
   ┌───▼──────▼──────▼─────────▼──────────▼────────▼───┐
   │            LanguageAdapter implementations         │
   │  index() · facts() · detectors() · build() ·       │
   │  test() · coverage() · characterize() · mutate()   │
   └───────────────────────┬───────────────────────────┘
                           │  SCIP symbols + normalised PatchFacts
   ┌───────────────────────▼───────────────────────────┐
   │  LANGUAGE-AGNOSTIC CORE                           │
   │  USG · reachability · invariants · clustering ·   │
   │  blast radius · semantic diff · gates · policy    │
   └───────────────────────────────────────────────────┘
```

## 6.2 Symbol identity: SCIP as the universal coordinate

Cross-language identity is solved by adopting **SCIP** (SCIP Code Intelligence Protocol) as the symbol
naming scheme. Every mainstream language has an SCIP or LSIF indexer, and the format gives globally
unique, stable, language-tagged symbol strings:

```
scip-java   maven ccabc/account-service 3.4.1 com/ccabc/account/AccountStatementController#getStatement().
scip-dotnet nuget Ccabc.Ledger 2.9.0 Ccabc.Ledger.StatementService`0#LoadAsync().
scip-ts     npm @ccabc/web-bff 1.7.2 src/routes/statement.ts/getStatement().
scip-python pypi ccabc-riskcalc 0.8.1 riskcalc/engine/__init__:score().
```

Why this matters concretely: the fingerprint, the change surface allowlist, the invariant zone
membership, the coverage map and the blast-radius query are **all keyed on the same string form**
regardless of language. A `FORBID_MODIFY` zone can span a Java filter and a TypeScript middleware in
one record, and the enforcement code does not branch on language.

Cross-language *edges* are not symbol resolution — they are seam resolution, handled by the contract
and runtime binders described in [04 §4.1](04-architectural-intelligence.md).

## 6.3 The LanguageAdapter contract

```python
class LanguageAdapter(Protocol):
    language: str
    capabilities: set[Capability]     # declared, not assumed — see §6.5

    # ── Knowledge ────────────────────────────────────────────────
    def index(self, repo: RepoRef, commit: str) -> ScipIndex: ...
    def call_edges(self, idx: ScipIndex) -> Iterator[Edge]: ...
    def framework_ingress(self, idx: ScipIndex) -> Iterator[IngressPoint]: ...
    def annotations(self, symbol: SymbolId) -> list[AnnotationFact]: ...
    def contracts(self, repo: RepoRef) -> list[ContractArtifact]: ...

    # ── Change analysis ──────────────────────────────────────────
    def patch_facts(self, before: Tree, after: Tree) -> PatchFacts:
        """THE critical method: normalise an AST-level delta into language-neutral facts."""
    def detectors(self) -> list[Detector]:      # compiled from the shared rule DSL

    # ── Execution ────────────────────────────────────────────────
    def build(self, ws: Workspace) -> BuildResult: ...
    def test(self, ws: Workspace, selection: TestSelection) -> TestResult: ...
    def coverage(self, ws: Workspace) -> CoverageMap: ...
    def characterize(self, ws: Workspace, surface: Surface) -> CharacterizationSuite: ...
    def mutate(self, ws: Workspace, surface: Surface) -> MutationScore: ...
```

### Per-language tooling

| Language | Index | Call graph / dataflow | Pattern detectors | Build / test | Coverage | Characterization |
|---|---|---|---|---|---|---|
| Java / Kotlin | scip-java | CodeQL + Soot/WALA; Spring bean graph from context metadata | Semgrep + CodeQL + custom AST rules | Maven/Gradle, JUnit | JaCoCo | JUnit golden-master + WireMock replay; PIT for mutation |
| C# (.NET Fx & Core) | scip-dotnet | Roslyn symbol/dataflow analysis + DI container graph | Roslyn analyzers + Semgrep | MSBuild/dotnet, xUnit/NUnit | coverlet | Snapshot tests + WireMock.NET; Stryker.NET |
| TypeScript / Node | scip-typescript | TS compiler API + ts-morph; route registry extraction | ESLint custom rules + Semgrep + CodeQL | npm/pnpm, Jest/Vitest | nyc / c8 | Supertest + nock/Polly.js recordings; Stryker |
| Python | scip-python | Jedi/pyright + PyCG; framework route extraction | Semgrep + Bandit-derived rules | pip/poetry, pytest | coverage.py | pytest + VCR.py cassettes; mutmut |
| React / Angular | scip-typescript | Component/router graph, prop & store dataflow | ESLint + Semgrep (DOM sinks, XSS) | Vite/webpack, Jest/Karma | c8 / istanbul | Playwright journeys + DOM snapshots; visual diff |

`CodeQL` is deliberately used where it spans multiple languages — it gives one query language for
taint reachability across Java, C#, TS/JS and Python, which reduces the number of independent
reachability implementations that must be kept semantically aligned.

## 6.4 The neutral fact model (`PatchFacts`)

Semantic diffing must be identical in *meaning* across languages, so each adapter lowers its
AST delta into a shared vocabulary. This is what allows one anti-cheat catalogue (D6) to govern six
languages.

```jsonc
{
  "language": "java",
  "symbol": "scip-java … AccountStatementController#getStatement().",
  "changes": [
    {"fact": "ANNOTATION_REMOVED",  "name": "PreAuthorize", "target": "method",
     "prev_value": "@accountAccessPolicy.canRead(#id, authentication)"},
    {"fact": "SIGNATURE_CHANGED",   "prev": "(String,String,Principal)", "next": "(String,Principal)",
     "visibility": "public", "removed_params": ["themeCallbackUrl"]},
    {"fact": "EXCEPTION_HANDLER_BROADENED", "prev": "catch(LedgerNotFoundException)",
     "next": "catch(Exception)", "body_effect": "SWALLOWS"},
    {"fact": "TXN_ATTRIBUTE_CHANGED", "prev": "readOnly=true", "next": "readOnly=false"},
    {"fact": "SUPPRESSION_ADDED", "kind": "checkmarx", "token": "// checkmarx-disable-next-line"},
    {"fact": "DTO_FIELD_REMOVED", "type": "StatementRequest", "field": "themeCallbackUrl"},
    {"fact": "TEST_DISABLED", "test": "…#negativeAuthMatrix", "mechanism": "@Disabled"},
    {"fact": "GUARD_CLAUSE_REMOVED", "predicate": "tenantId.equals(account.tenantId())"}
  ]
}
```

The equivalent TypeScript facts for the same class of misbehaviour lower to the *same* fact names:

| Neutral fact | Java | C# | TypeScript | Python |
|---|---|---|---|---|
| `AUTHZ_MARKER_REMOVED` | `@PreAuthorize` deleted | `[Authorize]` deleted | `requireOwner()` middleware removed from route | `@login_required` removed |
| `EXCEPTION_HANDLER_BROADENED` | `catch (Exception e) {}` | `catch (Exception) { }` | `catch (e) { /* ignore */ }` | `except Exception: pass` |
| `VALIDATION_REMOVED` | `@Valid` / `@NotNull` deleted | `[Required]` deleted | `zod` schema field relaxed | `pydantic` field validator removed |
| `CONTRACT_FIELD_REMOVED` | DTO field | DTO property | interface property / GraphQL field | dataclass / pydantic field |
| `SUPPRESSION_ADDED` | `@SuppressWarnings`, `// checkmarx-disable` | `#pragma warning disable` | `// eslint-disable`, `// nosemgrep` | `# noqa`, `# nosec` |
| `RATE_LIMIT_WEAKENED` | bucket4j config | policy attribute | `express-rate-limit` options | slowapi limits |

One detector — `ANTI_CHEAT_AUTHZ_MARKER_REMOVED` — then fires identically on all six runtimes.

## 6.5 Capability declaration and degradation policy

Not every language supports every tier equally, and pretending otherwise is how weak governance hides.
Adapters **declare** capabilities; the core reads the declaration and degrades explicitly.

```yaml
capability_matrix:
  java:       {static_dataflow: FULL,    call_graph: FULL,    mutation: FULL,    runtime_cov: FULL}
  kotlin:     {static_dataflow: FULL,    call_graph: FULL,    mutation: PARTIAL, runtime_cov: FULL}
  csharp:     {static_dataflow: FULL,    call_graph: FULL,    mutation: PARTIAL, runtime_cov: FULL}
  typescript: {static_dataflow: PARTIAL, call_graph: PARTIAL, mutation: PARTIAL, runtime_cov: FULL}
  python:     {static_dataflow: PARTIAL, call_graph: PARTIAL, mutation: PARTIAL, runtime_cov: PARTIAL}
  javascript: {static_dataflow: WEAK,    call_graph: WEAK,    mutation: NONE,    runtime_cov: PARTIAL}
```

Degradation rules (mechanical, not discretionary):

```
static_dataflow < FULL   ⇒ reachability confidence capped at MEDIUM
                         ⇒ no automatic VFP closure (FP_PROPOSED only, analyst confirms)
call_graph      < FULL   ⇒ blast radius adds +15 uncertainty penalty
                         ⇒ characterization coverage requirement raised (behavioural evidence
                            substitutes for structural evidence)
mutation        == NONE  ⇒ characterization suite must be traffic-recorded, not synthesised
                            (you cannot trust a generated test you cannot score)
runtime_cov     < FULL   ⇒ T3 tier is skipped rather than assumed negative
```

Dynamic languages get *stricter behavioural verification* precisely because they get *weaker static
verification*. The total assurance level is held roughly constant across the estate; what varies is
which evidence supplies it. That is the honest answer to "uniform governance across a polyglot
footprint" — uniform **assurance**, not uniform **mechanism**.

## 6.6 Frontend specifics

Micro-frontends (React, Angular) need three adjustments the backend model does not:

- **Ingress is user input, not HTTP.** Event handlers, router params, `postMessage`, `localStorage`
  reads, and URL fragments are the sources; DOM sinks (`innerHTML`, `dangerouslySetInnerHTML`,
  Angular `bypassSecurityTrust*`) are the sinks.
- **The security boundary is server-side.** A frontend "authorisation check" is UX, never a control.
  The invariant registry tags frontend guards as `UX_ONLY` so that an agent removing one is not
  treated as an `AUTHZ` breach — but an agent *adding* a frontend check to "fix" a server-side BOLA
  is flagged as `INEFFECTIVE_REMEDIATION`, which is a real and common agent failure.
- **Characterization is visual + DOM snapshot + network contract**, via Playwright: recorded journeys
  with DOM structure snapshots and asserted outbound API calls.

## 6.7 Legacy monolith specifics (Java EE / .NET Framework)

The oldest components are where static analysis is weakest and blast radius is highest — the worst
combination, and the one requiring explicit compensation:

| Problem | Compensation |
|---|---|
| Reflection, XML-wired beans, dynamic proxies | Container-metadata-driven edge extraction; unresolved dispatch ⇒ `LOW` confidence ⇒ no auto-close, no autonomous merge |
| No test harness / untestable God classes | Characterization by **traffic replay against a shadow instance** rather than by unit test; if even that is impossible, the component is `AGENT_INELIGIBLE` and findings route to humans with analysis support only |
| Shared mutable static state, shared DB coupling | `WRITES`-edge modelling on `Table` nodes; any patch touching a table written by ≥2 components gets +20 blast radius and mandatory cross-component integration tests |
| Build times measured in tens of minutes | Pre-warmed build caches per component; batch size caps tuned to keep gate wall-clock inside the lane budget |
| Transaction boundaries spanning many classes | `TXN` zone spans the whole propagation subtree, not just the annotated method — computed transitively at index time |

**Declaring components ineligible is a supported outcome.** A platform that claims uniform automation
over a 20-year-old monolith it cannot characterise is lying about its assurance level; one that marks
those components `ANALYSIS_ONLY` and routes them to humans is telling the truth and is still useful —
triage, reachability, correlation, clustering and blast radius all still apply.
