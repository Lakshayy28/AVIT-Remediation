# 04 — Cross-Component Architectural Intelligence & Invariant Indexing

## 4.1 The Universal Symbol Graph (USG)

A single property graph spanning all 18+ components of App `CCABC`. It is the substrate for
reachability, correlation, clustering, blast radius, invariant proximity and regression-test selection
— every one of those is a traversal on this graph, which is why it is built once and shared (D1).

### Node types

| Node | Key | Notable properties |
|---|---|---|
| `Component` | `ccabc.account-service` | language, runtime, criticality tier, deployment unit, owning team |
| `Artifact` | maven/nuget/npm GAV | version, transitive closure hash |
| `Type` | SCIP symbol | visibility, is_dto, is_entity, annotations |
| `Method` | SCIP symbol | signature, visibility, annotations, cyclomatic complexity, LOC, txn attributes |
| `Field` | SCIP symbol | type, serialised name, PII/PCI classification |
| `Endpoint` | `GET /accounts/{id}/statement@account-service` | auth requirements, gateway exposure, openapi operationId |
| `Topic` | `ledger.statement.requested` | schema subject + version, partition key |
| `Table` / `Column` | `LEDGER.ACCOUNT_STATEMENT` | PII class, owning component |
| `ConfigKey` | `partner.theme.allowlist` | per-env values, is_feature_flag |
| `Contract` | `openapi:account-service:v3` | version, consumers |
| `TestCase` | test symbol | suite, covers[], is_characterization |
| `InvariantZone` | `HIZ-CCABC-0031` | class, enforcement, ratified_by |

### Edge types

`CALLS` · `OVERRIDES` · `IMPLEMENTS` · `READS` / `WRITES` (field, table) · `EXPOSES` (endpoint→method) ·
`PUBLISHES` / `SUBSCRIBES` (method↔topic) · `SERIALISES` (type→contract) · `DEPENDS_ON` (component,
artifact) · `PROTECTED_BY` (method→filter/policy) · `GUARDED_BY` (method→config key) ·
`COVERS` (test→symbol) · `IN_ZONE` (symbol→invariant zone) · `CONSUMES_CONTRACT`.

Every edge carries **`confidence`** and **`provenance`**:

```
STATIC_RESOLVED    direct call, statically resolvable       confidence 1.00
CONTRACT_INFERRED  bound via OpenAPI/proto/Avro/topic name   confidence 0.85
CONFIG_INFERRED    bound via DI/bean/config metadata         confidence 0.75
HEURISTIC          name/URL-template matching                confidence 0.50
RUNTIME_OBSERVED   seen in OTel traces                       confidence 0.99  (promotes any of the above)
```

Confidence is not decoration — it is load-bearing. The reachability engine's degradation policy keys
on it, and any conclusion depending on a `HEURISTIC` edge cannot reach `HIGH` confidence and therefore
cannot auto-close a finding or auto-merge a patch.

### The hard part: cross-component edges

Within a component, a call graph is a solved problem. Across a Node.js BFF → Spring Boot service →
Java EE monolith → Kafka, there is no call graph — there are **seams**. Guardian resolves seams with
dedicated resolvers, in descending order of trustworthiness:

1. **Runtime trace binding (best).** OTel `http.route` + `service.name` + span parent/child directly
   yields `bff.getStatement → account-service GET /accounts/{id}/statement`. Where distributed tracing
   is deployed, this is ground truth and it promotes every weaker edge it confirms.
2. **Contract binding.** Client call site → URL template normalisation (`/accounts/${id}/statement` →
   `/accounts/{id}/statement`) → OpenAPI `operationId` → server handler method. Same technique for
   gRPC (`package.Service/Method` FQN), Kafka (topic name + Avro subject), and JMS queues.
3. **Generated-client binding.** Where clients are generated from the spec (openapi-generator,
   protoc), the generated symbol is a direct, high-confidence bridge.
4. **Shared-database binding.** The monolith and a microservice touching the same table is a real
   coupling edge even with no call path — modelled as `WRITES`/`READS` on `Table` nodes, and it is
   frequently the coupling that produces surprise regressions in a legacy estate.
5. **Name heuristics (last resort, `HEURISTIC` confidence).** Flagged for human confirmation; never
   sufficient alone for an auto-decision.

### Freshness and cost

Full re-index of 18 components is a nightly job; **incremental re-index is triggered per merged commit**
and completes in minutes for the affected component plus its seam neighbours. Every graph query records
the `graph_snapshot_id` it ran against, so a verdict is always reproducible against the exact graph
state that produced it — a property the evidence store depends on.

## 4.2 High-Invariance Zones (HIZ)

A High-Invariance Zone is a region of the graph where **behaviour-preserving is more important than
finding-closing**, and where an autonomous agent's edit must be treated as guilty until proven
innocent.

### Zone classes

| Class | What it protects | Typical markers |
|---|---|---|
| `AUTHN` | Identity establishment | `SecurityFilterChain`, OAuth2/OIDC handlers, token validation, session creation, `[Authorize]`, passport strategies |
| `AUTHZ` | Access decisions | `@PreAuthorize`/`@PostAuthorize`, `AccessDecisionManager`, policy beans, RBAC/ABAC filters, row-level tenancy predicates |
| `TXN` | Atomicity boundaries | `@Transactional` attrs, `TransactionTemplate`, UOW scopes, saga/outbox coordinators |
| `IDEMPOTENCY` | Exactly-once semantics | dedup keys, `@KafkaListener` ack modes, outbox tables, batch restart markers |
| `CONCURRENCY` | Distributed locks | Redis/ZooKeeper lock acquire-release lifecycles, `synchronized`, `SELECT … FOR UPDATE` |
| `RATE_LIMIT` | Throttling/quota | bucket4j, gateway policies, BFF limiter middleware |
| `CONTRACT` | Consumer-visible shape | DTOs, proto messages, Avro schemas, OpenAPI-referenced types, public method signatures |
| `CRYPTO` | Key handling, signing | KMS clients, JWT signing/verification, encryption helpers |
| `PII_PCI` | Sensitive data handling | classified fields, masking/tokenisation utilities, audit writers |
| `CACHE` | Coherency assumptions | `@Cacheable` keys, TTL config, invalidation paths |

### How zones are discovered (five independent signals, fused)

1. **Declarative markers** — annotation/decorator/config pattern rules per language
   ([policy/invariant-rules.yaml](../policy/invariant-rules.yaml)). Deterministic, high precision.
2. **Structural signals** — high fan-in, high betweenness centrality, shared-library membership,
   presence on many ingress→sink paths. Catches unmarked chokepoints that no annotation reveals.
3. **Historical signals** — files implicated in past incidents, reverted commits, hotfixes, high
   change-failure rate from the deployment record. *Where has breaking things actually hurt before?*
4. **Organisational signals** — CODEOWNERS entries for security/architecture teams, ADR references,
   files under a compliance scope (SOX/PCI-tagged paths).
5. **Oracle-proposed, human-ratified** — semantic invariants that no marker can express ("a statement
   may only be read by the owning tenant, *or* by the batch service account holding
   `LEDGER_READ_ALL`"). Proposed by Copilot Chat, ratified by a human, then mechanically enforced.

Signals 1–4 are automatic and immediate. Signal 5 requires ratification precisely because it is the
only one whose source is a language model.

### Zone record and enforcement levels

```yaml
zone_id: HIZ-CCABC-0031
class: AUTHZ
title: "Account statement read is tenant-scoped or LEDGER_READ_ALL-scoped"
components: [account-service, core-ledger]
symbols:
  - "scip:java …AccountStatementController#getStatement()."
  - "scip:java …AccountStatementService#loadStatement()."
  - "scip:java …AccountAccessPolicy#canRead()."
enforcement: REQUIRE_PROOF          # FORBID_MODIFY | REQUIRE_PROOF | ALLOW_WITH_TEST
proof_tests:
  - "…AccountAccessPolicyCharacterizationTest#negativeAuthMatrix"
  - "pact:web-bff@v3/statement-forbidden-for-other-tenant"
forbidden_edits:
  - "remove_or_weaken_annotation: [PreAuthorize, PostAuthorize, RolesAllowed]"
  - "broaden_expression: hasRole|hasAuthority → permitAll|isAuthenticated"
derived_from: [ADR-014, MYT-88231, ratification:PR#4412]
ratified_by: "jane.doe@corp (Security Architect)"
ratified_at: "2026-09-02T09:11:00Z"
version: 3
```

Three enforcement levels, and the difference matters operationally:

- **`FORBID_MODIFY`** — comes in two scopes, and conflating them is a real design error:
  - *whole-symbol* (no `forbidden_edits` listed): the symbol is not in any agent's change surface,
    ever. Filter chains, crypto helpers, token validators. An agent needing to change one must emit
    `BLOCKED`.
  - *facet-scoped* (`forbidden_edits` listed): the symbol stays editable, but the named facets are
    forbidden and enforced by the semantic-diff detectors. `HIZ-CCABC-0052` below is facet-scoped —
    it forbids changing the transaction attributes of `loadStatement`, not adding an authorisation
    guard to it. Treating it as whole-symbol would make the correct fix undelegable.
- **`REQUIRE_PROOF`** — editable, but the patch must pass the named `proof_tests` *and* is routed to
  `SECURITY_ARCHITECT` review regardless of blast-radius score.
- **`ALLOW_WITH_TEST`** — editable with characterization coverage; peer review suffices.

### Invariants as code

Zone definitions live in-repo at `.guardian/invariants/*.yaml`, are CODEOWNER-protected by the security
architecture team, and change through normal pull-request review. This gives version history, blame,
review, and rollback for the rules that govern autonomous change — and makes the trust boundary of D3
concrete: **the model can open a PR against this file; only a human can merge it.**

## 4.3 Regression-test mapping

Selecting "the exact downstream test suites requiring execution" is a graph query, not a heuristic:

```
tests(change_surface) =
      COVERS⁻¹(touched_symbols)                          # unit + characterization via coverage map
    ∪ COVERS⁻¹(callers*(touched_symbols, depth≤3))       # upstream unit tests
    ∪ contract_tests(contracts_touched)                  # Pact/proto/Avro/OpenAPI compat suites
    ∪ consumer_tests(CONSUMES_CONTRACT⁻¹(contracts_touched))   # OTHER components' consumer tests
    ∪ zone_proof_tests(zones_touched)                    # HIZ-mandated proofs
    ∪ e2e_journeys(endpoints reachable from touched_symbols)
    ∪ always_on_smoke(component)
```

The `consumer_tests` term is the one that a per-repo CI pipeline structurally cannot compute — it
requires knowing that `web-bff` consumes `account-service`'s OpenAPI v3 contract. This is a primary
justification for a central graph rather than per-repo tooling.

Coverage-based `COVERS` edges come from instrumented test runs (JaCoCo, coverlet, nyc/c8, coverage.py)
published as build artefacts and ingested nightly.
