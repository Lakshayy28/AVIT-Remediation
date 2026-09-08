# 08 — Bounded Agent Delegation: Remediation Contracts

## 8.1 Raw repository access vs. a bounded contract

The contrast, stated precisely:

| Dimension | Raw repo + finding text | Bounded Remediation Contract |
|---|---|---|
| **Objective** | Implicit and single-term: *make the scanner stop reporting* | Explicit and multi-term: resolve finding **∧** preserve invariants **∧** stay in surface **∧** satisfy acceptance criteria |
| **Action space** | Entire repository, including CI config, tests, suppression files, security config | Sparse checkout of an allowlisted surface; `SecurityConfig.java` is physically absent |
| **Knowledge of intent** | None. The agent cannot know `themeCallbackUrl` is a partner feature | Ratified invariants, ADR excerpts, traffic profile, and named consumers are in the contract |
| **Definition of done** | "Scanner is quiet" — agent self-assesses | Pre-committed acceptance oracle the agent cannot modify or observe-and-overfit |
| **Failure behaviour** | Improvise: delete the parameter, widen the catch, disable the test | `BLOCKED` report with rationale — a first-class, rewarded outcome |
| **Coordination** | None; N agents edit the same file concurrently | Symbol-level write leases; one contract holds the lease |
| **Auditability** | A diff and a hope | Contract id → evidence bundle → gate artefacts → verdict, all immutable |
| **Blast containment** | Whatever the agent decided to touch | Change surface is enforced twice: sandbox-side and at gate G0 |

The essential move: **an agent optimising within a constrained feasible region produces safe output
even when its reasoning is mediocre.** The engineering effort goes into defining the region, not into
coaxing the model.

## 8.2 Behavioural locking (characterization testing)

Recorded and pinned **before** the agent starts, because a golden master captured after an agent has
already edited the code is worthless.

### What gets recorded

| Dimension | Mechanism | Catches |
|---|---|---|
| **HTTP request/response pairs** | Traffic sampled from prod/UAT (sanitised), replayed via WireMock/nock/WireMock.NET; status, headers, body shape and values | Contract drift, status changes, field removal, serialisation changes |
| **Negative-authorisation matrix** | Cartesian product of {owner, other-tenant, service-account, expired-token, anonymous, wrong-scope} × endpoint | The BOLA class specifically — and it is the single highest-value recording for an AUTHZ fix |
| **Emitted domain events** | Kafka producer interception: topic, key, schema id, payload | Silent event-shape changes that break consumers asynchronously |
| **Database effects** | Statement capture + before/after row snapshots on a seeded fixture DB | Extra writes, dropped writes, changed transaction scope |
| **Transaction spans** | Instrumented transaction manager: count, isolation, propagation, duration | `readOnly=true → false`, boundary widening, lock escalation risk |
| **Concurrency/lock lifecycle** | Lock acquire/release ordering trace | Distributed lock leaks, lock-order inversions |
| **Rate-limit / quota behaviour** | Burst probes at configured thresholds | Weakened or removed limiters |
| **Latency envelope** | p50/p95/p99 under fixed load | N+1 queries, sync calls added inside loops or transactions |
| **Logging/audit side effects** | Structured-log assertions on required audit events | Removed audit trails (a compliance regression that no functional test catches) |

Where traffic replay is impossible (legacy monolith, no test harness), generated characterization
tests are used **only if** they pass a mutation-score threshold — a generated test suite that cannot
kill mutants is not evidence. If neither is achievable, the component is `T5 ineligible` (§7.6) and
routes to humans. This is a real limit and is stated as one rather than papered over.

### Pinning and immutability

```
characterization_lock:
  suite_path: "account-service/src/test/java/…/AccountStatementCharacterizationTest.java"
  recorded_at: "2026-09-08T02:14:00Z"
  recorded_against_commit: "a91f3c7"
  case_count: 42
  suite_sha256: "9c1e…"
  fixtures_sha256: "4ab0…"
  mutation_score: 0.78
  mount: READ_ONLY          # sandbox-enforced
  gate_check: G0 re-verifies both hashes; mismatch ⇒ immediate REJECT
```

### `expected_delta` — the crux of the whole design

A security fix is *supposed* to change behaviour. A characterization suite that forbids all change
would block every valid fix; one that permits any change proves nothing. The resolution is to declare
the intended change **before the agent runs**, in the contract, and require exact conformance:

```yaml
expected_delta:
  - case_id: "negAuth.otherTenant.getStatement"
    before: {status: 200, body_schema: "StatementResponse"}
    after:  {status: 403, body_schema: "ProblemDetail", body_match: {type: "…/forbidden"}}
    justification: "MYT-88231 — cross-tenant read must be denied"
  - case_id: "theme.nonAllowlistedHost"
    before: {status: 200, outbound_call: "http://attacker.example/theme.json"}
    after:  {status: 400, outbound_call: null}
    justification: "CX-441902 — SSRF egress must be blocked at validation"
policy:
  unlisted_case_change: REJECT      # any other behavioural difference fails G3
  unmet_expected_delta: REJECT      # a declared change that did NOT happen fails G3 too
```

Both halves matter. `unlisted_case_change: REJECT` catches collateral damage. `unmet_expected_delta:
REJECT` catches the agent that made the tests pass without actually fixing the vulnerability — the
most important anti-cheat check in the system, and one a plain regression suite cannot express.

## 8.3 The Remediation Contract

Full schema: [`schemas/remediation-contract.schema.json`](../schemas/remediation-contract.schema.json).
Worked example: [`schemas/examples/contract-FU-CCABC-2211.json`](../schemas/examples/contract-FU-CCABC-2211.json).

Structure, section by section:

```
identity        contract_id, fix_unit, batch, attempt, issued_at, expires_at, lease_ids
objective       what must become true, stated as verifiable predicates — never "fix the vulnerability"
evidence        findings with full flow paths, reproduction steps, PoC requests
business_context ratified invariants + ADR excerpts + traffic profile + named downstream consumers
change_surface  allow[] / deny[] / read_only_context[]  (symbol- and path-level)
forbidden_ops   the deny-by-default behaviour list (§8.4)
required_patterns exemplar commits/symbols showing the house-approved way to do this
invariants      ratified invariants in scope, each with its proof test
expected_delta  the ONLY permitted behaviour change
acceptance      the gate list the patch must pass, verbatim
verification_plan the exact test selection that will run
workspace       sparse checkout spec, branch namespace, egress allowlist, credential scope
budget          wall clock, iterations, tool calls, tokens, permitted dependency changes
escalation      how to emit BLOCKED, and what a good BLOCKED report contains
provenance      required rationale mapping each hunk → contract clause
```

### Objective, stated as predicates

```yaml
objective:
  must_become_true:
    - id: OBJ-1
      predicate: "MYT-88231 no longer reproduces: GET /accounts/{id}/statement as a principal
                  whose tenant does not own {id} and lacking scope LEDGER_READ_ALL returns 403"
      proof: "characterization case negAuth.otherTenant.getStatement matches expected_delta"
    - id: OBJ-2
      predicate: "CX-441902 taint path source→sink is broken: themeCallbackUrl cannot cause an
                  outbound request to a host outside the per-tenant allowlist"
      proof: "PartnerThemeIT#rejectsNonAllowlistedHost AND Checkmarx re-scan reports 0 findings
              for rule SSRF in StatementThemeResolver"
  must_remain_true:
    - "INV-CCABC-0031 (AUTHZ): owner-tenant OR LEDGER_READ_ALL may read"
    - "INV-CCABC-0044 (CONTRACT): themeCallbackUrl remains an accepted request parameter"
    - "INV-CCABC-0052 (TXN): loadStatement remains within one readOnly transaction"
    - "INV-CCABC-0058 (CONTRACT): StatementRequested Avro v4 shape unchanged"
```

Note that `must_remain_true` is expressed *before* the agent writes a line. This is what converts the
platform from a reviewer of agent output into a specifier of agent input.

## 8.4 Forbidden operations (deny-by-default)

Enforced in three places: sandbox pre-commit hook (fast feedback to the agent), gate G0 (contract
conformance), and gate G2 (semantic diff detectors). Triple enforcement is deliberate — the sandbox
hook is a convenience the agent could in principle evade; G0 and G2 are not.

```yaml
forbidden_operations:
  security_controls:
    - remove_or_weaken: [PreAuthorize, PostAuthorize, RolesAllowed, Secured, Authorize,
                         requireAuth middleware, login_required]
    - modify: [SecurityFilterChain, WebSecurityConfigurer, authentication providers,
               token validators, CORS policy, CSRF configuration]
    - broaden: ["hasRole/hasAuthority → permitAll|isAuthenticated|anonymous"]
  validation:
    - remove: [Valid, NotNull, Size, Pattern, custom validators, zod/pydantic constraints]
    - weaken: ["allowlist → denylist", "regex anchor removal", "type narrowing removal"]
  error_handling:
    - broaden_catch: ["specific exception → Exception/Throwable/bare except/catch(e)"]
    - swallow: ["empty catch body", "catch that returns a default success value"]
  contracts:
    - change: [public method signatures, DTO/record fields, proto field numbers or names,
               Avro schema in a non-backward-compatible way, OpenAPI request/response schemas,
               DB column drop/rename]
  verification_integrity:
    - modify_or_delete: [characterization tests, invariant files (.guardian/**), CI workflows,
                         coverage thresholds, quality gates]
    - disable: ["@Disabled/@Ignore/skip/xit/pytest.mark.skip on any existing test"]
    - weaken_assertions: ["assertTrue(true)", "expect(true).toBe(true)", "removed assertions"]
  scanner_silencing:
    - add: [SuppressWarnings for security rules, "// nosec", "# noqa", NOSONAR,
            checkmarx/blackduck/prisma ignore entries, .snyk policy, baseline files,
            scanner exclusion config]
  non_functional:
    - change: [Transactional attributes, isolation/propagation, lock acquire/release ordering,
               cache keys or TTLs, rate-limit thresholds, thread pool sizing, timeouts]
    - introduce: ["remote call inside a loop", "blocking call on a reactive thread",
                  "synchronous call inside an existing transaction", "unbounded cache or collection"]
  capability_removal:
    - delete: [endpoints, request parameters, feature flags, public methods]
      # Sometimes legitimate — but never an agent's unilateral call. Requires product-owner
      # sign-off, so it is forbidden inside a contract and must be raised as BLOCKED.
  dependencies:
    - add_or_upgrade: ["any coordinate not in budget.allowed_dependency_changes"]
```

Each entry maps 1:1 to a detector in [`policy/anti-cheat-rules.yaml`](../policy/anti-cheat-rules.yaml),
so the prohibition and its enforcement cannot drift apart.

## 8.5 Escalation: making `BLOCKED` a first-class success

The most dangerous moment is when a correct fix is impossible inside the boundaries. An unbounded
agent improvises there — and improvisation is exactly the distortion mechanism. So `BLOCKED` is
explicitly instructed, explicitly rewarded, and explicitly measured.

```yaml
escalation_protocol:
  when:
    - "A required change falls outside change_surface.allow"
    - "The fix necessarily violates a must_remain_true invariant"
    - "A forbidden operation is the only viable remediation"
    - "expected_delta cannot be achieved without unlisted behavioural change"
    - "Budget exhausted"
  action: "Emit BLOCKED with the report below. Do NOT partially apply, do NOT improvise,
           do NOT weaken any control to make progress."
  report_schema:
    blocked_reason: enum[SURFACE_TOO_NARROW, INVARIANT_CONFLICT, FORBIDDEN_OP_REQUIRED,
                         MISSING_CONTEXT, BUDGET_EXHAUSTED, AMBIGUOUS_INTENT]
    analysis: "What you understand the vulnerability to be"
    attempted_approaches: [{approach, why_rejected}]
    required_surface_expansion: [symbols/files you would need]
    invariant_conflict: {invariant_id, why_incompatible}
    recommended_human_action: "…"
  scoring: "BLOCKED with an accurate report is recorded as a SUCCESSFUL outcome for the agent's
            historical success rate. A gate rejection is recorded as a FAILURE.
            The incentive gradient must point away from improvisation."
```

That last line is the design intent in one sentence: **if guessing is penalised and honest refusal is
not, the agent's cheapest path stops being the one that breaks production.**

## 8.6 Sandbox and iteration loop

```
issue contract ──► sandbox (sparse checkout, RO characterization, egress allowlist, scoped token)
                        │
                        ├─ agent may: read surface + read_only_context, edit surface,
                        │             run build, run the verification_plan locally
                        ├─ agent may not: edit outside surface, edit tests/invariants/CI,
                        │             install unlisted deps, reach the network beyond allowlist
                        ▼
                  patch bundle (diff + rationale mapping hunks → contract clauses)
                        │
                        ▼
                  quarantine bucket ──► Decision Plane pulls (agent has no write path to evidence)
                        │
                        ▼
                  G0…G8  ──► PASS ──► policy verdict
                        └──► FAIL ──► structured rejection ──► attempt+1 (max 2)
                                          │
                                          └── after attempt 2: HUMAN_FIX, agent stands down,
                                              full evidence bundle handed to the engineer
```

The attempt cap is non-negotiable. Without it, a determined agent iterating against a gate becomes an
adversarial search for a patch that satisfies the checks without fixing the problem — and given enough
attempts, that search sometimes succeeds. Two attempts, then a human.

## 8.7 Structured rejection (the feedback the agent actually needs)

A rejection that says "gates failed" produces a random walk on the next attempt. The rejection carries
the same structure as the contract, so attempt 2 is a constrained repair rather than a fresh guess:

```json
{
  "contract_id": "RC-CCABC-2211-a1",
  "verdict": "REJECT_AND_REISSUE",
  "attempt": 1,
  "blockers": [
    {"detector": "ANTI_CHEAT_AUTHZ_MARKER_BROADENED",
     "location": "AccountStatementController#getStatement()",
     "observed": "@PreAuthorize(\"hasRole('ADMIN')\")",
     "why": "Violates INV-CCABC-0031: owner-tenant principals and LEDGER_READ_ALL service accounts must retain access. This denies both.",
     "exemplar": "see AccountAccessPolicy usage in TransactionHistoryController#list() (commit 7f21ab)"},
    {"detector": "ANTI_CHEAT_CONTRACT_FIELD_REMOVED",
     "location": "StatementRequest.themeCallbackUrl",
     "why": "Violates INV-CCABC-0044 and breaks pact web-bff@v3 and partner tenant PTNR-7.",
     "required": "Constrain the value; do not remove the field."}
  ],
  "guidance": "Enforce authorisation via the existing AccountAccessPolicy bean at the SERVICE layer (so the Kafka and batch paths are covered), and validate themeCallbackUrl against PartnerThemeAllowlist with private-IP-range rejection and redirects disabled.",
  "surface_unchanged": true,
  "attempts_remaining": 1
}
```
