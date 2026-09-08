# 09 — Deterministic Gating, Semantic Diffing & Merging

Reference implementations: [`algorithms/guardian/semantic_diff.py`](../algorithms/guardian/semantic_diff.py),
[`algorithms/guardian/gate.py`](../algorithms/guardian/gate.py).
Detector catalogue: [`policy/anti-cheat-rules.yaml`](../policy/anti-cheat-rules.yaml).

## 9.1 Why line diffs are insufficient

A textual diff cannot distinguish these two three-line changes:

```diff
- } catch (LedgerNotFoundException e) {
-     throw new StatementUnavailableException(e);
+ } catch (Exception e) {
+     return StatementResponse.empty();
```

```diff
- } catch (LedgerNotFoundException e) {
-     throw new StatementUnavailableException(e);
+ } catch (LedgerNotFoundException | LedgerTimeoutException e) {
+     throw new StatementUnavailableException(e);
```

Both are "3 lines changed in a catch block". The first swallows every failure — including the new
`AccessDeniedException` the security fix is supposed to raise — and silently converts a 403 into a
200 with an empty body. The second is a legitimate widening. Only an AST/graph-level fact model
separates them: the first yields `EXCEPTION_HANDLER_BROADENED{to: Exception, body_effect: SWALLOWS}`,
the second yields `EXCEPTION_HANDLER_BROADENED{to: sibling-specific, body_effect: RETHROWS}`.

The semantic diff engine consumes the neutral `PatchFacts` model ([06 §6.4](06-polyglot-governance.md))
plus the USG delta, and runs deterministic detectors. **Detectors are pure functions over facts** —
same facts in, same verdict out, no model in the loop.

## 9.2 Anti-cheat detector catalogue

~40 detectors in eight families. Severity: `BLOCKER` (auto-reject), `REVIEW` (escalate tier),
`INFO` (annotate).

### Family 1 — Authorisation & authentication tampering
| ID | Fires on | Severity |
|---|---|---|
| `AC-AUTHZ-01` | `AUTHZ_MARKER_REMOVED` on a method previously protected | BLOCKER |
| `AC-AUTHZ-02` | `AUTHZ_EXPRESSION_BROADENED` (`hasRole` → `isAuthenticated`/`permitAll`) | BLOCKER |
| `AC-AUTHZ-03` | `AUTHZ_EXPRESSION_NARROWED_BEYOND_INVARIANT` — new expression denies a principal class the ratified invariant requires to retain access | BLOCKER |
| `AC-AUTHZ-04` | Authorisation added at controller only, while the invariant zone spans the service layer (leaves Kafka/batch paths unprotected) | REVIEW |
| `AC-AUTHN-01` | Any edit inside an `AUTHN` `FORBID_MODIFY` zone (filter chain, token validator) | BLOCKER |
| `AC-AUTHN-02` | `csrf().disable()`, CORS `*`, `SSL verification disabled`, session fixation protection removed | BLOCKER |

`AC-AUTHZ-03` is the detector that catches the most common well-intentioned agent failure: locking
everyone out to make the finding go away. It is only expressible because the invariant states who
*must retain* access — a plain "is there an authorisation check?" rule would pass this patch.

### Family 2 — Validation & sanitisation removal
`AC-VAL-01` validation annotation/decorator removed · `AC-VAL-02` guard clause deleted from a method
on a tainted path · `AC-VAL-03` allowlist converted to denylist · `AC-VAL-04` regex anchors removed
or made permissive · `AC-VAL-05` sanitiser call removed from a source→sink path · `AC-VAL-06` type
constraint widened (`UUID` → `String`). All BLOCKER except `AC-VAL-06` (REVIEW).

### Family 3 — Error-handling abuse
`AC-ERR-01` catch broadened to `Exception`/`Throwable`/bare `except`/`catch(e)` (BLOCKER) ·
`AC-ERR-02` empty or logging-only catch body where the previous body propagated (BLOCKER) ·
`AC-ERR-03` catch that returns a success value on failure (BLOCKER) ·
`AC-ERR-04` new catch wrapping the newly-added security check — the "neutralise my own fix" pattern
(BLOCKER) · `AC-ERR-05` `throws` clause removed from a public method (REVIEW).

### Family 4 — Contract mutation
`AC-CON-01` public signature change · `AC-CON-02` DTO/record field removed, renamed or retyped ·
`AC-CON-03` proto field number reuse or rename · `AC-CON-04` Avro schema incompatible under the
subject's compatibility mode · `AC-CON-05` OpenAPI breaking change (openapi-diff classification) ·
`AC-CON-06` DB column drop/rename/narrow · `AC-CON-07` serialised name change (`@JsonProperty`) ·
`AC-CON-08` enum value removed. BLOCKER when consumers exist; REVIEW otherwise.

### Family 5 — Verification integrity (agent attacking its own oracle)
`AC-TST-01` characterization suite or fixture hash mismatch · `AC-TST-02` any existing test deleted ·
`AC-TST-03` test disabled/skipped · `AC-TST-04` assertion removed or weakened to a tautology ·
`AC-TST-05` coverage/quality thresholds lowered · `AC-TST-06` CI workflow modified · `AC-TST-07`
test moved out of the default suite. **All BLOCKER, unconditionally.** There is no legitimate reason
for a remediation contract to touch the verification apparatus; if one exists, it is a `BLOCKED`
report, not a patch.

### Family 6 — Scanner silencing
`AC-SUP-01` security-rule suppression annotation/comment added · `AC-SUP-02` scanner ignore/baseline
file modified · `AC-SUP-03` scanner exclusion config or path filter added · `AC-SUP-04` finding
marked accepted-risk from within a patch · `AC-SUP-05` dependency ignore rule added. All BLOCKER.

### Family 7 — Non-functional invariant violations
`AC-NFR-01` `@Transactional`/transaction-scope attribute changed · `AC-NFR-02` transaction boundary
widened (write introduced into a `readOnly` scope) · `AC-NFR-03` lock acquire/release asymmetry or
reordering · `AC-NFR-04` cache key or TTL changed · `AC-NFR-05` rate-limit threshold raised or
limiter removed · `AC-NFR-06` remote call introduced inside a loop · `AC-NFR-07` synchronous call
introduced inside an open transaction · `AC-NFR-08` blocking call on a reactive/event-loop thread ·
`AC-NFR-09` unbounded collection or cache introduced · `AC-NFR-10` idempotency key or dedup check
removed. BLOCKER inside the corresponding zone; REVIEW otherwise.

### Family 8 — Capability removal & dependency drift
`AC-CAP-01` endpoint, request parameter, or public method deleted (BLOCKER — product decision, not an
agent decision) · `AC-CAP-02` feature flag hard-disabled · `AC-CAP-03` code path made unreachable
rather than fixed (detected as a USG edge deletion that severs an ingress→symbol path with live
traffic) · `AC-DEP-01` dependency added/upgraded outside the contract allowlist · `AC-DEP-02` license
class change · `AC-DEP-03` new transitive CVE introduced.

`AC-CAP-03` deserves note: "make the vulnerable code unreachable" is a *sometimes legitimate*
remediation, which is precisely why it must never be silent. Runtime evidence decides — if the path
carries production traffic, deleting it is a capability removal masquerading as a fix.

## 9.3 The gate pipeline (G0–G8)

Fail-fast, cheapest-first. Every stage writes an immutable artefact to the evidence store. Stages
G0–G2 require no test execution, which means the overwhelming majority of bad patches are rejected in
under a minute rather than after a 30-minute test run.

```
G0  CONTRACT CONFORMANCE                                          ~5s
    ├ every changed path ∈ change_surface.allow
    ├ no changed path ∈ change_surface.deny
    ├ characterization suite + fixture hashes unchanged
    ├ .guardian/** unchanged; CI workflows unchanged
    ├ dependency changes ⊆ budget.allowed_dependency_changes
    └ patch rationale present and maps every hunk to a contract clause
        FAIL ⇒ REJECT (no further stages run)

G1  BUILD & STATIC HYGIENE                                        ~2–15m (cached)
    ├ compile every affected component (and every component consuming a touched contract)
    ├ type check, lint, format
    └ no new compiler warnings in the security-relevant category set

G2  SEMANTIC DIFF / ANTI-CHEAT                                    ~20s
    ├ PatchFacts per language adapter
    ├ ~40 detectors (§9.2)
    ├ invariant-zone membership check (FORBID_MODIFY / REQUIRE_PROOF)
    └ USG delta: removed edges, new cross-component edges, severed ingress paths
        any BLOCKER ⇒ REJECT_AND_REISSUE with structured rejection

G3  CHARACTERIZATION / GOLDEN MASTER                              ~5–20m
    ├ replay all recorded cases
    ├ diff observed vs recorded across ALL dimensions (§8.2)
    ├ every difference must appear in expected_delta and match it exactly
    └ every expected_delta entry must actually be observed
        unlisted change ⇒ REJECT   |   unmet expected change ⇒ REJECT (fix did not land)

G4  CONTRACT & INTEGRATION                                        ~10–30m
    ├ pact provider verification for every consumer of touched contracts
    ├ openapi-diff (non-breaking), protobuf breaking-change check, Avro compat vs subject mode
    ├ cross-component integration tests in an ephemeral environment
    └ DB migration forward/backward compatibility

G5  SECURITY RE-EVALUATION                                        ~10–40m
    ├ Mythos re-scan: target semantic finding resolved
    ├ Checkmarx incremental: target taint path resolved, zero new ≥ MEDIUM
    ├ BlackDuck: no new CVE, no license class change
    ├ Prisma: no new container/IaC drift
    └ zero suppressions introduced (cross-check with AC-SUP family)

G6  PROOF-OF-FIX (negative/exploit tests)                         ~2–5m
    ├ execute the PoC derived from the finding evidence; it MUST now fail to exploit
    ├ AUTHZ: full negative-auth matrix
    ├ SSRF: egress attempt to a non-allowlisted host must be refused at validation,
    │        verified at the egress proxy (no outbound connection attempted)
    └ zone proof_tests for every touched invariant zone

G7  NFR / PERFORMANCE SMOKE  (HIZ-touching or BRS ≥ 50)           ~10–20m
    ├ latency envelope within the recorded budget
    ├ transaction span count and scope unchanged
    ├ query count unchanged (N+1 detection)
    └ lock hold time within budget

G8  POLICY & COMPLIANCE                                           ~1m
    ├ SBOM delta reviewed, license policy satisfied
    ├ signed commits, SLSA provenance attestation on the build
    ├ CODEOWNERS satisfiable, audit record complete
    └ evidence bundle complete and hash-sealed
```

**Gate independence.** No stage may consume another stage's *judgement*, only its artefacts. G5 does
not get to say "G3 passed so this is fine." This keeps failures interpretable and prevents a single
weak stage from laundering a bad patch through the rest.

## 9.4 Triage matrix: autonomous merge vs review vs escalation

Deterministic policy (OPA/Rego), evaluated only when every gate has passed. Any gate BLOCKER
short-circuits to `REJECT_AND_REISSUE` or `HUMAN_FIX` before this table is consulted.

| Condition (evaluated top-down; first match wins) | Verdict |
|---|---|
| Any G0–G8 `BLOCKER` and `attempt < 2` | `REJECT_AND_REISSUE` |
| Any G0–G8 `BLOCKER` and `attempt ≥ 2` | `HUMAN_FIX` (agent stands down, evidence handed over) |
| Agent emitted `BLOCKED` | `HUMAN_FIX` (recorded as agent success) |
| Touches `FORBID_MODIFY` zone | `SECURITY_ARCHITECT` — and flag as contract-scoping defect |
| Touches `AUTHN` / `AUTHZ` / `CRYPTO` zone | `SECURITY_ARCHITECT` |
| Breaking contract change (even if consumers updated) | `SECURITY_ARCHITECT` + consumer-owner sign-off |
| BRS ≥ 75 | `HUMAN_FIX` (should not have been delegated; contract policy defect) |
| BRS 50–74 | `SECURITY_ARCHITECT` |
| BRS 25–49 | `PEER_REVIEW` (CODEOWNERS) |
| BRS < 25 **and** no zone touched **and** no contract touched **and** mutation score ≥ 0.6 **and** oracle raised no `invariant_risk` **and** attempt == 1 **and** adapter capabilities not degraded | `MERGE_AUTONOMOUS` |
| otherwise | `PEER_REVIEW` |

Two properties of this table are deliberate:

- **`MERGE_AUTONOMOUS` requires a conjunction of eight conditions.** Autonomy is the narrow exception,
  granted only where the change is small, uncoupled, well-tested and boring. Expected to cover ~30% of
  volume — mostly dependency bumps and templated single-file fixes — which is where the throughput
  actually is.
- **`attempt == 1`** is required for autonomy. A patch that needed a second try after a gate rejection
  has demonstrated the agent misjudged the problem once; a human looks at the second attempt.

## 9.5 Merge orchestration

```
verdict = MERGE_AUTONOMOUS | approved review
    │
    ├─ acquire merge-train slot for the component (leases held since dispatch)
    ├─ rebase onto current main
    ├─ RE-RUN G1, G2, G3, G4 against the rebased result      ← non-negotiable
    │     (a patch verified against a stale main is unverified; this closes the
    │      "both PRs passed independently, composite was never tested" hole)
    ├─ merge (squash, contract id + finding ids + evidence bundle URI in the message)
    ├─ progressive rollout: canary 5% → 25% → 100%
    ├─ SLO watch 24h: error rate, latency, auth-failure rate, business KPI for the endpoint
    │     regression ⇒ AUTO-REVERT, reopen findings, contract → HUMAN_FIX
    ├─ post-merge scanner verification on main (all four scanners)
    └─ close constituent findings, release leases, seal evidence bundle (WORM)
```

The **auth-failure-rate** metric in the SLO watch is specifically included because the most likely
production symptom of an over-corrected authorisation fix is a spike in legitimate users getting 403s
— a failure that error-rate and latency monitoring will happily report as "healthy".

## 9.6 What this catches, mapped to the stated failure modes

| Documented agent failure | Caught by |
|---|---|
| Stripping/weakening business validation to break a taint chain | `AC-VAL-*` (G2) + characterization diff (G3) |
| Modifying signatures / breaking OpenAPI, Protobuf, Avro contracts | `AC-CON-*` (G2) + pact/openapi-diff/avro-compat (G4) |
| Over-engineering or corrupting security interceptors, locking out users | `AC-AUTHZ-02/03`, `AC-AUTHN-01` (G2) + negative-auth matrix (G3, G6) + auth-failure SLO watch |
| Violating txn boundaries, lock lifecycles, cache tiers, rate limits | `AC-NFR-*` (G2) + transaction/lock/latency recordings (G3) + G7 |
| Hundreds of uncoordinated conflicting PRs | Clustering + symbol leases + merge trains + rebase re-verification (D7, §9.5) |
| Silencing the scanner instead of fixing | `AC-SUP-*` (G2) + G5 re-scan + G6 proof-of-fix + `unmet_expected_delta` (G3) |
| Making vulnerable code unreachable instead of fixing | `AC-CAP-03` (G2, USG edge-deletion analysis with runtime traffic evidence) |
| Disabling the tests that would have caught it | `AC-TST-*` (G2, unconditional BLOCKER) + G0 hash pinning |
