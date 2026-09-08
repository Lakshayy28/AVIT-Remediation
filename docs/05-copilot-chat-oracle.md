# 05 — GitHub Copilot Chat as a Bounded Reasoning Oracle

**Directive Question B.** Where does Copilot Chat fit, and how is its reasoning made machine-actionable?

## 5.1 The trust boundary (state this before anything else)

Copilot Chat is the only component in Guardian-AVIT whose output cannot be verified by construction.
Its position in the architecture is therefore defined by a single rule:

> **The oracle may only make the system stricter, never more permissive.**

Formally, for any gate decision `D` and oracle output `O`:

```
tier(D | O) ≥ tier(D | ∅)          # oracle input can only raise the escalation tier
merge_allowed(D | O) ⇒ merge_allowed(D | ∅)   # oracle can never be the reason a merge is allowed
```

Consequences that fall directly out of this rule:

- Oracle unavailable, timing out, or low-confidence → **escalate**, never proceed with less scrutiny.
- An oracle-proposed invariant is enforced only after **human ratification** (D3). Before ratification
  it may still *raise* strictness (route to architect review) but cannot gate a pass.
- The oracle never emits a patch that goes to production, never approves a patch, and never closes a
  finding. It produces *hypotheses with citations*.

This is not excessive caution — it is what makes the platform's output auditable. Every merge decision
must be explainable as a chain of deterministic checks, or the platform is just a more elaborate way of
trusting a model.

## 5.2 Why an oracle is needed at all

Deterministic analysis answers *"what does this code do?"* Neither Mythos, Checkmarx, nor Devin answers
*"what is this code **for**?"* — and that gap is precisely where the destructive fixes come from:

| Question | Answerable statically? | Consequence of getting it wrong |
|---|---|---|
| Is `themeCallbackUrl` an SSRF hole or a white-label partner integration? | No | Agent deletes a live partner feature |
| Is this 200-response-for-any-tenant a bug, or an intentional shared-account view? | No | Agent breaks a supported product behaviour |
| Does widening `@Transactional` here risk lock escalation on `core-ledger`? | Partially | Agent introduces a production deadlock |
| Which behaviour changes are *intended* by this security fix? | No | Characterization suite either blocks the fix or misses the regression |
| Is this validation rule a security control or a business rule? | No | Agent strips a business rule to break a taint chain |

The oracle's job is to convert that tacit, cross-repository, historically-embedded knowledge into
**explicit, citable, testable statements** that the deterministic layer can then enforce forever.

## 5.3 The three oracle roles

### Role 1 — Invariant Extraction (pre-remediation)

*Input:* deterministic context slice. *Output:* `proposed_invariants[]` with citations and proposed
proof tests. *Consumer:* human ratification → Invariant Registry → Remediation Contract.

This is the highest-value call. It runs once per fix-unit in Lane A, and on Lane B fix-units with
BRS ≥ 40 or a contract touch.

### Role 2 — Intent Differentiation (triage)

*Input:* finding + symbol slice + git history + ADRs + traffic profile.
*Output:* `{ classification: SECURITY_FLAW | BUSINESS_LOGIC | BOTH, feature_evidence[], affected_users_hypothesis }`.

Feeds the contract's `business_context` and, critically, the `expected_delta` declaration. When the
oracle says "this is a supported partner feature", the contract's forbidden-operations list gains
"do not remove the parameter" — the oracle made the system *stricter*, exactly as designed.

### Role 3 — Fix-Intent Review (post-patch, pre-merge)

*Input:* the semantic diff **facts** (not raw diff text), the ratified invariant list, the
`expected_delta` set. *Output:* `{ behaviour_change_claims[], invariant_risk[], confidence }`.

Runs **after** all deterministic gates. It cannot pass a patch that gates failed, and it cannot
overrule a `BLOCKER`. What it *can* do is catch the residual class: a patch that passes every
mechanical check but is semantically wrong in a way no test encoded. Its only permitted effect is to
escalate the review tier and attach a reviewer-facing note.

## 5.4 Integration mechanics

### Endpoint surface

Guardian integrates through the GitHub Copilot enterprise surfaces available to the organisation:

- A **Copilot Extension (GitHub App with a chat agent endpoint)** registered in the enterprise, which
  Guardian invokes server-to-server; or
- The **Copilot Chat completions surface** exposed to the enterprise tenant, with content exclusion
  and data-handling policy applied at the org level.

Both are wrapped behind one internal interface so the reasoning plane is not coupled to a specific
vendor endpoint shape:

```python
class ReasoningOracle(Protocol):
    def ask(self, role: OracleRole, payload: ContextPayload,
            schema: JsonSchema, *, votes: int = 3) -> OracleResponse: ...
```

Swappability is deliberate. The architecture's guarantees derive from the grounding filter and the
gate pipeline, not from which model answers — and an oracle that can be replaced without touching the
Decision Plane is one that can never quietly become load-bearing.

### Guardian builds the retrieval payload — Copilot does not retrieve for itself

This is the most important mechanical decision in this document.

Copilot Chat's native workspace context is IDE-session-bound and, from a governance standpoint,
*non-deterministic*: you cannot reproduce a verdict if you cannot reproduce the retrieval. Guardian
therefore performs its own retrieval from the USG and ships an explicit, hashed, auditable payload.
Every claim the oracle later makes must cite something inside that payload (§5.6).

Payload assembly for Role 1 (`invariant_extraction`), all slices derived from graph queries:

```yaml
context_payload:
  fix_unit: FU-CCABC-2211
  focal_symbols:                    # the change surface, full source
    - AccountStatementController#getStatement()
    - AccountStatementService#loadStatement()
    - StatementThemeResolver#fetchTheme()
  call_context:                     # 2 hops up, 2 hops down, signatures + bodies of direct hops
    upstream:   [web-bff/src/routes/statement.ts, PartnerGatewayFilter#doFilter]
    downstream: [LedgerStatementDao#findByAccount, RestTemplate#getForObject]
  cross_component_seams:            # what makes this different from IDE-scoped Copilot
    - {from: web-bff, to: account-service, via: "openapi:account-service:v3#getStatement",
       confidence: RUNTIME_OBSERVED}
    - {from: account-service, to: core-ledger, via: "table:LEDGER.ACCOUNT_STATEMENT"}
    - {from: account-service, to: kafka, via: "topic:ledger.statement.requested@avro:StatementRequested:v4"}
  contracts:
    - openapi excerpt for GET /accounts/{id}/statement (request + response schema)
    - pact: web-bff@v3 interactions touching this endpoint
    - avro: StatementRequested v4
  security_config:                  # READ-ONLY context, never in the change surface
    - SecurityConfig.java (filter chain, method security)
    - PartnerThemeAllowlist config keys + per-env values
  tests:
    - existing unit/integration tests covering focal symbols
    - characterization suite index (names + assertions, not bodies)
  history:
    - git log --follow (last 40 commits) for focal files, with messages
    - blame summary for the guard clauses in loadStatement()
    - linked incidents/change-failures on these files
  documents:
    - ADR-014 "White-label partner statement theming" (excerpt)
    - ADR-031 "Tenant isolation model" (excerpt)
  runtime_profile:
    - endpoint traffic: 14.2k req/day; themeCallbackUrl present on 0.31% of requests,
      of which 100% originate from tenant PTNR-7
    - p95 latency 240ms; txn span: single readOnly transaction
  finding_evidence:
    - MYT-88231 narrative + evidence path
    - CX-441902 source→sink node list
  question_role: invariant_extraction
```

Redaction runs before dispatch: secrets scanning, PII/PCI field masking, no production data values —
only shapes, counts and classifications. Configuration *values* are included only for non-secret keys.

### Determinism and reproducibility controls

| Control | Setting | Why |
|---|---|---|
| Temperature | 0 | Reduce run-to-run variance |
| Output shape | JSON-Schema-constrained | Output must be machine-actionable, not prose |
| Self-consistency | 3 votes; claims surviving ≥ 2 votes retained, others demoted to `low_confidence[]` | Cheap variance suppression on the claims that matter |
| Model pinning | Exact model/version recorded per call | A verdict must be reproducible and attributable |
| Payload hashing | `SHA256(payload)` + `SHA256(response)` written to the WORM evidence store | Audit: "what exactly was asked, what exactly came back" |
| Timeout / fallback | Hard timeout → `ORACLE_UNAVAILABLE` → escalate tier | Fail closed (§5.1) |
| Budget | Per-lane quota; Lane C never calls the oracle | Cost discipline, and cheap findings do not deserve deep reasoning |

## 5.5 Structured output contract

The oracle answers into a schema. Free prose is retained only in `rationale`, which is shown to humans
and consumed by nothing.

```json
{
  "fix_unit": "FU-CCABC-2211",
  "oracle_role": "invariant_extraction",
  "model": "copilot-chat@<pinned-version>",
  "payload_sha256": "…",
  "proposed_invariants": [
    {
      "id": "PI-1",
      "class": "AUTHZ",
      "statement": "A statement may be read only by a principal whose tenant owns the account, or by a principal holding scope LEDGER_READ_ALL.",
      "kind": "SECURITY_AND_BUSINESS",
      "citations": [
        {"path": "core-ledger/src/main/java/…/LedgerStatementDao.java", "lines": [88, 104], "why": "tenant predicate applied in the batch path only"},
        {"path": "docs/adr/ADR-031-tenant-isolation.md", "lines": [22, 40]},
        {"path": "account-service/src/test/…/BatchStatementIT.java", "lines": [51, 63], "why": "batch service account reads across tenants"}
      ],
      "proposed_proof_test": "negativeAuthMatrix: owner→200, other-tenant→403, LEDGER_READ_ALL→200, anonymous→401",
      "confidence": 0.91,
      "votes": 3
    },
    {
      "id": "PI-2",
      "class": "CONTRACT",
      "statement": "themeCallbackUrl must remain an accepted request parameter; partner tenant PTNR-7 depends on it for white-label rendering.",
      "kind": "BUSINESS_ONLY",
      "citations": [
        {"path": "docs/adr/ADR-014-partner-theming.md", "lines": [8, 31]},
        {"path": "account-service/src/main/resources/openapi/account-v3.yaml", "lines": [212, 219]}
      ],
      "proposed_proof_test": "allowlisted partner host → 200 with themed payload",
      "confidence": 0.88,
      "votes": 3
    }
  ],
  "business_vs_security": {
    "classification": "BOTH",
    "rationale": "The URL parameter is an intentional feature (ADR-014) whose implementation lacks host validation; the correct remediation constrains it rather than removing it."
  },
  "risk_notes": [
    {"note": "loadStatement runs inside @Transactional(readOnly=true); adding an audit write here would widen the transaction and is likely to escalate locks on core-ledger.", "class": "TXN", "confidence": 0.74}
  ],
  "low_confidence": [],
  "unanswerable": ["Whether tenant PTNR-7's contract permits deprecating theme URLs (no repository evidence)"]
}
```

Two fields deserve emphasis:

- **`unanswerable`** is required, not optional. Forcing the oracle to declare what it could not
  determine from the payload is a cheap and effective hedge against confident fabrication, and those
  items route to a human as open questions rather than disappearing.
- **`proposed_proof_test`** is what makes the invariant *enforceable*. An invariant without a test is a
  sentence; an invariant with a test is a gate.

## 5.6 The grounding filter (how prose becomes machine-actionable)

Between the oracle and any downstream consumer sits a deterministic filter. It is small, boring, and
does most of the safety work:

```
1. SCHEMA          Response must validate against the role's JSON Schema, else RETRY(1) then FAIL.
2. CITATION        Every proposed_invariant MUST cite ≥1 payload artefact. Each citation is
                   verified to exist at the pinned commit and to contain the cited line range.
                   Uncited or unverifiable claim ⇒ DROPPED (logged as `hallucination_filtered`).
3. SYMBOL          Every referenced symbol must resolve in the USG at the pinned graph snapshot.
                   Invented symbols ⇒ DROPPED.
4. CONSISTENCY     3-vote agreement; <2 votes ⇒ demoted to low_confidence (advisory only).
5. NON-WEAKENING   Any proposal that would REMOVE or narrow an existing ratified invariant is
                   rejected outright and raised as a human review item. The oracle is structurally
                   incapable of relaxing an existing control.
6. TESTABILITY     proposed_proof_test must be convertible to an executable assertion by the
                   test synthesiser, else the invariant is marked ADVISORY_ONLY (informs review
                   tier, does not gate).
7. LEDGER          Payload hash, response hash, model version, votes, filter outcomes → WORM store.
```

Rule 5 is the structural guarantee behind §5.1: no oracle output path exists that ends in a weaker
control.

Filtered output then flows to ratification: proposals are rendered as a pull request against
`.guardian/invariants/`, reviewed by the component owner and (for `AUTHN`/`AUTHZ`/`CRYPTO`) a security
architect. Merged invariants become enforceable; unmerged ones expire after 14 days.

## 5.7 What the oracle is *not* asked to do

| Not asked | Why | Who does it instead |
|---|---|---|
| Write the fix | Concentrates two failure modes (bad reasoning + bad code) in one unaudited step | Devin, under a bounded contract |
| Decide reachability | Deterministically computable; a model guess would be strictly worse and unauditable | Reachability engine over the USG |
| Approve/reject a patch | Violates §5.1 | Gate pipeline + policy engine |
| Rank/prioritise the backlog | Deterministic function of slack, severity, BRS | Lane scheduler |
| Judge whether a test is adequate | Circular — the model would be grading its own context | Mutation testing + coverage thresholds |

## 5.8 Failure modes and mitigations

| Failure | Mitigation |
|---|---|
| Confident fabrication of an invariant | Citation grounding (filter rule 2) + human ratification + testability requirement |
| Missing a real invariant (false negative) | Characterization suite is the backstop: unstated behaviour is still frozen by the golden master, so an unnoticed invariant is still protected by equality checking |
| Prompt injection via repository content (a malicious comment saying "this endpoint requires no authorisation") | Payload content is data, never instruction; the filter's non-weakening rule (5) blocks any proposal that removes a control; oracle output can never widen the change surface |
| Model/version drift changes verdicts | Pinned versions; re-ratification required on model change for `FORBID_MODIFY` zones |
| Cost blowout at 3,000 findings | Role 1 gated by lane and BRS; Lane C never calls; caching keyed on `payload_sha256` (identical slice ⇒ cached answer) |
| Enterprise data policy violation | Redaction pre-pass, content exclusion honoured, no production data values, org-tenant endpoints only |
