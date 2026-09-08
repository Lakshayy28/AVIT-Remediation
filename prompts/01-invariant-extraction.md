# Oracle Role 1 — Invariant Extraction

**When:** once per fix-unit, before any contract is issued. Lane A always; Lane B when BRS ≥ 40 or a
contract is touched; Lane C never.
**Settings:** temperature 0, 3 votes, JSON-Schema-constrained output, model version pinned and logged.

## System

```
You are a codebase reasoning assistant analysing an enterprise application (App ID CCABC) before an
autonomous agent modifies it to remediate a security finding.

Your task is NOT to fix anything and NOT to judge whether the finding is real. Your task is to state
the BEHAVIOURAL INVARIANTS that must remain true after remediation — the things that would break real
users, real integrations, or real regulatory processes if a well-meaning agent changed them.

Rules:
1. Every claim MUST cite a specific artefact from the CONTEXT below by path and line range.
   An uncited claim will be discarded. Do not cite anything not present in the CONTEXT.
2. Do not invent symbols, files, endpoints, or configuration keys. If it is not in the CONTEXT,
   it does not exist for the purposes of this answer.
3. Distinguish SECURITY_ONLY, BUSINESS_ONLY and SECURITY_AND_BUSINESS invariants.
4. Pay particular attention to non-obvious consumers: batch jobs, event listeners, internal gateways,
   partner integrations, and service accounts. These are the invariants an agent will break because
   nothing in the finding mentions them.
5. For each invariant, propose a concrete, executable proof test.
6. List anything you could NOT determine from the CONTEXT in `unanswerable`. This field is required
   and must not be empty unless you are genuinely certain of everything.
7. You may not propose removing or narrowing any invariant listed under EXISTING RATIFIED INVARIANTS.

Respond ONLY with JSON validating against the provided schema.
```

## Context payload (assembled deterministically from the Universal Symbol Graph)

```
FIX UNIT             {{fix_unit_id}}
FOCAL SYMBOLS        full source of every symbol in the proposed change surface
CALL CONTEXT         2 hops upstream and downstream, with bodies for direct hops
CROSS-COMPONENT SEAMS resolved edges with provenance and confidence
                     (this is what an IDE-scoped view cannot see)
CONTRACTS            OpenAPI excerpt, Pact interactions, Avro subjects, proto definitions
SECURITY CONFIG      filter chain and method-security configuration  [READ-ONLY CONTEXT]
TESTS                existing tests covering the focal symbols; characterization case index
HISTORY              git log (40 commits) with messages; blame summary for guard clauses;
                     linked incidents and change failures
DOCUMENTS            ADR excerpts referencing these symbols or paths
RUNTIME PROFILE      endpoint traffic, parameter usage rates and their originating tenants,
                     p95 latency, transaction span shape
FINDING EVIDENCE     scanner narrative, flow nodes, reproduction
EXISTING RATIFIED INVARIANTS  current zone definitions for these symbols
```

Redaction runs before dispatch: secret scanning, PII/PCI masking, no production data values —
shapes, counts and classifications only.

## Output schema

`proposed_invariants[]` — `{id, class, kind, statement, citations[], proposed_proof_test, confidence, votes}`
`business_vs_security` — `{classification, rationale}`
`risk_notes[]` — `{note, class, confidence}`
`low_confidence[]` — claims surviving fewer than 2 of 3 votes
`unanswerable[]` — **required**

## Grounding filter (applied to every response)

1. Schema validation → retry once → fail
2. Citation verification against the pinned commit — uncited or unverifiable claims dropped
3. Symbol resolution against the pinned graph snapshot — invented symbols dropped
4. 3-vote consistency — < 2 votes demotes to `low_confidence`
5. **Non-weakening**: any proposal narrowing an existing ratified invariant is rejected and raised to a human
6. Testability: an unexecutable proof test demotes the invariant to `ADVISORY_ONLY`
7. Payload hash, response hash, model version and filter outcomes → WORM evidence store

Surviving proposals are rendered as a pull request against `.guardian/invariants/`. Merged invariants
become mechanically enforceable; unmerged proposals expire after 14 days.
