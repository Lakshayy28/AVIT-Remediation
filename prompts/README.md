# Copilot Chat oracle prompts

Three roles, three prompts, three JSON Schemas. Every response passes the seven-step grounding filter
in [docs/05](../docs/05-copilot-chat-oracle.md) §5.6 before any consumer sees it.

| File | Role | Consumer |
|---|---|---|
| `01-invariant-extraction.md` | What business rules must remain true? | Human ratification → Invariant Registry |
| `02-intent-differentiation.md` | Is this a flaw or a feature? | `business_context` + `expected_delta` in the contract |
| `03-fix-intent-review.md` | Does this patch change business behaviour? | Review-tier escalation only |

**Invariant across all three:** the oracle can only make the system stricter. There is no response it
can produce that permits a merge, closes a finding, or relaxes a control.
