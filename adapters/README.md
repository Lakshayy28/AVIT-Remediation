# Scanner adapters

Adapters are independently deployed and versioned. They may **not** reach the Universal Symbol
Graph, the invariant registry, or the evidence store — they translate, nothing more. This is what
keeps the Telemetry Plane's untrusted input from coupling to the Knowledge Plane's authoritative
state, and what lets a Checkmarx export-format change break exactly one component.

## Contract

```python
class ScanAdapter(Protocol):
    source_id: str            # "mythos5" | "checkmarx" | "blackduck" | "prisma"
    schema_version: str

    def discover(self, since: datetime) -> Iterator[ScanBatchRef]: ...
    def parse(self, ref: ScanBatchRef) -> Iterator[RawFinding]: ...
    def to_canonical(self, raw: RawFinding, ctx: RepoContext) -> CanonicalVulnerabilityRecord: ...
```

Rules every adapter must honour:

1. **Never drop a row silently.** A malformed row goes to the quarantine topic with its original
   bytes preserved. Silent row loss in a scanner integration is undetectable and unrecoverable.
2. **Never partially ingest a batch after a schema drift.** Validate the whole batch's shape first;
   a drift halts it and alerts, rather than mis-mapping 900 findings into the wrong columns.
3. **Never guess a commit.** A finding that cannot be bound to `(repo, commit_sha)` lands in
   `UNBOUND`, not in `NEW` with a plausible-looking default.
4. **Populate `class_payload` with the correct discriminant.** The typed union is what lets one
   pipeline serve four scanners without becoming mush.
5. **Emit idempotently.** Re-ingesting the same batch must produce identical fingerprints and no
   state churn.

## Batch CSV/XLSX mapping

Drop-zone batches are mapped declaratively so a column rename is a reviewed config change, not a
code change:

```yaml
# adapters/mappings/mythos5-export-v5.4.yaml
source_id: mythos5
schema_version: "5.4"
detect:
  required_headers: ["Finding ID", "Application", "Component", "File", "Line Start", "Category"]
map:
  source.native_id:        "Finding ID"
  app_id:                  "Application"
  location.component:      "Component"
  location.paths[0]:       "File"
  location.primary_symbol.line_range[0]: "Line Start"
  location.primary_symbol.line_range[1]: "Line End"
  class_payload.category:  {column: "Category", transform: upper_snake}
  class_payload.narrative: "Description"
  severity.level:          {column: "Severity", lookup: {Critical: CRITICAL, High: HIGH,
                                                          Medium: MEDIUM, Low: LOW}}
constant:
  class_payload.type: SEMANTIC_LOGIC
  sla.class: SEMANTIC_7D
validate:
  - "severity.level in [CRITICAL, HIGH, MEDIUM, LOW, INFO]"
  - "location.paths[0] matches ^[^/].*\\.(java|kt|cs|ts|tsx|js|py)$"
dry_run_required: true      # a new or changed mapping must pass a dry run before a live batch
```

## Source-specific notes

| Source | Hard part |
|---|---|
| **Mythos 5** | Findings describe intent violations spanning several methods. Anchor to *all* named symbols, not one line, or the change surface will be wrong. |
| **Checkmarx** | Preserve the complete source→sink node list. It is what lets the flow be replayed against a later commit and what feeds the G6 proof-of-fix test. |
| **BlackDuck** | Coordinates are packages. Project to `vulnerable_symbols` where the CVE→symbol map exists so reachability is VEX-grade rather than package-level guessing. License findings have no code fix and take a separate sub-type. |
| **Prisma Cloud** | Coordinates are images and IaC resources. Resolve to the repo path that *produces* them via build provenance — an agent cannot edit a running container. |
