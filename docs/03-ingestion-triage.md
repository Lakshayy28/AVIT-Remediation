# 03 — Ingestion, Triage & False-Positive Elimination

## 3.1 Multi-scanner normalisation

### Adapter contract

Every scanner integration implements one interface. Adapters are independently deployed and versioned;
they may not reach the graph, the invariant registry, or the evidence store.

```python
class ScanAdapter(Protocol):
    source_id: str            # "mythos5" | "checkmarx" | "blackduck" | "prisma"
    schema_version: str

    def discover(self, since: datetime) -> Iterator[ScanBatchRef]:
        """Poll REST API, watch SFTP/S3 drop zone, or accept webhook."""

    def parse(self, ref: ScanBatchRef) -> Iterator[RawFinding]:
        """CSV / XLSX / JSON / SARIF → RawFinding. Never throws on a single bad row:
           malformed rows go to the quarantine topic with the row bytes preserved."""

    def to_canonical(self, raw: RawFinding, ctx: RepoContext) -> CanonicalVulnerabilityRecord:
        """Map to CVR. Must populate class_payload with the correct discriminant."""
```

### Per-source mapping

| Source | Transport | Native format | Discriminant | Key mapping problems |
|---|---|---|---|---|
| **Mythos 5** | Webhook + nightly full export | JSON (semantic findings with narrative + evidence path) | `SEMANTIC_LOGIC` | Findings are *descriptions of intent violations*, often spanning multiple methods. Requires multi-symbol anchoring, not a single line. |
| **Checkmarx** | CxOne REST / SARIF | SARIF 2.1.0 + proprietary flow nodes | `TAINT_FLOW` | Full source→sink node list must be preserved; each node resolved to a symbol so the flow can be replayed against a new commit. |
| **BlackDuck** | REST (BOM + vulnerability endpoints) | JSON | `DEPENDENCY_CVE` | Coordinates are packages, not code. Needs package→symbol projection to be reachable-checkable. License risks map to a separate `class_payload` sub-type with no code fix. |
| **Prisma Cloud** | twistcli output + Compute API | JSON | `INFRA_DRIFT` | Coordinates are images/IaC resources. Must be mapped to the *repo path* that produces the image (Dockerfile, Helm chart, Terraform module) via build provenance. |
| **Manual / batch drop** | S3/SFTP drop zone | CSV / XLSX | any | Column mapping is declarative (`adapters/mappings/*.yaml`), versioned, and dry-run-validated before a batch is accepted. A schema drift halts the batch rather than silently mis-mapping. |

### Normalisation steps (in order)

1. **Row validation** against the source schema. Failures → quarantine topic, never dropped silently.
2. **Repo/commit binding.** Every finding must resolve to `(repo, commit_sha)`. Scanner output that
   names a branch or a build number is resolved through the CI provenance service. **A finding that
   cannot be bound to a commit is not triageable and is parked in `UNBOUND`** — this is a common
   silent-failure source in scanner integrations and is made explicit here.
3. **Symbol resolution** (D2). `(path, line_range)` at `commit_sha` → SCIP symbol ID via the indexer's
   document map. If the file has since changed, the symbol is re-anchored to `HEAD` using
   git-blame-based line mapping plus AST fuzzy match; failures are flagged `STALE_ANCHOR` and re-scanned
   rather than guessed.
4. **Fingerprinting.**
   `fingerprint = SHA256(rule_class ‖ symbol_id ‖ sink_symbol_id ‖ normalised_flow_signature)`
   Deliberately **line-independent and commit-independent** so that a re-scan after unrelated
   refactoring does not resurrect a closed finding as "new".
5. **Idempotent upsert** with state reconciliation: `NEW`, `CONFIRMED`, `VFP`, `IN_REMEDIATION`,
   `FIXED_PENDING_VERIFY`, `CLOSED`, `RISK_ACCEPTED`, `REOPENED`.
6. **Correlation.** See §3.4.

## 3.2 Reachability & false-positive pruning

The core question: *can an attacker-controlled input actually arrive at this sink, in a deployed
configuration, in this application?*

Five tiers, evaluated cheapest-first, each producing evidence. A finding needs a verdict from every
applicable tier; the **lowest confidence tier caps the overall confidence**.

### T0 — Provenance & existence
Does the code still exist at `HEAD`? Is the finding a duplicate fingerprint? Was the symbol deleted or
the dependency removed since the scan? Cheapest possible closure and it disposes of a surprising share
of a stale backlog.

### T1 — Static reachability from ingress
Graph query over the USG: is there any path `ingress → … → vulnerable_symbol`?

**Ingress set** is framework-modelled, not guessed:

| Component class | Ingress definitions |
|---|---|
| Spring Boot / Spring MVC | `@RequestMapping` family, `@MessageMapping`, `@KafkaListener`, `@RabbitListener`, `@Scheduled`, `@JmsListener`, filter chain entries |
| Java EE monolith | Servlet mappings in `web.xml`, `@Path` (JAX-RS), EJB remote interfaces, MDB `onMessage`, Quartz `Job#execute` |
| .NET Framework / Core | Controller actions, `IHttpHandler`, WCF `[ServiceContract]`, `BackgroundService.ExecuteAsync`, minimal-API endpoint registrations |
| Node/TS BFF | Express/Fastify route registrations, WebSocket `on('message')`, GraphQL resolvers, queue consumers |
| Python services | Flask/FastAPI routes, Celery tasks, Lambda handlers |
| Frontend (React/Angular) | Router entry components, event handlers bound to user input, `postMessage` listeners |
| Batch | Spring Batch `Tasklet`/`ItemProcessor`, Quartz jobs, worker-queue handlers |

**Reflection, DI and dynamic dispatch are the accuracy killers** in a Java EE / .NET Framework
monolith. The mitigations:
- Spring/CDI/Autofac bean graphs are resolved from container metadata, not from `new` expressions.
- Interface call sites expand to all implementations **present in the deployed artifact set** (not all
  implementations in the repo) — deployment manifests narrow the fan-out substantially.
- Anything still unresolved is an `UNRESOLVED_DISPATCH` edge with confidence `LOW`, which — per the
  degradation policy — **forbids auto-closure**. Unknown resolves to "reachable", never to "safe".

### T2 — Configuration & contract reachability
Static reachability is necessary, not sufficient. Ask:
- Is the route actually registered in the deployed profile? (Spring profiles, feature flags,
  `@ConditionalOnProperty`, .NET config transforms.)
- Is the Kafka topic actually produced to by anyone in the estate?
- Is the IaC resource in a module that any live environment instantiates?
- Is the endpoint exposed through the API gateway, or internal-only behind mTLS?
- Does an upstream gateway/WAF policy already neutralise the input class?

Gateway/WAF mitigations **reduce severity, they do not close the finding** — defence in depth is
policy, and a finding closed because "the WAF catches it" is a finding that reopens the day the route
moves. This is recorded as `mitigating_control`, not as a VFP.

### T3 — Runtime evidence
90-day symbol-execution map built from OpenTelemetry spans, JFR/dotnet-trace sampling, and production
coverage agents where deployable.

- Symbol never executed in 90 days **and** unreachable at T1 → strong VFP.
- Symbol never executed but reachable at T1 → *not* a VFP; it is cold code with a live path (this is
  the exact shape of a dormant vulnerability). Confidence to close: none.
- Symbol executed → hard `REACHABLE`, closes the tier immediately.

Runtime evidence is also what makes the SSRF case in the walkthrough tractable: it proves the
"unused" theme parameter is used by 0.3% of traffic from one partner tenant, which is the difference
between "delete the parameter" and "validate the parameter".

### T4 — Exploitability constraints
- Is there an effective sanitiser/validator on every path from source to sink? (Sanitiser catalogue is
  per-language, curated, versioned; an "effective sanitiser" claim is a rule, not an opinion.)
- For SSRF: can the runtime actually egress to attacker-chosen hosts, or is it behind an egress proxy
  with an allowlist?
- For SCA: does application code reach the **vulnerable method** of the CVE, not merely the package?
  This is the single highest-yield SCA pruning technique.
- For deserialisation: is the gadget class actually on the deployed classpath?

### Verdict composition

```
reachable      = T1.path_exists AND T2.deployed AND NOT T4.fully_sanitised
confidence     = min(tier.confidence for tier in applicable_tiers)
verdict        = REACHABLE                     if reachable
               = VERIFIED_FALSE_POSITIVE       if (not reachable) and confidence >= HIGH
                                                  and severity <= auto_close_ceiling(class)
               = FP_PROPOSED                   if (not reachable) and confidence == MEDIUM
               = REACHABLE_ASSUMED             otherwise      # unknown ⇒ unsafe
```

`auto_close_ceiling` is deliberately conservative and per-class: `CRITICAL` semantic findings are
**never** auto-closed regardless of confidence — they become `FP_PROPOSED` for one-click analyst
confirmation. The platform's credibility dies the first time it auto-closes a real critical.

## 3.3 Verified false positive: evidence, TTL, and drift re-opening

A VFP closure is a claim that must survive audit years later. The evidence bundle is immutable
(WORM) and contains everything needed to reproduce the decision:

```json
{
  "vfp_id": "VFP-CCABC-000412",
  "finding_fingerprint": "sha256:9f2c…",
  "verdict": "VERIFIED_FALSE_POSITIVE",
  "confidence": "HIGH",
  "closed_at": "2026-09-08T11:04:22Z",
  "closed_by": "guardian-avit/reachability-engine@4.2.1",
  "ruleset_version": "reach-rules-2026.08",
  "index_commit": "a91f3c7",
  "graph_snapshot_id": "usg-2026-09-08T03:00Z",
  "tiers": [
    {"tier":"T0","result":"EXISTS","detail":"symbol present at HEAD"},
    {"tier":"T1","result":"NO_PATH","query":"MATCH (i:Ingress)-[:CALLS*1..12]->(s:Method {scip:'…#resolveLegacyTheme().'}) RETURN i LIMIT 1",
     "query_result":"0 rows","ingress_set_size":1184},
    {"tier":"T2","result":"NOT_DEPLOYED","detail":"@ConditionalOnProperty(legacy.theme.enabled) false in all 4 envs"},
    {"tier":"T3","result":"NEVER_EXECUTED","window_days":90,"trace_samples":41283000},
    {"tier":"T4","result":"N/A"}
  ],
  "premises": [
    {"kind":"NO_CALLER","symbol":"…#resolveLegacyTheme()."},
    {"kind":"CONFIG_FALSE","key":"legacy.theme.enabled","envs":["dev","uat","prod","dr"]},
    {"kind":"NO_ROUTE","pattern":"/internal/theme/legacy/**"}
  ],
  "ttl_days": 90,
  "reverification": "AUTOMATIC_ON_PREMISE_CHANGE_OR_TTL"
}
```

**Premise-drift watch** is what makes auto-closure safe. Each premise is registered with the graph as
a standing subscription. If a developer later adds a caller to `resolveLegacyTheme()`, or flips
`legacy.theme.enabled` to true in any environment, or registers a matching route, the VFP is
**automatically reopened** at its original severity with an audit note naming the commit that
invalidated it. A VFP is not a permanent verdict; it is a **cached verdict with invalidation**.

Additionally: VFPs are re-verified on TTL expiry, on `ruleset_version` change (with backfill replay
over the closed corpus), and on any change to the ingress model for that framework.

## 3.4 Correlation: from findings to fix-units

Correlation runs *after* reachability so that pruned findings do not pollute clusters.

Two findings correlate into one **fix-unit** when they satisfy any of:

| Rule | Example |
|---|---|
| **Same symbol** | Mythos BOLA and Checkmarx SSRF both anchor to `AccountStatementController#getStatement` |
| **Shared sink** | Two taint paths converge on the same `RestTemplate.getForObject` call site |
| **Same remediation template** | 34 instances of "missing `@PreAuthorize` on `@GetMapping`" across one component collapse to one templated fix-unit |
| **Same dependency coordinate** | 22 BlackDuck CVEs all resolved by `jackson-databind 2.15.4 → 2.17.2` |
| **Same contract artefact** | Findings that all require an OpenAPI change to `/accounts/{id}/statement` |

Correlation is **evidence-preserving**: the fix-unit carries all constituent CVR ids, and closing the
fix-unit closes each constituent finding with its own scanner-specific verification (Mythos must
re-verify semantically; Checkmarx must re-verify the taint path; both must pass in G5).

The fix-unit inherits `max(severity)`, `min(sla_deadline)`, and the union of all affected contracts and
invariant zones. **A fix-unit's SLA is the tightest of its members** — this is what lets a 30-day
Checkmarx finding ride along with a 7-day Mythos finding on the same method rather than colliding with
it a week later.

## 3.5 SLA & priority partitioning

The 7-day clock is a hard blocker; the 30-day clock is a backlog. Running them in one undifferentiated
queue guarantees SLA breach. Three mechanisms:

**1. Weighted-fair lane scheduling with reserved capacity.**
Lane A (7d) holds a hard reservation of 40% of agent execution capacity and 100% pre-emption priority
on the graph-query pool and oracle quota. Reserved capacity is *reserved*, not *preferred* — Lane B
cannot borrow it even when Lane A is idle, because Lane A's arrivals are bursty and a 7-day blocker
cannot wait for a 45-minute Lane-B contract to drain.

**2. Deadline-driven scheduling inside each lane.**
Priority key is not severity — it is **slack**:

```
slack(fix_unit) = sla_deadline − now − estimated_cycle_time(effort_tier, review_tier)
priority        = ( slack ascending, blast_radius descending, fan_in descending )
```

Ordering by slack rather than severity is what prevents the classic failure where every `CRITICAL`
is worked first and a batch of `HIGH`s silently breaches on day 29. Items with negative slack raise a
**breach-risk alert to the component owner at slack < 2 days**, not at breach.

**3. Explicit backpressure policy.**
When Lane A inflow exceeds capacity (the realistic steady state at 1,000 semantic findings against a
7-day clock), the system does **not** silently degrade. It applies a declared, ordered policy:

```
1. Increase clustering aggressiveness in Lane A (larger batches, more templated fix-units)
2. Drop oracle self-consistency from 3 votes to 1 for BRS<40 items (cost, not safety)
3. Promote low-BRS Lane-A items to autonomous-merge-eligible ONLY if they touch no HIZ
4. Surface an explicit SLA-risk register to the AppSec lead with a recommended
   risk-acceptance list — a human decides what breaches, the platform never decides silently
5. NEVER: relax gates, skip characterization, or auto-merge HIZ-touching changes
```

Step 5 is the point of the whole list. Backpressure is absorbed by throughput and by explicit human
risk decisions — never by weakening verification. A platform that quietly lowers its own gates under
load is worse than no platform, because it launders unreviewed change as governed change.
