"""Fixture modelling the App CCABC footprint and the walkthrough scenario (docs/10).

Deliberately small enough to reason about by hand, while exercising every mechanism:
cross-component seams, a batch caller in another repo, a partner gateway that bypasses the BFF,
an AUTHZ zone spanning two layers, and a FORBID_MODIFY transaction zone.
"""
from __future__ import annotations

import random

from guardian.usg import USG, Node
from guardian.clustering import FixUnit
from guardian.semantic_diff import Fact, Context

# ── symbol shorthands ───────────────────────────────────────────────────────
BFF_ROUTE   = "web-bff:src/routes/statement.ts/getStatement()."
BFF_MW      = "web-bff:src/middleware/ownership.ts/requireOwner()."
PARTNER_GW  = "account-service:…/PartnerGatewayFilter#doFilter()."
CTRL        = "account-service:…/AccountStatementController#getStatement()."
SVC         = "account-service:…/AccountStatementService#loadStatement()."
THEME       = "account-service:…/StatementThemeResolver#fetchTheme()."
REST_SINK   = "account-service:…/RestTemplate#getForObject()."
DAO         = "core-ledger:…/LedgerStatementDao#findByAccount()."
BATCH       = "statement-batch:…/StatementBatchTasklet#execute()."
SECCONF     = "account-service:…/SecurityConfig#filterChain()."
LEGACY_THEME= "account-service:…/StatementThemeResolver#resolveLegacyTheme()."
KAFKA_TOPIC = "topic:ledger.statement.requested"
AUDIT_SVC   = "audit-service:…/StatementAuditListener#onMessage()."


def build_graph() -> USG:
    g = USG()

    def m(sid, component, language="java", ingress=False, kind="Method", **attrs):
        return g.add_node(Node(sid, kind, component, language,
                               {"is_ingress": ingress, **attrs}))

    m(BFF_ROUTE, "web-bff", "typescript", ingress=True, endpoint="GET /api/statement")
    m(BFF_MW, "web-bff", "typescript")
    m(PARTNER_GW, "account-service", ingress=True, endpoint="partner-gw")
    m(CTRL, "account-service", ingress=True, endpoint="GET /accounts/{id}/statement")
    m(SVC, "account-service")
    m(THEME, "account-service")
    m(REST_SINK, "account-service")
    m(DAO, "core-ledger")
    m(BATCH, "statement-batch", ingress=True, endpoint="nightly batch")
    m(SECCONF, "account-service")
    m(LEGACY_THEME, "account-service")
    m(KAFKA_TOPIC, "kafka", kind="Topic")
    m(AUDIT_SVC, "audit-service", ingress=True)

    g.add_edge(BFF_ROUTE, BFF_MW, "CALLS")
    g.add_edge(BFF_MW, CTRL, "CALLS", "RUNTIME_OBSERVED")      # seam resolved by tracing
    g.add_edge(PARTNER_GW, CTRL, "CALLS", "CONTRACT_INFERRED")  # bypasses the BFF middleware
    g.add_edge(CTRL, SVC, "CALLS")
    g.add_edge(SVC, DAO, "CALLS", "CONTRACT_INFERRED")          # cross-component, shared table
    g.add_edge(SVC, THEME, "CALLS")
    g.add_edge(THEME, REST_SINK, "CALLS")
    g.add_edge(BATCH, SVC, "CALLS", "CONFIG_INFERRED")          # the caller nothing in the finding mentions
    g.add_edge(SVC, KAFKA_TOPIC, "PUBLISHES")
    g.add_edge(KAFKA_TOPIC, AUDIT_SVC, "SUBSCRIBES", "CONTRACT_INFERRED")
    # LEGACY_THEME deliberately has no inbound edge — the VFP demonstration.
    return g


ZONES = {
    "HIZ-CCABC-0031": {
        "id": "HIZ-CCABC-0031", "class": "AUTHZ", "enforcement": "REQUIRE_PROOF",
        "symbols": [CTRL, SVC], "invariants": ["INV-CCABC-0031", "INV-CCABC-0038"],
        "service_layer_invariant": "INV-CCABC-0038",
    },
    "HIZ-CCABC-0044": {
        "id": "HIZ-CCABC-0044", "class": "CONTRACT", "enforcement": "REQUIRE_PROOF",
        "symbols": [CTRL], "invariants": ["INV-CCABC-0044"],
    },
    "HIZ-CCABC-0052": {
        "id": "HIZ-CCABC-0052", "class": "TXN", "enforcement": "FORBID_MODIFY",
        "symbols": [SVC], "invariants": ["INV-CCABC-0052"],
        # Facet-scoped: these specific edits are forbidden, not every edit to the symbol.
        # The compliant fix adds a guard clause here and must remain delegable.
        "forbidden_edits": ["TXN_ATTRIBUTE_CHANGED", "SYNC_CALL_IN_TXN_ADDED"],
    },
    "HIZ-CCABC-0009": {
        "id": "HIZ-CCABC-0009", "class": "AUTHN", "enforcement": "FORBID_MODIFY",
        "symbols": [SECCONF], "invariants": [],
    },
}

INVARIANTS = {
    "INV-CCABC-0031": {
        "id": "INV-CCABC-0031", "class": "AUTHZ",
        "statement": "Owner-tenant OR scope LEDGER_READ_ALL may read a statement.",
        "required_principal_classes": ["OWNER_TENANT", "LEDGER_READ_ALL"],
        "ratified_by": "jane.doe@corp",
    },
    "INV-CCABC-0038": {
        "id": "INV-CCABC-0038", "class": "AUTHZ",
        "statement": "Enforcement must occur at the service layer, not only the controller.",
        "required_principal_classes": ["OWNER_TENANT", "LEDGER_READ_ALL"],
    },
    "INV-CCABC-0044": {
        "id": "INV-CCABC-0044", "class": "CONTRACT",
        "statement": "themeCallbackUrl remains an accepted request parameter (ADR-014, tenant PTNR-7).",
    },
    "INV-CCABC-0052": {
        "id": "INV-CCABC-0052", "class": "TXN",
        "statement": "loadStatement stays within one readOnly transaction span; no writes inside it.",
    },
}

SYMBOL_ZONES = {
    CTRL: ["HIZ-CCABC-0031", "HIZ-CCABC-0044"],
    SVC:  ["HIZ-CCABC-0031", "HIZ-CCABC-0052"],
    SECCONF: ["HIZ-CCABC-0009"],
}

DEPLOYMENT = {
    LEGACY_THEME: {"deployed": False, "flag": "legacy.theme.enabled",
                   "envs": ["dev", "uat", "prod", "dr"],
                   "detail": "@ConditionalOnProperty(legacy.theme.enabled) false in all 4 envs"},
}

RUNTIME = {
    CTRL: {"executions": 14210, "window_days": 90},
    SVC: {"executions": 14210, "window_days": 90},
    THEME: {"executions": 44, "window_days": 90},
    DAO: {"executions": 2100000, "window_days": 90},
    LEGACY_THEME: {"executions": 0, "window_days": 90},
    "themeCallbackUrl": {"requests_per_day": 44, "origin": "100% tenant PTNR-7"},
    "GET /accounts/{id}/statement?themeCallbackUrl → StatementThemeResolver#fetchTheme":
        {"requests_per_day": 44, "origin": "tenant PTNR-7"},
}

# ── the two correlated findings, plus the VFP demonstration ─────────────────
FINDINGS = [
    {"id": "MYT-88231", "symbol": CTRL, "class": "SEMANTIC_LOGIC", "severity": "CRITICAL",
     "scanner": "mythos5", "rule": "BOLA"},
    {"id": "CX-441902", "symbol": THEME, "class": "TAINT_FLOW", "severity": "HIGH",
     "scanner": "checkmarx", "rule": "SSRF"},
    {"id": "CX-441950", "symbol": LEGACY_THEME, "class": "TAINT_FLOW", "severity": "MEDIUM",
     "scanner": "checkmarx", "rule": "SSRF"},
    {"id": "MYT-88999", "symbol": SECCONF, "class": "SEMANTIC_LOGIC", "severity": "CRITICAL",
     "scanner": "mythos5", "rule": "AUTHN_BYPASS"},
]

CHANGE_SURFACE = {
    "symbols": [CTRL, SVC, THEME],
    "contracts": ["openapi:account-service:v3#getStatement"],
    "contract_consumers": 3,
    "coverage": 0.62,
    "mutation_score": 0.78,
    "incidents_365d": 1,
    "traffic_percentile": 0.75,
    "data_class": "FINANCIAL",
    "components": ["account-service", "core-ledger"],
    "calls_into_txn": True,
    "touches_legacy_monolith": True,
    "degraded_adapters": False,
    "contract_breaking": False,
}


# ── walkthrough Step 4: the flawed patch, as PatchFacts ─────────────────────
FLAWED_PATCH_FACTS = [
    Fact("AUTHZ_EXPRESSION_CHANGED", CTRL, prev="isAuthenticated()", next="hasRole('ADMIN')",
         detail={"direction": "NARROWED", "admits_principal_classes": ["ADMIN"]}),
    Fact("AUTHZ_CHECK_ADDED", CTRL, detail={"layer": "controller", "also_enforced_at": []}),
    Fact("EXCEPTION_HANDLER_BROADENED", CTRL, prev=None, next="catch(Exception)",
         detail={"body_effect": "SWALLOWS", "returns_success_value": True,
                 "wraps_new_security_check": True}),
    Fact("SIGNATURE_CHANGED", CTRL, prev="(String,String,Principal)", next="(String,Principal)",
         detail={"visibility": "public", "removed_params": ["themeCallbackUrl"], "consumers": 3}),
    Fact("REQUEST_PARAM_DELETED", CTRL, detail={"name": "themeCallbackUrl"}),
    Fact("DTO_FIELD_REMOVED", "account-service:…/dto/StatementRequest#themeCallbackUrl.",
         detail={"consumers": 3}),
    Fact("TXN_ATTRIBUTE_CHANGED", SVC, prev="readOnly=true", next="readOnly=false",
         detail={"write_introduced": "auditRepo.save(...)"}),
    Fact("SUPPRESSION_ADDED", THEME, next="// checkmarx-disable-next-line SSRF",
         detail={"scanner": "checkmarx"}),
    Fact("TEST_DISABLED", "account-service:…/AccountStatementCharacterizationTest#negativeAuthMatrix().",
         detail={"mechanism": "@Disabled"}),
]

# ── walkthrough Step 6: the compliant patch, as PatchFacts ──────────────────
COMPLIANT_PATCH_FACTS = [
    Fact("AUTHZ_MARKER_STRENGTHENED", CTRL, prev="isAuthenticated()",
         next="@accountAccessPolicy.canRead(#id, authentication)",
         detail={"admits_principal_classes": ["OWNER_TENANT", "LEDGER_READ_ALL"]}),
    Fact("AUTHZ_CHECK_ADDED", CTRL, detail={"layer": "controller", "also_enforced_at": [SVC]}),
    Fact("GUARD_CLAUSE_ADDED", SVC, detail={"predicate": "accessPolicy.canRead(id, auth)"}),
    Fact("VALIDATION_ADDED", THEME, detail={"validator": "UrlAllowlistValidator"}),
    Fact("EGRESS_CLIENT_SUBSTITUTED", THEME, prev="RestTemplate#getForObject",
         next="egressProxyClient#getForObject"),
    Fact("EVENT_PUBLISHED_VIA_OUTBOX", SVC, next="StatementAccessAudited"),
    Fact("TEST_ADDED", "account-service:…/PartnerThemeIT#rejectsNonAllowlistedHost()."),
]

CHARACTERIZATION_HASHES = {
    "account-service/src/test/java/…/AccountStatementCharacterizationTest.java":
        "4d9ae1c07b3f2a8890c5613de2f4471bb0a9c2d5e6f18734ac0b91de2f5a6c83",
}


def context_for(patch: str) -> Context:
    observed = {}
    graph_delta = {}
    if patch == "flawed":
        observed = {list(CHARACTERIZATION_HASHES)[0]:
                    "7e0219bc4f1a90d3aa1188f0c4e73b90d2e5a61c9f4b03872de1a5c9037fb214"}
        graph_delta = {
            "observed_hashes": observed,
            "ingress_paths_severed":
                ["GET /accounts/{id}/statement?themeCallbackUrl → StatementThemeResolver#fetchTheme"],
        }
    else:
        graph_delta = {"observed_hashes": {}, "ingress_paths_severed": []}
    return Context(
        invariants=INVARIANTS, zones=ZONES, symbol_zones=SYMBOL_ZONES,
        contract_consumers={"openapi:account-service:v3#getStatement": ["web-bff", "partner-gw", "PTNR-7"]},
        runtime=RUNTIME, allowed_dependency_changes=[],
        characterization_hashes=CHARACTERIZATION_HASHES, graph_delta=graph_delta,
        exemplars={"AC-AUTHZ-03": "TransactionHistoryController#list() + TransactionAccessPolicy (commit 7f21ab)"},
    )


# ── characterization recording for G3 ───────────────────────────────────────
RECORDED = {
    "happyPath.owner.getStatement":   {"status": 200, "schema": "StatementResponse"},
    "negAuth.otherTenant.controller": {"status": 200, "schema": "StatementResponse"},
    "negAuth.otherTenant.directService": {"returns": "Statement"},
    "negAuth.ledgerReadAll.batch":    {"status": 200, "schema": "StatementResponse"},
    "negAuth.anonymous":              {"status": 401},
    "negAuth.wrongScope.partnerGw":   {"status": 200},
    "theme.allowlistedHost":          {"status": 200, "themed": True},
    "theme.nonAllowlistedHost":       {"status": 200, "outbound_call": "http://attacker.example/t.json"},
    "theme.privateIpHost":            {"status": 200, "outbound_call": "http://169.254.169.254/latest/meta-data/"},
    "theme.redirectToPrivate":        {"status": 200, "outbound_call": "redirect→10.0.0.5"},
    "kafka.statementRequested":       {"schema_id": 4, "key": "accountId"},
    "txn.spanReadOnly":               {"spans": 1, "readOnly": True},
    "audit.statementAccessLogged":    {"events": 1},
    "db.readOnlyStatements":          {"writes": 0},
}

EXPECTED_DELTA = {
    "cases": [
        {"case_id": "negAuth.otherTenant.controller", "after": {"status": 403, "schema": "ProblemDetail"}},
        {"case_id": "negAuth.otherTenant.directService", "after": {"throws": "AccessDeniedException"}},
        {"case_id": "negAuth.wrongScope.partnerGw", "after": {"status": 403}},
        {"case_id": "theme.nonAllowlistedHost", "after": {"status": 400, "outbound_call": None}},
        {"case_id": "theme.privateIpHost", "after": {"status": 400, "outbound_call": None}},
        {"case_id": "theme.redirectToPrivate", "after": {"status": 400, "outbound_call": None}},
    ],
    "policy": {"unlisted_case_change": "REJECT", "unmet_expected_delta": "REJECT"},
}

OBSERVED_FLAWED = dict(RECORDED)
OBSERVED_FLAWED.update({
    "happyPath.owner.getStatement":   {"status": 403, "schema": "ProblemDetail"},   # customers locked out
    "negAuth.ledgerReadAll.batch":    {"status": 403, "schema": "ProblemDetail"},   # batch locked out
    "negAuth.otherTenant.controller": {"status": 200, "schema": "StatementResponse"},  # swallowed ⇒ unfixed
    "negAuth.otherTenant.directService": {"returns": "Statement"},                  # unfixed
    "negAuth.wrongScope.partnerGw":   {"status": 403},
    "theme.allowlistedHost":          {"status": 400},                              # partner broken
    "theme.nonAllowlistedHost":       {"status": 200, "outbound_call": "http://attacker.example/t.json"},
    "theme.privateIpHost":            {"status": 400, "outbound_call": None},
    "theme.redirectToPrivate":        {"status": 400, "outbound_call": None},
    "txn.spanReadOnly":               {"spans": 1, "readOnly": False},
    "audit.statementAccessLogged":    {"events": 0},
    "db.readOnlyStatements":          {"writes": 1},
})

OBSERVED_COMPLIANT = dict(RECORDED)
OBSERVED_COMPLIANT.update({
    "negAuth.otherTenant.controller": {"status": 403, "schema": "ProblemDetail"},
    "negAuth.otherTenant.directService": {"throws": "AccessDeniedException"},
    "negAuth.wrongScope.partnerGw":   {"status": 403},
    "theme.nonAllowlistedHost":       {"status": 400, "outbound_call": None},
    "theme.privateIpHost":            {"status": 400, "outbound_call": None},
    "theme.redirectToPrivate":        {"status": 400, "outbound_call": None},
})


# ── synthetic backlog for the clustering demonstration ──────────────────────
def synthetic_backlog(n: int = 1190, seed: int = 20260908) -> list[FixUnit]:
    """A backlog shaped like the post-triage inflow in docs/00.

    Deliberately Pareto-skewed across components rather than uniform: real scan backlogs
    concentrate in a handful of large, old, high-traffic components. A uniform fixture would
    make the clustering problem artificially easy in one respect (small per-component volume)
    and artificially hard in another (18 components each paying the per-lane batch overhead).
    """
    rnd = random.Random(seed)
    #            component              lang          team            lane-A eligible  weight
    components = [
        ("core-ledger",          "java",       "ledger-core",  False, 16),
        ("account-service",      "java",       "payments-core", True, 14),
        ("legacy-crm",           "csharp",     "crm",          False, 12),
        ("payment-service",      "kotlin",     "payments-core", True, 10),
        ("web-bff",              "typescript", "channel",       True,  8),
        ("card-service",         "java",       "cards",         True,  7),
        ("partner-gateway",      "csharp",     "channel",      False,  6),
        ("risk-engine",          "python",     "risk",          True,  5),
        ("statement-batch",      "java",       "payments-core", False, 4),
        ("web-portal",           "typescript", "channel",      False,  4),
        ("notification-service", "java",       "comms",        False,  3),
        ("recon-batch",          "java",       "ledger-core",  False,  3),
        ("audit-service",        "java",       "compliance",   False,  2),
        ("mobile-bff",           "typescript", "channel",      False,  2),
        ("fx-service",           "kotlin",     "treasury",     False,  2),
        ("admin-portal",         "typescript", "channel",      False,  1),
        ("doc-service",          "python",     "content",      False,  1),
        ("scheduler",            "java",       "platform",     False,  1),
    ]
    weights = [c[4] for c in components]
    # Dependency upgrades only arise where a vulnerable coordinate is actually present.
    dep_components = {"core-ledger", "account-service", "legacy-crm", "payment-service",
                      "web-bff", "web-portal", "risk-engine", "card-service"}
    templates = ["AUTHZ_OBJECT_OWNERSHIP_CHECK", "SANITISE_SQL_PARAM", "ESCAPE_HTML_SINK",
                 "VALIDATE_OUTBOUND_URL", "ADD_CSRF_TOKEN", "PIN_DESERIALISATION_ALLOWLIST",
                 "IAC_TIGHTEN_SG", "SECURE_COOKIE_FLAGS", "RATE_LIMIT_ENDPOINT"]
    deps = ["org.springframework:spring-web", "com.fasterxml.jackson.core:jackson-databind",
            "org.apache.commons:commons-text", "lodash", "urllib3", "Newtonsoft.Json"]

    units: list[FixUnit] = []
    for i in range(n):
        comp, lang, team, lane_a_eligible, _ = rnd.choices(components, weights=weights, k=1)[0]
        is_dep = comp in dep_components and rnd.random() < 0.11
        if is_dep:
            dep = rnd.choice(deps)
            files = frozenset({f"{comp}/build-manifest"})
            symbols = frozenset()
            module, template, lane_u = f"{comp}:build", "DEP_UPGRADE", "C"
        else:
            dep = None
            template = rnd.choice(templates)
            module = f"{comp}:mod{rnd.randint(1, 5)}"
            fileno = rnd.randint(1, 18)
            files = frozenset({f"{comp}/{module.split(':')[1]}/File{fileno}.src"})
            symbols = frozenset({f"{comp}:File{fileno}#m{rnd.randint(1, 4)}()"})
            lane_u = "A" if (lane_a_eligible and rnd.random() < 0.16) else "B"
        units.append(FixUnit(
            id=f"FU-{i:05d}", component=comp, files=files, symbols=symbols, module=module,
            fix_template=template, lane=lane_u, team=team, language=lang,
            sla_deadline="2026-09-15" if lane_u == "A" else "2026-10-08",
            severity=rnd.choice(["CRITICAL", "HIGH", "HIGH", "MEDIUM", "MEDIUM", "LOW"]),
            blast_radius=rnd.choice([8, 12, 18, 22, 31, 40, 52, 61, 68, 74]),
            dependency_coord=dep,
            contracts=frozenset({f"openapi:{comp}:v1"}) if rnd.random() < 0.18 else frozenset(),
            zones=frozenset({f"HIZ-{comp}-{rnd.randint(1, 3)}"}) if rnd.random() < 0.12 else frozenset(),
        ))
    return units
