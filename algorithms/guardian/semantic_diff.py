"""Semantic diff / anti-cheat detectors (docs/09 §9.2, policy/anti-cheat-rules.yaml).

Detectors are PURE FUNCTIONS over language-neutral PatchFacts + graph delta + invariant registry.
No model participates. Same facts in ⇒ same verdict out — which is what makes a merge decision
explainable as a chain of deterministic checks rather than an appeal to a model's judgement.

PatchFacts are emitted by per-language adapters (docs/06 §6.4), so one catalogue governs Java,
Kotlin, C#, TypeScript, Python and frontend JavaScript.
"""
from __future__ import annotations

from dataclasses import dataclass, field

BLOCKER, REVIEW, INFO = "BLOCKER", "REVIEW", "INFO"

POSITIVE_FACTS = {
    "AUTHZ_MARKER_STRENGTHENED", "GUARD_CLAUSE_ADDED", "VALIDATION_ADDED",
    "SANITISER_CALL_ADDED", "EGRESS_CLIENT_SUBSTITUTED", "PARAMETERISED_QUERY_SUBSTITUTED",
    "EVENT_PUBLISHED_VIA_OUTBOX", "TEST_ADDED",
}


@dataclass
class Fact:
    fact: str
    symbol: str
    language: str = "java"
    prev: object = None
    next: object = None
    detail: dict = field(default_factory=dict)


@dataclass
class Finding:
    detector: str
    family: str
    severity: str
    message: str
    location: str
    invariant_violated: str | None = None
    exemplar: str | None = None
    runtime_evidence: str | None = None


@dataclass
class Context:
    """Everything a detector may consult. All of it is deterministic platform state."""
    invariants: dict = field(default_factory=dict)        # invariant_id -> record
    zones: dict = field(default_factory=dict)             # zone_id -> record
    symbol_zones: dict = field(default_factory=dict)      # symbol -> [zone_id]
    contract_consumers: dict = field(default_factory=dict)  # artefact -> [consumer]
    runtime: dict = field(default_factory=dict)           # symbol/param -> usage stats
    allowed_dependency_changes: list = field(default_factory=list)
    characterization_hashes: dict = field(default_factory=dict)
    graph_delta: dict = field(default_factory=dict)
    exemplars: dict = field(default_factory=dict)         # detector -> exemplar pointer


def _zones_of(ctx: Context, symbol: str) -> list[dict]:
    return [ctx.zones[z] for z in ctx.symbol_zones.get(symbol, []) if z in ctx.zones]


def _invariants_for(ctx: Context, symbol: str) -> list[dict]:
    out = []
    for zone in _zones_of(ctx, symbol):
        for inv_id in zone.get("invariants", []):
            if inv_id in ctx.invariants:
                out.append(ctx.invariants[inv_id])
    return out


# ── Family 1: authorisation & authentication ────────────────────────────────
def d_authz(facts: list[Fact], ctx: Context) -> list[Finding]:
    out: list[Finding] = []
    for f in facts:
        if f.fact == "AUTHZ_MARKER_REMOVED":
            out.append(Finding("AC-AUTHZ-01", "authz", BLOCKER,
                               "Authorisation control removed from a previously protected symbol.",
                               f.symbol))
        if f.fact == "AUTHZ_EXPRESSION_CHANGED":
            direction = f.detail.get("direction")
            if direction == "BROADENED":
                out.append(Finding("AC-AUTHZ-02", "authz", BLOCKER,
                                   f"Authorisation expression broadened: {f.prev} -> {f.next}", f.symbol))
            elif direction == "NARROWED":
                admits = set(f.detail.get("admits_principal_classes", []))
                for inv in _invariants_for(ctx, f.symbol):
                    required = set(inv.get("required_principal_classes", []))
                    denied = required - admits
                    if denied:
                        out.append(Finding(
                            "AC-AUTHZ-03", "authz", BLOCKER,
                            "Authorisation narrowed beyond the ratified invariant: the new expression "
                            f"denies principal class(es) {sorted(denied)} that must retain access.",
                            f.symbol, invariant_violated=inv["id"],
                            exemplar=ctx.exemplars.get("AC-AUTHZ-03")))
        if f.fact == "AUTHZ_CHECK_ADDED":
            layer = f.detail.get("layer")
            for zone in _zones_of(ctx, f.symbol):
                if zone["class"] != "AUTHZ":
                    continue
                deeper = [s for s in zone["symbols"] if s != f.symbol]
                covered = set(f.detail.get("also_enforced_at", []))
                if layer == "controller" and deeper and not set(deeper) <= covered:
                    uncovered = sorted(set(deeper) - covered)
                    out.append(Finding(
                        "AC-AUTHZ-04", "authz", BLOCKER,
                        "Authorisation enforced at the controller only; other ingress paths reach "
                        f"{uncovered} directly and remain unprotected.",
                        f.symbol, invariant_violated=zone.get("service_layer_invariant")))
        if f.fact in {"CSRF_DISABLED", "CORS_WILDCARD", "TLS_VERIFY_DISABLED",
                      "SESSION_FIXATION_PROTECTION_REMOVED", "COOKIE_FLAGS_WEAKENED"}:
            out.append(Finding("AC-AUTHN-02", "authz", BLOCKER,
                               f"Transport or session protection weakened: {f.fact}", f.symbol))
        for zone in _zones_of(ctx, f.symbol):
            facets = zone.get("forbidden_edits")
            in_scope = (not facets) or f.fact in facets
            if zone["class"] == "AUTHN" and zone.get("enforcement") == "FORBID_MODIFY" \
                    and in_scope and f.fact not in POSITIVE_FACTS:
                out.append(Finding("AC-AUTHN-01", "authz", BLOCKER,
                                   f"Edit inside AUTHN FORBID_MODIFY zone {zone['id']}.", f.symbol))
    return out


# ── Family 2: validation ────────────────────────────────────────────────────
def d_validation(facts: list[Fact], ctx: Context) -> list[Finding]:
    table = {
        "VALIDATION_REMOVED": ("AC-VAL-01", BLOCKER, "Validation constraint removed."),
        "GUARD_CLAUSE_REMOVED": ("AC-VAL-02", BLOCKER, "Guard clause deleted on a tainted path."),
        "VALIDATION_STRATEGY_INVERTED": ("AC-VAL-03", BLOCKER, "Allowlist converted to denylist."),
        "SANITISER_CALL_REMOVED": ("AC-VAL-05", BLOCKER, "Sanitiser removed from a source→sink path."),
        "PARAM_TYPE_WIDENED": ("AC-VAL-06", REVIEW, "Parameter type constraint widened."),
    }
    out = []
    for f in facts:
        if f.fact == "REGEX_CHANGED" and (f.detail.get("anchors_removed") or f.detail.get("class_broadened")):
            out.append(Finding("AC-VAL-04", "validation", BLOCKER, "Validation regex weakened.", f.symbol))
        if f.fact in table:
            det, sev, msg = table[f.fact]
            out.append(Finding(det, "validation", sev, msg, f.symbol))
    return out


# ── Family 3: error handling ────────────────────────────────────────────────
def d_error_handling(facts: list[Fact], ctx: Context) -> list[Finding]:
    out = []
    for f in facts:
        if f.fact != "EXCEPTION_HANDLER_BROADENED":
            continue
        nxt = str(f.next or "")
        broad = any(t in nxt for t in ("Exception", "Throwable", "except:", "catch (e)", "catch(e)"))
        effect = f.detail.get("body_effect")
        if broad:
            out.append(Finding("AC-ERR-01", "error_handling", BLOCKER,
                               f"Catch broadened to {f.next}.", f.symbol))
        if effect == "SWALLOWS":
            out.append(Finding("AC-ERR-02", "error_handling", BLOCKER,
                               "Exception swallowed where the previous body propagated.", f.symbol))
        if f.detail.get("returns_success_value"):
            out.append(Finding("AC-ERR-03", "error_handling", BLOCKER,
                               "Failure path converted to a success-shaped return value.", f.symbol))
        if f.detail.get("wraps_new_security_check"):
            out.append(Finding("AC-ERR-04", "error_handling", BLOCKER,
                               "The new catch block encloses the newly added security check — the patch "
                               "neutralises its own fix; the security exception never reaches the caller.",
                               f.symbol))
    return out


# ── Family 4: contracts ─────────────────────────────────────────────────────
def d_contracts(facts: list[Fact], ctx: Context) -> list[Finding]:
    table = {
        "SIGNATURE_CHANGED": ("AC-CON-01", "Public method signature changed."),
        "DTO_FIELD_REMOVED": ("AC-CON-02", "DTO field removed."),
        "DTO_FIELD_RENAMED": ("AC-CON-02", "DTO field renamed."),
        "DTO_FIELD_RETYPED": ("AC-CON-02", "DTO field retyped."),
        "PROTO_FIELD_RENUMBERED": ("AC-CON-03", "Protobuf field number reused."),
        "AVRO_INCOMPATIBLE": ("AC-CON-04", "Avro schema incompatible with the subject's compatibility mode."),
        "OPENAPI_BREAKING": ("AC-CON-05", "OpenAPI breaking change."),
        "COLUMN_DROPPED": ("AC-CON-06", "Database column dropped."),
        "SERIALIZED_NAME_CHANGED": ("AC-CON-07", "Serialised field name changed."),
        "ENUM_VALUE_REMOVED": ("AC-CON-08", "Enum value removed."),
    }
    out = []
    for f in facts:
        if f.fact not in table:
            continue
        det, msg = table[f.fact]
        if f.fact == "SIGNATURE_CHANGED" and f.detail.get("visibility") != "public":
            continue
        consumers = f.detail.get("consumers", 0)
        sev = BLOCKER if consumers else REVIEW
        inv = None
        for i in _invariants_for(ctx, f.symbol):
            if i.get("class") == "CONTRACT":
                inv = i["id"]
        out.append(Finding(det, "contracts", sev,
                           f"{msg} Live consumers: {consumers}.", f.symbol, invariant_violated=inv))
    return out


# ── Family 5: verification integrity (all unconditional blockers) ───────────
def d_verification_integrity(facts: list[Fact], ctx: Context) -> list[Finding]:
    table = {
        "TEST_DELETED": ("AC-TST-02", "Existing test deleted."),
        "TEST_DISABLED": ("AC-TST-03", "Existing test disabled or skipped."),
        "ASSERTION_REMOVED": ("AC-TST-04", "Assertion removed."),
        "ASSERTION_TAUTOLOGICAL": ("AC-TST-04", "Assertion weakened to a tautology."),
        "THRESHOLD_LOWERED": ("AC-TST-05", "Coverage or quality threshold lowered."),
        "CI_WORKFLOW_MODIFIED": ("AC-TST-06", "CI workflow modified."),
        "TEST_SUITE_MEMBERSHIP_CHANGED": ("AC-TST-07", "Test moved out of the default suite."),
    }
    out = []
    for f in facts:
        if f.fact in table:
            det, msg = table[f.fact]
            out.append(Finding(det, "verification_integrity", BLOCKER,
                               msg + " No remediation contract may modify the verification apparatus; "
                                     "the correct output in that case is a BLOCKED report.", f.symbol))
    for path, expected in ctx.characterization_hashes.items():
        observed = ctx.graph_delta.get("observed_hashes", {}).get(path)
        if observed and observed != expected:
            out.append(Finding("AC-TST-01", "verification_integrity", BLOCKER,
                               f"Characterization artefact hash mismatch (expected {expected[:12]}…, "
                               f"observed {observed[:12]}…).", path))
    return out


# ── Family 6: scanner silencing ─────────────────────────────────────────────
def d_suppression(facts: list[Fact], ctx: Context) -> list[Finding]:
    table = {
        "SUPPRESSION_ADDED": ("AC-SUP-01", "Scanner suppression added."),
        "SCANNER_BASELINE_MODIFIED": ("AC-SUP-02", "Scanner ignore/baseline file modified."),
        "SCANNER_EXCLUSION_ADDED": ("AC-SUP-03", "Scanner exclusion or path filter added."),
        "RISK_ACCEPTANCE_IN_CODE": ("AC-SUP-04", "Finding marked accepted-risk from within a patch."),
        "DEPENDENCY_IGNORE_ADDED": ("AC-SUP-05", "Dependency ignore rule added."),
    }
    return [Finding(*(table[f.fact][0], "suppression", BLOCKER,
                      f"{table[f.fact][1]} ({f.next})", f.symbol))
            for f in facts if f.fact in table]


# ── Family 7: non-functional invariants ─────────────────────────────────────
def d_nfr(facts: list[Fact], ctx: Context) -> list[Finding]:
    out = []
    for f in facts:
        zone_classes = {z["class"] for z in _zones_of(ctx, f.symbol)}
        forbid = any(z.get("enforcement") == "FORBID_MODIFY" for z in _zones_of(ctx, f.symbol))
        in_nfr_zone = bool({"TXN", "CONCURRENCY", "IDEMPOTENCY", "RATE_LIMIT", "CACHE"} & zone_classes)
        sev = BLOCKER if (in_nfr_zone or forbid) else REVIEW
        inv = next((i["id"] for i in _invariants_for(ctx, f.symbol)
                    if i.get("class") in {"TXN", "CONCURRENCY", "IDEMPOTENCY"}), None)

        if f.fact == "TXN_ATTRIBUTE_CHANGED":
            out.append(Finding("AC-NFR-01", "nfr", sev,
                               f"Transaction attributes changed: {f.prev} -> {f.next}.", f.symbol,
                               invariant_violated=inv))
            if f.detail.get("write_introduced") or (f.prev == "readOnly=true" and f.next != "readOnly=true"):
                out.append(Finding("AC-NFR-02", "nfr", BLOCKER,
                                   "Transaction boundary widened: a write was introduced into a readOnly "
                                   f"span ({f.detail.get('write_introduced', 'attribute change')}).",
                                   f.symbol, invariant_violated=inv))
        simple = {
            "LOCK_ACQUIRE_REMOVED": ("AC-NFR-03", "Lock acquisition removed."),
            "LOCK_RELEASE_MOVED": ("AC-NFR-03", "Lock release relocated."),
            "LOCK_ORDER_CHANGED": ("AC-NFR-03", "Lock acquisition order changed."),
            "CACHE_KEY_CHANGED": ("AC-NFR-04", "Cache key changed."),
            "CACHE_TTL_CHANGED": ("AC-NFR-04", "Cache TTL changed."),
            "RATE_LIMIT_RAISED": ("AC-NFR-05", "Rate limit weakened."),
            "RATE_LIMITER_REMOVED": ("AC-NFR-05", "Rate limiter removed."),
            "REMOTE_CALL_IN_LOOP_ADDED": ("AC-NFR-06", "Remote call introduced inside a loop."),
            "SYNC_CALL_IN_TXN_ADDED": ("AC-NFR-07", "Synchronous call introduced inside an open transaction."),
            "BLOCKING_CALL_ON_EVENT_LOOP": ("AC-NFR-08", "Blocking call on a reactive thread."),
            "UNBOUNDED_ACCUMULATOR_ADDED": ("AC-NFR-09", "Unbounded collection or cache introduced."),
            "IDEMPOTENCY_KEY_REMOVED": ("AC-NFR-10", "Idempotency key removed."),
            "DEDUP_CHECK_REMOVED": ("AC-NFR-10", "Deduplication check removed."),
        }
        if f.fact in simple:
            det, msg = simple[f.fact]
            out.append(Finding(det, "nfr", sev, msg, f.symbol, invariant_violated=inv))
    return out


# ── Family 8: capability removal & dependency drift ─────────────────────────
def d_capability(facts: list[Fact], ctx: Context) -> list[Finding]:
    out = []
    for f in facts:
        if f.fact in {"ENDPOINT_DELETED", "REQUEST_PARAM_DELETED", "PUBLIC_METHOD_DELETED"}:
            key = f.detail.get("name", f.symbol)
            usage = ctx.runtime.get(key, {})
            evidence = (f"{usage.get('requests_per_day', 0)} req/day"
                        + (f", origin {usage['origin']}" if usage.get("origin") else "")) if usage else None
            out.append(Finding("AC-CAP-01", "capability", BLOCKER,
                               "Capability removal is a product decision and is not delegable to an agent.",
                               f.symbol, runtime_evidence=evidence))
        if f.fact == "FEATURE_FLAG_HARDCODED_FALSE":
            out.append(Finding("AC-CAP-02", "capability", BLOCKER,
                               "Feature flag hard-disabled rather than the defect fixed.", f.symbol))
        if f.fact == "DEPENDENCY_CHANGED":
            coord = f.detail.get("coordinate", "")
            if coord not in ctx.allowed_dependency_changes:
                out.append(Finding("AC-DEP-01", "dependencies", BLOCKER,
                                   f"Dependency change outside the contract allowlist: {coord}.", f.symbol))

    # AC-CAP-03: severing a live ingress path is a capability removal wearing a fix's clothing.
    for severed in ctx.graph_delta.get("ingress_paths_severed", []):
        usage = ctx.runtime.get(severed, {})
        if usage.get("requests_per_day", 0) > 0:
            out.append(Finding("AC-CAP-03", "capability", BLOCKER,
                               "Vulnerable path made unreachable rather than fixed; the severed path "
                               "carries production traffic.", severed,
                               runtime_evidence=f"{usage['requests_per_day']} req/day"))
    return out


DETECTORS = [d_authz, d_validation, d_error_handling, d_contracts,
             d_verification_integrity, d_suppression, d_nfr, d_capability]


def run(facts: list[Fact], ctx: Context) -> tuple[list[Finding], list[Fact]]:
    """Returns (findings, positive_facts). Positive facts are recorded so a reviewer can see what
    the patch DID, not only what it did not do."""
    raw: list[Finding] = []
    for detector in DETECTORS:
        raw.extend(detector(facts, ctx))

    # One defect at one location is one finding, even when it violates several invariants.
    # Emitting it once per invariant inflates the blocker count and buries the reviewer.
    merged: dict[tuple[str, str], Finding] = {}
    for f in raw:
        key = (f.detector, f.location)
        if key not in merged:
            merged[key] = f
            continue
        prev = merged[key]
        invs = [i for i in (prev.invariant_violated, f.invariant_violated) if i]
        prev.invariant_violated = ", ".join(dict.fromkeys(invs)) or None

    order = {BLOCKER: 0, REVIEW: 1, INFO: 2}
    findings = sorted(merged.values(), key=lambda f: (order[f.severity], f.detector, f.location))
    positives = [f for f in facts if f.fact in POSITIVE_FACTS]
    return findings, positives
