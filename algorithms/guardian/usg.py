"""Universal Symbol Graph — the shared substrate for every downstream decision.

Reachability, correlation, clustering, blast radius and regression-test selection are all
traversals on this one graph. That is the mechanical justification for ADR-001's unified spine.
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field

# Edge provenance → confidence. Confidence is load-bearing, not decoration: the reachability
# degradation policy keys on it, and any conclusion resting on a HEURISTIC edge can never reach
# HIGH confidence, and therefore can never auto-close a finding or auto-merge a patch.
PROVENANCE_CONFIDENCE = {
    "STATIC_RESOLVED": 1.00,
    "RUNTIME_OBSERVED": 0.99,
    "CONTRACT_INFERRED": 0.85,
    "CONFIG_INFERRED": 0.75,
    "HEURISTIC": 0.50,
}

TRAVERSAL_EDGES = {"CALLS", "EXPOSES", "PUBLISHES", "SUBSCRIBES", "OVERRIDES", "IMPLEMENTS"}


@dataclass
class Node:
    id: str
    kind: str                       # Component | Type | Method | Endpoint | Topic | Table | ConfigKey | TestCase
    component: str = ""
    language: str = ""
    attrs: dict = field(default_factory=dict)


@dataclass
class Edge:
    src: str
    dst: str
    kind: str
    provenance: str = "STATIC_RESOLVED"

    @property
    def confidence(self) -> float:
        return PROVENANCE_CONFIDENCE.get(self.provenance, 0.5)


class USG:
    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}
        self.edges: list[Edge] = []
        self._out: dict[str, list[Edge]] = defaultdict(list)
        self._in: dict[str, list[Edge]] = defaultdict(list)

    # ── construction ────────────────────────────────────────────────────────
    def add_node(self, node: Node) -> Node:
        self.nodes[node.id] = node
        return node

    def add_edge(self, src: str, dst: str, kind: str, provenance: str = "STATIC_RESOLVED") -> Edge:
        e = Edge(src, dst, kind, provenance)
        self.edges.append(e)
        self._out[src].append(e)
        self._in[dst].append(e)
        return e

    # ── queries ─────────────────────────────────────────────────────────────
    def out_edges(self, nid: str, kinds: set[str] | None = None) -> list[Edge]:
        return [e for e in self._out[nid] if kinds is None or e.kind in kinds]

    def in_edges(self, nid: str, kinds: set[str] | None = None) -> list[Edge]:
        return [e for e in self._in[nid] if kinds is None or e.kind in kinds]

    def ingress_nodes(self) -> list[Node]:
        """Framework-modelled entry points, not guessed. See docs/03 §T1."""
        return [n for n in self.nodes.values() if n.attrs.get("is_ingress")]

    def paths_to(self, target: str, max_depth: int = 12) -> list[list[str]]:
        """All ingress→target paths, with the minimum edge confidence carried along.

        Returns the *paths*, not just a boolean, because a VFP closure must record the exact
        query and its result to be auditable years later.
        """
        results: list[list[str]] = []
        for ingress in self.ingress_nodes():
            q: deque[tuple[str, list[str]]] = deque([(ingress.id, [ingress.id])])
            seen = {ingress.id}
            while q:
                cur, path = q.popleft()
                if len(path) > max_depth:
                    continue
                if cur == target:
                    results.append(path)
                    continue
                for e in self.out_edges(cur, TRAVERSAL_EDGES):
                    if e.dst not in seen or e.dst == target:
                        seen.add(e.dst)
                        q.append((e.dst, path + [e.dst]))
        return results

    def path_confidence(self, path: list[str]) -> float:
        """A path is only as trustworthy as its weakest seam."""
        conf = 1.0
        for a, b in zip(path, path[1:]):
            edges = [e for e in self._out[a] if e.dst == b]
            if edges:
                conf = min(conf, max(e.confidence for e in edges))
        return conf

    def callers(self, nid: str, depth: int = 1) -> set[str]:
        frontier, seen = {nid}, set()
        for _ in range(depth):
            nxt: set[str] = set()
            for n in frontier:
                for e in self.in_edges(n, {"CALLS", "EXPOSES", "OVERRIDES"}):
                    if e.src not in seen:
                        nxt.add(e.src)
            seen |= nxt
            frontier = nxt
        return seen

    def downstream_components(self, nid: str) -> set[str]:
        """Distinct components that could observe a change to this symbol."""
        comps: set[str] = set()
        for src in self.callers(nid, depth=4):
            node = self.nodes.get(src)
            if node and node.component:
                comps.add(node.component)
        node = self.nodes.get(nid)
        if node:
            comps.discard(node.component)
        return comps

    def pagerank(self, damping: float = 0.85, iterations: int = 40) -> dict[str, float]:
        """Structural importance. Reverse edges: a symbol many things call is central."""
        n = len(self.nodes)
        if n == 0:
            return {}
        rank = {nid: 1.0 / n for nid in self.nodes}
        out_deg = {nid: len(self.out_edges(nid, TRAVERSAL_EDGES)) for nid in self.nodes}
        for _ in range(iterations):
            nxt = {nid: (1.0 - damping) / n for nid in self.nodes}
            for nid, r in rank.items():
                deg = out_deg[nid]
                if deg == 0:
                    share = damping * r / n
                    for other in nxt:
                        nxt[other] += share
                else:
                    share = damping * r / deg
                    for e in self.out_edges(nid, TRAVERSAL_EDGES):
                        nxt[e.dst] += share
            rank = nxt
        return rank

    def percentile_rank(self, values: dict[str, float], nid: str) -> float:
        if nid not in values or not values:
            return 0.0
        v = values[nid]
        below = sum(1 for x in values.values() if x < v)
        return below / max(1, len(values) - 1)
