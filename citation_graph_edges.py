"""
citation_graph_edges.py

Four-edge citation-graph renderer for the Hardseal Field Report §6 closing
demo. Consumes a directory of markdown documents and emits an edge list with
four named categories:

    VALID                  : citation target exists as a document in the bundle
    ORPHAN                 : document in bundle has no incoming citations
    RECYCLED_AUTHORITY     : the same target is cited from >= 3 unrelated
                             control families (template-reuse signal)
    HALLUCINATION_KILL_SHOT: citation target is a specific, named document
                             that does not exist anywhere in the bundle

This is the rendering layer the paper promises in Outline v0.3.1 §6. It is
separate from the CitationGraphDetector in mismatch_engine_ai.py, which
returns a composite topology score (depth / orphan-rate / cycles) rather than
a typed edge list.

Sacred Rule: stdlib-only.

Usage:
    python citation_graph_edges.py samples/citation_kill_shot_demo/
    python citation_graph_edges.py samples/citation_kill_shot_demo/ --json

Author: Rico Allen + Claude (Hardseal), April 2026.
"""
from __future__ import annotations

import json
import re
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, List, Set, Tuple


# ---------------------------------------------------------------------------
# Edge taxonomy
# ---------------------------------------------------------------------------

class EdgeType(str, Enum):
    VALID = "valid"
    ORPHAN = "orphan"
    RECYCLED_AUTHORITY = "recycled_authority"
    HALLUCINATION_KILL_SHOT = "hallucination_kill_shot"


@dataclass
class Edge:
    edge_type: str
    source_doc: str
    target_id: str
    context: str
    reason: str

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class BundleReport:
    bundle_path: str
    documents: List[str]
    edges: List[Edge]
    edge_counts: Dict[str, int]
    wall_time_ms: float
    verdict: str

    def to_dict(self) -> Dict:
        return {
            "bundle_path": self.bundle_path,
            "documents": self.documents,
            "edge_counts": self.edge_counts,
            "wall_time_ms": round(self.wall_time_ms, 2),
            "verdict": self.verdict,
            "edges": [e.to_dict() for e in self.edges],
        }


# ---------------------------------------------------------------------------
# Citation extraction patterns
#
# Two pattern families:
#   (1) Identifier-form:  "Policy AC-001 v2.0", "SOP-442", "Runbook IR-102"
#   (2) Named-form:       "Access Control Policy v2.1", "Media Protection Policy"
#
# Both canonicalize to a consistent ID string.
# ---------------------------------------------------------------------------

_KINDS = r"Policy|SOP|Procedure|Runbook|Standard|Plan"

# Identifier-form: kind + optional family code + number + optional version.
_CITE_ID_RE = re.compile(
    rf"\b(?P<kind>{_KINDS})"
    r"[\s\-]*(?P<family>[A-Z]{2,5})?"
    r"[\s\-]*#?(?P<number>\d{2,4})"
    r"(?:[\s\-]*v(?P<version>\d+(?:\.\d+)*))?",
    re.IGNORECASE,
)

# Named-form: canonical compliance-doc names. The 17 NIST SP 800-171
# family-aligned doc names plus common extras.
_NAMED_FAMILIES = [
    "Access Control",
    "Awareness and Training",
    "Audit and Accountability",
    "Configuration Management",
    "Identification and Authentication",
    "Incident Response",
    "Maintenance",
    "Media Protection",
    "Personnel Security",
    "Physical Protection",
    "Risk Assessment",
    "Security Assessment",
    "System and Communications Protection",
    "System and Information Integrity",
    "Acceptable Use",
    "Change Management",
    "Continuous Monitoring",
]

_CITE_NAMED_RE = re.compile(
    r"\b(?P<name>(?:" + "|".join(re.escape(n) for n in _NAMED_FAMILIES) + r")"
    r"\s(?:Policy|Plan|Procedure|Standard|SOP))"
    r"(?:\s+v(?P<version>\d+(?:\.\d+)*))?",
    re.IGNORECASE,
)


def _canonicalize_id(kind: str, family: str, number: str, version: str) -> str:
    kind = kind.title()
    family = (family or "").upper()
    ident = f"{kind}-{family}-{number}" if family else f"{kind}-{number}"
    if version:
        ident = f"{ident} v{version}"
    return ident


def _canonicalize_name(name: str, version: str) -> str:
    # Title-case each word, preserve the natural phrasing
    parts = [p[:1].upper() + p[1:].lower() if p and p[0].isalpha() else p
             for p in name.split()]
    ident = " ".join(parts)
    if version:
        ident = f"{ident} v{version}"
    return ident


def extract_citations(text: str,
                      adjacency_gap: int = 5) -> List[Dict]:
    """
    Return a list of citation dicts: {id, context, start, end, kind}.

    De-duplicates in two passes:
        (1) Drop any hit whose span is contained in / overlaps a preceding hit.
        (2) Drop a named-form hit that appears within `adjacency_gap` characters
            of an identifier-form hit — these are almost always a parenthetical
            expansion of the same citation ("Policy-IA-005 v1.3 (Identification
            and Authentication Policy)") and should be treated as one citation.
    """
    hits: List[Tuple[str, int, int, str]] = []  # (ident, start, end, kind)

    for m in _CITE_ID_RE.finditer(text):
        ident = _canonicalize_id(
            m.group("kind"),
            m.group("family") or "",
            m.group("number"),
            m.group("version") or "",
        )
        hits.append((ident, m.start(), m.end(), "id"))

    for m in _CITE_NAMED_RE.finditer(text):
        ident = _canonicalize_name(
            m.group("name"),
            m.group("version") or "",
        )
        hits.append((ident, m.start(), m.end(), "named"))

    # Pass 1: span-contained dedupe
    hits.sort(key=lambda t: (t[1], -t[2]))
    pass1: List[Tuple[str, int, int, str]] = []
    last_end = -1
    for ident, s, e, kind in hits:
        if s >= last_end:
            pass1.append((ident, s, e, kind))
            last_end = e

    # Pass 2: merge adjacent id + named hits (parenthetical expansions)
    pass2: List[Tuple[str, int, int, str]] = []
    skip_next_if_named = False
    last_id_end = -10_000
    for i, (ident, s, e, kind) in enumerate(pass1):
        if kind == "named" and (s - last_id_end) <= adjacency_gap:
            # This named form is a parenthetical expansion of the prior id form
            continue
        pass2.append((ident, s, e, kind))
        if kind == "id":
            last_id_end = e

    out = []
    for ident, s, e, kind in pass2:
        context_start = max(0, s - 40)
        context_end = min(len(text), e + 40)
        context = text[context_start:context_end].replace("\n", " ").strip()
        out.append({
            "id": ident,
            "context": context,
            "start": s,
            "end": e,
            "kind": kind,
        })
    return out


# ---------------------------------------------------------------------------
# Bundle doc-ID resolution
# ---------------------------------------------------------------------------

_HEADING_ID_RE = re.compile(
    rf"^#\s*(?P<kind>{_KINDS})"
    r"[\s\-]*(?P<family>[A-Z]{2,5})?"
    r"[\s\-]*#?(?P<number>\d{2,4})"
    r"(?:[\s\-]*v(?P<version>\d+(?:\.\d+)*))?",
    re.IGNORECASE | re.MULTILINE,
)

_HEADING_NAMED_RE = re.compile(
    r"^#\s*(?P<name>(?:" + "|".join(re.escape(n) for n in _NAMED_FAMILIES) + r")"
    r"\s(?:Policy|Plan|Procedure|Standard|SOP))"
    r"(?:\s+v(?P<version>\d+(?:\.\d+)*))?",
    re.IGNORECASE | re.MULTILINE,
)


def canonical_id_for_file(path: Path, text: str) -> Tuple[str, Set[str], bool]:
    """
    Resolve a canonical doc ID for a bundle file plus any self-aliases.

    Returns:
        (canonical_id, self_aliases, is_narrative)

    Preference order for canonical_id:
        1. First '# Policy-AC-001 v2.0' style heading
        2. First '# Access Control Policy v2.1' style heading
        3. Filename-stem fallback (policy_ac_001 -> Policy-AC-001)

    self_aliases always includes the canonical id AND any alternate form that
    appears in the doc's own H1 heading — e.g. both "Policy-AC-001 v2.0" and
    "Access Control Policy" for a heading like "# Policy-AC-001 v2.0: Access
    Control Policy". Citations matching any alias are dropped as self-refs.

    is_narrative is True if this file is an SSP/POA&M/audit/report narrative
    (a top-of-graph doc), which is exempt from the ORPHAN check.
    """
    aliases: Set[str] = set()
    canonical = ""

    m_id = _HEADING_ID_RE.search(text)
    if m_id:
        canonical = _canonicalize_id(
            m_id.group("kind"),
            m_id.group("family") or "",
            m_id.group("number"),
            m_id.group("version") or "",
        )
        aliases.add(canonical)

    # Collect any named-form aliases from the heading line itself
    # (e.g. "# Policy-AC-001 v2.0: Access Control Policy")
    first_line = text.split("\n", 1)[0] if text else ""
    for m in _CITE_NAMED_RE.finditer(first_line):
        aliases.add(_canonicalize_name(
            m.group("name"),
            m.group("version") or "",
        ))

    if not canonical:
        m_named = _HEADING_NAMED_RE.search(text)
        if m_named:
            canonical = _canonicalize_name(
                m_named.group("name"),
                m_named.group("version") or "",
            )
            aliases.add(canonical)

    is_narrative = False
    if not canonical:
        stem = path.stem
        stem_lower = stem.lower()
        # Narrative-filename conventions: "ssp_", "poam_", "au_",
        # "report_", "narrative_", or NIST-section-prefixed ("3.1.1_...")
        narrative_prefix = stem_lower.startswith(
            ("ssp_", "poam_", "au_", "ca_", "report_", "narrative_")
        )
        nist_section = bool(re.match(r"^\d+\.\d+(?:\.\d+)?_", stem_lower))
        if narrative_prefix or nist_section:
            is_narrative = True
            canonical = stem
        else:
            parts = stem.split("_")
            recognized_kinds = {"policy", "sop", "procedure", "runbook", "standard", "plan"}
            if (len(parts) >= 3
                    and parts[0].lower() in recognized_kinds
                    and parts[1].isalpha()):
                canonical = f"{parts[0].title()}-{parts[1].upper()}-{parts[2]}"
            else:
                # Unknown shape — treat as narrative (conservative: do not
                # accuse an unknown doc of being an orphan policy).
                is_narrative = True
                canonical = stem
        aliases.add(canonical)

    return canonical, aliases, is_narrative


# ---------------------------------------------------------------------------
# Control-family inference (for recycled-authority unrelatedness check)
# ---------------------------------------------------------------------------

_FAMILY_KEYWORDS = [
    ("AC", ["access control"]),
    ("AT", ["awareness and training", "awareness"]),
    ("AU", ["audit and accountability", "audit"]),
    ("CM", ["configuration management"]),
    ("IA", ["identification and authentication", "identification"]),
    ("IR", ["incident response", "incident"]),
    ("MA", ["maintenance"]),
    ("MP", ["media protection"]),
    ("PS", ["personnel security"]),
    ("PE", ["physical protection", "physical"]),
    ("RA", ["risk assessment"]),
    ("CA", ["security assessment"]),
    ("SC", ["system and communications protection", "boundary protection"]),
    ("SI", ["system and information integrity"]),
]


def infer_family(doc_id: str, text: str = "") -> str:
    # ID-form: "Policy-AC-001" -> "AC"
    parts = doc_id.split("-")
    if len(parts) >= 2 and parts[1].isupper() and 2 <= len(parts[1]) <= 5:
        return parts[1]
    # NIST-form in filename: "ssp_3_1_1" -> AC (3.1 is AC family)
    m = re.match(r"(?:ssp|poam|au)_3_(\d+)_", doc_id.lower())
    if m:
        section = int(m.group(1))
        if 1 <= section <= 22:
            family_map = {1: "AC", 2: "AT", 3: "AU", 4: "CM", 5: "IA", 6: "IR",
                          7: "MA", 8: "MP", 9: "PS", 10: "PE", 11: "RA",
                          12: "CA", 13: "SC", 14: "SI"}
            return family_map.get(section, "?")
    # Named-form: scan keywords in ID and text
    hay = (doc_id + " " + text).lower()
    for fam, kws in _FAMILY_KEYWORDS:
        for kw in kws:
            if kw in hay:
                return fam
    return "?"


# ---------------------------------------------------------------------------
# Renderer
# ---------------------------------------------------------------------------

def render_bundle(bundle_dir: Path,
                  recycled_authority_threshold: int = 3) -> BundleReport:
    """
    Render the four-edge citation graph for a bundle of markdown documents.

    Args:
        bundle_dir: directory containing the evidence bundle (*.md files).
        recycled_authority_threshold: minimum distinct control families that
            must cite the same target to classify edges as RECYCLED_AUTHORITY.

    Returns:
        BundleReport with edge list, counts, wall-time, and one-line verdict.
    """
    t0 = time.perf_counter()

    docs: Dict[str, Tuple[Path, str]] = {}
    doc_families: Dict[str, str] = {}
    doc_aliases: Dict[str, Set[str]] = {}
    narrative_docs: Set[str] = set()
    for p in sorted(bundle_dir.iterdir()):
        if p.suffix != ".md" or p.name.startswith("_"):
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        ident, aliases, is_narrative = canonical_id_for_file(p, text)
        docs[ident] = (p, text)
        doc_families[ident] = infer_family(ident, text) or infer_family(p.stem)
        doc_aliases[ident] = aliases
        if is_narrative:
            narrative_docs.add(ident)

    # Build a global alias -> canonical-id resolver so citations of a named
    # form hit the same target as citations of the identifier form.
    alias_to_canonical: Dict[str, str] = {}
    for canonical, aliases in doc_aliases.items():
        for a in aliases:
            alias_to_canonical[a] = canonical

    edges: List[Edge] = []
    citing_families_per_target: Dict[str, Set[str]] = defaultdict(set)

    for src_id, (_, text) in docs.items():
        src_family = doc_families.get(src_id, "?")
        src_aliases = doc_aliases.get(src_id, {src_id})
        for cite in extract_citations(text):
            target = cite["id"]
            # Skip self-references (any alias of this doc)
            if target in src_aliases:
                continue
            # Resolve named-form target to canonical id if possible
            target = alias_to_canonical.get(target, target)

            if target in docs:
                edges.append(Edge(
                    edge_type=EdgeType.VALID.value,
                    source_doc=src_id,
                    target_id=target,
                    context=cite["context"],
                    reason=f"Target '{target}' resolves to {docs[target][0].name} in bundle.",
                ))
                if src_family != "?":
                    citing_families_per_target[target].add(src_family)
            else:
                edges.append(Edge(
                    edge_type=EdgeType.HALLUCINATION_KILL_SHOT.value,
                    source_doc=src_id,
                    target_id=target,
                    context=cite["context"],
                    reason=(
                        f"Target '{target}' is named with document-level "
                        f"specificity but does not exist in the contractor's "
                        f"own bundle. Likely fabricated by LLM assistance."
                    ),
                ))

    # Promote VALID edges to RECYCLED_AUTHORITY where the target is cited
    # from >= threshold distinct unrelated control families.
    recycled_targets: Set[str] = {
        tgt for tgt, fams in citing_families_per_target.items()
        if len(fams) >= recycled_authority_threshold
    }
    for e in edges:
        if e.edge_type == EdgeType.VALID.value and e.target_id in recycled_targets:
            fams = sorted(citing_families_per_target[e.target_id])
            e.edge_type = EdgeType.RECYCLED_AUTHORITY.value
            e.reason = (
                f"Target '{e.target_id}' is cited from {len(fams)} unrelated "
                f"control families ({', '.join(fams)}), suggesting template "
                f"reuse rather than independent authority."
            )

    # ORPHAN: supporting bundle docs that appear as citation targets of
    # nothing at all. Narrative docs (SSPs, POA&Ms, audit reports) are
    # exempt — they are top-of-graph by design.
    incoming: Set[str] = {
        e.target_id for e in edges
        if e.edge_type in (EdgeType.VALID.value, EdgeType.RECYCLED_AUTHORITY.value)
    }
    for doc_id in docs:
        if doc_id in narrative_docs:
            continue
        if doc_id not in incoming:
            edges.append(Edge(
                edge_type=EdgeType.ORPHAN.value,
                source_doc="(bundle)",
                target_id=doc_id,
                context=f"File: {docs[doc_id][0].name}",
                reason=(
                    f"Document '{doc_id}' exists in the bundle but is not cited "
                    f"by any SSP, POA&M, or procedure narrative. Assessor will "
                    f"ask why it was submitted."
                ),
            ))

    counts = dict(Counter(e.edge_type for e in edges))

    verdict_parts = []
    if counts.get(EdgeType.HALLUCINATION_KILL_SHOT.value, 0) > 0:
        verdict_parts.append(
            f"{counts[EdgeType.HALLUCINATION_KILL_SHOT.value]} HALLUCINATION_KILL_SHOT"
            f" — DISQUALIFYING."
        )
    if counts.get(EdgeType.RECYCLED_AUTHORITY.value, 0) > 0:
        verdict_parts.append(
            f"{counts[EdgeType.RECYCLED_AUTHORITY.value]} RECYCLED_AUTHORITY"
            f" — template-reuse suspected."
        )
    if counts.get(EdgeType.ORPHAN.value, 0) > 0:
        verdict_parts.append(
            f"{counts[EdgeType.ORPHAN.value]} ORPHAN — uncited artifacts."
        )
    if not verdict_parts:
        verdict_parts.append("No citation-graph anomalies detected.")
    verdict = " ".join(verdict_parts)

    wall_time_ms = (time.perf_counter() - t0) * 1000.0

    return BundleReport(
        bundle_path=str(bundle_dir),
        documents=sorted(docs.keys()),
        edges=edges,
        edge_counts=counts,
        wall_time_ms=wall_time_ms,
        verdict=verdict,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _main(argv=None) -> int:
    import argparse
    p = argparse.ArgumentParser(
        description=(
            "Four-edge citation-graph renderer for the Hardseal Field Report "
            "§6 closing demo. Stdlib-only."
        )
    )
    p.add_argument("bundle_dir", help="Directory of markdown documents")
    p.add_argument("--json", action="store_true", help="Emit JSON report")
    p.add_argument("--recycled-threshold", type=int, default=3,
                   help="Min distinct control families for RECYCLED_AUTHORITY (default: 3)")
    args = p.parse_args(argv)

    rep = render_bundle(
        Path(args.bundle_dir),
        recycled_authority_threshold=args.recycled_threshold,
    )

    if args.json:
        print(json.dumps(rep.to_dict(), indent=2))
        return 0

    print(f"BUNDLE: {rep.bundle_path}")
    print(f"DOCUMENTS ({len(rep.documents)}):")
    for d in rep.documents:
        print(f"  - {d}")
    print()
    print(f"WALL TIME:   {rep.wall_time_ms:.1f} ms")
    print(f"EDGE COUNTS: {rep.edge_counts}")
    print(f"VERDICT:     {rep.verdict}")
    print()
    print("EDGES:")
    for e in rep.edges:
        label = e.edge_type.upper()
        print(f"  [{label}]  {e.source_doc}  ->  {e.target_id}")
        print(f"      context: {e.context[:120]}")
        print(f"      reason:  {e.reason}")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
