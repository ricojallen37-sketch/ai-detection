"""
mismatch_engine_ai.py

Hardseal AI-era evidence contamination detection engine.

Purpose
-------
Defense contractors are increasingly submitting SSPs, POA&Ms, and evidence
narratives that were generated, in whole or in part, by large language models.
A C3PAO assessor who spots the resulting patterns (boilerplate clustering,
fabricated citations, batch-stamped evidence, LLM residual phrasing) will widen
the scope of scrutiny across adjacent controls.

This module detects those patterns BEFORE the assessor does. It runs inside the
contractor's own environment and produces a composite contamination score plus
per-detector findings that map to specific NIST SP 800-171A objectives.

Sacred Rule
-----------
Zero external dependencies. Python standard library only.

Why this is a security differentiator, not a limitation:
- Every third-party dependency is attack surface.
- This engine must be runnable inside a CUI boundary without importing new trust.
- Vanta and Drata require agents. Hardseal does not.

Detectors (v1.1)
-----------------
1. BoilerplateClusteringDetector
   Pairwise Jaccard similarity on normalized token sets across control
   narratives. Flags pairs above a threshold, then transitively clusters them
   into boilerplate families. v1.1: enriched evidence with pairwise
   similarities and shared token samples.

2. PromptLeakageDetector
   Regex-based scan for LLM residual phrasing and "AI tells" (em-dashes,
   hedging clusters, meta-commentary phrases). v1.1: max-risk hybrid
   scoring (worst-case drives 70%, mean adds 30%). Medium patterns demoted
   to require combination signals to reduce false positives.

3. TimestampRegularityDetector
   Detects batch-stamped evidence metadata.

4. MappingDensityDetector
   Flags overclaimed evidence artifact reuse.

5. CitationGraphDetector
   Identifies broken and fabricated document references within narratives.

6. StatisticalAnomalyDetector
   v1.1: Now three sub-signals: Shannon entropy CV, sentence-length CV,
   and type-token ratio CV. Harder to evade, more robust detection.

7. SpecificityDeficitDetector [NEW v1.1]
   Scores narratives for implementation-detail density. Catches generic
   AI-generated language that lacks named systems, tools, roles, cadences,
   and evidence artifact identifiers.

8. ContradictionDetector [NEW v1.1]
   The "killer missing piece." Extracts structured assertions (frequencies,
   tools, ownership) from narratives and flags cross-control contradictions.
   Dict-based assertion graph, stdlib-only.

Control Mapping
---------------
Flagged artifacts commonly degrade confidence for objectives under:
  3.11.1  Risk Assessment: periodic risk assessments
  3.12.1  Security Assessment: periodic security assessment
  3.12.3  Security Assessment: monitoring on ongoing basis
  3.3.1   Audit: create and retain system audit logs
  3.14.6  System Integrity: monitor systems for attacks and indicators

Security+ Domain Linkage
------------------------
Domain 4 (Security Operations) and Domain 5 (Security Program Management and
Oversight) both require defenders to detect and respond to anomalous inputs.
LLM-generated compliance artifacts are anomalous inputs.

Kill Chain Linkage
------------------
Weaponization and Delivery stages. An attacker or a lazy consultant who injects
AI-generated narratives into an SSP weaponizes the compliance deliverable
itself. The detection engine sits on the Delivery boundary: it inspects the
artifact before it becomes authoritative.

Author: Rico Allen, Hardseal LLC, April 2026.
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Iterable, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Tokenization and normalization
# ---------------------------------------------------------------------------

# Tokens are runs of alphanumeric characters, lowercased. Punctuation is
# dropped because we want token-set comparison, not style comparison.
_TOKEN_RE = re.compile(r"[A-Za-z0-9]+")

# Stop tokens commonly inflate Jaccard similarity on compliance text. We keep
# the list tight and stdlib-defined; no NLTK.
_STOP_TOKENS = frozenset(
    {
        "a", "an", "and", "are", "as", "at", "be", "by", "for", "from",
        "has", "have", "in", "is", "it", "its", "of", "on", "or", "that",
        "the", "this", "to", "was", "were", "will", "with", "which",
        "these", "those", "also", "any", "all", "not", "but", "per",
        "such", "within", "via", "across", "into", "our", "their",
    }
)


def tokenize(text: str) -> List[str]:
    """Normalize text to a lowercase alphanumeric token list, minus stopwords."""
    if not text:
        return []
    return [t for t in _TOKEN_RE.findall(text.lower()) if t not in _STOP_TOKENS]


def token_set(text: str) -> frozenset:
    """Return the set of distinct normalized tokens in text."""
    return frozenset(tokenize(text))


# ---------------------------------------------------------------------------
# Jaccard similarity
# ---------------------------------------------------------------------------

def jaccard(a: frozenset, b: frozenset) -> float:
    """Standard Jaccard index over two token sets. Returns value in [0, 1]."""
    if not a and not b:
        return 0.0
    union = a | b
    if not union:
        return 0.0
    return len(a & b) / len(union)


# ---------------------------------------------------------------------------
# Detector base
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """A single contamination finding surfaced by a detector."""
    detector: str
    severity: str           # INFO, LOW, MEDIUM, HIGH
    score: float            # contribution to composite, in [0, 1]
    description: str
    evidence: Dict = field(default_factory=dict)


@dataclass
class DetectorResult:
    """Aggregate output of a single detector."""
    name: str
    score: float            # detector score in [0, 1]
    findings: List[Finding] = field(default_factory=list)
    severity_override: str = None  # v1.1: force package severity (e.g. HIGH)

    def to_dict(self) -> Dict:
        d = {
            "name": self.name,
            "score": round(self.score, 3),
            "findings": [
                {
                    "severity": f.severity,
                    "score": round(f.score, 3),
                    "description": f.description,
                    "evidence": f.evidence,
                }
                for f in self.findings
            ],
        }
        if self.severity_override:
            d["severity_override"] = self.severity_override
        return d


# ---------------------------------------------------------------------------
# Detector 1: Boilerplate Clustering
# ---------------------------------------------------------------------------

class BoilerplateClusteringDetector:
    """
    Detect copy-paste patterns across control narratives.

    Method
    ------
    1. Tokenize each narrative with stopword removal.
    2. Compute pairwise Jaccard similarity.
    3. Flag pairs with similarity >= threshold (default 0.80).
    4. Transitively cluster flagged pairs using a union-find equivalent.

    Score
    -----
    fraction_in_cluster = (count of narratives that belong to any cluster of
                           size >= 2) / total narratives.
    The detector score is fraction_in_cluster, clamped to [0, 1].

    Why this maps to assessor behavior
    ----------------------------------
    A C3PAO assessor reading two AC-family narratives that are 87 percent
    identical will ask how those controls can share that much implementation
    text if the underlying systems are different. That question widens scope.
    """

    name = "BoilerplateClustering"

    def __init__(self, similarity_threshold: float = 0.80):
        if not 0.0 < similarity_threshold <= 1.0:
            raise ValueError("similarity_threshold must be in (0.0, 1.0].")
        self.threshold = similarity_threshold

    def run(self, narratives: Dict[str, str]) -> DetectorResult:
        """
        narratives: mapping of control_id -> narrative text.
        """
        control_ids = list(narratives.keys())
        token_sets = {cid: token_set(narratives[cid]) for cid in control_ids}

        pairs: List[Tuple[str, str, float]] = []
        for i, a in enumerate(control_ids):
            for b in control_ids[i + 1:]:
                sim = jaccard(token_sets[a], token_sets[b])
                if sim >= self.threshold:
                    pairs.append((a, b, sim))

        # Union-find clusters on flagged pairs.
        parent: Dict[str, str] = {c: c for c in control_ids}

        def find(x: str) -> str:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(x: str, y: str) -> None:
            rx, ry = find(x), find(y)
            if rx != ry:
                parent[rx] = ry

        for a, b, _ in pairs:
            union(a, b)

        clusters: Dict[str, List[str]] = {}
        for c in control_ids:
            r = find(c)
            clusters.setdefault(r, []).append(c)

        nontrivial = [members for members in clusters.values() if len(members) >= 2]
        in_cluster = sum(len(m) for m in nontrivial)
        score = in_cluster / len(control_ids) if control_ids else 0.0

        findings: List[Finding] = []
        for members in nontrivial:
            severity = "HIGH" if len(members) >= 4 else "MEDIUM"

            # v1.1: Compute pairwise similarities within cluster for evidence
            cluster_pairs = []
            for i, a in enumerate(sorted(members)):
                for b in sorted(members)[i + 1:]:
                    sim = jaccard(token_sets[a], token_sets[b])
                    cluster_pairs.append({"pair": [a, b], "similarity": round(sim, 3)})

            # v1.1: Find shared tokens across cluster (the boilerplate itself)
            if len(members) >= 2:
                shared = token_sets[members[0]]
                for m in members[1:]:
                    shared = shared & token_sets[m]
                shared_sample = sorted(shared)[:15]  # top 15 for readability
            else:
                shared_sample = []

            findings.append(
                Finding(
                    detector=self.name,
                    severity=severity,
                    score=len(members) / len(control_ids),
                    description=(
                        f"Boilerplate cluster of {len(members)} narratives "
                        f"sharing >= {int(self.threshold * 100)}% token overlap. "
                        "An assessor will ask for environment-specific evidence "
                        "per control and will not accept shared language."
                    ),
                    evidence={
                        "members": sorted(members),
                        "threshold": self.threshold,
                        "pairwise_similarities": cluster_pairs,
                        "shared_tokens_sample": shared_sample,
                        "why_it_matters": (
                            "Identical or near-identical narratives across "
                            "distinct controls indicate template-driven "
                            "generation. Each control requires its own "
                            "implementation-specific description."
                        ),
                        "remediation": (
                            "Rewrite each narrative to describe the specific "
                            "system, tool, and process that implements that "
                            "control in your environment. No two controls "
                            "should share >50% of their narrative text."
                        ),
                        "confidence": "HIGH" if len(members) >= 4 else "MEDIUM",
                    },
                )
            )

        return DetectorResult(name=self.name, score=score, findings=findings)


# ---------------------------------------------------------------------------
# Detector 2: Prompt Leakage Signatures
# ---------------------------------------------------------------------------

class PromptLeakageDetector:
    """
    Detect residual LLM-generated phrasing inside narratives.

    Method
    ------
    Two pattern families are counted against narrative length:

      HIGH-severity patterns: unambiguous LLM tells. A match is almost always
        evidence that an LLM produced the text.

      MEDIUM-severity patterns: style tells. Common in LLM output and rare in
        human-written SSPs.

    Score
    -----
    per_narrative_score = clamp( (high_hits * 0.5 + medium_hits * 0.15) / 1.0 )
    detector_score = mean of per-narrative scores across all narratives.

    Weights favor precision over recall; one "As an AI compliance assistant"
    match should dominate the narrative's score.
    """

    name = "PromptLeakage"

    _HIGH_PATTERNS = [
        r"\bas an ai\b",
        r"\bas your compliance assistant\b",
        r"\bi cannot\b",
        r"\blanguage model\b",
        r"\bi am not able to\b",
        r"\bcertainly[!,]? here\b",
        r"\bsure[!,]? here\b",
        r"\bas a compliance assistant\b",
        r"\bhope this helps\b",
    ]

    _MEDIUM_PATTERNS = [
        r"\bit is important to note\b",
        r"\bit should be noted\b",
        r"\bplease note that\b",
        r"\bit is worth noting\b",
        r"\bin conclusion\b",
        r"\bin summary\b",
        r"\bleverage[s]?\b",
        r"\brobust\b",
        r"\bseamless\b",
        r"\bcomprehensive\b",
        r"\bstate[\- ]of[\- ]the[\- ]art\b",
        r"\butilize[sd]?\b",
        r"\bdelve into\b",
    ]

    # Em-dash and en-dash are AI tells in defense compliance writing.
    # We count their frequency and let density push the score up.
    _DASH_CHARS = ("\u2014", "\u2013")

    def __init__(self):
        self._high_re = [re.compile(p, re.IGNORECASE) for p in self._HIGH_PATTERNS]
        self._medium_re = [re.compile(p, re.IGNORECASE) for p in self._MEDIUM_PATTERNS]

    def _score_narrative(self, text: str) -> Tuple[float, Dict]:
        if not text:
            return 0.0, {"high_hits": 0, "medium_hits": 0, "dash_count": 0,
                         "matched_phrases": []}

        high_hits = sum(1 for rx in self._high_re for _ in rx.finditer(text))
        medium_hits = sum(1 for rx in self._medium_re for _ in rx.finditer(text))
        dash_count = sum(text.count(d) for d in self._DASH_CHARS)

        # v1.1: Collect matched phrases for evidence enrichment
        matched_phrases = []
        for rx in self._high_re:
            for m in rx.finditer(text):
                matched_phrases.append({"pattern": m.group(), "severity": "HIGH"})
        for rx in self._medium_re:
            for m in rx.finditer(text):
                matched_phrases.append({"pattern": m.group(), "severity": "MEDIUM"})

        # Dashes contribute at 0.05 each, capped separately below.
        dash_component = min(0.30, dash_count * 0.05)

        # v1.1: Demote medium patterns — they only contribute when combined
        # with other signals. A standalone "robust" or "comprehensive" in
        # legitimate compliance writing should not trigger a finding.
        # Medium patterns need at least 2 different signal types to count:
        # (medium_hits >= 2) OR (medium_hits >= 1 AND dash_count >= 2) OR
        # (medium_hits >= 1 AND high_hits >= 1).
        medium_signals = sum([
            medium_hits >= 2,       # multiple medium patterns present
            dash_count >= 2,        # dash abuse signal
            high_hits >= 1,         # high pattern confirms AI origin
        ])
        if medium_signals == 0:
            # Isolated medium patterns demoted to zero weight
            effective_medium = 0.0
        else:
            effective_medium = medium_hits * 0.15

        raw = high_hits * 0.50 + effective_medium + dash_component
        score = min(1.0, raw)

        return score, {
            "high_hits": high_hits,
            "medium_hits": medium_hits,
            "effective_medium_weight": round(effective_medium, 3),
            "dash_count": dash_count,
            "matched_phrases": matched_phrases,
        }

    def run(self, narratives: Dict[str, str]) -> DetectorResult:
        if not narratives:
            return DetectorResult(name=self.name, score=0.0, findings=[])

        findings: List[Finding] = []
        per_scores: List[float] = []

        for cid, text in narratives.items():
            score, evidence = self._score_narrative(text)
            per_scores.append(score)
            if score >= 0.15:
                if evidence["high_hits"] > 0:
                    severity = "HIGH"
                elif evidence["medium_hits"] >= 3 or evidence["dash_count"] >= 3:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"

                # v1.1: Extract excerpt with surrounding context
                excerpt = ""
                if evidence["matched_phrases"]:
                    first_match = evidence["matched_phrases"][0]["pattern"]
                    idx = text.lower().find(first_match.lower())
                    if idx >= 0:
                        start = max(0, idx - 40)
                        end = min(len(text), idx + len(first_match) + 40)
                        excerpt = ("..." if start > 0 else "") + text[start:end] + ("..." if end < len(text) else "")

                findings.append(
                    Finding(
                        detector=self.name,
                        severity=severity,
                        score=score,
                        description=(
                            f"Prompt leakage signature detected in narrative "
                            f"{cid}. An assessor interviewing the narrative "
                            "author will expect them to defend this text in "
                            "their own words."
                        ),
                        evidence={
                            "control_id": cid,
                            "high_hits": evidence["high_hits"],
                            "medium_hits": evidence["medium_hits"],
                            "dash_count": evidence["dash_count"],
                            "matched_phrases": evidence["matched_phrases"],
                            "excerpt": excerpt,
                            "why_it_matters": (
                                "LLM residual phrasing signals that narrative "
                                "text was not authored by the system owner. "
                                "A C3PAO assessor will interview the author and "
                                "expect domain-specific answers."
                            ),
                            "remediation": (
                                "Rewrite flagged narratives in the system owner's "
                                "voice with environment-specific details: named "
                                "systems, responsible roles, review cadences, and "
                                "evidence artifact references."
                            ),
                            "confidence": "HIGH" if evidence["high_hits"] > 0 else "MEDIUM",
                        },
                    )
                )

        # v1.1: Max-risk hybrid scoring. One "as an AI" across 110 controls
        # must NOT get averaged into silence. Worst-case drives 70% of the
        # score; mean adds context for overall package health.
        max_score = max(per_scores) if per_scores else 0.0
        mean_score = sum(per_scores) / len(per_scores)
        detector_score = min(1.0, max_score * 0.70 + mean_score * 0.30)

        # Severity override: if ANY finding is HIGH, the package is HIGH
        # regardless of the composite number.
        package_severity = None
        if any(f.severity == "HIGH" for f in findings):
            package_severity = "HIGH"

        result = DetectorResult(
            name=self.name,
            score=min(1.0, detector_score),
            findings=findings,
        )
        # Attach severity override as metadata on the result
        result.severity_override = package_severity
        return result


# ---------------------------------------------------------------------------
# Detector 3: Timestamp Regularity
# ---------------------------------------------------------------------------

class TimestampRegularityDetector:
    """
    Detect batch-stamped evidence metadata.

    Method
    ------
    Accepts a mapping of artifact_id -> ISO 8601 timestamp string.
    Analyzes the distribution of:
      1. Seconds components (batch tools often stamp :00 or identical seconds)
      2. Inter-timestamp intervals (machine-generated evidence has uniform gaps)
      3. Burst density (too many artifacts within a narrow window)

    Score
    -----
    Combines three sub-signals:
      - round_second_ratio: fraction of timestamps with :00 seconds
      - interval_regularity: low stdev of inter-timestamp gaps (normalized)
      - burst_ratio: fraction of artifacts created within a 60-second window

    Why this maps to assessor behavior
    ----------------------------------
    A C3PAO assessor reviewing evidence metadata will notice when 40 evidence
    artifacts were all created at 2:00:00 AM on the same Tuesday. That pattern
    screams batch generation, not organic compliance activity.
    """

    name = "TimestampRegularity"

    def __init__(self, round_second_threshold: float = 0.60,
                 burst_window_seconds: int = 60,
                 burst_ratio_threshold: float = 0.50):
        self.round_second_threshold = round_second_threshold
        self.burst_window_seconds = burst_window_seconds
        self.burst_ratio_threshold = burst_ratio_threshold

    def _parse_timestamps(self, timestamps: Dict[str, str]) -> List[Tuple[str, float]]:
        """Parse ISO 8601 timestamps to (artifact_id, epoch_seconds) pairs."""
        import calendar
        import time

        parsed = []
        for aid, ts_str in timestamps.items():
            try:
                # Handle common ISO formats: YYYY-MM-DDTHH:MM:SS, with optional Z or +offset
                clean = ts_str.strip().replace("Z", "+00:00")
                # Strip timezone offset for simplistic stdlib parsing
                if "+" in clean[10:]:
                    clean = clean[:clean.rindex("+")]
                elif clean.count("-") > 2:
                    # Negative offset like -05:00
                    parts = clean.rsplit("-", 1)
                    if ":" in parts[-1] and len(parts[-1]) <= 6:
                        clean = parts[0]

                # Parse YYYY-MM-DDTHH:MM:SS
                fmt = "%Y-%m-%dT%H:%M:%S"
                if "." in clean:
                    fmt = "%Y-%m-%dT%H:%M:%S.%f"
                t = time.strptime(clean, fmt)
                epoch = calendar.timegm(t)
                parsed.append((aid, epoch))
            except (ValueError, OverflowError):
                continue  # Skip unparseable timestamps
        return sorted(parsed, key=lambda x: x[1])

    def run(self, timestamps: Dict[str, str], **kwargs) -> DetectorResult:
        """
        timestamps: mapping of artifact_id -> ISO 8601 timestamp string.
        """
        if not timestamps or len(timestamps) < 3:
            return DetectorResult(name=self.name, score=0.0, findings=[])

        parsed = self._parse_timestamps(timestamps)
        if len(parsed) < 3:
            return DetectorResult(name=self.name, score=0.0, findings=[])

        findings: List[Finding] = []

        # Sub-signal 1: Round-second ratio
        round_seconds = sum(1 for _, epoch in parsed if epoch % 60 == 0)
        round_ratio = round_seconds / len(parsed)

        if round_ratio >= self.round_second_threshold:
            findings.append(Finding(
                detector=self.name,
                severity="HIGH" if round_ratio >= 0.80 else "MEDIUM",
                score=round_ratio,
                description=(
                    f"{int(round_ratio * 100)}% of evidence timestamps fall on "
                    "exact minute boundaries (:00 seconds). This pattern is "
                    "consistent with batch-generation tools, not organic "
                    "compliance activity."
                ),
                evidence={"round_second_ratio": round(round_ratio, 3),
                          "round_count": round_seconds,
                          "total": len(parsed),
                          "why_it_matters": (
                              "Timestamps landing on exact minute boundaries "
                              "at this rate are inconsistent with organic "
                              "evidence collection and suggest batch generation."
                          ),
                          "remediation": (
                              "Review evidence creation workflow. Genuine "
                              "compliance artifacts should have natural "
                              "timestamps from actual system activity."
                          ),
                          "confidence": "HIGH" if round_ratio >= 0.80 else "MEDIUM"},
            ))

        # Sub-signal 2: Interval regularity (low stdev = suspiciously uniform)
        intervals = []
        for i in range(1, len(parsed)):
            intervals.append(parsed[i][1] - parsed[i - 1][1])

        if intervals:
            mean_interval = sum(intervals) / len(intervals)
            variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
            stdev = math.sqrt(variance)
            # Normalize: coefficient of variation. Low CV = suspiciously regular.
            cv = stdev / mean_interval if mean_interval > 0 else 0.0
            regularity_score = max(0.0, 1.0 - cv) if cv < 1.0 else 0.0

            if regularity_score >= 0.70 and len(intervals) >= 3:
                findings.append(Finding(
                    detector=self.name,
                    severity="HIGH" if regularity_score >= 0.90 else "MEDIUM",
                    score=regularity_score,
                    description=(
                        f"Evidence timestamps show suspiciously regular intervals "
                        f"(CV={cv:.2f}). Organic evidence creation produces varied "
                        "gaps; uniform spacing suggests automated generation."
                    ),
                    evidence={"coefficient_of_variation": round(cv, 3),
                              "regularity_score": round(regularity_score, 3),
                              "mean_interval_seconds": round(mean_interval, 1),
                              "why_it_matters": (
                                  "Uniform inter-timestamp spacing is a "
                                  "hallmark of scripted evidence generation."
                              ),
                              "remediation": (
                                  "Ensure evidence artifacts are collected from "
                                  "actual system events, not batch-generated."
                              ),
                              "confidence": "HIGH" if regularity_score >= 0.90 else "MEDIUM"},
                ))

        # Sub-signal 3: Burst density
        epochs = [e for _, e in parsed]
        max_burst = 0
        for i, e in enumerate(epochs):
            burst = sum(1 for e2 in epochs if abs(e2 - e) <= self.burst_window_seconds)
            max_burst = max(max_burst, burst)
        burst_ratio = max_burst / len(parsed)

        if burst_ratio >= self.burst_ratio_threshold:
            findings.append(Finding(
                detector=self.name,
                severity="HIGH" if burst_ratio >= 0.75 else "MEDIUM",
                score=burst_ratio,
                description=(
                    f"{max_burst} of {len(parsed)} evidence artifacts were created "
                    f"within a {self.burst_window_seconds}-second window. "
                    "An assessor will question whether evidence collected this "
                    "rapidly reflects genuine compliance activity."
                ),
                evidence={"burst_count": max_burst,
                          "burst_ratio": round(burst_ratio, 3),
                          "window_seconds": self.burst_window_seconds,
                          "why_it_matters": (
                              "Evidence artifacts created in rapid succession "
                              "suggest automated generation, not genuine "
                              "compliance activity spread over time."
                          ),
                          "remediation": (
                              "Space evidence collection across actual "
                              "operational periods. Evidence should reflect "
                              "real compliance activities."
                          ),
                          "confidence": "HIGH" if burst_ratio >= 0.75 else "MEDIUM"},
            ))

        # Composite: average of sub-signal scores that fired
        if findings:
            score = sum(f.score for f in findings) / len(findings)
        else:
            score = 0.0

        return DetectorResult(name=self.name, score=min(1.0, score), findings=findings)


# ---------------------------------------------------------------------------
# Detector 4: Mapping Density (Evidence Artifact Reuse)
# ---------------------------------------------------------------------------

class MappingDensityDetector:
    """
    Detect overclaimed evidence artifact reuse across controls.

    Method
    ------
    Accepts a mapping of control_id -> list of evidence artifact IDs.
    Counts how many controls each artifact is mapped to. Flags artifacts
    that appear in an unrealistic number of controls.

    Score
    -----
    overclaimed_ratio = (count of controls covered by overclaimed artifacts) /
                        total controls.

    Why this maps to assessor behavior
    ----------------------------------
    A C3PAO assessor reviewing an evidence matrix expects most artifacts to
    apply to 1-3 controls (some crosscutting policies may apply to more).
    When a single screenshot or log export appears as evidence for 15+
    controls, the assessor concludes the contractor is padding, not proving.
    """

    name = "MappingDensity"

    def __init__(self, max_reuse_count: int = 5):
        self.max_reuse_count = max_reuse_count

    def run(self, evidence_map: Dict[str, List[str]], **kwargs) -> DetectorResult:
        """
        evidence_map: mapping of control_id -> list of evidence artifact IDs.
        """
        if not evidence_map:
            return DetectorResult(name=self.name, score=0.0, findings=[])

        # Count how many controls each artifact serves
        artifact_controls: Dict[str, List[str]] = {}
        for cid, artifacts in evidence_map.items():
            for art in artifacts:
                artifact_controls.setdefault(art, []).append(cid)

        findings: List[Finding] = []
        overclaimed_controls: set = set()

        for art, controls in artifact_controls.items():
            if len(controls) > self.max_reuse_count:
                overclaimed_controls.update(controls)
                findings.append(Finding(
                    detector=self.name,
                    severity="HIGH" if len(controls) >= self.max_reuse_count * 2 else "MEDIUM",
                    score=len(controls) / len(evidence_map),
                    description=(
                        f"Evidence artifact '{art}' is mapped to {len(controls)} "
                        f"controls (threshold: {self.max_reuse_count}). "
                        "An assessor will challenge whether a single artifact "
                        "genuinely demonstrates implementation across this many "
                        "distinct security requirements."
                    ),
                    evidence={"artifact": art,
                              "mapped_to_count": len(controls),
                              "controls": sorted(controls),
                              "threshold": self.max_reuse_count,
                              "why_it_matters": (
                                  "A single evidence artifact mapped to this "
                                  "many controls suggests padding rather than "
                                  "genuine per-control proof of implementation."
                              ),
                              "remediation": (
                                  "Provide control-specific evidence for each "
                                  "requirement. Crosscutting policies may apply "
                                  "to 2-3 controls but not " + str(len(controls)) + "."
                              ),
                              "confidence": "HIGH" if len(controls) >= self.max_reuse_count * 2 else "MEDIUM"},
                ))

        score = len(overclaimed_controls) / len(evidence_map) if evidence_map else 0.0
        return DetectorResult(name=self.name, score=min(1.0, score), findings=findings)


# ---------------------------------------------------------------------------
# Detector 5: Citation Graph Anomalies
# ---------------------------------------------------------------------------

class CitationGraphDetector:
    """
    Detect broken and fabricated document references within narratives.

    Method
    ------
    Scans each narrative for citation-like patterns:
      - Document IDs (e.g., "POL-001", "SOP-2024-003", "Ref. 12")
      - Policy/procedure titles in quotes
      - Section references (e.g., "Section 3.2", "per Appendix A")

    Then cross-references citations against a provided document inventory.
    Citations to documents NOT in the inventory are flagged as phantom
    references -- a hallmark of LLM fabrication.

    Score
    -----
    phantom_ratio = phantom_citations / total_citations.

    Why this maps to assessor behavior
    ----------------------------------
    An assessor who reads "per Information Security Policy ISP-2024-003,
    Section 4.7" will request that document. If it does not exist, the
    narrative is fabricated. This is a failing finding that cannot be
    remediated during the assessment.
    """

    name = "CitationGraph"

    # Regex patterns for common citation formats in compliance documents.
    _CITATION_PATTERNS = [
        # Document IDs: POL-001, SOP-2024-003, ISP-003, etc.
        re.compile(r"\b([A-Z]{2,6}-\d{1,4}(?:-\d{1,4})?)\b"),
        # Section references: Section 3.2, Appendix A, etc.
        re.compile(r"\b(?:Section|Appendix|Annex)\s+([A-Z0-9][A-Z0-9.]*)\b", re.IGNORECASE),
    ]

    def __init__(self):
        pass

    def _extract_citations(self, text: str) -> List[str]:
        """Extract all citation-like references from text."""
        citations = []
        for pat in self._CITATION_PATTERNS:
            citations.extend(m.group(1) for m in pat.finditer(text))
        return citations

    def run(self, narratives: Dict[str, str],
            document_inventory: List[str] = None, **kwargs) -> DetectorResult:
        """
        narratives: mapping of control_id -> narrative text.
        document_inventory: list of known document IDs/titles. If None,
            detector checks for internal consistency only (duplicate IDs
            across narratives referencing different content).
        """
        if not narratives:
            return DetectorResult(name=self.name, score=0.0, findings=[])

        inventory_set = set(document_inventory) if document_inventory else None

        all_citations: Dict[str, List[str]] = {}  # citation -> list of control_ids
        per_control_citations: Dict[str, List[str]] = {}

        for cid, text in narratives.items():
            cites = self._extract_citations(text)
            per_control_citations[cid] = cites
            for c in cites:
                all_citations.setdefault(c, []).append(cid)

        total_unique_citations = len(all_citations)
        if total_unique_citations == 0:
            return DetectorResult(name=self.name, score=0.0, findings=[])

        findings: List[Finding] = []

        # Check 1: Phantom references (if inventory provided)
        if inventory_set is not None:
            phantom = {c: cids for c, cids in all_citations.items()
                       if c not in inventory_set}
            if phantom:
                phantom_ratio = len(phantom) / total_unique_citations
                for cite, cids in phantom.items():
                    findings.append(Finding(
                        detector=self.name,
                        severity="HIGH",
                        score=phantom_ratio,
                        description=(
                            f"Phantom citation '{cite}' referenced in "
                            f"{len(cids)} narrative(s) but not found in "
                            "document inventory. This is a hallmark of "
                            "LLM-fabricated references."
                        ),
                        evidence={"citation": cite,
                                  "referenced_in": sorted(cids),
                                  "in_inventory": False,
                                  "why_it_matters": (
                                      "An assessor who reads this citation will "
                                      "request the document. If it does not exist, "
                                      "the narrative is fabricated — a failing "
                                      "finding that cannot be remediated during "
                                      "the assessment."
                                  ),
                                  "remediation": (
                                      "Remove the phantom reference or create the "
                                      "cited document with genuine content that "
                                      "supports the control narrative."
                                  ),
                                  "confidence": "HIGH"},
                    ))

        # Check 2: Citation uniformity (same citations reused across many controls)
        heavily_reused = {c: cids for c, cids in all_citations.items()
                         if len(cids) >= max(3, len(narratives) * 0.5)}
        if heavily_reused:
            reuse_ratio = len(heavily_reused) / total_unique_citations
            for cite, cids in heavily_reused.items():
                findings.append(Finding(
                    detector=self.name,
                    severity="MEDIUM",
                    score=reuse_ratio,
                    description=(
                        f"Citation '{cite}' appears in {len(cids)} of "
                        f"{len(narratives)} narratives. Heavy citation reuse "
                        "suggests template-driven generation rather than "
                        "control-specific documentation."
                    ),
                    evidence={"citation": cite,
                              "appears_in_count": len(cids),
                              "total_narratives": len(narratives),
                              "why_it_matters": (
                                  "Heavy citation reuse across unrelated controls "
                                  "suggests template-driven generation where the "
                                  "same references were injected without regard "
                                  "for control-specific relevance."
                              ),
                              "remediation": (
                                  "Ensure each control narrative cites documents "
                                  "that specifically support that control's "
                                  "implementation, not generic policies."
                              ),
                              "confidence": "MEDIUM"},
                ))

        if findings:
            score = max(f.score for f in findings)
        else:
            score = 0.0

        return DetectorResult(name=self.name, score=min(1.0, score), findings=findings)


# ---------------------------------------------------------------------------
# Detector 6: Statistical Anomaly (Entropy Variance)
# ---------------------------------------------------------------------------

class StatisticalAnomalyDetector:
    """
    Detect suspiciously uniform text entropy across narratives.

    Method
    ------
    1. Compute Shannon entropy of the character distribution for each narrative.
    2. Compute the coefficient of variation (CV) across all narrative entropies.
    3. A low CV means all narratives have near-identical entropy -- a signal
       that a single model produced them with consistent token distributions.

    Organic human-written compliance text varies in entropy because different
    authors write different controls with different vocabulary richness,
    sentence structures, and technical depth.

    Score
    -----
    If CV < threshold (default 0.05), flag as suspicious.
    Score = 1.0 - (CV / threshold), clamped to [0, 1].

    Why this maps to assessor behavior
    ----------------------------------
    While an assessor does not compute entropy, they notice when every
    narrative "reads the same" despite describing different controls. The
    entropy detector quantifies that gut feeling.
    """

    name = "StatisticalAnomaly"

    def __init__(self, cv_threshold: float = 0.05, min_narratives: int = 5):
        self.cv_threshold = cv_threshold
        self.min_narratives = min_narratives

    def _shannon_entropy(self, text: str) -> float:
        """Compute Shannon entropy of character distribution in text."""
        if not text:
            return 0.0
        counts = Counter(text.lower())
        total = sum(counts.values())
        entropy = 0.0
        for count in counts.values():
            if count > 0:
                p = count / total
                entropy -= p * math.log(p, 2)
        return entropy

    def _sentence_lengths(self, text: str) -> List[int]:
        """Split text into sentences and return word counts per sentence."""
        # Simple sentence boundary: period/question/exclamation followed by space/EOL
        sentences = re.split(r'[.!?]+(?:\s|$)', text)
        lengths = [len(s.split()) for s in sentences if s.strip()]
        return lengths

    def _type_token_ratio(self, text: str) -> float:
        """Compute type-token ratio (vocabulary richness). Higher = more diverse."""
        tokens = tokenize(text)
        if not tokens:
            return 0.0
        return len(set(tokens)) / len(tokens)

    @staticmethod
    def _cv(values: List[float]) -> float:
        """Compute coefficient of variation for a list of values."""
        if not values or len(values) < 2:
            return 0.0
        mean = sum(values) / len(values)
        if mean <= 0:
            return 0.0
        variance = sum((v - mean) ** 2 for v in values) / len(values)
        return math.sqrt(variance) / mean

    def run(self, narratives: Dict[str, str], **kwargs) -> DetectorResult:
        """
        narratives: mapping of control_id -> narrative text.

        v1.1: Three sub-signals now contribute to the score:
          1. Shannon entropy CV (original) -- character distribution uniformity
          2. Sentence-length CV -- structural uniformity across narratives
          3. Type-token ratio CV -- vocabulary richness uniformity
        """
        if not narratives or len(narratives) < self.min_narratives:
            return DetectorResult(name=self.name, score=0.0, findings=[])

        # Filter out very short narratives (< 50 chars) which skew metrics
        valid = {cid: text for cid, text in narratives.items() if len(text) >= 50}
        if len(valid) < self.min_narratives:
            return DetectorResult(name=self.name, score=0.0, findings=[])

        findings: List[Finding] = []
        sub_scores: List[float] = []

        # Sub-signal 1: Shannon entropy CV (original)
        entropies = {cid: self._shannon_entropy(text) for cid, text in valid.items()}
        entropy_values = list(entropies.values())
        mean_entropy = sum(entropy_values) / len(entropy_values)

        if mean_entropy > 0:
            entropy_cv = self._cv(entropy_values)

            if entropy_cv < self.cv_threshold:
                s = max(0.0, min(1.0, 1.0 - (entropy_cv / self.cv_threshold)))
                sub_scores.append(s)
                findings.append(Finding(
                    detector=self.name,
                    severity="HIGH" if s >= 0.70 else "MEDIUM",
                    score=s,
                    description=(
                        f"Narrative entropy variance is suspiciously low "
                        f"(CV={entropy_cv:.4f}, threshold={self.cv_threshold}). "
                        f"All {len(valid)} narratives show near-identical "
                        "character distributions, consistent with single-model "
                        "generation rather than multi-author compliance writing."
                    ),
                    evidence={
                        "signal": "entropy_cv",
                        "coefficient_of_variation": round(entropy_cv, 4),
                        "mean_entropy": round(mean_entropy, 4),
                        "narrative_count": len(valid),
                        "per_narrative_entropy": {
                            cid: round(e, 4) for cid, e in entropies.items()
                        },
                        "why_it_matters": (
                            "Uniform entropy across narratives means every control "
                            "description has near-identical character distributions. "
                            "This is a statistical fingerprint of single-model "
                            "generation."
                        ),
                        "remediation": (
                            "Have different subject-matter experts author narratives "
                            "for their respective control families."
                        ),
                        "confidence": "HIGH" if s >= 0.70 else "MEDIUM",
                    },
                ))

        # Sub-signal 2: Sentence-length CV across narratives
        # For each narrative, compute mean sentence length, then check
        # if those means are suspiciously uniform across narratives.
        mean_sent_lengths = {}
        for cid, text in valid.items():
            sl = self._sentence_lengths(text)
            if sl:
                mean_sent_lengths[cid] = sum(sl) / len(sl)

        if len(mean_sent_lengths) >= self.min_narratives:
            sl_values = list(mean_sent_lengths.values())
            sl_cv = self._cv(sl_values)

            if sl_cv < 0.10:  # very uniform sentence structure
                s = max(0.0, min(1.0, 1.0 - (sl_cv / 0.10)))
                sub_scores.append(s)
                findings.append(Finding(
                    detector=self.name,
                    severity="MEDIUM",
                    score=s,
                    description=(
                        f"Mean sentence lengths are suspiciously uniform across "
                        f"narratives (CV={sl_cv:.4f}). Different controls "
                        "authored by different people produce varied sentence "
                        "structures."
                    ),
                    evidence={
                        "signal": "sentence_length_cv",
                        "coefficient_of_variation": round(sl_cv, 4),
                        "mean_sentence_length": round(sum(sl_values) / len(sl_values), 1),
                        "narrative_count": len(mean_sent_lengths),
                        "why_it_matters": (
                            "Uniform sentence length across unrelated controls "
                            "suggests a single author or model produced all text."
                        ),
                        "remediation": (
                            "Ensure narratives reflect the natural writing "
                            "style of the responsible system owners."
                        ),
                        "confidence": "MEDIUM",
                    },
                ))

        # Sub-signal 3: Type-token ratio CV across narratives
        ttr_values = {}
        for cid, text in valid.items():
            ttr = self._type_token_ratio(text)
            if ttr > 0:
                ttr_values[cid] = ttr

        if len(ttr_values) >= self.min_narratives:
            ttr_list = list(ttr_values.values())
            ttr_cv = self._cv(ttr_list)

            if ttr_cv < 0.08:  # very uniform vocabulary richness
                s = max(0.0, min(1.0, 1.0 - (ttr_cv / 0.08)))
                sub_scores.append(s)
                findings.append(Finding(
                    detector=self.name,
                    severity="MEDIUM",
                    score=s,
                    description=(
                        f"Vocabulary richness (type-token ratio) is suspiciously "
                        f"uniform across narratives (CV={ttr_cv:.4f}). LLMs "
                        "produce consistent vocabulary density regardless of "
                        "the technical domain being described."
                    ),
                    evidence={
                        "signal": "type_token_ratio_cv",
                        "coefficient_of_variation": round(ttr_cv, 4),
                        "mean_ttr": round(sum(ttr_list) / len(ttr_list), 4),
                        "narrative_count": len(ttr_values),
                        "why_it_matters": (
                            "Different control families (AC, AU, SC) use "
                            "different technical vocabularies. Uniform richness "
                            "across all families is a model artifact."
                        ),
                        "remediation": (
                            "Control narratives should reflect domain-specific "
                            "terminology for each family."
                        ),
                        "confidence": "MEDIUM",
                    },
                ))

        # Composite: average of sub-signals that fired
        if sub_scores:
            score = sum(sub_scores) / len(sub_scores)
        else:
            score = 0.0

        return DetectorResult(name=self.name, score=min(1.0, score), findings=findings)


# ---------------------------------------------------------------------------
# Detector 7: Specificity Deficit (v1.1)
# ---------------------------------------------------------------------------

class SpecificityDeficitDetector:
    """
    Detect narratives that lack implementation-specific details.

    Method
    ------
    AI-generated compliance narratives use generic language: "the organization
    implements access controls to protect systems." Real SSP narratives name
    specific systems, tools, roles, cadences, and artifacts.

    This detector scores each narrative for the density of implementation
    details:
      - Named systems/hostnames/VLAN names
      - Responsible roles (not generic "the organization")
      - Tool/platform names (e.g., "Microsoft Entra ID", "Splunk", "CrowdStrike")
      - Review cadences (e.g., "monthly", "quarterly", "annually")
      - Evidence artifact identifiers (ticket IDs, policy IDs)
      - Procedure owners with names

    Score
    -----
    specificity_score = implementation_detail_count / narrative_word_count
    Narratives below a density threshold are flagged.

    Why this maps to assessor behavior
    ----------------------------------
    An assessor reading "The organization implements robust access controls"
    will immediately ask: "Which system? Who reviews? How often? Show me."
    Generic language triggers scope expansion.
    """

    name = "SpecificityDeficit"

    # Patterns that indicate implementation specificity
    _SPECIFICITY_PATTERNS = [
        # Named tools/platforms (common in DIB environments)
        re.compile(r"\b(?:Microsoft|Azure|AWS|Google|Splunk|CrowdStrike|"
                   r"SentinelOne|Palo Alto|Fortinet|Cisco|Okta|Duo|"
                   r"SailPoint|CyberArk|Tenable|Nessus|Qualys|Rapid7|"
                   r"Entra|Intune|Defender|BitLocker|SIEM|SOAR|EDR|"
                   r"ServiceNow|Jira|Confluence|SharePoint)\b", re.IGNORECASE),
        # Specific roles (not generic "the organization")
        re.compile(r"\b(?:ISSO|ISSM|System\s+Administrator|"
                   r"Security\s+Manager|IT\s+Manager|IT\s+Director|"
                   r"CISO|CTO|CIO|Network\s+Administrator|"
                   r"Compliance\s+Officer|FSO|Facility\s+Security)\b", re.IGNORECASE),
        # Review cadences
        re.compile(r"\b(?:daily|weekly|biweekly|monthly|quarterly|"
                   r"semi[\-\s]?annually|annually|every\s+\d+\s+days|"
                   r"every\s+\d+\s+months|within\s+\d+\s+(?:hours?|days?))\b",
                   re.IGNORECASE),
        # IP addresses, subnets, VLANs
        re.compile(r"\b(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?|"
                   r"VLAN[\s\-]?\d+|subnet)\b", re.IGNORECASE),
        # Ticket/policy IDs
        re.compile(r"\b(?:[A-Z]{2,6}-\d{3,}|POL-\d+|SOP-\d+|"
                   r"INC-\d+|CHG-\d+|REQ-\d+)\b"),
        # Hostnames / server names (common patterns)
        re.compile(r"\b(?:srv|dc|fw|sw|ap|ws|db|app|web|mail|vpn|dns|dhcp)"
                   r"[\-]\w+\b", re.IGNORECASE),
    ]

    # Generic phrases that indicate LACK of specificity
    _GENERIC_PHRASES = [
        re.compile(r"\bthe organization\b", re.IGNORECASE),
        re.compile(r"\bappropriate measures\b", re.IGNORECASE),
        re.compile(r"\bsufficient controls\b", re.IGNORECASE),
        re.compile(r"\bapplicable systems\b", re.IGNORECASE),
        re.compile(r"\ball relevant\b", re.IGNORECASE),
        re.compile(r"\bauthorized personnel\b", re.IGNORECASE),
        re.compile(r"\bdesignated individuals\b", re.IGNORECASE),
        re.compile(r"\bsecurity mechanisms\b", re.IGNORECASE),
        re.compile(r"\bprotective measures\b", re.IGNORECASE),
        re.compile(r"\bin accordance with policy\b", re.IGNORECASE),
        re.compile(r"\bestablished procedures\b", re.IGNORECASE),
    ]

    def __init__(self, specificity_threshold: float = 0.02,
                 generic_threshold: int = 3):
        self.specificity_threshold = specificity_threshold  # details per word
        self.generic_threshold = generic_threshold  # max generic phrases

    def _analyze_narrative(self, text: str) -> Dict:
        """Analyze a single narrative for specificity indicators."""
        words = text.split()
        word_count = len(words)
        if word_count < 10:
            return {"word_count": word_count, "specific_count": 0,
                    "generic_count": 0, "density": 0.0, "matches": [],
                    "generic_matches": []}

        # Count specificity indicators
        specific_matches = []
        for pat in self._SPECIFICITY_PATTERNS:
            for m in pat.finditer(text):
                specific_matches.append(m.group())

        # Count generic phrases
        generic_matches = []
        for pat in self._GENERIC_PHRASES:
            for m in pat.finditer(text):
                generic_matches.append(m.group())

        density = len(specific_matches) / word_count if word_count > 0 else 0.0

        return {
            "word_count": word_count,
            "specific_count": len(specific_matches),
            "generic_count": len(generic_matches),
            "density": density,
            "matches": specific_matches[:10],  # cap for readability
            "generic_matches": generic_matches[:10],
        }

    def run(self, narratives: Dict[str, str], **kwargs) -> DetectorResult:
        if not narratives:
            return DetectorResult(name=self.name, score=0.0, findings=[])

        findings: List[Finding] = []
        deficit_count = 0

        for cid, text in narratives.items():
            analysis = self._analyze_narrative(text)
            if analysis["word_count"] < 10:
                continue

            is_deficit = (
                analysis["density"] < self.specificity_threshold
                and analysis["generic_count"] >= self.generic_threshold
            )

            if is_deficit:
                deficit_count += 1
                # Higher severity when ZERO specific details found
                severity = "HIGH" if analysis["specific_count"] == 0 else "MEDIUM"
                findings.append(Finding(
                    detector=self.name,
                    severity=severity,
                    score=max(0.0, 1.0 - (analysis["density"] / self.specificity_threshold)),
                    description=(
                        f"Narrative {cid} lacks implementation-specific details "
                        f"(density={analysis['density']:.4f}, "
                        f"threshold={self.specificity_threshold}). "
                        f"Found {analysis['generic_count']} generic phrases "
                        f"and only {analysis['specific_count']} specific "
                        "implementation details."
                    ),
                    evidence={
                        "control_id": cid,
                        "specificity_density": round(analysis["density"], 4),
                        "specific_matches": analysis["matches"],
                        "generic_phrases_found": analysis["generic_matches"],
                        "word_count": analysis["word_count"],
                        "why_it_matters": (
                            "An assessor reading generic language will "
                            "immediately ask 'which system? who reviews? "
                            "how often?' and widen scope when answers are "
                            "not in the narrative."
                        ),
                        "remediation": (
                            "Replace generic language with named systems, "
                            "responsible roles (e.g., 'IT Manager'), specific "
                            "tools (e.g., 'Microsoft Entra ID'), and review "
                            "cadences (e.g., 'monthly')."
                        ),
                        "confidence": "HIGH" if analysis["specific_count"] == 0 else "MEDIUM",
                    },
                ))

        eligible = sum(1 for cid, text in narratives.items() if len(text.split()) >= 10)
        score = deficit_count / eligible if eligible > 0 else 0.0

        return DetectorResult(name=self.name, score=min(1.0, score), findings=findings)


# ---------------------------------------------------------------------------
# Detector 8: Contradiction Detection (v1.1)
# ---------------------------------------------------------------------------

class ContradictionDetector:
    """
    Detect contradictions between SSP claims and cross-narrative assertions.

    Method
    ------
    The "killer missing piece" identified by all three war panel members.
    Assessors don't just ask "does this sound like AI?" -- they ask "does
    this SSP claim match the evidence?"

    This detector extracts structured assertions from narratives:
      - System/tool claims (e.g., "MFA is enforced via Duo")
      - Frequency claims (e.g., "quarterly access reviews")
      - Ownership claims (e.g., "IT Manager is responsible")

    Then cross-references assertions across controls to find conflicts:
      - Same system described differently in different controls
      - Conflicting frequency claims (weekly vs monthly)
      - Different owners claimed for the same process

    Score
    -----
    contradiction_ratio = contradictions_found / total_assertions

    Why this maps to assessor behavior
    ----------------------------------
    If control 3.1.1 says "MFA is enforced for all CUI systems" and the
    evidence for 3.5.3 shows MFA is disabled, the assessor has a finding
    that cascades across the entire Access Control family.
    """

    name = "ContradictionDetection"

    # Patterns to extract assertions
    _FREQUENCY_PATTERNS = [
        re.compile(r"\b(daily|weekly|biweekly|monthly|quarterly|"
                   r"semi[\-\s]?annual(?:ly)?|annual(?:ly)?|"
                   r"every\s+\d+\s+(?:days?|weeks?|months?|years?))\b",
                   re.IGNORECASE),
    ]

    _TOOL_PATTERNS = [
        re.compile(r"\b(Microsoft\s+\w+|Azure\s+\w+|AWS\s+\w+|"
                   r"Google\s+\w+|Splunk|CrowdStrike|SentinelOne|"
                   r"Palo\s+Alto|Fortinet|Cisco\s+\w+|Okta|Duo|"
                   r"SailPoint|CyberArk|Tenable|Nessus|Qualys|"
                   r"BitLocker|Intune|Defender\s*\w*|SIEM|SOAR|EDR)\b",
                   re.IGNORECASE),
    ]

    _OWNER_PATTERNS = [
        re.compile(r"\b(ISSO|ISSM|System\s+Administrator|"
                   r"Security\s+Manager|IT\s+Manager|IT\s+Director|"
                   r"CISO|CTO|CIO|Network\s+Administrator|"
                   r"Compliance\s+Officer|FSO)\b", re.IGNORECASE),
    ]

    # Map frequency terms to a normalized order for comparison
    _FREQ_ORDER = {
        "daily": 1, "weekly": 2, "biweekly": 3, "monthly": 4,
        "quarterly": 5, "semi-annually": 6, "semiannually": 6,
        "semi annually": 6, "annually": 7, "annual": 7,
    }

    def __init__(self):
        pass

    def _extract_assertions(self, cid: str, text: str) -> List[Dict]:
        """Extract structured assertions from a narrative."""
        assertions = []

        # Extract frequency claims
        for pat in self._FREQUENCY_PATTERNS:
            for m in pat.finditer(text):
                # Get surrounding context to identify what the frequency applies to
                start = max(0, m.start() - 60)
                end = min(len(text), m.end() + 60)
                context = text[start:end]
                assertions.append({
                    "type": "frequency",
                    "value": m.group(1).lower().strip(),
                    "control_id": cid,
                    "context": context,
                })

        # Extract tool/system claims
        for pat in self._TOOL_PATTERNS:
            for m in pat.finditer(text):
                assertions.append({
                    "type": "tool",
                    "value": m.group(1).strip(),
                    "control_id": cid,
                    "context": text[max(0, m.start()-40):min(len(text), m.end()+40)],
                })

        # Extract ownership claims
        for pat in self._OWNER_PATTERNS:
            for m in pat.finditer(text):
                assertions.append({
                    "type": "owner",
                    "value": m.group(1).strip(),
                    "control_id": cid,
                    "context": text[max(0, m.start()-40):min(len(text), m.end()+40)],
                })

        return assertions

    def _find_contradictions(self, assertions: List[Dict]) -> List[Dict]:
        """Find contradictions between assertions from different controls."""
        contradictions = []

        # Group assertions by type
        by_type: Dict[str, List[Dict]] = {}
        for a in assertions:
            by_type.setdefault(a["type"], []).append(a)

        # Check frequency contradictions: different frequencies for similar contexts
        freq_assertions = by_type.get("frequency", [])
        if len(freq_assertions) >= 2:
            # Group by context similarity (simplified: look for keyword overlap)
            for i, a in enumerate(freq_assertions):
                a_tokens = set(tokenize(a["context"]))
                for b in freq_assertions[i+1:]:
                    if a["control_id"] == b["control_id"]:
                        continue
                    b_tokens = set(tokenize(b["context"]))
                    overlap = len(a_tokens & b_tokens)
                    # If contexts share significant words, frequencies should match
                    if overlap >= 3 and a["value"] != b["value"]:
                        # Check if they're meaningfully different frequencies
                        a_order = self._FREQ_ORDER.get(a["value"], 0)
                        b_order = self._FREQ_ORDER.get(b["value"], 0)
                        if a_order > 0 and b_order > 0 and a_order != b_order:
                            contradictions.append({
                                "type": "frequency_mismatch",
                                "assertion_a": a,
                                "assertion_b": b,
                                "detail": (
                                    f"Control {a['control_id']} claims "
                                    f"'{a['value']}' but {b['control_id']} "
                                    f"claims '{b['value']}' for a similar process."
                                ),
                            })

        # Check ownership contradictions: different owners for same process area
        # Group by CMMC family prefix (e.g., "3.1" for Access Control)
        owner_assertions = by_type.get("owner", [])
        owner_by_family: Dict[str, List[Dict]] = {}
        for a in owner_assertions:
            # Extract family from control_id (e.g., "AC.L2-3.1.1" -> "3.1")
            family_match = re.search(r"(\d+\.\d+)", a["control_id"])
            if family_match:
                family = family_match.group(1)
                owner_by_family.setdefault(family, []).append(a)

        for family, owners in owner_by_family.items():
            unique_owners = set(o["value"].lower() for o in owners)
            if len(unique_owners) >= 3:
                # 3+ different owners for same family is suspicious
                contradictions.append({
                    "type": "owner_inconsistency",
                    "family": family,
                    "owners": list(unique_owners),
                    "controls": list(set(o["control_id"] for o in owners)),
                    "detail": (
                        f"Control family {family} has {len(unique_owners)} "
                        f"different responsible parties across controls. "
                        "This may indicate template-generated ownership "
                        "assignments rather than actual organizational structure."
                    ),
                })

        return contradictions

    def run(self, narratives: Dict[str, str], **kwargs) -> DetectorResult:
        if not narratives or len(narratives) < 2:
            return DetectorResult(name=self.name, score=0.0, findings=[])

        # Extract all assertions
        all_assertions = []
        for cid, text in narratives.items():
            all_assertions.extend(self._extract_assertions(cid, text))

        if not all_assertions:
            return DetectorResult(name=self.name, score=0.0, findings=[])

        # Find contradictions
        contradictions = self._find_contradictions(all_assertions)

        findings: List[Finding] = []
        for c in contradictions:
            severity = "HIGH" if c["type"] == "frequency_mismatch" else "MEDIUM"
            findings.append(Finding(
                detector=self.name,
                severity=severity,
                score=min(1.0, 0.5),  # each contradiction is significant
                description=c["detail"],
                evidence={
                    "contradiction_type": c["type"],
                    "detail": c,
                    "why_it_matters": (
                        "Contradictory claims across controls signal that "
                        "narratives were generated without understanding "
                        "the actual environment. An assessor finding a "
                        "contradiction will widen scope to the entire family."
                    ),
                    "remediation": (
                        "Reconcile conflicting claims. Ensure all narratives "
                        "in the same control family describe the actual "
                        "implementation consistently."
                    ),
                    "confidence": "HIGH" if c["type"] == "frequency_mismatch" else "MEDIUM",
                },
            ))

        if contradictions:
            score = min(1.0, len(contradictions) * 0.25)
        else:
            score = 0.0

        return DetectorResult(name=self.name, score=score, findings=findings)


# ---------------------------------------------------------------------------
# Engine: composite scoring
# ---------------------------------------------------------------------------

# v1.0 weights. All 6 detectors now active.
# Boilerplate and Prompt Leakage remain highest-weighted because they are
# the most directly assessor-visible signals. The 4 new detectors add depth.
# v1.1 weights. 8 detectors now active. Contradiction and Specificity
# are high-value assessor signals. Original detectors rebalanced.
_DEFAULT_WEIGHTS: Dict[str, float] = {
    "BoilerplateClustering": 0.18,
    "PromptLeakage": 0.18,
    "TimestampRegularity": 0.10,
    "MappingDensity": 0.08,
    "CitationGraph": 0.12,
    "StatisticalAnomaly": 0.08,
    "SpecificityDeficit": 0.13,
    "ContradictionDetection": 0.13,
}


def run_engine(
    narratives: Dict[str, str],
    weights: Dict[str, float] = None,
    timestamps: Dict[str, str] = None,
    evidence_map: Dict[str, List[str]] = None,
    document_inventory: List[str] = None,
) -> Dict:
    """
    Run all v1.0 detectors against compliance evidence.

    Parameters
    ----------
    narratives : mapping of control_id -> narrative text.
        Required for Boilerplate, PromptLeakage, CitationGraph, StatisticalAnomaly.
    timestamps : mapping of artifact_id -> ISO 8601 timestamp.
        Required for TimestampRegularity. If None, that detector returns 0.
    evidence_map : mapping of control_id -> list of evidence artifact IDs.
        Required for MappingDensity. If None, that detector returns 0.
    document_inventory : list of known document IDs.
        Optional for CitationGraph. If provided, enables phantom reference detection.

    Returns a dict with:
      composite_score: float in [0, 1]
      severity_tier:   LOW / ELEVATED / HIGH / CRITICAL
      detectors:       list of per-detector results
    """
    if weights is None:
        weights = _DEFAULT_WEIGHTS

    results: List[DetectorResult] = []

    # Detectors that operate on narratives
    results.append(BoilerplateClusteringDetector().run(narratives))
    results.append(PromptLeakageDetector().run(narratives))
    results.append(CitationGraphDetector().run(narratives, document_inventory=document_inventory))
    results.append(StatisticalAnomalyDetector().run(narratives))
    results.append(SpecificityDeficitDetector().run(narratives))
    results.append(ContradictionDetector().run(narratives))

    # Detectors that operate on metadata
    if timestamps:
        results.append(TimestampRegularityDetector().run(timestamps))
    else:
        results.append(DetectorResult(name="TimestampRegularity", score=0.0))

    if evidence_map:
        results.append(MappingDensityDetector().run(evidence_map))
    else:
        results.append(DetectorResult(name="MappingDensity", score=0.0))

    # Weighted composite. Any detector not present in weights contributes 0.
    total_weight = sum(weights.get(r.name, 0.0) for r in results)
    if total_weight <= 0:
        composite = 0.0
    else:
        composite = sum(
            r.score * weights.get(r.name, 0.0) for r in results
        ) / total_weight

    if composite < 0.25:
        tier = "LOW"
    elif composite < 0.50:
        tier = "ELEVATED"
    elif composite < 0.75:
        tier = "HIGH"
    else:
        tier = "CRITICAL"

    # v1.1: Severity override — if any detector forces HIGH, the package
    # cannot be rated below ELEVATED regardless of composite score.
    has_severity_override = any(
        getattr(r, 'severity_override', None) == "HIGH" for r in results
    )
    if has_severity_override and tier == "LOW":
        tier = "ELEVATED"

    return {
        "engine_version": "1.1",
        "composite_score": round(composite, 3),
        "severity_tier": tier,
        "detectors": [r.to_dict() for r in results],
        "weights": dict(weights),
        "narratives_scanned": len(narratives),
        "detector_count": len(results),
    }


def load_narratives_json(path: str) -> Dict[str, str]:
    """
    Load a JSON file of the form:
      { "AC.L2-3.1.1": "narrative text ...", "AC.L2-3.1.2": "..." }
    """
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("narratives JSON must be an object of control_id -> text")
    return {str(k): str(v) for k, v in data.items()}


# ---------------------------------------------------------------------------
# CLI entry point (optional, stdlib-only)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Backward-compatibility layer (v1.0 API)
# ---------------------------------------------------------------------------
# Companion tools (build_integrity_report, wild_sample_runner,
# falcon_edge_demo_driver, test_template_guard) use the v1.0 API.
# This shim maps the old interface onto the v1.1 run_engine() internals.

# v1.0 class name aliases
BoilerplateClusterDetector = BoilerplateClusteringDetector
SentenceStructureAnomalyDetector = StatisticalAnomalyDetector

class Confidence(str, Enum):
    """Confidence classification from v1.0 API."""
    CLEAN = "CLEAN"
    PARTIAL = "PARTIALLY_CONTAMINATED"
    CONTAMINATED = "CONTAMINATED"
    SYNTHETIC = "LIKELY_SYNTHETIC"


@dataclass
class LegacyFinding:
    """v1.0-compatible Finding format."""
    heuristic: str
    artifact_id: str
    score: float
    evidence: str
    nist_objectives: tuple = ()
    recommendation: str = ""

    def to_dict(self) -> dict:
        return {
            "heuristic": self.heuristic,
            "artifact_id": self.artifact_id,
            "score": self.score,
            "evidence": self.evidence,
            "nist_objectives": list(self.nist_objectives),
            "recommendation": self.recommendation,
        }


@dataclass
class Report:
    """v1.0-compatible Report format."""
    artifact_id: str
    confidence: Confidence
    aggregate_score: float
    findings: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "artifact_id": self.artifact_id,
            "confidence": self.confidence.value,
            "aggregate_score": self.aggregate_score,
            "findings": [f.to_dict() if hasattr(f, "to_dict") else f for f in self.findings],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)


class AIProvenanceDetector:
    """
    v1.0-compatible wrapper around the v1.1 run_engine() function.

    Usage (unchanged from v1.0):
        detector = AIProvenanceDetector()
        report = detector.analyze_packet(
            narratives={"3.1.1": "...", "3.13.1": "..."},
            citation_edges=[("ssp", "policy_ac")],
            timestamps_by_artifact={"audit.log": [datetime, ...]},
        )
        print(report.to_json())
    """

    def __init__(self, weights: Optional[Dict[str, float]] = None,
                 template_guard=None):
        self.weights = weights
        self.template_guard = template_guard

    def analyze_artifact(self, artifact_id: str, text: str,
                         timestamps: Optional[list] = None) -> Report:
        """Analyze a single artifact (wraps run_engine with one narrative)."""
        narratives = {artifact_id: text}
        ts_map = {artifact_id: timestamps} if timestamps else None
        return self.analyze_packet(narratives, timestamps_by_artifact=ts_map)

    def analyze_packet(self, narratives: Dict[str, str],
                       citation_edges: Optional[list] = None,
                       timestamps_by_artifact: Optional[dict] = None) -> Report:
        """Analyze a full evidence packet (delegates to run_engine)."""
        # If a template guard is configured, strip boilerplate before scoring
        if self.template_guard is not None:
            narratives = {
                k: self.template_guard.strip_boilerplate(v)
                for k, v in narratives.items()
            }
        kwargs = {"narratives": narratives, "weights": self.weights}
        if timestamps_by_artifact is not None:
            kwargs["timestamps"] = timestamps_by_artifact
        result = run_engine(**kwargs)

        # Convert v1.1 output to v1.0 Report format
        findings = []
        for det in result.get("detectors", []):
            for f in det.get("findings", []):
                findings.append(LegacyFinding(
                    heuristic=det["name"],
                    artifact_id=f.get("control_id", "PACKET"),
                    score=det["score"],
                    evidence=f.get("description", ""),
                    recommendation=f.get("evidence", {}).get("remediation", ""),
                ))

        confidence = self._classify(result["composite_score"], result.get("detectors", []))
        return Report(
            artifact_id="PACKET",
            confidence=confidence,
            aggregate_score=result["composite_score"],
            findings=findings,
        )

    @staticmethod
    def _classify(agg: float, detectors: list) -> Confidence:
        strong = sum(1 for d in detectors if d.get("score", 0) >= 0.7)
        if strong >= 2 or agg >= 0.65:
            return Confidence.SYNTHETIC
        if strong >= 1 or agg >= 0.4:
            return Confidence.CONTAMINATED
        if agg >= 0.2:
            return Confidence.PARTIAL
        return Confidence.CLEAN


if __name__ == "__main__":
    import argparse
    import os
    import sys

    parser = argparse.ArgumentParser(
        description="Hardseal AI-era evidence contamination detector."
    )
    parser.add_argument(
        "input",
        help="Path to a JSON file (control_id -> narrative) or a directory of .md/.txt narrative files.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the full result as JSON instead of a human summary.",
    )
    parser.add_argument(
        "--template",
        default=None,
        help="Path to a template skeleton file for template-guard comparison (optional).",
    )
    args = parser.parse_args()

    input_path = args.input
    if os.path.isdir(input_path):
        # Directory mode: read every .md / .txt file as a narrative
        narratives: Dict[str, str] = {}
        for fname in sorted(os.listdir(input_path)):
            if fname.startswith("_"):
                continue  # skip template skeletons
            if fname.endswith((".md", ".txt")):
                control_id = os.path.splitext(fname)[0]
                fpath = os.path.join(input_path, fname)
                with open(fpath, "r", encoding="utf-8") as fh:
                    narratives[control_id] = fh.read()
        if not narratives:
            print(f"No .md or .txt files found in {input_path}", file=sys.stderr)
            sys.exit(1)
    else:
        narratives = load_narratives_json(input_path)

    result = run_engine(narratives)

    if args.json:
        print(json.dumps(result, indent=2))
        sys.exit(0)

    print(f"Narratives scanned: {result['narratives_scanned']}")
    print(f"Composite score:    {result['composite_score']} ({result['severity_tier']})")
    print()
    for det in result["detectors"]:
        print(f"  Detector: {det['name']}   score={det['score']}")
        for f in det["findings"]:
            print(f"    [{f['severity']}] {f['description']}")
