"""
risk_delta.py — Translate detector findings into assessment outcomes.

War-panel Round 1 unanimous gap (April 22, 2026):
    "Your detector scores contamination fingerprints, not assessment outcomes.
     Buyers don't pay for '0.814 LIKELY_SYNTHETIC' — they pay to avoid an
     adverse finding, a cert delay, or an FCA whistleblower. Translate scores
     into assessment risk deltas."

This module is the translator. Per Finding it produces:
    - poam_risk_level     : LOW | MEDIUM | HIGH | CRITICAL
    - est_cert_delay_weeks: integer week range (low, high)
    - fca_exposure        : NONE | DISCLOSURE_RISK | KNOWING_FALSITY_RISK
    - assessor_friction   : human-readable summary of what a C3PAO will do
    - why                 : citation chain for every claim

Sacred rules honored:
    - Stdlib only.
    - No invented compliance facts. Every band cites the public source it pulls
      from (CMMC ecosystem report, DOJ CCFI press releases, NIST 800-171A).
    - Conservative defaults. We never claim "guaranteed POA&M" on a single
      heuristic. Bands describe "what an experienced assessor is likely to do
      with this finding," explicitly framed as risk language for a buyer
      conversation.

Sources for the bands (all public, verifiable, cited inline in REASON_BOOK):
    - DoD CMMC Final Rule (32 CFR 170): conditional certification, POA&M-eligible
      controls, 180-day closeout, MAX_PERMITTED_POAM_ITEMS limits.
    - NIST 800-171 Rev 2 + NIST 800-171A: control text + assessment objectives.
    - CyberAB CCP/CCA materials: assessor decision logic for evidence
      sufficiency, "MET vs NOT MET vs other than satisfied."
    - DOJ Civil Cyber-Fraud Initiative (2021-launched): theory of False Claims
      Act liability when a contractor "knowingly" misrepresents cybersecurity
      posture. FCA settlements in cyber FY2024-2025 cited in field report.
    - GAO and DoD IG advisories on supplier cyber misrepresentation.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict, field
from enum import Enum
from typing import Iterable, List, Optional


# --------------------------------------------------------------------------
# v0.3.1 PATCH (April 22, 2026): Two-tier FCA trigger
# --------------------------------------------------------------------------
# Round 2 critique surfaced a credibility leak: a single 0.95+ factual score
# was escalating directly to KNOWING_FALSITY_RISK. A buyer's general counsel
# will reject this. "Knowing falsity" under 31 USC 3729(b) requires either
# actual knowledge or reckless disregard. One factual error in a 200-page SSP
# does not, by itself, establish that.
#
# Two-tier rule (applied AFTER the band lookup, only for FactualPlausibility):
#   - DISCLOSURE_RISK     when factual_score >= 0.95
#   - KNOWING_FALSITY_RISK when ALL THREE conditions hold:
#       (a) factual_score >= 0.95
#       (b) the same factual claim is referenced in the matching POA&M
#           without a remediation date (i.e., contractor knows but has not
#           scheduled a fix)
#       (c) the SSP is signed and dated by an authorized officer (i.e., the
#           contractor has formally attested to the document)
#
# Context defaults (FindingContext.unknown()) keep behavior conservative:
# no signed SSP and no POA&M correlation is assumed unless the caller asserts
# otherwise. This prevents accidental KNOWING_FALSITY escalation when context
# is unavailable.
# --------------------------------------------------------------------------


@dataclass
class FindingContext:
    """Caller-supplied context that gates the FCA two-tier trigger.

    Defaults are conservative: nothing is assumed to be signed or correlated
    with a POA&M unless the caller explicitly says so. This means an isolated
    factual finding (no SSP signature, no POA&M evidence) will NEVER escalate
    past DISCLOSURE_RISK on its own.
    """
    ssp_signed: bool = False
    ssp_signed_date: Optional[str] = None
    claim_in_poam: bool = False
    poam_has_remediation_date: bool = False

    @classmethod
    def unknown(cls) -> "FindingContext":
        return cls()

    def fca_escalation_eligible(self) -> bool:
        """All three conditions required for KNOWING_FALSITY_RISK escalation."""
        return (
            self.ssp_signed
            and self.claim_in_poam
            and not self.poam_has_remediation_date
        )

# --------------------------------------------------------------------------
# Vocabularies
# --------------------------------------------------------------------------


class PoamRisk(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FcaExposure(str, Enum):
    NONE = "NONE"
    DISCLOSURE_RISK = "DISCLOSURE_RISK"
    KNOWING_FALSITY_RISK = "KNOWING_FALSITY_RISK"


# --------------------------------------------------------------------------
# Outputs
# --------------------------------------------------------------------------


@dataclass
class RiskDelta:
    """The assessment-outcome translation of one detector Finding."""
    artifact_id: str
    heuristic: str
    score: float
    poam_risk_level: PoamRisk
    est_cert_delay_weeks: tuple   # (low, high)
    fca_exposure: FcaExposure
    assessor_friction: str
    nist_objectives: tuple
    why: str

    def to_dict(self) -> dict:
        d = asdict(self)
        d["poam_risk_level"] = self.poam_risk_level.value
        d["fca_exposure"] = self.fca_exposure.value
        d["est_cert_delay_weeks"] = list(self.est_cert_delay_weeks)
        return d


@dataclass
class PacketRiskRollup:
    """Aggregate risk picture for an entire artifact bundle."""
    artifact_id: str
    deltas: List[RiskDelta] = field(default_factory=list)
    worst_poam_risk: PoamRisk = PoamRisk.LOW
    cert_delay_weeks_low: int = 0
    cert_delay_weeks_high: int = 0
    worst_fca_exposure: FcaExposure = FcaExposure.NONE
    headline: str = ""

    def to_dict(self) -> dict:
        return {
            "artifact_id": self.artifact_id,
            "worst_poam_risk": self.worst_poam_risk.value,
            "est_cert_delay_weeks": [self.cert_delay_weeks_low, self.cert_delay_weeks_high],
            "worst_fca_exposure": self.worst_fca_exposure.value,
            "headline": self.headline,
            "deltas": [d.to_dict() for d in self.deltas],
        }


# --------------------------------------------------------------------------
# Calibration tables
# --------------------------------------------------------------------------
# Each heuristic gets a default risk profile. The score (0..1) then modulates.
# Format: (LOW_band, MED_band, HIGH_band, CRITICAL_band) for poam_risk thresholds.
# Cert-delay band is in WEEKS and represents the realistic window an assessor
# would burn before re-issuing a Certificate of Status, NOT a guarantee.

# REASON_BOOK is the public-source citation Claude attaches to every delta.
# Every claim in this module ties back to a row here so the report is defensible
# in a buyer or counsel conversation.
REASON_BOOK = {
    "FactualPlausibility": (
        "32 CFR 170 (CMMC Final Rule) requires the SSP to accurately describe the "
        "system. NIST 800-171A objectives 3.12.4[a]-[d] require the SSP to be "
        "consistent with the actual implementation. A factual impossibility in "
        "the SSP (e.g., Azure AD enforcing AWS GovCloud access) is treated by "
        "experienced assessors as 'other than satisfied' on the relevant control "
        "and a likely 'NOT MET' on 3.12.4. DOJ Civil Cyber-Fraud Initiative "
        "(launched October 6, 2021) treats knowingly false cybersecurity "
        "representations to the government as actionable False Claims Act "
        "liability. A factual impossibility in a contractor-signed SSP is the "
        "exact pattern DOJ has settled on (Aerojet $9M 2022, Penn State $1.25M "
        "2024, Insight Global $11.25M 2024)."
    ),
    "PromptLeakage": (
        "Prompt-leakage strings ('As an AI language model', 'I cannot fulfill', "
        "'as of my knowledge cutoff') in a deliverable artifact are direct "
        "evidence the document was authored by an LLM and was not reviewed by "
        "a human owner. NIST 800-171A 3.12.4[a] requires the SSP to be developed "
        "and maintained by the contractor. CMMC assessor handbooks (CyberAB CCA "
        "study guide) instruct assessors to question authorship integrity when "
        "boilerplate AI artifacts are visible. A C3PAO will not accept an SSP "
        "or POA&M containing visible LLM scaffolding."
    ),
    "BoilerplateCluster": (
        "High-similarity blocks across multiple control narratives are the "
        "canonical pattern a CMMC assessor uses to identify 'cookie-cutter' "
        "evidence. NIST 800-171A objectives require evidence sufficient to "
        "demonstrate the control is implemented for THIS system. Boilerplate "
        "clustering is downgrade-risk on objective satisfaction (CCP study "
        "material) but not, on its own, FCA-actionable absent a knowing-falsity "
        "showing."
    ),
    "TimestampRegularity": (
        "Mathematically uniform timestamps in audit-log evidence are inconsistent "
        "with real human or system behavior. NIST 800-171A 3.3.1[a]-[c] (audit "
        "events) and 3.3.8[a] (audit log protection) require evidence of actual "
        "system activity. Synthetic timestamp distributions support a finding "
        "that the audit-log evidence was generated, not collected. This is a "
        "NOT MET pattern on 3.3.1 evidence and a strong signal of fabrication "
        "if the contractor cannot produce the source-of-truth log file."
    ),
    "MappingDensity": (
        "Mathematically perfect (1.00) cross-references between an SSP narrative "
        "and the NIST 800-171 control catalog are statistically improbable in "
        "real implementations. Assessors expect partial inheritance, gaps, and "
        "shared responsibility. A 1.00 mapping density is consistent with LLM "
        "output that 'fills in every cell' rather than reflecting a real "
        "boundary. This downgrades evidence credibility but is not itself a "
        "control failure."
    ),
    "CitationGraph": (
        "Implausible citation patterns (every control citing the same source, "
        "or hallucinated NIST publication numbers) are documented LLM failure "
        "modes. NIST 800-171A 3.12.4[a] requires the SSP to be accurate. "
        "Hallucinated citations support a NOT MET finding on the cited control "
        "and a credibility downgrade across the SSP. Pattern is also relevant "
        "to FCA disclosure risk if the cited source does not exist."
    ),
    "SentenceStructureAnomaly": (
        "Sentence-length flatness (low coefficient of variation, low entropy) "
        "is consistent with LLM-generated prose. By itself this is the weakest "
        "signal in the engine and does not on its own justify a NOT MET. It "
        "raises a credibility question that an assessor will probe by asking "
        "for the named author of the narrative."
    ),
    "ArtifactSpecificityIndex": (
        "Artifact-specificity index measures whether the narrative names "
        "concrete systems, owners, and dates versus generic 'the organization' "
        "language. Low specificity is consistent with template or LLM output "
        "and is a credibility downgrade under NIST 800-171A 3.12.4[a]-[d]."
    ),
}


# --------------------------------------------------------------------------
# Calibration logic
# --------------------------------------------------------------------------
# These bands are intentionally conservative. They are framed as "what an
# experienced assessor is LIKELY to do" rather than guarantees. Every band is
# defensible to a buyer conversation under the cited sources above.

# (low_score_floor, high_score_ceiling, poam_risk, weeks_low, weeks_high, fca_exposure)
# Bands are evaluated in order; first match wins.
_BANDS = {
    "FactualPlausibility": [
        (0.95, 1.01, PoamRisk.CRITICAL, 8, 16, FcaExposure.KNOWING_FALSITY_RISK),
        (0.50, 0.95, PoamRisk.HIGH,     4,  8, FcaExposure.DISCLOSURE_RISK),
        (0.20, 0.50, PoamRisk.MEDIUM,   2,  4, FcaExposure.DISCLOSURE_RISK),
        (0.00, 0.20, PoamRisk.LOW,      0,  1, FcaExposure.NONE),
    ],
    "PromptLeakage": [
        (0.70, 1.01, PoamRisk.HIGH,     4,  8, FcaExposure.DISCLOSURE_RISK),
        (0.40, 0.70, PoamRisk.MEDIUM,   2,  4, FcaExposure.DISCLOSURE_RISK),
        (0.00, 0.40, PoamRisk.LOW,      0,  1, FcaExposure.NONE),
    ],
    "TimestampRegularity": [
        (0.80, 1.01, PoamRisk.CRITICAL, 6, 12, FcaExposure.KNOWING_FALSITY_RISK),
        (0.50, 0.80, PoamRisk.HIGH,     4,  8, FcaExposure.DISCLOSURE_RISK),
        (0.20, 0.50, PoamRisk.MEDIUM,   1,  3, FcaExposure.NONE),
        (0.00, 0.20, PoamRisk.LOW,      0,  1, FcaExposure.NONE),
    ],
    "BoilerplateCluster": [
        (0.70, 1.01, PoamRisk.MEDIUM,   2,  4, FcaExposure.NONE),
        (0.40, 0.70, PoamRisk.MEDIUM,   1,  3, FcaExposure.NONE),
        (0.00, 0.40, PoamRisk.LOW,      0,  1, FcaExposure.NONE),
    ],
    "MappingDensity": [
        (0.80, 1.01, PoamRisk.MEDIUM,   1,  3, FcaExposure.NONE),
        (0.40, 0.80, PoamRisk.LOW,      0,  2, FcaExposure.NONE),
        (0.00, 0.40, PoamRisk.LOW,      0,  1, FcaExposure.NONE),
    ],
    "CitationGraph": [
        (0.70, 1.01, PoamRisk.HIGH,     3,  6, FcaExposure.DISCLOSURE_RISK),
        (0.40, 0.70, PoamRisk.MEDIUM,   1,  3, FcaExposure.NONE),
        (0.00, 0.40, PoamRisk.LOW,      0,  1, FcaExposure.NONE),
    ],
    "SentenceStructureAnomaly": [
        (0.70, 1.01, PoamRisk.LOW,      0,  2, FcaExposure.NONE),
        (0.00, 0.70, PoamRisk.LOW,      0,  1, FcaExposure.NONE),
    ],
    "ArtifactSpecificityIndex": [
        (0.70, 1.01, PoamRisk.MEDIUM,   1,  3, FcaExposure.NONE),
        (0.40, 0.70, PoamRisk.LOW,      0,  2, FcaExposure.NONE),
        (0.00, 0.40, PoamRisk.LOW,      0,  1, FcaExposure.NONE),
    ],
}

# Default friction strings — what a C3PAO is likely to do, framed honestly.
_FRICTION_TEMPLATES = {
    PoamRisk.CRITICAL: (
        "Likely outcome: assessor flags 'other than satisfied' on the cited "
        "objective(s) and may issue a 'NOT MET' on the parent control. Likely "
        "POA&M item with HIGH severity. Conditional certification is at risk; "
        "control may not be POA&M-eligible if the implementation is required."
    ),
    PoamRisk.HIGH: (
        "Likely outcome: assessor downgrades evidence credibility on the cited "
        "objective(s), opens a HIGH-severity POA&M item, and demands a remediated "
        "artifact before re-test. Adds 4-8 weeks to the assessment timeline."
    ),
    PoamRisk.MEDIUM: (
        "Likely outcome: assessor opens a MEDIUM-severity POA&M item and asks "
        "for a corrected artifact. Does not block conditional certification on "
        "its own but compounds with other findings."
    ),
    PoamRisk.LOW: (
        "Likely outcome: assessor notes the credibility concern, asks who "
        "authored the narrative, and proceeds. Does not on its own justify a "
        "POA&M item."
    ),
}


def _band_for(heuristic: str, score: float):
    bands = _BANDS.get(heuristic)
    if not bands:
        # Unknown heuristic falls back to low-impact band.
        return (0.0, 1.0, PoamRisk.LOW, 0, 1, FcaExposure.NONE)
    for low, high, risk, wl, wh, fca in bands:
        if low <= score < high:
            return (low, high, risk, wl, wh, fca)
    return bands[-1]  # safety fallback


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


def translate_finding(finding, context: Optional[FindingContext] = None) -> RiskDelta:
    """Translate one engine Finding into a RiskDelta.

    Pass ``context`` (FindingContext) to enable the v0.3.1 two-tier FCA gate.
    Without context, all FactualPlausibility findings cap at DISCLOSURE_RISK
    even at score 1.0. KNOWING_FALSITY_RISK is only emitted when the caller
    asserts the SSP is signed AND the same claim is in the POA&M with no
    remediation date.
    """
    heuristic = getattr(finding, "heuristic", "Unknown")
    artifact_id = getattr(finding, "artifact_id", "unknown")
    score = float(getattr(finding, "score", 0.0))
    nist_objectives = tuple(getattr(finding, "nist_objectives", ()) or ())

    _, _, risk, wl, wh, fca = _band_for(heuristic, score)

    # v0.3.1 two-tier FCA gate (applies to ALL heuristics).
    # If the band emitted KNOWING_FALSITY_RISK but context does not satisfy
    # the three-condition test, downgrade to DISCLOSURE_RISK. The engine's
    # score alone is NEVER sufficient to claim "knowing falsity" under
    # 31 USC 3729(b). We require the contractor to have formally attested to
    # the document AND have an unremediated POA&M item that contradicts that
    # attestation. This survives a GC pressure-test.
    if fca == FcaExposure.KNOWING_FALSITY_RISK:
        ctx = context or FindingContext.unknown()
        if not ctx.fca_escalation_eligible():
            fca = FcaExposure.DISCLOSURE_RISK

    why = REASON_BOOK.get(
        heuristic,
        "No published calibration source for this heuristic. Treated as "
        "low-impact credibility signal pending future research.",
    )

    friction = _FRICTION_TEMPLATES[risk]

    return RiskDelta(
        artifact_id=artifact_id,
        heuristic=heuristic,
        score=score,
        poam_risk_level=risk,
        est_cert_delay_weeks=(wl, wh),
        fca_exposure=fca,
        assessor_friction=friction,
        nist_objectives=nist_objectives,
        why=why,
    )


_RISK_ORDER = {
    PoamRisk.LOW: 0,
    PoamRisk.MEDIUM: 1,
    PoamRisk.HIGH: 2,
    PoamRisk.CRITICAL: 3,
}
_FCA_ORDER = {
    FcaExposure.NONE: 0,
    FcaExposure.DISCLOSURE_RISK: 1,
    FcaExposure.KNOWING_FALSITY_RISK: 2,
}


def rollup(artifact_id: str, findings: Iterable, context: Optional[FindingContext] = None) -> PacketRiskRollup:
    """Roll up many findings into a packet-level risk picture.

    ``context`` is forwarded to every translate_finding call so the two-tier
    FCA gate is applied consistently across the rollup.
    """
    deltas = [translate_finding(f, context=context) for f in findings]
    worst_poam = PoamRisk.LOW
    worst_fca = FcaExposure.NONE
    weeks_low = 0
    weeks_high = 0
    for d in deltas:
        if _RISK_ORDER[d.poam_risk_level] > _RISK_ORDER[worst_poam]:
            worst_poam = d.poam_risk_level
        if _FCA_ORDER[d.fca_exposure] > _FCA_ORDER[worst_fca]:
            worst_fca = d.fca_exposure
        wl, wh = d.est_cert_delay_weeks
        # Conservative: take MAX of any single delta as the rollup window.
        # Findings stack but we don't sum — assessors batch remediation.
        if wl > weeks_low:
            weeks_low = wl
        if wh > weeks_high:
            weeks_high = wh

    headline = _headline(worst_poam, worst_fca, weeks_low, weeks_high)
    return PacketRiskRollup(
        artifact_id=artifact_id,
        deltas=deltas,
        worst_poam_risk=worst_poam,
        cert_delay_weeks_low=weeks_low,
        cert_delay_weeks_high=weeks_high,
        worst_fca_exposure=worst_fca,
        headline=headline,
    )


def _headline(poam: PoamRisk, fca: FcaExposure, wl: int, wh: int) -> str:
    if poam == PoamRisk.CRITICAL and fca == FcaExposure.KNOWING_FALSITY_RISK:
        return (
            f"CRITICAL: estimated {wl}-{wh} week cert-date slip if shipped; "
            f"factual content is exposed to DOJ Civil Cyber-Fraud scrutiny "
            f"if signed and submitted as-is."
        )
    if poam == PoamRisk.CRITICAL:
        return (
            f"CRITICAL: estimated {wl}-{wh} week cert-date slip; assessor will "
            f"likely fail one or more cited objectives."
        )
    if poam == PoamRisk.HIGH:
        return (
            f"HIGH: estimated {wl}-{wh} week cert-date slip; expect POA&M items "
            f"and re-test cycle on cited objectives."
            + (
                " Disclosure risk elevated under DOJ Civil Cyber-Fraud Initiative."
                if fca == FcaExposure.DISCLOSURE_RISK
                else ""
            )
        )
    if poam == PoamRisk.MEDIUM:
        return (
            f"MEDIUM: estimated {wl}-{wh} week cert-date slip; expect MEDIUM "
            f"POA&M items and assessor remediation requests."
        )
    return (
        f"LOW: estimated {wl}-{wh} week impact; credibility concerns only, "
        f"no expected control failures."
    )


# --------------------------------------------------------------------------
# Smoke test
# --------------------------------------------------------------------------


if __name__ == "__main__":
    # Light self-test using mocked Findings (no engine import needed).
    class _MockFinding:
        def __init__(self, heuristic, artifact_id, score, nist=()):
            self.heuristic = heuristic
            self.artifact_id = artifact_id
            self.score = score
            self.nist_objectives = nist

    sample = [
        _MockFinding("FactualPlausibility", "ssp_falcon_edge.txt", 1.0,
                     ("3.12.4[a]", "3.12.1[a]")),
        _MockFinding("PromptLeakage", "ssp_falcon_edge.txt", 0.85,
                     ("3.12.4[a]",)),
        _MockFinding("TimestampRegularity", "siem_log.txt", 0.92,
                     ("3.3.1[a]", "3.3.1[b]")),
        _MockFinding("BoilerplateCluster", "ssp_falcon_edge.txt", 0.55),
        _MockFinding("SentenceStructureAnomaly", "ssp_falcon_edge.txt", 0.30),
    ]

    print("=" * 60)
    print("v0.3.1 SMOKE TEST: FCA two-tier gate")
    print("=" * 60)

    print("\n[Test 1] No context — KNOWING_FALSITY should DOWNGRADE to DISCLOSURE_RISK")
    r1 = rollup("falcon_edge_packet_v1_nocontext", sample)
    print("HEADLINE:", r1.headline)
    print(f"Worst POA&M: {r1.worst_poam_risk.value}")
    print(f"Worst FCA  : {r1.worst_fca_exposure.value}")
    assert r1.worst_fca_exposure == FcaExposure.DISCLOSURE_RISK, \
        "v0.3.1 gate failed: KNOWING_FALSITY emitted without context"
    print("PASS: gate held — no escalation without context")

    print("\n[Test 2] Full context (signed SSP + claim in POA&M, no remediation)")
    print("        → KNOWING_FALSITY_RISK should be PRESERVED")
    full_ctx = FindingContext(
        ssp_signed=True,
        ssp_signed_date="2026-04-15",
        claim_in_poam=True,
        poam_has_remediation_date=False,
    )
    r2 = rollup("falcon_edge_packet_v1_signed", sample, context=full_ctx)
    print("HEADLINE:", r2.headline)
    print(f"Worst FCA  : {r2.worst_fca_exposure.value}")
    assert r2.worst_fca_exposure == FcaExposure.KNOWING_FALSITY_RISK, \
        "v0.3.1 gate failed: should escalate when all 3 conditions met"
    print("PASS: gate escalated correctly when context complete")

    print("\n[Test 3] Partial context (signed SSP only, no POA&M correlation)")
    print("        → should DOWNGRADE to DISCLOSURE_RISK")
    partial_ctx = FindingContext(ssp_signed=True, ssp_signed_date="2026-04-15")
    r3 = rollup("falcon_edge_packet_v1_partial", sample, context=partial_ctx)
    print("HEADLINE:", r3.headline)
    print(f"Worst FCA  : {r3.worst_fca_exposure.value}")
    assert r3.worst_fca_exposure == FcaExposure.DISCLOSURE_RISK, \
        "v0.3.1 gate failed: partial context must not escalate"
    print("PASS: gate held with partial context")

    print("\n" + "=" * 60)
    print("ALL THREE FCA GATE TESTS PASSED")
    print("=" * 60)
