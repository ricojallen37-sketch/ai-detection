"""
test_risk_delta.py - Unit tests for the v0.3.1 two-tier FCA gate.

Round 2 critique (April 22, 2026):
    "A single 0.95+ factual score was escalating directly to
     KNOWING_FALSITY_RISK. A buyer's GC will reject this. '31 USC 3729(b)
     requires actual knowledge or reckless disregard. One factual error in
     a 200-page SSP does not, by itself, establish that."

These tests prove that v0.3.1 risk_delta correctly enforces the three-condition
escalation gate and that DISCLOSURE_RISK is the default posture absent
contractor-attestation context.

Stdlib only. Run either way:
    python3 -m unittest test_risk_delta -v
    python3 test_risk_delta.py
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ENGINE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(ENGINE_DIR))

from risk_delta import (
    FindingContext,
    FcaExposure,
    PoamRisk,
    translate_finding,
    rollup,
)


class MockFinding:
    """Duck-typed stand-in for engine Finding objects."""
    def __init__(self, heuristic: str, score: float,
                 artifact_id: str = "test.md",
                 nist_objectives: tuple = ()):
        self.heuristic = heuristic
        self.artifact_id = artifact_id
        self.score = score
        self.nist_objectives = nist_objectives


class TestFcaGate(unittest.TestCase):
    """FCA gate tests: the headline v0.3.1 behavior."""

    def test_factual_no_context_downgrades(self):
        """factual=1.0 with no context must downgrade KNOWING_FALSITY to DISCLOSURE."""
        f = MockFinding("FactualPlausibility", 1.0)
        d = translate_finding(f)
        self.assertEqual(d.fca_exposure, FcaExposure.DISCLOSURE_RISK)
        self.assertEqual(d.poam_risk_level, PoamRisk.CRITICAL,
                         "POA&M risk should still be CRITICAL even when FCA downgrades")

    def test_factual_signed_only_downgrades(self):
        """Signed SSP alone is NOT sufficient to escalate."""
        f = MockFinding("FactualPlausibility", 1.0)
        ctx = FindingContext(ssp_signed=True, ssp_signed_date="2026-04-15")
        d = translate_finding(f, context=ctx)
        self.assertEqual(d.fca_exposure, FcaExposure.DISCLOSURE_RISK)

    def test_factual_poam_only_downgrades(self):
        """POA&M correlation alone is NOT sufficient."""
        f = MockFinding("FactualPlausibility", 1.0)
        ctx = FindingContext(claim_in_poam=True)
        d = translate_finding(f, context=ctx)
        self.assertEqual(d.fca_exposure, FcaExposure.DISCLOSURE_RISK)

    def test_factual_poam_with_remediation_date_downgrades(self):
        """POA&M with active remediation shows contractor scheduled a fix."""
        f = MockFinding("FactualPlausibility", 1.0)
        ctx = FindingContext(
            ssp_signed=True,
            ssp_signed_date="2026-04-15",
            claim_in_poam=True,
            poam_has_remediation_date=True,
        )
        d = translate_finding(f, context=ctx)
        self.assertEqual(d.fca_exposure, FcaExposure.DISCLOSURE_RISK)

    def test_factual_full_context_escalates(self):
        """Signed SSP + POA&M claim + no remediation date = KNOWING_FALSITY."""
        f = MockFinding("FactualPlausibility", 1.0)
        ctx = FindingContext(
            ssp_signed=True,
            ssp_signed_date="2026-04-15",
            claim_in_poam=True,
            poam_has_remediation_date=False,
        )
        d = translate_finding(f, context=ctx)
        self.assertEqual(d.fca_exposure, FcaExposure.KNOWING_FALSITY_RISK)

    def test_factual_sub_threshold_score_never_escalates(self):
        """Below 0.95, the band returns DISCLOSURE_RISK; gate is irrelevant."""
        f = MockFinding("FactualPlausibility", 0.80)
        ctx = FindingContext(
            ssp_signed=True, claim_in_poam=True, poam_has_remediation_date=False,
        )
        d = translate_finding(f, context=ctx)
        self.assertEqual(d.fca_exposure, FcaExposure.DISCLOSURE_RISK)


class TestNonFactualHeuristics(unittest.TestCase):
    """Non-factual heuristics are not affected by the gate."""

    def test_prompt_leakage_never_escalates_without_gate(self):
        """PromptLeakage caps at DISCLOSURE_RISK; context must not escalate."""
        f = MockFinding("PromptLeakage", 1.0)
        ctx = FindingContext(
            ssp_signed=True, claim_in_poam=True, poam_has_remediation_date=False,
        )
        d = translate_finding(f, context=ctx)
        self.assertEqual(d.fca_exposure, FcaExposure.DISCLOSURE_RISK)

    def test_timestamp_regularity_also_gated(self):
        """TimestampRegularity at >=0.80 emits KNOWING_FALSITY in the band;
        the gate still applies: no context => downgrade."""
        f = MockFinding("TimestampRegularity", 0.95)
        d = translate_finding(f)
        self.assertEqual(d.fca_exposure, FcaExposure.DISCLOSURE_RISK)
        ctx = FindingContext(
            ssp_signed=True, claim_in_poam=True, poam_has_remediation_date=False,
        )
        d2 = translate_finding(f, context=ctx)
        self.assertEqual(d2.fca_exposure, FcaExposure.KNOWING_FALSITY_RISK)

    def test_boilerplate_and_sentence_are_not_fca(self):
        """Credibility-only heuristics must never emit FCA exposure."""
        for h, score in [
            ("BoilerplateCluster", 1.0),
            ("SentenceStructureAnomaly", 1.0),
            ("MappingDensity", 1.0),
            ("ArtifactSpecificityIndex", 1.0),
        ]:
            with self.subTest(heuristic=h):
                f = MockFinding(h, score)
                d = translate_finding(f)
                self.assertEqual(d.fca_exposure, FcaExposure.NONE,
                                 f"{h} should never emit FCA; got {d.fca_exposure}")


class TestRollup(unittest.TestCase):
    """Rollup behavior tests."""

    def test_rollup_worst_wins_on_fca(self):
        """Rollup picks the worst FCA across findings."""
        fs = [
            MockFinding("BoilerplateCluster", 0.8),
            MockFinding("PromptLeakage", 0.8),
            MockFinding("FactualPlausibility", 0.6),
        ]
        r = rollup("packet", fs)
        self.assertEqual(r.worst_fca_exposure, FcaExposure.DISCLOSURE_RISK)
        self.assertEqual(r.worst_poam_risk, PoamRisk.HIGH)

    def test_rollup_context_applies_to_all_findings(self):
        """Rollup-level context forwards to every finding."""
        fs = [
            MockFinding("FactualPlausibility", 1.0),
            MockFinding("TimestampRegularity", 0.95),
            MockFinding("PromptLeakage", 0.8),
        ]
        r_no = rollup("packet", fs)
        self.assertEqual(r_no.worst_fca_exposure, FcaExposure.DISCLOSURE_RISK)
        ctx = FindingContext(
            ssp_signed=True, claim_in_poam=True, poam_has_remediation_date=False,
        )
        r_full = rollup("packet", fs, context=ctx)
        self.assertEqual(r_full.worst_fca_exposure, FcaExposure.KNOWING_FALSITY_RISK)

    def test_rollup_week_range_is_max_not_sum(self):
        """Findings batch for remediation; take MAX single window, not sum."""
        fs = [
            MockFinding("FactualPlausibility", 1.0),
            MockFinding("PromptLeakage", 0.8),
            MockFinding("BoilerplateCluster", 0.8),
        ]
        r = rollup("packet", fs)
        self.assertEqual(r.cert_delay_weeks_low, 8)
        self.assertEqual(r.cert_delay_weeks_high, 16)

    def test_rollup_headline_reflects_critical_plus_knowing_falsity(self):
        """Headline should cite DOJ CCFI when KNOWING_FALSITY."""
        fs = [MockFinding("FactualPlausibility", 1.0)]
        ctx = FindingContext(
            ssp_signed=True, claim_in_poam=True, poam_has_remediation_date=False,
        )
        r = rollup("packet", fs, context=ctx)
        self.assertIn("Civil Cyber-Fraud", r.headline)


class TestFindingContextSemantics(unittest.TestCase):
    """FindingContext eligibility semantics."""

    def test_context_unknown_is_not_escalation_eligible(self):
        self.assertFalse(FindingContext.unknown().fca_escalation_eligible())

    def test_context_signed_plus_poam_no_date_is_eligible(self):
        ctx = FindingContext(
            ssp_signed=True, claim_in_poam=True, poam_has_remediation_date=False,
        )
        self.assertTrue(ctx.fca_escalation_eligible())

    def test_context_signed_plus_poam_with_date_is_not_eligible(self):
        ctx = FindingContext(
            ssp_signed=True, claim_in_poam=True, poam_has_remediation_date=True,
        )
        self.assertFalse(ctx.fca_escalation_eligible())


class TestDefensiveFallbacks(unittest.TestCase):
    """Defensive: unknown heuristic must not crash."""

    def test_unknown_heuristic_falls_back_low(self):
        f = MockFinding("SomeFutureHeuristic", 0.9)
        d = translate_finding(f)
        self.assertEqual(d.poam_risk_level, PoamRisk.LOW)
        self.assertEqual(d.fca_exposure, FcaExposure.NONE)


if __name__ == "__main__":
    unittest.main(verbosity=2)
