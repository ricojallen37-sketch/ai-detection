"""
test_mismatch_engine_ai.py

Unit tests for the v0.1 AI-era evidence contamination detection engine.

Stdlib-only (unittest). Run:
    python3 -m unittest test_mismatch_engine_ai.py
"""

from __future__ import annotations

import unittest

from mismatch_engine_ai import (
    BoilerplateClusteringDetector,
    CitationGraphDetector,
    ContradictionDetector,
    MappingDensityDetector,
    PromptLeakageDetector,
    SpecificityDeficitDetector,
    StatisticalAnomalyDetector,
    TimestampRegularityDetector,
    jaccard,
    run_engine,
    token_set,
    tokenize,
)


class TokenizationTests(unittest.TestCase):

    def test_tokenize_drops_punctuation_and_lowercases(self):
        text = "The QUICK brown fox, jumps over (the) lazy dog."
        tokens = tokenize(text)
        self.assertIn("quick", tokens)
        self.assertIn("brown", tokens)
        self.assertIn("fox", tokens)
        self.assertNotIn("the", tokens)
        # Punctuation is stripped; only alphanumerics survive.
        self.assertTrue(all(t.isalnum() for t in tokens))

    def test_tokenize_empty_string(self):
        self.assertEqual(tokenize(""), [])

    def test_tokenize_removes_stopwords(self):
        tokens = tokenize("it is what it is")
        self.assertEqual(tokens, ["what"])


class JaccardTests(unittest.TestCase):

    def test_identical_sets_score_1(self):
        a = frozenset({"one", "two"})
        self.assertEqual(jaccard(a, a), 1.0)

    def test_disjoint_sets_score_0(self):
        a = frozenset({"one"})
        b = frozenset({"two"})
        self.assertEqual(jaccard(a, b), 0.0)

    def test_empty_sets_score_0(self):
        self.assertEqual(jaccard(frozenset(), frozenset()), 0.0)

    def test_partial_overlap(self):
        a = frozenset({"alpha", "beta", "gamma"})
        b = frozenset({"beta", "gamma", "delta"})
        # intersection 2, union 4
        self.assertAlmostEqual(jaccard(a, b), 0.5)


class BoilerplateClusteringTests(unittest.TestCase):

    def setUp(self):
        self.detector = BoilerplateClusteringDetector(similarity_threshold=0.80)

    def test_no_boilerplate_returns_zero(self):
        narratives = {
            "AC.L2-3.1.1": (
                "Entra ID gates user access via security groups "
                "reviewed quarterly by the CISO designate."
            ),
            "AU.L2-3.3.1": (
                "Sentinel ingests sign-in and activity logs from "
                "Defender and on-prem file servers."
            ),
            "SI.L2-3.14.6": (
                "Monitoring workbooks run weekly and escalate alerts "
                "to the MSP on-call rotation."
            ),
        }
        result = self.detector.run(narratives)
        self.assertEqual(result.score, 0.0)
        self.assertEqual(result.findings, [])

    def test_boilerplate_cluster_is_flagged(self):
        body = (
            "Cardinal Point enforces authorized access through the Entra ID "
            "tenant. Membership is reviewed quarterly by the CISO designate "
            "and joiner mover leaver workflows are managed by People "
            "Operations. Non-compliant devices are denied at the Conditional "
            "Access layer."
        )
        narratives = {
            "AC.L2-3.1.1": body,
            "AC.L2-3.1.2": body,  # identical copy
            "AC.L2-3.1.3": body,  # identical copy
            "SI.L2-3.14.6": (
                "Monitoring workbooks run weekly and escalate alerts to the "
                "on-call rotation."
            ),
        }
        result = self.detector.run(narratives)
        self.assertGreater(result.score, 0.0)
        self.assertTrue(any("Boilerplate cluster" in f.description for f in result.findings))
        # Three of four narratives should be clustered.
        cluster_members = result.findings[0].evidence["members"]
        self.assertEqual(len(cluster_members), 3)

    def test_threshold_validation(self):
        with self.assertRaises(ValueError):
            BoilerplateClusteringDetector(similarity_threshold=0.0)
        with self.assertRaises(ValueError):
            BoilerplateClusteringDetector(similarity_threshold=1.5)


class PromptLeakageTests(unittest.TestCase):

    def setUp(self):
        self.detector = PromptLeakageDetector()

    def test_clean_narrative_scores_low(self):
        narratives = {
            "AC.L2-3.1.1": (
                "Cardinal Point enforces authorized access through the Entra "
                "ID tenant. Membership is reviewed quarterly by the CISO."
            ),
        }
        result = self.detector.run(narratives)
        self.assertLess(result.score, 0.15)
        self.assertEqual(result.findings, [])

    def test_high_pattern_match_flags_high_severity(self):
        narratives = {
            "AC.L2-3.1.1": (
                "As an AI compliance assistant, I can help you draft this "
                "control narrative."
            ),
        }
        result = self.detector.run(narratives)
        self.assertGreater(result.score, 0.0)
        self.assertEqual(result.findings[0].severity, "HIGH")

    def test_em_dash_contributes_to_score(self):
        clean = {"X": "Access is gated by Entra ID."}
        dashed = {"X": "Access is gated by Entra ID \u2014 reviewed quarterly \u2014 by the CISO."}
        clean_score = self.detector.run(clean).score
        dashed_score = self.detector.run(dashed).score
        self.assertGreater(dashed_score, clean_score)

    def test_medium_patterns_accumulate(self):
        narratives = {
            "AC.L2-3.1.1": (
                "It is important to note that our comprehensive, robust, "
                "state-of-the-art platform leverages a seamless workflow. "
                "In conclusion, please note that our solution utilizes "
                "best-in-class tooling."
            ),
        }
        result = self.detector.run(narratives)
        self.assertGreater(result.score, 0.15)
        self.assertTrue(any(f.severity in ("HIGH", "MEDIUM") for f in result.findings))


class TimestampRegularityTests(unittest.TestCase):

    def setUp(self):
        self.detector = TimestampRegularityDetector()

    def test_too_few_timestamps_returns_zero(self):
        timestamps = {"EV-001": "2026-04-01T10:00:00Z", "EV-002": "2026-04-01T11:00:00Z"}
        result = self.detector.run(timestamps)
        self.assertEqual(result.score, 0.0)

    def test_empty_timestamps_returns_zero(self):
        result = self.detector.run({})
        self.assertEqual(result.score, 0.0)

    def test_round_seconds_flagged(self):
        # All timestamps on exact minutes
        timestamps = {
            f"EV-{i:03d}": f"2026-04-01T10:{i:02d}:00Z" for i in range(10)
        }
        result = self.detector.run(timestamps)
        self.assertGreater(result.score, 0.0)
        self.assertTrue(any("minute boundaries" in f.description for f in result.findings))

    def test_organic_timestamps_score_low(self):
        # Spread over weeks with varied seconds
        timestamps = {
            "EV-001": "2026-03-05T09:14:33Z",
            "EV-002": "2026-03-12T14:47:11Z",
            "EV-003": "2026-03-19T08:02:55Z",
            "EV-004": "2026-03-26T16:39:07Z",
            "EV-005": "2026-04-02T11:22:41Z",
        }
        result = self.detector.run(timestamps)
        # No round-second findings since 0% are :00
        round_findings = [f for f in result.findings if "minute boundaries" in f.description]
        self.assertEqual(len(round_findings), 0)

    def test_burst_detection(self):
        # 5 artifacts all within 30 seconds
        timestamps = {
            "EV-001": "2026-04-01T10:00:01Z",
            "EV-002": "2026-04-01T10:00:05Z",
            "EV-003": "2026-04-01T10:00:12Z",
            "EV-004": "2026-04-01T10:00:22Z",
            "EV-005": "2026-04-01T10:00:30Z",
        }
        result = self.detector.run(timestamps)
        self.assertGreater(result.score, 0.0)
        burst_findings = [f for f in result.findings if "window" in f.description]
        self.assertTrue(len(burst_findings) > 0)

    def test_uniform_intervals_flagged(self):
        # Exactly 60 seconds apart (CV ~ 0)
        timestamps = {
            f"EV-{i:03d}": f"2026-04-01T10:{i:02d}:30Z" for i in range(10)
        }
        result = self.detector.run(timestamps)
        interval_findings = [f for f in result.findings if "CV=" in f.description]
        self.assertTrue(len(interval_findings) > 0)

    def test_unparseable_timestamps_skipped(self):
        timestamps = {
            "EV-001": "not-a-date",
            "EV-002": "also-bad",
            "EV-003": "nope",
        }
        result = self.detector.run(timestamps)
        self.assertEqual(result.score, 0.0)


class MappingDensityTests(unittest.TestCase):

    def setUp(self):
        self.detector = MappingDensityDetector(max_reuse_count=5)

    def test_no_overclaiming_scores_zero(self):
        evidence_map = {
            "AC.L2-3.1.1": ["screenshot-001", "log-001"],
            "AU.L2-3.3.1": ["log-002", "config-001"],
            "SI.L2-3.14.6": ["report-001"],
        }
        result = self.detector.run(evidence_map)
        self.assertEqual(result.score, 0.0)
        self.assertEqual(result.findings, [])

    def test_overclaimed_artifact_flagged(self):
        # One artifact mapped to 8 controls
        evidence_map = {
            f"AC.L2-3.1.{i}": ["shared-screenshot.png"] for i in range(8)
        }
        result = self.detector.run(evidence_map)
        self.assertGreater(result.score, 0.0)
        self.assertTrue(any("shared-screenshot.png" in f.description for f in result.findings))

    def test_empty_map_scores_zero(self):
        result = self.detector.run({})
        self.assertEqual(result.score, 0.0)

    def test_multiple_overclaimed_artifacts(self):
        evidence_map = {}
        for i in range(10):
            evidence_map[f"CTL-{i}"] = ["universal-policy.pdf", "universal-log.csv"]
        result = self.detector.run(evidence_map)
        self.assertGreater(result.score, 0.0)
        # Both artifacts should be flagged
        flagged_artifacts = {f.evidence["artifact"] for f in result.findings}
        self.assertIn("universal-policy.pdf", flagged_artifacts)
        self.assertIn("universal-log.csv", flagged_artifacts)

    def test_threshold_boundary(self):
        # Exactly at threshold (5) should NOT flag
        evidence_map = {f"CTL-{i}": ["doc.pdf"] for i in range(5)}
        result = self.detector.run(evidence_map)
        self.assertEqual(result.score, 0.0)

    def test_high_severity_at_double_threshold(self):
        # 10+ mappings with threshold of 5 => HIGH severity
        evidence_map = {f"CTL-{i}": ["padded.pdf"] for i in range(12)}
        result = self.detector.run(evidence_map)
        self.assertTrue(any(f.severity == "HIGH" for f in result.findings))


class CitationGraphTests(unittest.TestCase):

    def setUp(self):
        self.detector = CitationGraphDetector()

    def test_no_citations_scores_zero(self):
        narratives = {
            "AC.L2-3.1.1": "Access is controlled by Entra ID security groups.",
        }
        result = self.detector.run(narratives)
        self.assertEqual(result.score, 0.0)

    def test_phantom_citation_flagged(self):
        narratives = {
            "AC.L2-3.1.1": (
                "Access is controlled per Information Security Policy ISP-003, "
                "Section 4.7."
            ),
        }
        inventory = ["POL-001", "SOP-001"]  # ISP-003 not in inventory
        result = self.detector.run(narratives, document_inventory=inventory)
        self.assertGreater(result.score, 0.0)
        self.assertTrue(any("Phantom" in f.description for f in result.findings))

    def test_valid_citations_not_flagged(self):
        narratives = {
            "AC.L2-3.1.1": "Access per POL-001.",
        }
        inventory = ["POL-001"]
        result = self.detector.run(narratives, document_inventory=inventory)
        phantom_findings = [f for f in result.findings if "Phantom" in f.description]
        self.assertEqual(len(phantom_findings), 0)

    def test_citation_reuse_across_controls(self):
        # Same citation in many narratives (template-driven)
        narratives = {
            f"CTL-{i}": "Implemented per POL-001 Section 2.1 and SOP-001."
            for i in range(8)
        }
        result = self.detector.run(narratives)
        reuse_findings = [f for f in result.findings if "reuse" in f.description]
        self.assertTrue(len(reuse_findings) > 0)

    def test_empty_narratives_scores_zero(self):
        result = self.detector.run({})
        self.assertEqual(result.score, 0.0)

    def test_no_inventory_still_checks_reuse(self):
        narratives = {
            f"CTL-{i}": "As defined in POL-001 and SOP-002." for i in range(6)
        }
        # No inventory provided, should still check reuse patterns
        result = self.detector.run(narratives)
        self.assertIsNotNone(result)


class StatisticalAnomalyTests(unittest.TestCase):

    def setUp(self):
        self.detector = StatisticalAnomalyDetector(cv_threshold=0.05, min_narratives=5)

    def test_too_few_narratives_returns_zero(self):
        narratives = {
            "AC.L2-3.1.1": "Short narrative about access control." * 5,
            "AU.L2-3.3.1": "Short narrative about audit logs." * 5,
        }
        result = self.detector.run(narratives)
        self.assertEqual(result.score, 0.0)

    def test_uniform_entropy_flagged(self):
        # Identical narratives => zero entropy variance => HIGH flag
        base = (
            "Cardinal Point enforces authorized access through the Entra ID "
            "tenant with security groups reviewed quarterly by the CISO."
        )
        narratives = {f"CTL-{i}": base for i in range(10)}
        result = self.detector.run(narratives)
        self.assertGreater(result.score, 0.0)
        self.assertTrue(any(f.severity in ("HIGH", "MEDIUM") for f in result.findings))

    def test_varied_entropy_scores_low(self):
        # Very different narratives => high entropy variance => no flag
        narratives = {
            "AC.L2-3.1.1": "Access is gated by Azure Active Directory conditional access policies with MFA enforced for all privileged roles.",
            "AU.L2-3.3.1": "Sentinel workspace ingests Windows Security Event Logs, Linux syslog, and firewall connection logs for 12 months retention.",
            "IR.L2-3.6.1": "The incident response plan establishes a 4-hour initial triage SLA with escalation to the external DFIR retainer.",
            "PE.L2-3.10.1": "Physical access to the server room requires biometric scan plus badge tap with 24x7 CCTV recording.",
            "SC.L2-3.13.1": "Network segmentation uses VLAN tagging on the core switch with ACLs restricting CUI traffic to the enclave subnet only.",
            "MP.L2-3.8.1": "All removable media is encrypted with BitLocker To Go before any CUI transfer and inventoried in the asset register.",
        }
        result = self.detector.run(narratives)
        # With genuinely varied text, CV should be above threshold
        self.assertLessEqual(result.score, 0.5)

    def test_short_narratives_filtered(self):
        # Narratives under 50 chars should be excluded
        narratives = {f"CTL-{i}": "Short." for i in range(10)}
        result = self.detector.run(narratives)
        self.assertEqual(result.score, 0.0)

    def test_empty_narratives_returns_zero(self):
        result = self.detector.run({})
        self.assertEqual(result.score, 0.0)

    def test_entropy_evidence_includes_per_narrative(self):
        base = (
            "The organization implements access control policies and procedures "
            "that are reviewed annually by the security team and updated as needed."
        )
        narratives = {f"CTL-{i}": base for i in range(6)}
        result = self.detector.run(narratives)
        if result.findings:
            self.assertIn("per_narrative_entropy", result.findings[0].evidence)


class EngineIntegrationTests(unittest.TestCase):

    def test_clean_input_scores_low(self):
        narratives = {
            "AC.L2-3.1.1": (
                "Cardinal Point enforces authorized access through the Entra "
                "ID tenant. Group membership is reviewed quarterly by the "
                "CISO designate. Non-compliant devices are denied at the "
                "Conditional Access layer."
            ),
            "AU.L2-3.3.1": (
                "Sentinel ingests sign-in and activity logs from Defender "
                "for Endpoint, Defender for Cloud, and on-prem file servers "
                "via Log Analytics agent."
            ),
            "SI.L2-3.14.6": (
                "Monthly threat-hunt workbooks are reviewed by the CISO "
                "designate. Retention is set to 12 months in Sentinel plus "
                "24 months in archive."
            ),
        }
        result = run_engine(narratives)
        self.assertEqual(result["severity_tier"], "LOW")
        self.assertLess(result["composite_score"], 0.25)

    def test_contaminated_input_scores_elevated_or_higher(self):
        body = (
            "As an AI compliance assistant, it is important to note that our "
            "comprehensive, robust, state-of-the-art platform leverages a "
            "seamless workflow \u2014 reviewed quarterly \u2014 by our team."
        )
        narratives = {
            "AC.L2-3.1.1": body,
            "AC.L2-3.1.2": body,
            "AC.L2-3.1.3": body,
            "AC.L2-3.1.4": body,
            "AC.L2-3.1.5": body,
        }
        result = run_engine(narratives)
        self.assertIn(result["severity_tier"], ("ELEVATED", "HIGH", "CRITICAL"))
        self.assertGreater(result["composite_score"], 0.25)

    def test_full_engine_with_all_inputs(self):
        """Integration test exercising all 6 detectors simultaneously."""
        narratives = {
            "AC.L2-3.1.1": (
                "Cardinal Point enforces authorized access through the Entra ID "
                "tenant per POL-001. Group membership is reviewed quarterly."
            ),
            "AU.L2-3.3.1": (
                "Sentinel ingests sign-in and activity logs from Defender as "
                "described in SOP-001 Section 3.2."
            ),
            "SI.L2-3.14.6": (
                "Monitoring workbooks run weekly per SOP-002 and escalate to "
                "the MSP on-call rotation."
            ),
        }
        timestamps = {
            "EV-001": "2026-03-05T09:14:33Z",
            "EV-002": "2026-03-12T14:47:11Z",
            "EV-003": "2026-03-19T08:02:55Z",
        }
        evidence_map = {
            "AC.L2-3.1.1": ["screenshot-001", "log-001"],
            "AU.L2-3.3.1": ["log-002"],
            "SI.L2-3.14.6": ["report-001"],
        }
        document_inventory = ["POL-001", "SOP-001", "SOP-002"]

        result = run_engine(
            narratives,
            timestamps=timestamps,
            evidence_map=evidence_map,
            document_inventory=document_inventory,
        )
        self.assertIn("composite_score", result)
        self.assertIn("severity_tier", result)
        self.assertEqual(len(result["detectors"]), 8)
        self.assertEqual(result["narratives_scanned"], 3)

    def test_engine_runs_without_optional_inputs(self):
        """Engine should work with only narratives (metadata detectors return 0)."""
        narratives = {
            "AC.L2-3.1.1": "Access is gated by Entra ID conditional access.",
            "AU.L2-3.3.1": "Sentinel ingests logs from Defender for Endpoint.",
        }
        result = run_engine(narratives)
        self.assertEqual(len(result["detectors"]), 8)
        # Timestamp and MappingDensity detectors should be 0
        by_name = {d["name"]: d for d in result["detectors"]}
        self.assertEqual(by_name["TimestampRegularity"]["score"], 0.0)
        self.assertEqual(by_name["MappingDensity"]["score"], 0.0)

    def test_engine_all_contaminated(self):
        """Heavily contaminated input across all dimensions."""
        body = (
            "As an AI compliance assistant, it is important to note that our "
            "comprehensive, robust, state-of-the-art platform leverages a "
            "seamless workflow per ISP-999 Section 12.5."
        )
        narratives = {f"CTL-{i}": body for i in range(8)}
        timestamps = {
            f"EV-{i:03d}": f"2026-04-01T10:{i:02d}:00Z" for i in range(8)
        }
        evidence_map = {f"CTL-{i}": ["universal.pdf"] for i in range(8)}
        document_inventory = ["POL-001"]  # ISP-999 is phantom

        result = run_engine(
            narratives,
            timestamps=timestamps,
            evidence_map=evidence_map,
            document_inventory=document_inventory,
        )
        self.assertIn(result["severity_tier"], ("HIGH", "CRITICAL"))
        self.assertGreater(result["composite_score"], 0.50)


# -----------------------------------------------------------------------
# v1.1: SpecificityDeficitDetector tests
# -----------------------------------------------------------------------

class SpecificityDeficitTests(unittest.TestCase):

    def setUp(self):
        from mismatch_engine_ai import SpecificityDeficitDetector
        self.detector = SpecificityDeficitDetector()

    def test_generic_narrative_flagged(self):
        """Narrative with generic language and no specifics should be flagged."""
        narratives = {
            "AC.L2-3.1.1": (
                "The organization implements appropriate measures to ensure "
                "that all relevant systems are protected by sufficient controls. "
                "Authorized personnel follow established procedures to maintain "
                "security mechanisms in accordance with policy. The organization "
                "ensures that applicable systems are properly managed by "
                "designated individuals using protective measures."
            ),
        }
        result = self.detector.run(narratives)
        self.assertGreater(result.score, 0.0)
        self.assertTrue(len(result.findings) > 0)

    def test_specific_narrative_not_flagged(self):
        """Narrative with named systems, roles, and cadences should pass."""
        narratives = {
            "AC.L2-3.1.1": (
                "The IT Manager reviews Microsoft Entra ID conditional access "
                "policies monthly. CrowdStrike Falcon is deployed on all CUI "
                "endpoints per POL-001. The ISSO conducts quarterly access "
                "reviews using SailPoint IdentityNow. Firewall rules on "
                "fw-edge-01 restrict inbound traffic to VLAN-200."
            ),
        }
        result = self.detector.run(narratives)
        # Specific narrative should have high density and not be flagged
        self.assertEqual(len(result.findings), 0)

    def test_empty_narratives(self):
        result = self.detector.run({})
        self.assertEqual(result.score, 0.0)

    def test_short_narrative_skipped(self):
        """Very short narratives should be skipped, not flagged."""
        narratives = {"AC.L2-3.1.1": "Access is controlled."}
        result = self.detector.run(narratives)
        self.assertEqual(len(result.findings), 0)

    def test_evidence_includes_remediation(self):
        """Findings should include remediation guidance."""
        narratives = {
            "AC.L2-3.1.1": (
                "The organization implements appropriate measures to ensure "
                "that all relevant systems are protected by sufficient controls. "
                "Authorized personnel follow established procedures to maintain "
                "security mechanisms in accordance with policy."
            ),
        }
        result = self.detector.run(narratives)
        if result.findings:
            self.assertIn("remediation", result.findings[0].evidence)
            self.assertIn("why_it_matters", result.findings[0].evidence)


# -----------------------------------------------------------------------
# v1.1: ContradictionDetector tests
# -----------------------------------------------------------------------

class ContradictionDetectorTests(unittest.TestCase):

    def setUp(self):
        from mismatch_engine_ai import ContradictionDetector
        self.detector = ContradictionDetector()

    def test_frequency_contradiction_flagged(self):
        """Conflicting frequency claims for similar processes should be flagged."""
        narratives = {
            "AC.L2-3.1.1": (
                "The IT Manager conducts access reviews monthly to ensure "
                "all user accounts are appropriately provisioned."
            ),
            "AC.L2-3.1.2": (
                "The IT Manager conducts access reviews quarterly to verify "
                "user account provisioning is appropriate."
            ),
        }
        result = self.detector.run(narratives)
        # Should detect monthly vs quarterly for similar access review process
        self.assertGreater(result.score, 0.0)

    def test_consistent_narratives_no_contradiction(self):
        """Consistent claims across controls should not trigger findings."""
        narratives = {
            "AC.L2-3.1.1": (
                "The IT Manager uses Microsoft Entra ID for access control "
                "with monthly reviews of conditional access policies."
            ),
            "AC.L2-3.1.2": (
                "The ISSO reviews firewall rules on Palo Alto devices "
                "quarterly for network segmentation compliance."
            ),
        }
        result = self.detector.run(narratives)
        # Different contexts, different frequencies - not a contradiction
        self.assertEqual(result.score, 0.0)

    def test_empty_narratives(self):
        result = self.detector.run({})
        self.assertEqual(result.score, 0.0)

    def test_single_narrative(self):
        """Single narrative cannot have cross-control contradictions."""
        narratives = {"AC.L2-3.1.1": "Monthly access reviews by IT Manager."}
        result = self.detector.run(narratives)
        self.assertEqual(result.score, 0.0)

    def test_evidence_includes_remediation(self):
        """Contradiction findings should include remediation guidance."""
        narratives = {
            "AC.L2-3.1.1": (
                "The IT Manager conducts access reviews monthly to ensure "
                "all user accounts are appropriately provisioned."
            ),
            "AC.L2-3.1.2": (
                "The IT Manager conducts access reviews quarterly to verify "
                "user account provisioning is appropriate."
            ),
        }
        result = self.detector.run(narratives)
        if result.findings:
            self.assertIn("remediation", result.findings[0].evidence)
            self.assertIn("why_it_matters", result.findings[0].evidence)


# -----------------------------------------------------------------------
# v1.1: PromptLeakage scoring and demotion tests
# -----------------------------------------------------------------------

class PromptLeakageScoringV11Tests(unittest.TestCase):

    def setUp(self):
        self.detector = PromptLeakageDetector()

    def test_max_risk_hybrid_scoring(self):
        """One HIGH finding across many clean controls should still score high."""
        narratives = {
            f"AC.L2-3.1.{i}": "Access is controlled by Entra ID with monthly reviews."
            for i in range(1, 11)
        }
        # Inject one contaminated narrative
        narratives["AC.L2-3.1.1"] = (
            "As an AI compliance assistant, I can help you with access controls."
        )
        result = self.detector.run(narratives)
        # With max-risk hybrid, score should be meaningful (not averaged to ~0)
        self.assertGreater(result.score, 0.20)

    def test_severity_override_on_high_finding(self):
        """Any HIGH finding should set severity_override."""
        narratives = {
            "AC.L2-3.1.1": "As an AI language model, I implement access controls.",
        }
        result = self.detector.run(narratives)
        self.assertEqual(result.severity_override, "HIGH")

    def test_single_medium_pattern_demoted(self):
        """A lone 'robust' should NOT trigger a finding (demoted)."""
        narratives = {
            "AC.L2-3.1.1": (
                "We implemented a robust firewall configuration on our "
                "Palo Alto PA-3260 to segment the CUI boundary from the "
                "general corporate network at our Virginia facility."
            ),
        }
        result = self.detector.run(narratives)
        # Single "robust" with no other signals should be demoted
        self.assertEqual(len(result.findings), 0)

    def test_combined_medium_patterns_still_trigger(self):
        """Multiple medium patterns together should still trigger."""
        narratives = {
            "AC.L2-3.1.1": (
                "Our comprehensive, robust platform leverages a seamless "
                "state-of-the-art workflow. In summary, we utilize best "
                "practices throughout."
            ),
        }
        result = self.detector.run(narratives)
        self.assertGreater(result.score, 0.0)


# -----------------------------------------------------------------------
# v1.1: Enriched evidence tests
# -----------------------------------------------------------------------

class EnrichedEvidenceTests(unittest.TestCase):

    def test_boilerplate_includes_pairwise_similarities(self):
        """Boilerplate findings should include pairwise similarity data."""
        detector = BoilerplateClusteringDetector(similarity_threshold=0.70)
        narratives = {
            "AC.L2-3.1.1": "Access control implemented for all systems in scope.",
            "AC.L2-3.1.2": "Access control implemented for all systems in scope.",
        }
        result = detector.run(narratives)
        if result.findings:
            self.assertIn("pairwise_similarities", result.findings[0].evidence)
            self.assertIn("shared_tokens_sample", result.findings[0].evidence)
            self.assertIn("remediation", result.findings[0].evidence)

    def test_prompt_leakage_includes_matched_phrases(self):
        """PromptLeakage findings should include matched phrases."""
        detector = PromptLeakageDetector()
        narratives = {
            "AC.L2-3.1.1": "As an AI, it is important to note our access controls.",
        }
        result = detector.run(narratives)
        if result.findings:
            self.assertIn("matched_phrases", result.findings[0].evidence)
            self.assertIn("excerpt", result.findings[0].evidence)
            self.assertIn("remediation", result.findings[0].evidence)
            self.assertIn("confidence", result.findings[0].evidence)

    def test_engine_returns_version(self):
        """Engine result should include version number."""
        narratives = {"AC.L2-3.1.1": "Access control via Entra ID."}
        result = run_engine(narratives)
        self.assertEqual(result["engine_version"], "1.1")
        self.assertEqual(result["detector_count"], 8)


if __name__ == "__main__":
    unittest.main()
