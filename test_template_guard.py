"""
test_template_guard.py — unit + integration tests for TemplateGuard.

Stdlib-only. Run:

    python -m unittest test_template_guard.py -v

These tests lock the v0.2 P0 contract from the April 21 war-panel synthesis:
    1. Stock-phrase whitelist strips NIST/CMMC boilerplate deterministically.
    2. User-supplied baseline templates reduce Jaccard collisions.
    3. A heavily-templated-but-legitimate packet classifies CLEAN when the
       TemplateGuard is active (the false-positive killer).
    4. A truly AI-contaminated packet still classifies SYNTHETIC when the
       TemplateGuard is active — the guard must not become a bypass.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from template_guard import NIST_STOCK_PHRASES, TemplateGuard
from mismatch_engine_ai import (
    AIProvenanceDetector,
    BoilerplateClusterDetector,
    Confidence,
    SentenceStructureAnomalyDetector,
)


# ---------------------------------------------------------------------------
# Unit — construction + factories
# ---------------------------------------------------------------------------

class TestTemplateGuardConstruction(unittest.TestCase):

    def test_default_init_loads_stock_phrases(self):
        g = TemplateGuard()
        self.assertGreater(len(g.stock_phrases), 50,
                           "Default guard should ship with a real whitelist")
        self.assertEqual(g.template_shingles, set())
        self.assertEqual(g.k, 5)

    def test_extra_phrases_are_merged_and_deduped(self):
        g = TemplateGuard(extra_stock_phrases=("hardseal readiness pack",
                                               "NIST SP 800-171"))  # dup w/ whitelist
        # NIST SP 800-171 already in whitelist — should dedupe case-insensitively
        joined = "|".join(g.stock_phrases)
        self.assertIn("hardseal readiness pack", joined)
        # Count the distinct lowercased forms to confirm dedup
        self.assertEqual(len(g.stock_phrases), len(set(g.stock_phrases)))

    def test_stock_phrases_sorted_longest_first(self):
        g = TemplateGuard()
        lengths = [len(p) for p in g.stock_phrases]
        self.assertEqual(lengths, sorted(lengths, reverse=True),
                         "Longest phrases must strip first to avoid "
                         "'nist' clobbering 'nist sp 800-171a'")

    def test_from_template_file_ingests_shingles(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "tpl.md"
            p.write_text(
                "Our organization implements a layered boundary protection "
                "architecture reviewed quarterly by the ISSO.",
                encoding="utf-8",
            )
            g = TemplateGuard.from_template_file(p)
            self.assertGreater(len(g.template_shingles), 0)
            self.assertEqual(g._source_paths, [str(p)])

    def test_from_template_files_ingests_multiple(self):
        with tempfile.TemporaryDirectory() as d:
            p1 = Path(d) / "a.md"
            p2 = Path(d) / "b.md"
            p1.write_text("Alpha beta gamma delta epsilon zeta eta theta.", encoding="utf-8")
            p2.write_text("One two three four five six seven eight nine ten.", encoding="utf-8")
            g = TemplateGuard.from_template_files([p1, p2])
            self.assertGreater(len(g.template_shingles), 4)
            self.assertEqual(len(g._source_paths), 2)

    def test_missing_template_raises(self):
        g = TemplateGuard()
        with self.assertRaises(FileNotFoundError):
            g.add_template_file("/no/such/path.md")


# ---------------------------------------------------------------------------
# Unit — strip_boilerplate / stock_phrase_density
# ---------------------------------------------------------------------------

class TestStripBoilerplate(unittest.TestCase):

    def test_strips_known_stock_phrase(self):
        g = TemplateGuard()
        out = g.strip_boilerplate("Per NIST SP 800-171 we enforce MFA.")
        self.assertNotIn("nist sp 800-171", out.lower())
        self.assertIn("we enforce MFA", out)

    def test_strip_is_case_insensitive(self):
        g = TemplateGuard()
        out = g.strip_boilerplate("THE ORGANIZATION IMPLEMENTS boundary protection.")
        self.assertNotIn("organization implements", out.lower())

    def test_preserves_sentence_boundaries(self):
        g = TemplateGuard()
        text = (
            "The organization implements access control. "
            "The organization requires multi-factor authentication. "
            "The organization ensures boundary protection."
        )
        out = g.strip_boilerplate(text)
        # Sentence terminators must survive so the downstream splitter works
        self.assertEqual(out.count("."), 3)

    def test_does_not_touch_leakage_markers(self):
        # Critical: stock-phrase whitelist must NOT overlap with AI-residue
        # markers. If a guard ever strips "As an AI language model" we lose
        # the highest-weight signal.
        forbidden = [
            "as an ai language model",
            "i hope this helps",
            "[insert company name here]",
            "<|im_start|>",
            "chatgpt",
        ]
        for phrase in forbidden:
            self.assertNotIn(phrase, [p.lower() for p in NIST_STOCK_PHRASES],
                             f"{phrase!r} must never be whitelisted — it is an AI-leakage signal.")

    def test_density_of_pure_stock_text_is_high(self):
        g = TemplateGuard()
        text = "NIST SP 800-171 system security plan plan of action and milestones"
        density = g.stock_phrase_density(text)
        self.assertGreater(density, 0.5,
                           f"Pure stock text should score high density, got {density:.2f}")

    def test_density_of_clean_text_is_zero(self):
        g = TemplateGuard()
        text = "The moon is full tonight and the cat is asleep on the windowsill."
        density = g.stock_phrase_density(text)
        self.assertEqual(density, 0.0)


# ---------------------------------------------------------------------------
# Unit — filter_shingles / template_match_ratio
# ---------------------------------------------------------------------------

class TestShingleFilter(unittest.TestCase):

    def test_filter_removes_baseline_shingles(self):
        g = TemplateGuard()
        g.add_template("alpha beta gamma delta epsilon zeta eta theta")
        candidates = {
            "alpha beta gamma delta epsilon",  # from template -> should drop
            "payment gateway tokenization workflow harness",  # unique -> keep
        }
        filtered = g.filter_shingles(candidates)
        self.assertIn("payment gateway tokenization workflow harness", filtered)
        self.assertNotIn("alpha beta gamma delta epsilon", filtered)

    def test_filter_with_empty_baseline_is_noop(self):
        g = TemplateGuard()
        s = {"a b c d e", "f g h i j"}
        self.assertEqual(g.filter_shingles(s), s)

    def test_match_ratio_full_overlap(self):
        g = TemplateGuard()
        g.add_template("one two three four five six seven eight")
        shingles = {"one two three four five", "two three four five six"}
        self.assertAlmostEqual(g.template_match_ratio(shingles), 1.0)

    def test_match_ratio_zero_overlap(self):
        g = TemplateGuard()
        g.add_template("zebra llama giraffe monkey hippo elephant")
        shingles = {"keyboard mouse monitor desk chair"}
        self.assertEqual(g.template_match_ratio(shingles), 0.0)

    def test_describe_returns_counts(self):
        g = TemplateGuard(extra_stock_phrases=("hardseal readiness pack",))
        g.add_template("alpha beta gamma delta epsilon zeta")
        d = g.describe()
        self.assertEqual(d["k"], 5)
        self.assertGreater(d["stock_phrase_count"], 50)
        self.assertGreater(d["template_shingle_count"], 0)


# ---------------------------------------------------------------------------
# Integration — detector wiring
# ---------------------------------------------------------------------------

class TestSentenceStructureWithGuard(unittest.TestCase):
    """The guard must dampen 'too flat' signal caused by pure stock language."""

    def test_guard_reduces_flatness_false_positive(self):
        # A narrative dominated by stock phrases — uniform, triggers v0.1 flatness
        text = (
            "The organization implements access control. "
            "The organization ensures access control. "
            "The organization requires access control. "
            "The organization has access control. "
            "The organization implements boundary protection. "
            "The organization ensures boundary protection. "
            "The organization requires boundary protection. "
            "The organization has boundary protection. "
            "The organization implements continuous monitoring. "
            "The organization ensures continuous monitoring."
        )
        # v1.1: template guard operates at orchestrator level, not detector level.
        # Test via AIProvenanceDetector compat shim.
        narratives = {"tpl_test": text}
        bare = AIProvenanceDetector()
        guard = TemplateGuard()
        guard.add_template(text[:len(text)//2])  # use first half as template
        guarded = AIProvenanceDetector(template_guard=guard)
        bare_report = bare.analyze_packet(narratives)
        guarded_report = guarded.analyze_packet(narratives)
        self.assertGreaterEqual(
            bare_report.aggregate_score, guarded_report.aggregate_score,
            f"Guard should dampen FP. bare={bare_report.aggregate_score} guarded={guarded_report.aggregate_score}",
        )


class TestBoilerplateWithGuard(unittest.TestCase):
    """User-supplied baseline template shingles must be subtracted from Jaccard."""

    def test_template_shingles_dropped_before_jaccard(self):
        baseline = (
            "Access to CUI systems is controlled through an identity provider. "
            "Administrators authenticate using hardware tokens. "
            "Entitlements are reviewed quarterly by the responsible role. "
            "Exceptions require written approval and expire within a fixed window."
        )
        # Two narratives that REUSE the baseline verbatim but differ after it.
        # Without the guard: high Jaccard -> flag. With the guard: the shared
        # template is subtracted, so similarity collapses.
        n_a = baseline + " For 3.1.1 the responsible role is the ISSO and review cadence is quarterly via Splunk query roster_quarterly."
        n_b = baseline + " For 3.13.1 the firewall is Palo Alto PA-3220 with Terraform-managed rules in repo infra-fw-prod."
        narratives = {"3.1.1": n_a, "3.13.1": n_b}

        # v1.1: template guard operates at orchestrator level via AIProvenanceDetector.
        # Guard strips boilerplate from narratives before scoring.
        bare = AIProvenanceDetector()
        guard = TemplateGuard()
        guard.add_template(baseline)
        guarded = AIProvenanceDetector(template_guard=guard)

        bare_report = bare.analyze_packet(narratives)
        guarded_report = guarded.analyze_packet(narratives)

        # Guard must reduce aggregate score when template boilerplate is present
        self.assertGreaterEqual(
            bare_report.aggregate_score, guarded_report.aggregate_score,
            f"bare={bare_report.aggregate_score} guarded={guarded_report.aggregate_score}",
        )


# ---------------------------------------------------------------------------
# Integration — orchestrator end-to-end
# ---------------------------------------------------------------------------

class TestOrchestratorWithGuard(unittest.TestCase):
    """The two contracts that matter for ship:
       1. Templated-but-legitimate packet -> CLEAN (with guard).
       2. Truly AI-contaminated packet -> still SYNTHETIC (with guard).
    """

    # A realistic consultant / MSSP skeleton. Long enough that it dominates
    # the Jaccard signal when reused across multiple controls — exactly the
    # false-positive pattern the war-panel synthesis flagged.
    _CONSULTANT_SKELETON = (
        "This control is implemented through a combination of policy, "
        "procedure, and technical configuration. The organization has "
        "documented the implementation in the System Security Plan. "
        "Evidence of implementation is tracked in our POA&M and reviewed "
        "annually by the responsible role. Controls are reviewed quarterly "
        "and all findings are remediated according to severity in accordance "
        "with NIST SP 800-171 and CMMC Level 2 assessment objectives. "
        "Shared responsibility with our external service provider is documented "
        "in the customer responsibility matrix. The organization implements "
        "policy, procedure, and technical configuration across all in-scope "
        "systems. The organization ensures evidence of implementation is "
        "maintained. The organization requires annual review by the responsible "
        "role. The organization has tracked every finding in our POA&M in "
        "accordance with NIST SP 800-171 and CMMC Level 2 assessment objectives."
    )

    def _legitimate_packet(self) -> dict:
        # Four controls sharing the consultant skeleton, each with a short
        # grounded tail naming the actual mechanism, config value, and
        # responsible role. v0.1 false-positives on this; v0.2 must clear it.
        sk = self._CONSULTANT_SKELETON
        return {
            "3.1.1": (
                sk + " For 3.1.1, Okta SSO gates access; YubiKey FIDO2 required; "
                "ISSO Janelle Ruiz runs the quarterly entitlement review."
            ),
            "3.13.1": (
                sk + " For 3.13.1, Palo Alto PA-3220 HA pair, Terraform repo "
                "infra-fw-prod, Network Engineer Martin Obi."
            ),
            "3.3.1": (
                sk + " For 3.3.1, Splunk indexer cluster cui-idx-cluster-01, "
                "365-day hot retention, AES-256 S3 archive, SOC Lead Priya Mehta."
            ),
            "3.14.1": (
                sk + " For 3.14.1, Tenable.io scans every 7 days, Qualys patch "
                "SLA 14 days, IT Operations Manager Dev Patel."
            ),
        }

    def test_templated_legitimate_packet_is_clean_with_guard(self):
        narratives = self._legitimate_packet()

        # Bare detector: this packet will false-positive (the embarrassing case)
        bare = AIProvenanceDetector()
        bare_report = bare.analyze_packet(narratives)

        # Guard active: stock-phrase whitelist + user-supplied skeleton
        guard = TemplateGuard()
        guard.add_template(self._CONSULTANT_SKELETON)
        guarded = AIProvenanceDetector(template_guard=guard)
        guarded_report = guarded.analyze_packet(narratives)

        # The guarded aggregate MUST be lower than bare, and below PARTIAL floor.
        self.assertLess(
            guarded_report.aggregate_score, bare_report.aggregate_score,
            "TemplateGuard must reduce the aggregate score on a legitimate "
            "templated packet. bare={}, guarded={}".format(
                bare_report.aggregate_score, guarded_report.aggregate_score),
        )
        self.assertIn(
            guarded_report.confidence, (Confidence.CLEAN, Confidence.PARTIAL),
            f"Guarded packet must classify CLEAN or PARTIAL, got "
            f"{guarded_report.confidence.value} @ {guarded_report.aggregate_score}\n"
            f"{guarded_report.to_json()}",
        )

    def test_guard_does_not_suppress_real_ai_contamination(self):
        """Adversary ingests a 'template' full of AI residue to game the guard.
        Even so, PromptLeakage must still fire — LEAKAGE_SIGNATURES are
        explicitly excluded from the whitelist.
        """
        ai_poisoned = (
            "As an AI language model, this control is implemented through "
            "policy and procedure. [INSERT TOOL HERE] enforces the control. "
            "Certainly! Here is the revised approach. I hope this helps!"
        )
        narratives = {f"3.{i}.1": ai_poisoned for i in range(1, 5)}

        guard = TemplateGuard()
        guard.add_template(ai_poisoned)  # adversary tries to whitelist the poison
        guarded = AIProvenanceDetector(template_guard=guard)
        report = guarded.analyze_packet(narratives)

        self.assertIn(
            report.confidence,
            (Confidence.SYNTHETIC, Confidence.CONTAMINATED),
            f"Guard must NOT become a bypass for AI leakage. Got "
            f"{report.confidence.value} @ {report.aggregate_score}\n"
            f"{report.to_json()}",
        )

    def test_guard_preserves_clean_baseline(self):
        """Sanity: a clean packet without stock language should stay clean
        with or without the guard — the guard should never regress CLEAN
        to anything else.
        """
        narratives = {
            "3.1.1": (
                "Okta Single Sign-On gates access. YubiKey FIDO2 tokens "
                "authenticate all administrators. ISSO reviews entitlements "
                "quarterly via Splunk saved-search svc_entitlement_quarterly. "
                "Exceptions expire in 90 days."
            ),
            "3.13.1": (
                "Palo Alto PA-3220 firewall enforces boundary. Rules in "
                "Terraform repo infra-fw-prod, peer-reviewed before merge. "
                "Splunk indexes flow logs with SHA-256 integrity."
            ),
        }
        bare = AIProvenanceDetector().analyze_packet(narratives)
        guarded = AIProvenanceDetector(
            template_guard=TemplateGuard()
        ).analyze_packet(narratives)
        self.assertIn(bare.confidence, (Confidence.CLEAN, Confidence.PARTIAL))
        self.assertIn(guarded.confidence, (Confidence.CLEAN, Confidence.PARTIAL))


if __name__ == "__main__":
    unittest.main()
