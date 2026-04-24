"""
Schema regression tests for mismatch_engine_ai.py --json output.

These tests enforce the stability contract declared in
schema/score_v1.json. Any change to the engine output that breaks
schema conformance breaks the test suite, which prevents silent drift
between the published contract and actual emitted JSON.

Stdlib-only, like the rest of the engine.
"""

import json
import os
import subprocess
import sys
import unittest


REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
SCHEMA_PATH = os.path.join(REPO_ROOT, "schema", "score_v1.json")
ENGINE = os.path.join(REPO_ROOT, "mismatch_engine_ai.py")


class SchemaConformance(unittest.TestCase):
    """Validate live engine output against schema/score_v1.json."""

    @classmethod
    def setUpClass(cls):
        with open(SCHEMA_PATH) as f:
            cls.schema = json.load(f)

        cls.top_required = set(cls.schema["required"])
        cls.severity_enum = set(
            cls.schema["properties"]["severity_tier"]["enum"]
        )
        cls.detector_enum = set(
            cls.schema["properties"]["detectors"]["items"]
                    ["properties"]["name"]["enum"]
        )
        cls.detector_required = set(
            cls.schema["properties"]["detectors"]["items"]["required"]
        )
        cls.finding_severity_enum = set(
            cls.schema["properties"]["detectors"]["items"]
                    ["properties"]["findings"]["items"]
                    ["properties"]["severity"]["enum"]
        )

    def _run_engine(self, sample_rel_path, extra_args=None):
        args = [sys.executable, ENGINE,
                os.path.join(REPO_ROOT, sample_rel_path), "--json"]
        if extra_args:
            args.extend(extra_args)
        result = subprocess.run(args, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0,
                         msg=f"engine exited non-zero: {result.stderr}")
        return json.loads(result.stdout)

    def _validate(self, output):
        self.assertIsInstance(output, dict)
        # All required top-level fields present
        missing = self.top_required - set(output.keys())
        self.assertEqual(missing, set(),
                         msg=f"missing required top-level fields: {missing}")
        # composite_score in range
        self.assertIsInstance(output["composite_score"], (int, float))
        self.assertGreaterEqual(output["composite_score"], 0.0)
        self.assertLessEqual(output["composite_score"], 1.0)
        # severity_tier valid
        self.assertIn(output["severity_tier"], self.severity_enum)
        # engine_version is a string
        self.assertIsInstance(output["engine_version"], str)
        # narratives_scanned is non-negative int
        self.assertIsInstance(output["narratives_scanned"], int)
        self.assertGreaterEqual(output["narratives_scanned"], 0)
        # detector_count is positive int
        self.assertIsInstance(output["detector_count"], int)
        self.assertGreaterEqual(output["detector_count"], 1)
        # detectors array
        self.assertIsInstance(output["detectors"], list)
        self.assertEqual(len(output["detectors"]), output["detector_count"])
        for i, det in enumerate(output["detectors"]):
            with self.subTest(detector=i, name=det.get("name")):
                # Required detector fields present
                det_missing = self.detector_required - set(det.keys())
                self.assertEqual(det_missing, set(),
                                 msg=f"detector[{i}] missing required fields: {det_missing}")
                # Detector name is in enum
                self.assertIn(det["name"], self.detector_enum)
                # Score in range
                self.assertIsInstance(det["score"], (int, float))
                self.assertGreaterEqual(det["score"], 0.0)
                self.assertLessEqual(det["score"], 1.0)
                # Findings is a list
                self.assertIsInstance(det["findings"], list)
                for j, f in enumerate(det["findings"]):
                    with self.subTest(finding=j):
                        self.assertIn("severity", f)
                        self.assertIn("score", f)
                        self.assertIn("description", f)
                        self.assertIn(f["severity"], self.finding_severity_enum)
                        self.assertIsInstance(f["score"], (int, float))
                        self.assertIsInstance(f["description"], str)

    def test_clean_packet_conforms(self):
        self._validate(self._run_engine("samples/clean_packet"))

    def test_contaminated_packet_conforms(self):
        self._validate(self._run_engine("samples/contaminated_packet"))

    def test_templated_packet_conforms(self):
        self._validate(self._run_engine(
            "samples/templated_legitimate_packet",
        ))

    def test_schema_version_field(self):
        """Schema file declares a version and is draft 2020-12."""
        self.assertEqual(self.schema.get("version"), "2.0.0")
        self.assertIn("2020-12", self.schema.get("$schema", ""))

    def test_all_eight_detectors_enumerated(self):
        """Schema enum must list exactly the 8 shipped detectors."""
        expected = {
            "BoilerplateClustering",
            "PromptLeakage",
            "TimestampRegularity",
            "MappingDensity",
            "CitationGraph",
            "StatisticalAnomaly",
            "SpecificityDeficit",
            "ContradictionDetection",
        }
        self.assertEqual(self.detector_enum, expected)

    def test_all_four_severity_tiers_enumerated(self):
        """Schema enum must list exactly the 4 severity tiers."""
        expected = {
            "LOW",
            "ELEVATED",
            "HIGH",
            "CRITICAL",
        }
        self.assertEqual(self.severity_enum, expected)


if __name__ == "__main__":
    unittest.main()
