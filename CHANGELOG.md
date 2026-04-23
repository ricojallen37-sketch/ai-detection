# Changelog

All notable changes to the Hardseal AI-Detection engine are documented
here. This project follows semantic versioning.

## [Unreleased]

## [0.3.1] - 2026-04-23

### Released

1. First public open-source release under the MIT License at
   `github.com/hardseal/ai-detection`. The v0.3.1 tag is the first
   public tag; v0.1.0, v0.2.0, and v0.2.1 are bundled into the initial
   commit history as documentation of the iterative development path.
2. The combined scoring bundle commitment hash is unchanged from v0.2:
   `32f1e682b0544b1af20077cc33f0604ec76238489182190c8d77a1cb01f42bbf`.
   Scoring-layer additions in v0.3.1 (`risk_delta.py`) do not modify
   any weight, regex, or token in the committed v0.2 bundle.

### Changed

1. `risk_delta.py`: Two-tier FCA gate. Prior behavior escalated any
   `FactualPlausibility` finding at score >= 0.95 directly to
   `KNOWING_FALSITY_RISK`. A single factual error in a 200-page SSP does
   not, by itself, establish "knowing" falsity under 31 USC 3729(b). The

   new gate emits `DISCLOSURE_RISK` by default and only escalates to
   `KNOWING_FALSITY_RISK` when the caller asserts three conditions via
   `FindingContext`:
   (a) `ssp_signed=True` (the contractor formally attested),
   (b) `claim_in_poam=True` (the same claim is referenced in the POA&M),
   (c) `poam_has_remediation_date=False` (no scheduled fix).
   The same gate applies to `TimestampRegularity` at >= 0.80, which also
   emits `KNOWING_FALSITY_RISK` in its band table. Unknown or partial
   contexts default to `DISCLOSURE_RISK`. This posture survives general
   counsel review and avoids over-claiming FCA liability on a single
   detector signal.
2. `risk_delta.rollup()` accepts a `context: Optional[FindingContext]`
   and forwards it to every `translate_finding` call, so an entire
   packet rollup is evaluated consistently.
3. Falcon Edge v2 demo re-ran under v0.3.1. Packet remains
   `LIKELY_SYNTHETIC` at 0.814 with `CRITICAL` POA&M risk, but FCA
   exposure correctly caps at `DISCLOSURE_RISK` because no `FindingContext`
   is provided in the demo (and the demo POA&M includes a remediation
   date, which would disqualify escalation anyway). No regression.

### Added

1. `test_risk_delta.py`: 17 dedicated unit tests covering the two-tier
   gate across every pass/fail path (no context, partial contexts with
   only one condition met, full context, sub-threshold score,
   non-factual heuristics, rollup aggregation, headline rendering, and
   unknown-heuristic fallback). 17/17 passing. Sits alongside
   `test_mismatch_engine_ai.py` (26/26) and `test_template_guard.py`
   (22/22).
2. `wild_sample_runner.py`: Dual-mode runner (whole-file
   `analyze_artifact` + per-control `analyze_packet`) for SSP excerpts
   Hardseal did not author. Closes the "closed loop" credibility gap
   raised in Round 2 of the April 22 war panel.
3. `samples/wild_samples/`: Three non-Hardseal-authored SSP excerpts
   (A: generic LLM output, B: human-authored NIST-style, C:
   vendor-template boilerplate) covering precision, recall, and
   cross-narrative discrimination tests.
4. `WILD_SAMPLE_APPENDIX.md` and `build_wild_sample_appendix.py`: 1-page
   buyer-facing appendix rendering the dual-mode wild-sample results
   for attachment alongside the Falcon Edge v2 report.

### Planned for v0.3

1. `VersionHallucinationDetector`: flags named versions of products
   that do not exist (Splunk 42.0, Okta Verify 3.0).
2. `CrossArtifactTemporalConsistencyDetector`: flags SSP narrative
   claims that contradict timestamps in paired log artifacts.
3. `RoleLanguageDriftDetector`: flags within-packet voice drift
   between controls claimed to be authored by the same role.
4. `MetricPlausibilityDetector`: flags quantitative claims that fall
   outside empirical reference bands for a control family.
5. `HashWitnessDetector`: when a narrative claims a cryptographic
   attestation chain, verifies that the claim is structurally
   resolvable against the evidence bundle.

Target code ship: end of May 2026. Signatures already published in
the companion paper, Section 9 through Section 13.

## [0.2.1] - 2026-04-22

### Added

1. `REGULATORY_DISCLAIMER.md`. Explicit "no regulatory guarantee" clause.
   The detector produces heuristic signals, not assessor judgments. No
   Hardseal output is a substitute for a C3PAO's professional
   assessment. Addresses the liability-gap failure mode surfaced by the
   v0.3 open-source decision war panel.
2. `SUPPORT.md` plus `.github/ISSUE_TEMPLATE/` (config, bug, detector
   accuracy). Triage-aware routing: DIB contractor, C3PAO, and paid
   inquiries go to email with dated response SLAs; GitHub issues are
   best-effort with a weekly triage cadence. Addresses the solo-founder
   support-burden failure mode surfaced by the war panel.
3. `ANCHOR_PLAN.md`. Thirty-day and ninety-day commitments to keep
   Hardseal the named home of the standard: trademark filing, weekly
   release cadence through the paper drop, authorized-implementations
   registry, paper-as-canonical-reference, category vocabulary lock.
   Addresses the mindshare-capture failure mode surfaced by the war
   panel.

### Prepared

1. Public open-source release under the MIT License prepared for push
   to `github.com/hardseal/ai-detection`.
2. Internal `v0.2.1` tag. The `v0.2.0` tag from 2026-04-21 was the
   internal scoring-bundle release; `v0.2.1` bundled the three hardening
   docs. Scoring logic, weights, regex bundles, and commitment hashes
   are unchanged from `v0.2.0`.
3. Commitment hash of the combined scoring bundle remains
   `32f1e682b0544b1af20077cc33f0604ec76238489182190c8d77a1cb01f42bbf`.
   `verify_commitment.py` produces the same output under `v0.2.1` as
   under `v0.2.0`.

## [0.2.0] - 2026-04-21

### Added

1. `template_guard.py`. NIST/CMMC stock-phrase whitelist plus optional
   user-template shingle subtraction. Fixes the v0.1 false positive
   on legitimate heavily-templated packets.
2. `ArtifactSpecificityIndexDetector`. Ratio of grounding tokens
   (versions, hashes, IPs, paths, ticket IDs, dates, filenames) to
   named mechanisms. LLMs name; they do not ground.
3. Commitment hash publication. The four scoring bundles
   (`DEFAULT_WEIGHTS`, `LEAKAGE_SIGNATURES`, `_GROUNDING_PATTERNS`,
   `MECHANISM_TOKENS`) and a combined bundle are hashed under
   canonical JSON encoding and published in `README.md`. Reproducible
   via `verify_commitment.py`.
4. `bundle_v0.2.canonical.json`. Byte-for-byte canonical artifact
   for hash verification.
5. 22 new tests covering `template_guard.py`.
6. `samples/templated_legitimate_packet/` regression corpus.

### Changed

Weight rebalance driven by v0.1 war-panel red-team:

1. `PromptLeakage`: 0.25 to 0.15. Easy to scrub from adversary output.
2. `TimestampRegularity`: 0.20 to 0.25. Structural signal harder to fake.
3. `ArtifactSpecificityIndex`: new at 0.20.

Confidence-tier thresholds retuned to match the new weight vector.
Per-tier test assertions refreshed.

### Verified

1. 48 tests pass on Python 3.10, 3.11, 3.12.
2. Clean packet scores 0.13, CLEAN.
3. Contaminated packet scores 1.0, LIKELY_SYNTHETIC.
4. Templated legitimate packet scores 0.518 bare (CONTAMINATED, false
   positive) and 0.000 with `--template` (CLEAN, correct).

## [0.1.0] - 2026-04-21

### Added

1. Initial six-heuristic detection engine: `SentenceStructureAnomaly`,
   `BoilerplateCluster`, `TimestampRegularity`, `MappingDensity`,
   `CitationGraph`, `PromptLeakage`.
2. CLI for single-artifact and full-packet analysis.
3. 22 unit tests.
4. Clean and contaminated sample packets.
5. `THREAT_MODEL.md` with per-heuristic attack mapping and NIST
   800-171A crosswalk.

*Note on the v0.1.0 tag: v0.1.0 was a pre-public milestone folded into
the initial v0.2.0 commit of this repository. No standalone v0.1.0 tag
exists in the public git history; the earliest public tag is `v0.2.0`.*
