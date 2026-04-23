# Hardseal AI-Era Evidence Contamination Detector

**Version:** v0.3.1 (April 23, 2026). TemplateGuard + ArtifactSpecificityIndex + two-tier FCA Risk Delta + wild-sample validation.
**Status:** 65 tests passing. CLI working. 7-heuristic engine. Weight rebalance applied.
**License:** [MIT](LICENSE). Public release April 23, 2026.

## Who this is for

- **DIB contractor or compliance lead**: run on your SSP narratives before you hand the packet to a C3PAO. The detector surfaces AI-residue and low-specificity sections that will get challenged in assessment.
- **C3PAO assessor**: run on a client's submitted packet as a pre-assessment screen. CLEAN is a heuristic signal, not an attestation. See `REGULATORY_DISCLAIMER.md`.
- **MSSP or consultant**: use `--template` to subtract your known baseline skeleton so your templated work does not score as contaminated.
- **Security researcher or red-teamer**: `THREAT_MODEL.md`, `KNOWN_BYPASSES.md`, and the commitment hash are the serious reading.

## Reproduce in 30 seconds

Python 3.10 or newer. No dependencies. Engine operates locally with no outbound telemetry or external API calls.

```
git clone https://github.com/hardseal/ai-detection.git
cd ai-detection

# 1. A clean, human-authored packet.
python3 mismatch_engine_ai.py samples/clean_packet
#   expected: CLEAN at aggregate 0.16

# 2. A contaminated, LLM-pasted packet.
python3 mismatch_engine_ai.py samples/contaminated_packet
#   expected: LIKELY_SYNTHETIC at aggregate 1.00

# 3. A legitimate heavily-templated packet, protected by TemplateGuard.
python3 mismatch_engine_ai.py samples/templated_legitimate_packet \
    --template samples/templated_legitimate_packet/_TEMPLATE_SKELETON.md
#   expected: CLEAN at aggregate 0.00
```

Full CLI and JSON output reference: [USAGE_GUIDE.md](USAGE_GUIDE.md).
How to defeat each detector on purpose: [KNOWN_BYPASSES.md](KNOWN_BYPASSES.md).

**DIB contractor who wants a redacted review instead of running this yourself?** Email `rico@hardseal.ai` with subject line `[DIB]`. The first five readiness-pack integrity scans this month are free: three redacted narratives in; one-page memo plus a 15-minute call.

## Evaluation scope

This engine is calibrated on CMMC Level 2 evidence artifacts: SSP narratives, POA&M items, policy excerpts, and paired log artifacts. Running it on general prose, fiction, marketing copy, or source code is out of scope. Out-of-domain verdicts are not evidence for or against the stated use case. Supported input classes and expected score ranges are enumerated in `USAGE_GUIDE.md`.

## Why MIT

The trust layer of defense compliance cannot be closed source. A
C3PAO who cannot read the scoring logic cannot defend it to an
assessor. A contractor who cannot audit the regex bundles cannot run
the detector inside their CUI enclave with confidence. A researcher
who wants to challenge the engine's claims must be able to read them.

This engine is the wedge. It is deliberately free under MIT. The paid
product is the Hardseal Readiness Pack, which remediates what the engine
surfaces.

### What's new in v0.3.1

v0.3.1 adds the two-tier False Claims Act Risk Delta gate and closes the
closed-loop credibility gap with non-Hardseal-authored samples.

1. `risk_delta.py`: two-tier gate that prevents a single factual-plausibility
   finding from escalating to `KNOWING_FALSITY_RISK` under 31 USC 3729(b)
   absent three contextual conditions: signed SSP, claim referenced in POA&M,
   and no scheduled remediation date. Default posture is `DISCLOSURE_RISK`.
   This posture survives general counsel review and avoids over-claiming FCA
   liability on a single detector signal.
2. `wild_sample_runner.py`: dual-mode runner (whole-file `analyze_artifact`
   plus per-control `analyze_packet`) for SSP excerpts Hardseal did not author.
   Three wild samples shipped in `samples/wild_samples/` cover a generic LLM
   output, a human-authored NIST-style narrative, and a vendor-template
   boilerplate case.
3. `WILD_SAMPLE_APPENDIX.md`: a one-page buyer-facing appendix rendering the
   dual-mode results for attachment alongside the Falcon Edge v2 integrity
   report.
4. `test_risk_delta.py`: 17 dedicated unit tests covering the two-tier gate
   across every pass/fail path.

### What v0.2 shipped

v0.2 shipped `template_guard.py`, a stdlib-only module that hardcodes a
whitelist of NIST/CMMC stock phrases and lets a contractor pre-ingest their
actual MSSP or consultant template file so its shingles are subtracted
before Jaccard similarity is computed. LEAKAGE signatures are explicitly
excluded from the whitelist so the guard cannot become an AI-residue bypass.

v0.2 also added `ArtifactSpecificityIndexDetector` (ratio of grounding tokens
to named mechanisms), a weight rebalance (PromptLeakage 0.25 to 0.15,
TimestampRegularity 0.20 to 0.25, ArtifactSpecificityIndex new at 0.20), and
the SHA-256 commitment hash publication described in the next section.

Full release history is in `CHANGELOG.md`.

---

## Commitment Hashes (v0.2)

The scoring logic that controls every verdict in this release is frozen and
published. The four bundles below (the detector weight vector, the two regex
bundles, and the mechanism vocabulary) are the only inputs that change
scoring without a code change. Their canonical SHA-256 hashes as of April
21, 2026 are:

| Bundle | Items | SHA-256 |
|---|---|---|
| `weights` (DEFAULT_WEIGHTS) | 7 | `986bd08a3cb62bc93efd4000b97f8a8d6e28a5eae2cfe360cf1242d191fb4d57` |
| `leakage_signatures` | 17 | `c122f753626414c961b7449c6aaa4573c6754af3ad96381d20aa498361a6ba7b` |
| `grounding_patterns` | 16 | `2dbcf4153bf4b54f8e593af36e97d7f5035676367cfe7c7d41d63f0a04bd9c40` |
| `mechanism_tokens` | 56 | `bd2dfa4a309c34a4fdb75207f56c896c574705adaa046e06da9d70ba6df27185` |
| **Combined bundle** | 96 | `32f1e682b0544b1af20077cc33f0604ec76238489182190c8d77a1cb01f42bbf` |

**Canonical encoding:** `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")`.

**Reproduce:**

```
python3 verify_commitment.py
```

Any hash that differs from the values above means the scoring logic has
been modified since this publication. The published canonical bundle is
also checked into the repository at `bundle_v0.2.canonical.json` for
byte-for-byte comparison.

This is a one-way commitment: we can add heuristics and publish a v0.3
bundle with its own hashes, but we cannot silently retune the scoring on
v0.2. Assessors, contractors, and forks get a durable anchor for what the
engine computes today.

---

## Why this exists

CMMC Level 2 first-cycle assessments are failing at alarming rates, and a
rising share of the failures trace to one root cause: contractors pasting
CUI or compliance questions into consumer LLMs (ChatGPT, Claude, Gemini,
Copilot) and shipping the output as SSP narratives, policy documents, audit
logs, and risk assessments. C3PAO assessors are starting to catch it. No
compliance platform detects it *before* submission.

This module is the first open-source detection engine purpose-built for
CMMC Level 2 evidence packets.

It is Hardseal's wedge into the trust layer of AI-era defense compliance.

---

## What it does

Seven stdlib-only detection heuristics, orchestrated into a single
`Confidence` verdict per artifact or packet:

| # | Heuristic | Signal |
|---|---|---|
| 1 | SentenceStructureAnomaly | Coefficient of variation + Shannon entropy of sentence lengths |
| 2 | BoilerplateCluster | k-shingle Jaccard similarity across control narratives |
| 3 | TimestampRegularity | VMR of log inter-arrival times + round-second rounding rate |
| 4 | MappingDensity | Ratio of control-ID mentions to mechanism/tool tokens |
| 5 | CitationGraph | Max depth, orphan rate, cycle count across evidence artifacts |
| 6 | PromptLeakage | Regex hits against a curated list of LLM-residue phrases |
| 7 | ArtifactSpecificityIndex | Ratio of grounding tokens (versions, hashes, IPs, paths, ticket IDs, emails, dates, filenames) to named mechanisms. LLMs name; they do not ground. |

**v0.2 weight rebalance** (per war-panel rationale): PromptLeakage 0.25 to 0.15 (easy to scrub), TimestampRegularity 0.20 to 0.25 (structural signal is harder to fake), ArtifactSpecificityIndex new at 0.20.

See `THREAT_MODEL.md` for per-heuristic attack mapping, NIST 800-171A
objective coverage, Security+ domain alignment, and the assessor question
each heuristic answers.

---

## Files in this folder

| File | Purpose |
|---|---|
| `LICENSE` | MIT license text |
| `README.md` | This file |
| `SECURITY.md` | Vulnerability disclosure policy |
| `CONTRIBUTING.md` | Contribution guide. Stdlib-only is non-negotiable. |
| `CHANGELOG.md` | Versioned change log |
| `THREAT_MODEL.md` | Full threat model, kill chain, heuristic design rationale, honest limits, roadmap |
| `mismatch_engine_ai.py` | Main engine. Stdlib-only. 7 heuristics + TemplateGuard wiring. |
| `template_guard.py` | v0.2 Template False-Positive Guard. NIST/CMMC stock-phrase whitelist + user-template shingle ingestion. |
| `verify_commitment.py` | Reproduces the commitment hashes from the live module state |
| `bundle_v0.2.canonical.json` | Canonical bundle artifact, byte-for-byte hashable |
| `bundle_v0.2.json` | Human-readable bundle artifact |
| `risk_delta.py` | v0.3.1 two-tier FCA Risk Delta gate. Prevents single-detector escalation to `KNOWING_FALSITY_RISK` absent signed-SSP and POA&M context. |
| `factual_check.py` | Factual plausibility detector feeding `risk_delta.py`. |
| `rebuttal_generator.py` | Assessor-response generator that turns detector findings into answerable paragraphs. |
| `wild_sample_runner.py` | v0.3.1 dual-mode runner for SSP excerpts Hardseal did not author. Whole-file + per-control analysis. |
| `build_wild_sample_appendix.py` | Renders `WILD_SAMPLE_APPENDIX.md` from `wild_sample_report.json`. |
| `WILD_SAMPLE_APPENDIX.md` | One-page buyer-facing appendix for the Falcon Edge v2 integrity report. |
| `test_mismatch_engine_ai.py` | 26 unit tests covering v0.1 heuristics and orchestrator |
| `test_template_guard.py` | 22 unit + integration tests covering v0.2 TemplateGuard contract |
| `test_risk_delta.py` | 17 unit tests covering the v0.3.1 two-tier FCA gate |
| `.github/workflows/ci.yml` | GitHub Actions CI (tests + commitment hash + CLI demos on Python 3.10 / 3.11 / 3.12) |
| `samples/clean_packet/` | 3 hand-authored SSP narratives (3.1.1, 3.13.1, 3.3.1) with mechanism specifics |
| `samples/contaminated_packet/` | 3 parallel narratives deliberately built from LLM output |
| `samples/templated_legitimate_packet/` | **v0.2 regression sample.** 3 controls sharing a consultant skeleton + the skeleton itself (`_TEMPLATE_SKELETON.md`). Pass via `--template` to clear. |
| `samples/wild_samples/` | **v0.3.1 closed-loop corpus.** Three SSP excerpts not authored by Hardseal: A (generic LLM), B (human-authored NIST), C (vendor-template boilerplate). |
| `docs/internal/` | Outbound templates and versioned red-team prompts used during development. |
| `paper/STATE-OF-AI-ERA-COMPLIANCE-EVIDENCE.md` | Companion technical paper: *State of AI-Era Defense Compliance Evidence* |
| `paper/outreach/` | Draft outreach to C3PAOs and MSP integrators |

---

## Usage

### Run the tests

```
python3 -m unittest test_mismatch_engine_ai test_template_guard test_risk_delta -v
```

Expected output: **65 tests pass** on Python 3.10, 3.11, and 3.12.

### CLI on a single artifact

```
python3 mismatch_engine_ai.py path/to/ssp_narrative.md
```

### CLI on a full packet

```
python3 mismatch_engine_ai.py path/to/evidence_dir/ --json
```

### CLI on a full packet with TemplateGuard (v0.2)

```
python3 mismatch_engine_ai.py path/to/evidence_dir/ \
    --template path/to/mssp_skeleton.md \
    --template path/to/consultant_skeleton.md
```

The NIST/CMMC stock-phrase whitelist is always active. `--template` is
additive: pass the contractor's (or MSSP's) actual baseline skeleton and
its shingles are subtracted before Jaccard similarity is computed. Files
passed via `--template` are automatically excluded from the narrative set.

### Library

```python
from mismatch_engine_ai import AIProvenanceDetector

detector = AIProvenanceDetector()
report = detector.analyze_packet(
    narratives={"3.1.1": "...", "3.13.1": "..."},
    citation_edges=[("ssp", "policy"), ("policy", "log_query")],
    timestamps_by_artifact={"audit.log": [datetime1, datetime2, ...]},
)
print(report.confidence.value)   # "CLEAN" | "PARTIALLY_CONTAMINATED" | "CONTAMINATED" | "LIKELY_SYNTHETIC"
print(report.aggregate_score)    # 0.0 .. 1.0
print(report.to_json())
```

---

## v0.1 demo output

Clean packet (human-authored narratives naming Okta, YubiKey, Splunk, TLS 1.3, Palo Alto, etc.):

```
Confidence:       CLEAN
Aggregate Score:  0.13
```

Contaminated packet (visible LLM residue + citation-only narratives):

```
Confidence:       LIKELY_SYNTHETIC
Aggregate Score:  1.0
Findings: 3x PromptLeakage score 1.0 (CRITICAL),
          3x MappingDensity score 1.0,
          "As an AI language model" / "Certainly! Here" / "[INSERT X HERE]" caught
```

The delta between the two packets is exactly what Hardseal sells to a DIB contractor before their C3PAO assessment.

---

## v0.2 demo: the false-positive fix

The war-panel found one embarrassing v0.1 failure mode: a legitimate
consultant-built SSP with a dominant template skeleton reused across
controls. v0.2's `TemplateGuard` fixes it. From the integration test
`test_templated_legitimate_packet_is_clean_with_guard`:

```
Four-control legitimate packet (consultant skeleton + grounded tails)

  BARE v0.1:    CONTAMINATED   aggregate 0.518
                BoilerplateCluster score 0.76 on every control
                Max Jaccard 0.779 (false positive)

  GUARDED v0.2: CLEAN          aggregate 0.000
                All heuristics below 0.50
```

Crucially, the guard does not become a bypass. The
`test_guard_does_not_suppress_real_ai_contamination` test confirms that
even if an adversary ingests an AI-residue-poisoned text as a "template",
`PromptLeakage` still fires because LEAKAGE_SIGNATURES are explicitly
excluded from the whitelist.

---

## Sacred rules honored

1. **Zero external dependencies.** `import` statements: `argparse`, `json`, `math`, `re`, `statistics`, `sys`, `collections`, `dataclasses`, `datetime`, `enum`, `pathlib`, `typing`, `hashlib`. All stdlib. A C3PAO can audit the supply chain in an afternoon.
2. **Deterministic.** Same input produces the same score and the same classification. Auditor-replayable.
3. **No network calls.** Safe to run inside a CUI enclave with no internet access.
4. **No telemetry.** No data leaves the machine.
5. **Every score is explained.** Each `Finding` includes human-readable evidence and a concrete recommendation.

---

## Where this sits in the Hardseal mission

| Mission artifact | Status |
|---|---|
| `mismatch_engine_ai.py` v0.1 (Code) | SHIPPED April 21, 2026 |
| War panel red-team of v0.1 (four-panel, unanimous template-FP finding) | SHIPPED April 21, 2026 |
| `template_guard.py` v0.2 (P0 blocker per war panel) | SHIPPED April 21, 2026 |
| v0.2 ArtifactSpecificityIndex + weight rebalance + SHA-256 bundle commitment | SHIPPED April 21, 2026 |
| v0.2.1 hardening docs (REGULATORY_DISCLAIMER, SUPPORT, ANCHOR_PLAN) | SHIPPED April 22, 2026 |
| v0.3.1 two-tier FCA Risk Delta + wild-sample closed-loop validation | SHIPPED April 23, 2026 |
| MIT public release on GitHub | SHIPPED April 23, 2026 |
| Field Report: *State of AI-Era Defense Compliance Evidence* (Paper) | TARGET April 27, 2026 |
| v0.4 shipping the five remaining detectors published in the paper | TARGET end of May 2026 |
| Conference Demo: *AI-Era Attacks on CMMC Evidence* (Stage) | TARGET Q1 2027 |

Code, Paper, Stage. Own the trust layer of AI-era defense compliance.

---

*"The attack surface of AI-era compliance is not the tooling. It is the evidence."*
Rico Allen, Founder, Hardseal
