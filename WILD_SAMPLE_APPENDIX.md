# Appendix: Wild Sample Run
## Hardseal AI Evidence Integrity Report: v0.3.1

**Report date:** April 22, 2026
**Engine version:** v0.3.1 (factual + risk + rebuttal + two-tier FCA gate)
**Runner:** `wild_sample_runner.py` (dual-mode: whole-file + per-control packet)

---

## Why this page exists

The main Falcon Edge Systems demo is a closed loop. Hardseal authored the
contractor, the controls, the impossibilities, and the rules that catch them.
A seasoned DIB CISO will discount that demo in thirty seconds unless the
engine is proven against SSP text Hardseal did not write. This appendix closes
that gap.

The engine was pointed at three SSP excerpts the Hardseal team did not author.
Each excerpt covers NIST 800-171 Rev 2 controls 3.1.1, 3.1.2, 3.1.3, and
3.1.20. The engine was run in two modes: a whole-file analyze_artifact pass
(exercises SentenceStructureAnomaly, MappingDensity, PromptLeakage,
ArtifactSpecificityIndex, FactualPlausibility) and a per-control
analyze_packet pass (adds BoilerplateCluster across narratives).

## Samples

| ID | Provenance | What it tests |
|----|------------|---------------|
| A  | Generic LLM output, prompted "Write an SSP narrative for NIST 800-171 control 3.1.1." No company context. No instructions to be specific. No instructions to hide AI tells. | **Recall.** Does the engine flag text that is pure LLM platitude with zero operational grounding. |
| B  | Human-authored in the style of NIST 800-171 reference narratives and publicly available DoD example SSPs. Named owners (Pena, Kowalski). Specific tools (Entra ID Government, Palo Alto PA-3220). Concrete dates. Gaps acknowledged with POA&M IDs. | **Precision.** Does the engine leave a well-written human SSP alone. |
| C  | Vendor or MSP template pattern. The same paragraph skeleton repeated across four controls with only the heading changed. Common in cookie-cutter compliance deliverables. | **Cross-narrative boilerplate.** Does the engine catch the single failure mode every C3PAO assessor flags on sight. |

## Results

| Sample | Mode A whole-file | Mode B per-control packet | Primary heuristic |
|--------|-------------------|---------------------------|-------------------|
| **A** Generic LLM | CONTAMINATED (0.451) | CONTAMINATED (0.548) | SentenceStructureAnomaly + BoilerplateCluster on 3.1.1, 3.1.2 |
| **B** Human-authored | CLEAN (0.000) | CLEAN (0.000) | No findings |
| **C** Vendor template | CONTAMINATED (0.643) | **LIKELY_SYNTHETIC (1.000)** | BoilerplateCluster fires 1.000 on every control |

The engine produced a clean separation: 0.00 on the human-authored sample,
0.45 to 0.55 on the generic-LLM sample, 0.64 to 1.00 on the vendor template.
Zero false positives on Sample B. Both contamination patterns (flatness and
copy-paste skeleton) were caught on the correct heuristic.

## What this proves

1. The engine discriminates between human-authored and non-human-authored SSP
   text without being fed seeded impossibilities.
2. BoilerplateCluster is the dominant signal for template-pattern
   contamination. Vendor-template Sample C scored Jaccard 1.000 between every
   pair of control narratives.
3. SentenceStructureAnomaly is the dominant signal for LLM-generated prose.
   Sample A was flagged on flatness even when it contained zero "as an AI"
   hard tells.
4. A NIST-style human SSP with named owners, dated reviews, specific tool
   versions, and gap acknowledgments passes the engine cleanly. A buyer who
   writes operationally grounded SSPs should not fear false-positive risk.

## What this does not prove (and the v0.4 backlog it generates)

1. Sample A's PromptLeakage score was 0.000. v0.3 flags only hard LLM tells
   (ChatML tokens, "as an AI language model", vendor name drops). Soft
   stylistic tells ("leverages", "industry-standard", "comprehensive") are
   intentionally out of scope for precision reasons. A v0.4 stylistic-tell
   signature is on the backlog with a low weight.
2. Sample A's ArtifactSpecificityIndex was 0.000 despite the narrative
   containing no tool versions, no named owners, no ticket IDs, and no
   dates. That is a genuine recall gap. A v0.4 revision of the specificity
   index will lower the grounding threshold for text that has zero named
   artifacts at all.
3. Three samples is a demonstration, not a benchmark. A v0.4 benchmark
   corpus (target: 15 to 20 SSP excerpts across clean, consultant-template,
   and LLM-contaminated classes) will yield real precision and recall
   numbers. That benchmark is the next engine deliverable.

## Sample provenance (for auditability)

- Sample A was produced by prompting a general-purpose LLM with a single
  sentence and no further guidance. The prompt and the raw output are on
  file for assessor or buyer inspection.
- Sample B was written from public NIST 800-171 reference patterns and the
  style of publicly available DoD CIO example SSPs. All named people, ticket
  IDs, and tenant references are fictional placeholders used to establish
  specificity. No real Lockheed Martin, Microsoft, or Palo Alto Networks
  artifacts are quoted.
- Sample C was written from the general structure of boilerplate vendor
  compliance templates. It contains no proprietary vendor language and no
  trademarked content.

Full sample text, the runner script, the run command, and the raw JSON
output are available under `samples/wild_samples/` and `wild_sample_report.json`
in the engine repository. Independent reruns should produce identical numeric
scores on the same engine version.

---

*Hardseal AI Evidence Integrity Report is a point-in-time diagnostic. It does
not constitute a CMMC assessment, a legal opinion, or a representation under
the False Claims Act. See `REGULATORY_DISCLAIMER.md` for full terms.*
