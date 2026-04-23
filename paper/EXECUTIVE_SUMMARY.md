# State of AI-Era Defense Compliance Evidence

## Executive Summary

**A Field Report on Twelve Attack Patterns, Their Detection Signatures,
and the NIST 800-171A Objectives They Intersect.**

**Author:** Rico Allen, Founder, Hardseal
**Ship date:** April 27, 2026
**Status (April 22, 2026):** Pre-release executive summary. Full report
drops on April 27.

---

## Thesis

> The attack surface of AI-era defense compliance is not the tooling.
> It is the evidence.

Every Defense Industrial Base contractor facing CMMC Level 2 assessment
now has on-tap access to tools (ChatGPT, Claude, Gemini, Copilot) that
can produce a plausible-looking System Security Plan, Plan of Action
and Milestones, policy, procedure, and audit-log narrative in under an
hour. Assessors (C3PAOs, Certified CMMC Assessors, Registered
Practitioners) do not have a corresponding tool to detect what those
AI-authored artifacts look like. The Phase 2 enforcement deadline
(November 10, 2026) arrives into a market where the supply of
compliance theater has decoupled from the supply of detection
capability.

This field report closes that gap. It catalogs twelve attack patterns
observed across pre-assessment packets, ships detection signatures for
seven of them (shipped as a stdlib-only Python engine under MIT
license), and documents the remaining five with signatures-only so that
practitioners can build their own detectors.

Every pattern is mapped to the NIST 800-171A assessment objective it
intersects and the CompTIA Security+ SY0-701 domain it teaches to.

---

## The twelve attack patterns

**Detection shipping in v0.2 (seven):**

1. **Sentence structure flatness** (H1). LLM output exhibits a
   coefficient of variation on sentence length roughly half that of
   human-authored text. Weak signal alone, corroborating in aggregate.

2. **Cross-control boilerplate clustering** (H2). The same generative
   shell reused across 50+ unrelated controls produces high k-shingle
   Jaccard similarity. Catches the MSP industrialization pattern.

3. **Synthetic audit log timestamp regularity** (H3). Real event
   streams follow Poisson-ish distributions with microsecond precision.
   Synthetic logs are too regular or too round.

4. **Citation-heavy, mechanism-light narratives** (H4). LLMs over-cite
   control IDs. Real implementers name the tool and its configuration.

5. **Shallow citation graphs** (H5). AI-generated packets have depth 1-2
   citation chains, high orphan rates, and circular citations between
   artifacts.

6. **Prompt leakage** (H6). Residue phrases ("As an AI language model,"
   "Certainly! Here is," "[INSERT COMPANY NAME HERE]") are near-certain
   proof of un-edited LLM paste.

7. **Artifact specificity deficit** (H7). LLMs name mechanisms but do
   not ground them. Grounding tokens (versions, hashes, IPs, paths,
   ticket IDs, dates, filenames) are rare in synthetic artifacts.

**Signature-only documentation (five, in the full report):**

8. **Hallucinated control inheritance** from cloud service providers
   the contractor does not actually use.

9. **Fabricated POA&M closure evidence** where the remediation
   narrative contradicts the original finding.

10. **Synthetic incident response timeline** where the dwell time, root
    cause, and lessons learned read as generic textbook boilerplate.

11. **Inverted scope claims** where the SSP narrows the CUI boundary
    below what the contract requires, to reduce the packet's apparent
    burden.

12. **Template-inheritance drift** where a legitimate template has been
    re-prompted so many times it lost its anchor to the contractor's
    real environment.

---

## Why this matters for the market

No competitor publishes a detector for this class of artifact. Vanta,
Drata, Secureframe, Prevail, and Apptega are selling more AI generation
(auto-drafted SSPs). The generation is the attack surface. Detection is
the defense.

The Phase 2 enforcement deadline will produce a cohort of failed first-
cycle assessments. The public narrative about why they failed is not
yet written. This report writes it.

---

## How to read the full report

The full ~40-page report ships April 27 at
**hardseal.ai/research/state-of-ai-era-compliance-evidence**.

Each of the twelve sections follows the same format:

- **Pattern description:** what the attack looks like.
- **Example:** a redacted artifact exhibiting the pattern.
- **Detection signature:** the rule, regex, or statistical test.
- **NIST 800-171A mapping:** the assessment objective it intersects.
- **Security+ domain:** the training the pattern teaches to.
- **Recommended control:** what a contractor can do to avoid producing
  this pattern.

The report includes the full seven-heuristic engine as shipped in this
repository, reproducible against the `samples/` fixtures, with expected
outputs committed in `examples/`.

---

## What to do until April 27

1. Clone this repository. Run `python3 -m unittest
   test_mismatch_engine_ai.py`. Confirm 65 tests pass.
2. Run the engine against the three sample packets. Confirm the expected
   outputs (CLEAN at 0.16, LIKELY_SYNTHETIC at 1.00, CLEAN at 0.00 with
   template guard).
3. Read `KNOWN_BYPASSES.md` to understand what the engine does and does
   not catch.
4. Run the engine against one of your own real packets. Read the
   `USAGE_GUIDE.md` section on the three workflows.
5. If you find a pattern not listed here, open an issue. We credit
   contributors in the next release.

---

## Commitment

This summary is the committed pre-release. The full report on April 27
will not retract any pattern listed here, will not change any NIST
mapping, and will not weaken any detection signature. It will add
examples, a quantitative section on detection accuracy on an internal
test corpus of 200 packets, and the five signature-only patterns in
full.

The commitment bundle hash for v0.2 of the engine is:

`32f1e682b0544b1af20077cc33f0604ec76238489182190c8d77a1cb01f42bbf`

Verify with `python3 verify_commitment.py`.

---

*"The attack surface of AI-era compliance is not the tooling. It is the
evidence."*
Rico Allen, Founder, Hardseal
