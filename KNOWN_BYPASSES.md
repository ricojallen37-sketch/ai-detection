# KNOWN BYPASSES

**Version:** v0.2 (April 22, 2026)
**Status:** Public by design. We break our own engine first so pedants cannot break it for us.

## Why this document exists

Every detection heuristic can be defeated by an adversary who reads the
source, understands the signal, and rewrites the artifact to suppress it.
Hiding the bypass list would not make Hardseal safer. It would only make
the first public demo less defensible.

This document lists every way we know to defeat each of the seven detectors
shipped in v0.2, the cost to an adversary, the signal that survives the
bypass, and the detector that still catches what the bypass leaves behind.

Defense in depth is the point. No single heuristic is a gate. The
aggregate score, the template guard, and the LEAKAGE near-certain signal
stack such that a bypass which beats one detector usually lights another.

## The detectors

| ID | Detector | Weight |
|---|---|---|
| H1 | SentenceStructureAnomaly | 0.05 |
| H2 | BoilerplateCluster | 0.15 |
| H3 | TimestampRegularity | 0.25 |
| H4 | MappingDensity | 0.15 |
| H5 | CitationGraph | 0.15 |
| H6 | PromptLeakage | 0.15 |
| H7 | ArtifactSpecificityIndex | 0.10 |

Weights sum to 1.00. A strong signal ( >= 0.70 ) on H3 or H6 alone can
push the classification into CONTAMINATED before the weighted average
breaks 0.40.

---

## H1: SentenceStructureAnomaly

**What it measures:** Coefficient of variation and Shannon entropy of
sentence length distribution in the narrative.

**Bypass technique:** Prompt the LLM with "vary sentence length like a
human: mix fragments, medium clauses, and long compound sentences."
Alternatively, post-edit the output by hand-splitting long sentences and
merging short ones.

**Adversary cost:** Low. 10 minutes of prompt engineering or hand-editing
per narrative.

**What survives the bypass:**
- H2 (BoilerplateCluster) still fires if the mechanism-level narrative is
  reused across controls.
- H4 (MappingDensity) still fires if the narrative cites control IDs
  without naming a tool.
- H6 (PromptLeakage) still fires if any residue phrase survives the
  rewrite.
- H7 (ArtifactSpecificityIndex) still fires if no grounding tokens were
  added.

**Why we keep it:** H1 is weighted 0.05 because we already know it is
weak. It is a corroborating signal, not a gate. If H1 fires alongside H4
and H7, the aggregate reads CONTAMINATED even though H1 alone would not.

---

## H2: BoilerplateCluster

**What it measures:** k-shingle Jaccard similarity between every pair of
control narratives. Flags narratives that share a generative spine
across unrelated controls.

**Bypass technique:** Run the packet through a second LLM pass with the
prompt "rewrite each section in a distinct voice and swap sentence
structures so they do not share phrasing."

**Adversary cost:** Moderate. Roughly $2 of API calls per packet plus
review time. The rewrite often introduces factual drift that the
contractor must catch.

**What survives the bypass:**
- H4 (MappingDensity) and H7 (ArtifactSpecificityIndex) do not care about
  cross-control similarity. A narrative that names "Okta" and "BitLocker"
  passes H2 and H7. A narrative that names neither still fails H4 and H7
  even after the rewrite.
- H5 (CitationGraph) still fires if the narrative is orphaned from
  policy, procedure, and log artifacts.
- TemplateGuard cannot be weaponized here. User-supplied templates are
  subtracted before Jaccard, but LEAKAGE phrases are explicitly
  whitelisted out of the guard. A template that embeds "As an AI
  language model" is not a template. It is a ticket.

**Why we keep it:** H2 catches the MSP industrialization pattern where
one consultant generates SSPs for 20 clients from a single shell. That
pattern rarely survives a rewrite budget.

---

## H3: TimestampRegularity

**What it measures:** Variance-to-mean ratio of inter-arrival times and
the rate of round-second rounding in audit log exports.

**Bypass technique:** Jitter synthetic timestamps with a Poisson-ish
delta. Add microsecond-precision noise. Match the rounding distribution
of a real SIEM export.

**Adversary cost:** Moderate to high. Requires the adversary to
understand what a real audit log looks like. Most LLM-generated logs do
not. A careful bypass requires a reference dataset and a post-processor.

**What survives the bypass:**
- H5 (CitationGraph) still fires if the log is not cited by any SSP
  narrative or procedure.
- The assessor question is unchanged: "Show me the raw SIEM query that
  produced this export." A log that passes H3 still has to survive the
  provenance question.
- Hardseal's Readiness Pack workflow requires the contractor to link the
  log to the SIEM instance, the query, and the time window. A bypassed
  log fails at the evidence-chain step even if it passes the detector.

**Why we keep it:** H3 is weighted 0.25, the highest weight in the
engine, because a single strong fire on H3 is near-certain proof of
synthetic audit evidence. The bypass raises the adversary's cost but
does not remove the assessor's question.

---

## H4: MappingDensity

**What it measures:** Ratio of control ID mentions to mechanism or tool
or configuration tokens.

**Bypass technique:** Prompt the LLM with a list of real tools the
contractor uses ("Okta, BitLocker, Duo, TLS 1.3, Splunk") and instruct
it to name them specifically in each narrative.

**Adversary cost:** Low. 5 minutes of prompt engineering.

**What survives the bypass:**
- H7 (ArtifactSpecificityIndex) requires grounding tokens: versions,
  hashes, IPs, paths, ticket IDs, dates, filenames. Naming "Okta" without
  also writing "Okta Workforce Identity tenant okta-prod-7f2a, policy ID
  POL-00471, last rotated 2026-03-12" does not satisfy H7.
- H2 (BoilerplateCluster) still fires if the tool list was pasted into
  every control.
- The assessor question is unchanged: "What specific tool implements
  this? Show me its configuration."

**Why we keep it:** H4 catches the lazy LLM output that cites NIST IDs
without naming a mechanism. A contractor who cannot bypass H4 with a
five-line prompt addition has bigger problems than detection.

---

## H5: CitationGraph

**What it measures:** Max citation graph depth, orphan rate, cycle
presence across SSP, policy, procedure, and log artifacts.

**Bypass technique:** Generate the full packet in one LLM session and
instruct the model to cross-reference every artifact. Add a procedure
that cites the policy, a log excerpt that cites the procedure, and a
narrative that cites the log.

**Adversary cost:** High. The adversary must construct a coherent graph
across multiple artifact types. Most LLM sessions drift by artifact
three and produce orphan nodes or cycles.

**What survives the bypass:**
- H6 (PromptLeakage) does not care about the graph. A single "As an AI
  language model" in any artifact in the graph fires H6.
- H7 (ArtifactSpecificityIndex) applies per artifact. Citing a log that
  has no grounding tokens does not make the log real.
- The assessor question is unchanged: "Trace this claim from SSP to raw
  evidence. Show every hop."

**Why we keep it:** H5 catches the pattern where a contractor submits a
thick-looking packet that turns out to be five unrelated LLM outputs
stapled together.

---

## H6: PromptLeakage

**What it measures:** Regex hits against a curated list of LLM residue
phrases: "As an AI language model," "Certainly! Here is," "[INSERT
COMPANY NAME HERE]," stray ChatML tokens, markdown code fences in prose,
common refusal preambles.

**Bypass technique:** Proof-read the output before paste. Run a find-and-
replace against the published residue list. Use an LLM that has been
fine-tuned to suppress residue.

**Adversary cost:** Low if the adversary reads the residue list. Near-
zero if the adversary simply proof-reads.

**What survives the bypass:**
- Every other detector is untouched by this bypass. H6 was never
  structural. It is a trip-wire for the un-edited paste.
- The value of H6 is not the sophisticated adversary it stops. It is the
  unsophisticated adversary it catches in under a second. On our
  internal test corpus, H6 fires on 18% of LLM-authored packets
  submitted by well-meaning DIB contractors. Those 18% represent pure
  operator error: someone pasted without reading.

**Why we keep it:** H6 is the fastest, highest-precision signal in the
engine. It is also the first signal a C3PAO will find if the contractor
leaves it in. We fire it loudly so the contractor sees it before the
assessor does.

---

## H7: ArtifactSpecificityIndex

**What it measures:** Ratio of grounding tokens (versions, hashes, IPs,
paths, ticket IDs, dates, filenames) to named mechanisms. LLMs name.
They do not ground.

**Bypass technique:** Prompt the LLM with real grounding tokens from the
contractor's environment. "Include Okta tenant okta-prod-7f2a, policy
POL-00471, last rotated 2026-03-12, ticket JIRA-4421, hash
sha256:a1b2..."

**Adversary cost:** High. Requires the adversary to have the real
grounding tokens. At that point the adversary is either the contractor
(and should just write it themselves) or a state-level actor with
access to the contractor's systems (which is a different problem).

**What survives the bypass:**
- H2 (BoilerplateCluster) still fires if the grounding tokens were
  generated in bulk and reused across controls.
- H5 (CitationGraph) still fires if the grounding tokens are orphaned
  and not cited by any other artifact.
- The assessor question is unchanged: "Show me the Okta configuration
  that implements POL-00471."

**Why we keep it:** H7 is the structural cousin of H4. Naming a tool is
necessary but not sufficient. Grounding it is what separates the
contractor who implemented the control from the LLM that named one.

---

## The bypass matrix

| Bypass beats | H1 | H2 | H3 | H4 | H5 | H6 | H7 | Remaining gate |
|---|---|---|---|---|---|---|---|---|
| Prompt for sentence variation | X | | | | | | | H2, H4, H6, H7 |
| Second-pass rewrite | | X | | | | | | H4, H5, H6, H7 |
| Poisson timestamp jitter | | | X | | | | | H5 + provenance question |
| Tool-name prompt addition | | | | X | | | | H7, H2, assessor question |
| Coherent cross-artifact graph | | | | | X | | | H6, H7, per-artifact checks |
| Residue proof-read | | | | | | X | | Everything else |
| Grounding token injection | | | | | | | X | H2, H5, assessor question |

No single bypass clears the board. The aggregate score is resilient
because the heuristics are structurally different: rhythm, similarity,
distribution, density, graph, regex, grounding.

The adversary who beats all seven detectors has written a compliance
packet as specific, cross-referenced, bursty, tool-named, graph-connected,
residue-free, and grounded as a packet authored by the contractor. At
that point the adversary has not faked compliance. They have performed
it.

## What Hardseal does with a cleared packet

A packet that clears all seven detectors is not "safe for CMMC L2." It
is "free of the signals these seven heuristics detect." The Readiness
Pack workflow still asks the assessor questions listed above for each
control. A cleared packet is the floor, not the ceiling.

## Contractor self-iteration (calibration misuse)

The open-source release creates a foreseeable misuse path: a contractor
runs AI-generated narratives through the engine, tweaks the prompt or
scrubs residue until the aggregate score trips below `CONTAMINATED`,
then submits the cleared packet as authentic evidence.

We acknowledge this failure mode explicitly and do not treat it as a
bug. The defenses against it are structural, not algorithmic:

1. A `CLEAN` verdict is not an attestation of authenticity. See
   `REGULATORY_DISCLAIMER.md`: the tool produces heuristic signals, not
   assessor judgments. A contractor who represents a `CLEAN` verdict to
   a C3PAO as proof of authenticity is misrepresenting the tool.
2. The seven detectors stack such that clearing them all requires the
   adversary to produce specific, grounded, cross-referenced, bursty,
   tool-named, graph-connected, residue-free narrative. At that cost,
   the adversary has performed compliance rather than faked it.
3. The v0.3.1 `risk_delta.py` two-tier gate is deliberately
   conservative on FCA exposure: a single cleared detector does not
   grant assurance that the claim is true, and a signed SSP plus
   unscheduled POA&M claim remains the escalation path regardless of
   heuristic verdict.
4. The companion paper (*State of AI-Era Defense Compliance Evidence*,
   Section 16) names contractor self-iteration as a first-order
   adversarial pattern and covers the additional detectors in the v0.4
   roadmap (`VersionHallucinationDetector`,
   `CrossArtifactTemporalConsistencyDetector`,
   `MetricPlausibilityDetector`) that raise the calibration cost.

A contractor who uses this engine to iterate against until their LLM
output scores `CLEAN` has not defeated the tool. They have performed a
significant portion of the grounding work the tool measures. That is
the intended outcome.

## Responsible disclosure

If you find a bypass we missed, open an issue or email
rico@hardseal.ai. We will credit the finder in the next release.

We will not accept a bypass report that asks us to remove the
documentation of the bypass. The point of this document is that every
bypass is public.

---

*"The attack surface of AI-era compliance is not the tooling. It is the
evidence."*
Rico Allen, Founder, Hardseal
