# Anchor Plan: Keeping Hardseal the Named Home of the Standard

**Problem.** The repository is MIT licensed. Anyone can fork it. A
well-funded adjacent vendor (GRC SaaS, AI-security tool, consulting
shop) could take the engine unchanged, wrap it with a dashboard and a
distribution machine, and become the perceived home of CMMC
AI-contamination detection while Hardseal stays the original author in
the git log but loses the mindshare slot.

**Stance.** Welcome wrappers. Anchor the vocabulary, the reference
artifact, and the release cadence so every wrapper has to point back.

This document is a commitment, not a wish list. Each item has a named
owner (Rico Allen, solo founder) and a dated checkpoint.

---

## 1. License and attribution

1. The MIT header in every source file carries the line
   `Copyright 2026 Hardseal LLC. "Hardseal" is a trademark of
   Hardseal LLC.` The MIT license permits commercial reuse of the
   code. It does not permit reuse of the Hardseal name, the Hardseal
   logo, or the claim that a downstream product "is" Hardseal.
2. Any downstream product that uses the engine and wants to advertise
   that fact may apply to the `authorized-implementations` registry
   on `hardseal.ai`. Zero-cost, one-form application. Approved
   implementations may use the "Powered by Hardseal AI-Detection"
   mark. Unapproved implementations may not.

## 2. The paper is the reference

1. *State of AI-Era Defense Compliance Evidence* publishes on
   `hardseal.ai/research/state-of-ai-era-compliance-evidence` with a
   persistent DOI-style URL.
2. The paper is the canonical citation for every attack pattern,
   every detection signature, every NIST 800-171A crosswalk, and the
   failure-mode inventory. The paper is what a C3PAO quotes, not a
   fork's README.
3. Updates to the paper are dated, versioned, and public. Every
   scoring-change release in the code links back to the paper section
   that justifies the change.

## 3. Release cadence through 2026

1. Weekly release cadence through the paper drop. Minor version bump
   for added detectors or tuning changes. Patch bump for bug fixes.
2. Monthly release cadence post-paper through the November 10, 2026
   Phase 2 enforcement deadline.
3. Every release carries a commitment hash. Every scoring-change
   release re-runs `verify_commitment.py` and updates the README
   table.
4. A fork that lags the mainline by three releases is, by the time a
   DIB contractor hears about it, already out of date. Speed is the
   anchor.

## 4. Category vocabulary

1. The terms `SentenceStructureAnomaly`, `BoilerplateCluster`,
   `TimestampRegularity`, `MappingDensity`, `CitationGraph`,
   `PromptLeakage`, `ArtifactSpecificityIndex`, `TemplateGuard`, and
   the four confidence tiers (`CLEAN`, `PARTIALLY_CONTAMINATED`,
   `CONTAMINATED`, `LIKELY_SYNTHETIC`) are the published vocabulary.
   Hardseal uses them in every paper, every outreach, every release
   note.
2. Wrapper products that use different names for the same detectors
   pay a tax in buyer translation cost. The vocabulary anchors
   Hardseal.

## 5. Thirty-day anchor moves (April 23 through May 23, 2026)

1. Push `github.com/hardseal/ai-detection` public on April 23 with the
   MIT license, the v0.2 commitment hash, the full 65-test suite, the
   three hardening docs (`REGULATORY_DISCLAIMER.md`, `SUPPORT.md`, this
   file), and the v0.3.1 FCA Risk Delta plus wild-sample closed-loop
   validation.
2. Tag the public release `v0.3.1` on April 23. Internal tags `v0.2.0`
   and `v0.2.1` are bundled into the initial commit history.
3. Publish the paper on `hardseal.ai` on or before April 27.
4. Write the "why stdlib-only is a security differentiator"
   whitepaper and link it from the README by May 1.
5. File the Hardseal wordmark with the USPTO by May 10. Trademark
   filing strengthens the brand-protection clause in Section 1.
6. Open a "Called by Hardseal AI-Detection" page on `hardseal.ai`
   listing every documented use of the engine by a DIB contractor,
   an MSP, or a C3PAO. Social proof concentrates where the paper
   and the code point, not where a wrapper points.
7. Publish the first field-results note (anonymised packet
   characteristics, verdict distribution, measured false-positive
   rate against the templated-legitimate corpus) by May 15. Future
   fields reports land here, not on anyone else's blog.

## 6. Ninety-day anchor moves (through July 22, 2026)

1. Recruit at least two C3PAO pro-bono shadow-audit partners. A
   C3PAO saying "we ran the Hardseal detector on a client's packet"
   is worth more than any vendor dashboard.
2. Invite three independent security researchers to run the
   test suite, file issues, and publish findings. Named contributors
   appear in the README, the paper, and the release notes.
3. Publish v0.3 with the five remaining detectors from the paper's
   Section 9 through 13 roadmap. Shipped code, not promised code, is
   what wrappers cannot fake.

## 7. What we do not do

1. We do not add runtime dependencies to slow down forks. The
   stdlib-only rule is a product promise, not a competitive weapon.
2. We do not relicense to a restrictive license after the fact. A
   relicensing event is a trust-breaking failure the community will
   not forget.
3. We do not sue wrappers. We out-ship them, out-cite them, and
   out-publish them.

---

*The reference implementation is the one that keeps shipping, keeps
citing its own paper, keeps publishing field data, and keeps the
vocabulary fixed. We are that.*

*Rico Allen, April 22, 2026*
