# USAGE GUIDE

**Version:** v0.2 (April 22, 2026)
**Audience:** DIB contractors, C3PAO assessors, MSP / GRC consultants, and
security researchers who want to run Hardseal AI-Detection against a
real packet and understand the output.

---

## Install

Requires Python 3.10 or newer. No third-party dependencies. No network
calls. No telemetry.

```
git clone https://github.com/hardseal/ai-detection.git
cd ai-detection
python3 -m unittest test_mismatch_engine_ai.py
```

All 65 tests must pass before you trust an output.

---

## The three workflows

### Workflow 1: DIB contractor self-check

**Who:** A DIB contractor preparing a CMMC Level 2 packet for C3PAO
submission. Wants to know whether their SSP, policy, and procedure
artifacts contain signals that will embarrass them in front of an
assessor.

**Command:**
```
python3 mismatch_engine_ai.py path/to/your/ssp_directory --json > findings.json
```

**Interpretation:**
- **CLEAN:** No signals fired from these seven heuristics. Not a proof
  of compliance. Not a proof of human authorship. A floor, not a
  ceiling.
- **PARTIALLY_CONTAMINATED:** Corroborating signals fired. Review every
  flagged narrative. Fix LEAKAGE hits first.
- **CONTAMINATED:** At least one strong signal or an aggregate above
  0.40. Do not submit this packet. Rewrite the flagged artifacts.
- **LIKELY_SYNTHETIC:** Two or more strong signals or aggregate above
  0.65. The packet will not survive cursory C3PAO review. Do not submit.

**Next step:** For every `LIKELY_SYNTHETIC` or `CONTAMINATED` finding,
open the referenced artifact, read the flagged passage, and rewrite it
by hand. Hardseal does not auto-fix. A fix written by an LLM will often
fire the same detectors.

### Workflow 2: C3PAO shadow audit

**Who:** A C3PAO assessor or Registered Practitioner conducting a
pre-assessment readiness review for a client.

**Command:**
```
python3 mismatch_engine_ai.py /path/to/client/packet \
    --template /path/to/client/MSSP_template.md \
    --template /path/to/client/consultant_SSP_boilerplate.md \
    --json > client_findings.json
```

**Why the `--template` flag matters:** Legitimate heavily-templated
packets (MSSP-generated, GRC-exported, consultant boilerplate) look
rhythmically uniform. Without the template guard, a real packet reads
as synthetic. Pass every template the contractor actually uses. The
engine subtracts template shingles before similarity and flatness
analysis.

**Interpretation rule of thumb:** In a shadow audit, a
`PARTIALLY_CONTAMINATED` on three or more controls is the signal that
the contractor needs a rewrite engagement before the formal assessment.
A `LIKELY_SYNTHETIC` on any control is the signal that the packet is
not ready for the assessor.

### Workflow 3: Consultant or MSP CI hook

**Who:** A GRC consultant or MSP who generates SSPs across multiple
clients and wants to prevent a shared generative spine from firing H2
at the C3PAO.

**Command (pre-commit):**
```
#!/bin/bash
python3 mismatch_engine_ai.py ./clients/$CLIENT/packet --json \
  | python3 -c 'import json,sys; \
                d=json.load(sys.stdin); \
                sys.exit(0 if d["confidence"]=="CLEAN" else 1)'
```

**What this does:** Blocks the commit if the packet would not read as
CLEAN on the seven-heuristic panel. Forces the consultant to address
shared-spine issues before they are shipped to the client.

**Caveat:** A CI gate that blocks on anything except CLEAN will fire
false positives on first-pass drafts. Recommended posture is to block
on `LIKELY_SYNTHETIC` and log `CONTAMINATED` as a warning for the
consultant to resolve in review.

---

## Do / Don't

| Do | Don't |
|---|---|
| Treat CLEAN as "no signals from these seven heuristics" | Treat CLEAN as "safe for CMMC L2" |
| Pass `--template` for every real template the packet inherits from | Pass `--template` to suppress signals on a packet you know is synthetic |
| Fix LEAKAGE hits before anything else | Use an LLM to fix what an LLM wrote |
| Re-run after every rewrite | Assume a single run is a certificate |
| Read the per-finding detail, not just the top-line confidence | Submit a packet that fires H6 (PromptLeakage) on any artifact |
| Share the JSON output with your C3PAO as an artifact | Redact the JSON output to hide findings you have not fixed |
| Use the residue list in KNOWN_BYPASSES.md as a pre-flight checklist | Use the residue list to post-edit residue out of a synthetic packet |

---

## Annotated JSON output

Example from the contaminated sample packet. Comments are inline for
documentation. The engine does not emit comments in production JSON.

```jsonc
{
  "confidence": "LIKELY_SYNTHETIC",
  // One of: CLEAN, PARTIALLY_CONTAMINATED, CONTAMINATED, LIKELY_SYNTHETIC.

  "aggregate_score": 1.0,
  // Weighted average across all firing detectors. Range 0.0 to 1.0.

  "strong_signals": 3,
  // Number of detectors that fired with score >= 0.70. Two or more
  // strong signals force LIKELY_SYNTHETIC regardless of aggregate.

  "findings": [
    {
      "detector": "PromptLeakage",
      // H6. Near-certain signal. A single fire is near-proof of an
      // un-edited LLM paste.

      "score": 1.0,
      // 1.0 means one or more residue phrases matched.

      "strong": true,

      "evidence": [
        {
          "artifact": "3.1.1_access_control.md",
          "line": 4,
          "match": "As an AI language model, I can help draft..."
        }
      ],
      // Each evidence entry points to the exact artifact and line.

      "nist_objective": "3.12.4[a]",
      // NIST 800-171A assessment objective this detector maps to.

      "securityplus_domain": "5.4",
      // CompTIA Security+ SY0-701 domain.

      "assessor_question": "Why does your access control policy contain the phrase 'As an AI language model'?"
      // The question a C3PAO will ask if this is not fixed.
    },
    {
      "detector": "ArtifactSpecificityIndex",
      "score": 0.92,
      "strong": true,
      "evidence": [
        {
          "artifact": "3.13.1_boundary_protection.md",
          "reason": "Zero grounding tokens (no versions, hashes, IPs, paths, tickets, dates, filenames). Four named mechanisms."
        }
      ],
      "nist_objective": "3.12.4[b]",
      "securityplus_domain": "1.3",
      "assessor_question": "Show me the firewall configuration and the ticket that documents the last change."
    },
    {
      "detector": "BoilerplateCluster",
      "score": 0.78,
      "strong": true,
      "evidence": [
        {
          "pair": ["3.1.1_access_control.md", "3.13.1_boundary_protection.md"],
          "jaccard": 0.78,
          "shingle_size": 5
        }
      ],
      "nist_objective": "3.12.4[a]",
      "securityplus_domain": "5.4",
      "assessor_question": "Why does 3.1.1 (access control) read identical to 3.13.1 (boundary protection)? They protect different things."
    }
  ],

  "template_guard": {
    "applied": false,
    "templates_ingested": 0,
    "phrases_whitelisted": 47
    // Count of NIST/CMMC stock phrases stripped before flatness analysis.
    // LEAKAGE phrases are excluded from the whitelist.
  },

  "runtime_ms": 142,

  "engine_version": "0.2",
  "commitment_hash": "32f1e682b0544b1af20077cc33f0604ec76238489182190c8d77a1cb01f42bbf"
  // The combined canonical bundle hash. Use verify_commitment.py to
  // confirm the engine you ran matches the bundle published in v0.2.
}
```

---

## What the engine does not do

- **It does not read your mind about what is real.** CLEAN does not mean
  compliant. CONTAMINATED does not mean fraudulent. The engine detects
  signals. A human makes the call.
- **It does not phone home.** No network calls. Run it inside your CUI
  enclave.
- **It does not claim probabilistic guarantees.** Scores are heuristic.
  The output is "this warrants human review," not "this is 87.3%
  AI-generated."
- **It does not replace an assessor.** A CCP, CCA, or C3PAO makes the
  final call.
- **It does not fix what it finds.** Remediation is the Readiness Pack
  product. The detector is free. The fix is the commercial wedge.

---

## When to call the author

If the engine produces a result you cannot explain, open an issue or
email rico@hardseal.ai with the JSON output and a redacted excerpt of
the triggering artifact. Include the engine version and the commitment
hash. We will respond within three business days.

---

*"The detector is free. The fix isn't."*
