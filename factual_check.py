"""
factual_check.py - Content-Level Factual Plausibility Heuristic
================================================================
v0.3 addition to AIProvenanceDetector.

Catches content-level factual hallucinations that the fingerprint-based
heuristics (sentence flatness, boilerplate, timestamp regularity, mapping
density, citation graph, prompt leakage, artifact specificity) cannot
catch by design.

Why this exists
---------------
The April 2026 war-panel pressure test surfaced one unanimous gap:
the engine scored a Falcon Edge SSP narrative as CLEAN despite an
Azure-AD-on-AWS-GovCloud factual hallucination that a C3PAO would
shred on first review. The fingerprint heuristics catch *how* the
text was generated. This heuristic catches *what* the text claims.

Approach
--------
1. INCOMPATIBILITY ALLOWLIST: a curated, conservative list of pairs
   that are operationally impossible or near-impossible in a real
   CMMC Level 2 enclave. Conservative on purpose: every entry has a
   public vendor-doc citation. False positives here cost the contractor
   trust, so we only flag pairs we can defend at a C3PAO assessment.

2. SCORE: 1.0 per match, capped at 1.0 for the heuristic. We do not
   stack multiple impossibilities to >1.0 because one impossibility
   already invalidates the artifact.

3. RECOMMENDATION: name the impossibility, cite the vendor reason,
   tell the contractor what to verify.

Sacred rule: stdlib-only. Every entry in the allowlist is a static
string pattern. No NLP. No external knowledge base. Audit-ready in
an afternoon.

Maps to NIST 800-171A objective 3.12.4[a]: "the system security plan
is developed... and accurately describes... how the requirements are
implemented." A factual error is not "accurate description."

License: Proprietary - Hardseal LLC.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

# Import v1.0-compatible Finding from the engine compat layer.
from mismatch_engine_ai import LegacyFinding as Finding


# ---------------------------------------------------------------------------
# Incompatibility allowlist
# ---------------------------------------------------------------------------
# Format: (left_pattern, right_pattern, label, why, verify_step)
#   - left_pattern and right_pattern are case-insensitive regex strings.
#   - A match requires BOTH patterns appearing in the same artifact, within
#     the same paragraph (separated by <2 newlines) for context coupling.
#   - Each entry must be defensible at a C3PAO assessment. Add an entry
#     only when the technical impossibility has a public vendor doc.
# ---------------------------------------------------------------------------

INCOMPATIBILITIES = [
    # Identity provider boundary errors -- the Falcon Edge demo case.
    (
        r"\bazure ad\b|\bentra id\b|\bazure active directory\b",
        r"\baws gov(\s|-)?cloud\b",
        "Azure AD / Entra ID enforcing policy on AWS GovCloud workloads",
        "Azure AD Conditional Access enforces policy on Microsoft-resource "
        "sign-ins (M365, Azure, registered apps via SAML/OIDC). It does not "
        "natively enforce policy on AWS GovCloud compute, S3, or VPC "
        "resources. Cross-cloud requires AWS IAM Identity Center federation, "
        "AWS-side conditional access, or a third-party CASB.",
        "Verify the actual identity broker for AWS GovCloud workloads. If "
        "AWS IAM Identity Center is in use, document the trust relationship. "
        "If a CASB sits in front, document the CASB. Do not claim Azure AD "
        "Conditional Access alone is enforcing AWS-side access.",
    ),
    # FedRAMP boundary confusion.
    (
        r"\bm365\b|\bmicrosoft 365\b|\boffice 365\b",
        r"\bcommercial\b.{0,40}\bcui\b|\bcui\b.{0,40}\bcommercial\b",
        "Commercial M365 tenant claimed to store CUI",
        "Microsoft 365 Commercial is not authorized for CUI under DFARS "
        "252.204-7012 / NIST 800-171. CUI in Microsoft Cloud requires "
        "GCC High (FedRAMP High + DoD IL5 path) or GCC + compensating "
        "controls per the DoD Cloud Acceptable Use Policy.",
        "Verify the tenant SKU. Pull the tenant ID from the M365 admin "
        "center and confirm Commercial / GCC / GCC High. Document the "
        "FedRAMP authorization level and DoD provisional authorization "
        "if any.",
    ),
    # Encryption boundary errors.
    (
        r"\bbitlocker\b",
        r"\bfips 140-?2 (validated|compliant)\b.{0,80}\bdefault\b|\bdefault\b.{0,80}\bfips 140-?2\b",
        "BitLocker claimed FIPS 140-2 validated by default",
        "BitLocker requires explicit Group Policy configuration "
        "('System cryptography: Use FIPS compliant algorithms') to operate "
        "in FIPS-validated mode. The default install is not FIPS-validated. "
        "Microsoft documents the GPO requirement at admin.microsoft.com.",
        "Pull the GPO export and confirm the FIPS algorithms policy is "
        "Enabled. Capture a screenshot of the BitLocker recovery key "
        "metadata showing AES-256 / XTS-AES.",
    ),
    # Logging boundary errors.
    (
        r"\bsplunk (free|cloud trial)\b",
        r"\baudit log retention\b|\b3\.3\.1\b|\b3\.3\.6\b|\b3\.3\.8\b",
        "Splunk Free or Cloud Trial used for CMMC audit log retention",
        "Splunk Free is capped at 500MB/day ingest with no retention "
        "guarantees and no role-based access; Splunk Cloud Trial is "
        "non-production. Neither satisfies the storage capacity, "
        "retention, or RBAC requirements implicit in 3.3.1 / 3.3.6 / "
        "3.3.8.",
        "Verify the Splunk license file (splunk show license) and "
        "confirm Enterprise tier with sufficient ingest and retention "
        "for the documented log volume.",
    ),
    # Backup / continuity confusion.
    (
        r"\bonedrive\b|\bsharepoint\b",
        r"\bcui backup\b|\bcui retention\b|\bbackup of cui\b",
        "OneDrive or SharePoint cited as the CUI backup mechanism",
        "OneDrive / SharePoint provide versioning, not backup. The "
        "Microsoft-published Shared Responsibility Model is explicit: "
        "Microsoft retains data per service tier, customer is responsible "
        "for backup, restore, and long-term retention of CUI.",
        "Identify the actual backup product (Veeam, Commvault, Druva, "
        "AWS Backup, etc.) and document RPO/RTO. SharePoint version "
        "history alone is not 3.8.9 evidence.",
    ),
    # Patch management impossibilities.
    (
        r"\bwindows update for business\b",
        r"\bcui (workstation|server|endpoint)\b.{0,60}\b(real-?time|same-?day|hourly)\b",
        "WUfB claimed to deliver same-day or real-time patching on CUI endpoints",
        "Windows Update for Business uses deferral rings (typically 2-30 "
        "days) and depends on the device's network connectivity and "
        "scheduled scan window. Real-time or same-day patching across a "
        "CUI fleet requires a managed product (Intune, SCCM, WSUS, or a "
        "third-party RMM) with a documented SLA.",
        "Pull the WUfB ring configuration from Intune and document the "
        "actual deferral periods. Map the realistic patch latency against "
        "3.14.1 evidence expectations.",
    ),
    # MFA boundary errors.
    (
        r"\bsms\b|\btext message\b|\bemail otp\b",
        r"\bmfa for (privileged|admin|cui)\b|\b3\.5\.3\b",
        "SMS or email OTP cited as MFA for privileged or CUI access",
        "NIST SP 800-63B retired SMS OTP for AAL2 in 2017, and CMMC "
        "Level 2 traces back to 800-63B for authenticator strength. "
        "Email OTP has never been an authorized AAL2 factor. CMMC "
        "assessors look for FIDO2, smart card / PIV, or TOTP via a "
        "validated authenticator app at minimum.",
        "Document the actual MFA factors in use. If SMS is still active "
        "anywhere on a privileged or CUI access path, treat it as a P1 "
        "POA&M item and plan a YubiKey or smart-card cutover.",
    ),
    # Network segmentation confusion.
    (
        r"\bvlan\b",
        r"\b(boundary|enclave) protection\b|\b3\.13\.1\b|\b3\.13\.5\b",
        "VLAN cited alone as boundary protection for the CUI enclave",
        "VLANs provide L2 segmentation, not boundary protection. NIST "
        "800-171 / NIST SP 800-41 require stateful inspection at the "
        "boundary (firewall, NGFW, or equivalent). A VLAN is a "
        "complement to, not a substitute for, the boundary control.",
        "Identify the firewall enforcing inspection between the CUI "
        "VLAN and other zones. Pull the rule set, confirm default-deny, "
        "and document the inspection vendor and version.",
    ),
]


# Pre-compile for hot path.
_COMPILED = [
    (re.compile(left, re.IGNORECASE), re.compile(right, re.IGNORECASE),
     label, why, verify)
    for (left, right, label, why, verify) in INCOMPATIBILITIES
]


# ---------------------------------------------------------------------------
# Heuristic
# ---------------------------------------------------------------------------

@dataclass
class FactualMatch:
    label: str
    why: str
    verify: str
    left_excerpt: str
    right_excerpt: str

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "why": self.why,
            "verify": self.verify,
            "left_excerpt": self.left_excerpt,
            "right_excerpt": self.right_excerpt,
        }


class FactualPlausibilityDetector:
    """
    Detects operationally impossible tech-stack claims in CUI evidence
    narratives. Curated allowlist; conservative by design.

    A "match" requires both sides of an incompatibility to appear in
    the SAME artifact AND within the same paragraph window (no blank
    line gap > 1) so we do not false-positive on a glossary.
    """

    NAME = "FactualPlausibility"
    NIST = ("3.12.4[a]", "3.12.1[a]")

    # Paragraphs are separated by 2+ consecutive newlines.
    _PARA_SPLIT = re.compile(r"\n\s*\n")

    def detect(self, artifact_id: str, text: str) -> Finding:
        matches: list[FactualMatch] = []
        paragraphs = self._PARA_SPLIT.split(text)

        for para in paragraphs:
            for left_re, right_re, label, why, verify in _COMPILED:
                left = left_re.search(para)
                right = right_re.search(para)
                if left and right:
                    matches.append(
                        FactualMatch(
                            label=label,
                            why=why,
                            verify=verify,
                            left_excerpt=left.group(0)[:80],
                            right_excerpt=right.group(0)[:80],
                        )
                    )

        # One impossibility is enough to invalidate; we do not over-stack.
        score = 1.0 if matches else 0.0

        if matches:
            evidence = (
                f"{len(matches)} factual impossibility(ies) detected. "
                f"First: {matches[0].label!r}."
            )
            rec = (
                f"REJECT artifact and require correction. {matches[0].why} "
                f"Verification: {matches[0].verify}"
            )
        else:
            evidence = "No tech-stack impossibilities detected against curated allowlist."
            rec = "Factual plausibility within expected range."

        finding = Finding(self.NAME, artifact_id, score, evidence, self.NIST, rec)
        # Attach structured matches so the report builder can render them.
        # Findings are dataclasses; we add an attribute that to_dict will
        # carry through via asdict() because asdict only walks declared
        # fields. So we stash on a side channel instead.
        finding.factual_matches = [m.to_dict() for m in matches]  # type: ignore[attr-defined]
        return finding


# ---------------------------------------------------------------------------
# Convenience: standalone analyzer for a packet
# ---------------------------------------------------------------------------

def analyze_packet(narratives: dict) -> dict:
    """
    Run the factual heuristic across a packet of artifacts.
    Returns {artifact_id: list_of_match_dicts} for every artifact with
    at least one match.
    """
    detector = FactualPlausibilityDetector()
    out: dict = {}
    for aid, text in narratives.items():
        f = detector.detect(aid, text)
        matches = getattr(f, "factual_matches", [])
        if matches:
            out[aid] = matches
    return out


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    sample = (
        "Our environment uses Okta for identity, Azure AD Conditional "
        "Access for policy enforcement on AWS GovCloud workloads, "
        "Splunk for logging, and BitLocker for disk encryption.\n\n"
        "Audit logs satisfy 3.3.1, 3.3.6, and 3.3.8 via Splunk Cloud Trial."
    )
    det = FactualPlausibilityDetector()
    result = det.detect("ssp_3.1.1_smoke", sample)
    print(f"Score: {result.score}")
    print(f"Evidence: {result.evidence}")
    print(f"Recommendation: {result.recommendation}")
    print(f"Matches: {len(getattr(result, 'factual_matches', []))}")
    for m in getattr(result, "factual_matches", []):
        print(f"  - {m['label']}")
