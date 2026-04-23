"""
wild_sample_runner.py - Run v0.3 detector against samples Rico did not author.

Round 2 critique gap:
    "Falcon Edge is a closed loop. Rico authored the impossibilities AND
     the rules that detect them. A 5-year DIB CISO will discount the entire
     packet within 30 seconds unless you prove the engine works on a sample
     you didn't write."

This runner:
    1. Loads three SSP excerpts from /samples/wild_samples/
       A - generic LLM-generated SSP (no impossibilities, soft AI tells)
       B - human-authored, NIST-style (concrete, named, gaps acknowledged)
       C - vendor-template boilerplate (cookie-cutter pattern)
    2. Strips preamble and non-narrative metadata before scoring.
    3. Runs the v0.3 stack in TWO modes per sample:
         MODE A: whole-file analyze_artifact() - single-artifact perspective
         MODE B: per-control analyze_packet() - cross-narrative BoilerplateCluster
    4. Reports per-sample verdicts side by side.
    5. Picks the best sample for the appendix (the one that most credibly
       demonstrates engine discrimination without depending on seeded traps).

Stdlib only.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ENGINE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(ENGINE_DIR))

from mismatch_engine_ai import AIProvenanceDetector, Confidence  # noqa: E402
from factual_check import FactualPlausibilityDetector  # noqa: E402
from risk_delta import rollup as risk_rollup  # noqa: E402

WILD_DIR = ENGINE_DIR / "samples" / "wild_samples"
OUT_JSON = ENGINE_DIR / "wild_sample_report.json"

# Strip the preamble block before scoring so we do not contaminate
# the detector with our own annotation text.
_CONTROL_HDR = re.compile(r"\*\*Control:\s*(\d+\.\d+\.\d+)[^*]*\*\*", re.IGNORECASE)


def extract_narratives(text: str) -> tuple[str, dict]:
    """Return (full_text_stripped_of_preamble, per_control_narratives).

    full_text_stripped_of_preamble concatenates every control body in order
    (without the '**Control: X.Y.Z ...**' header lines or the file preamble).
    per_control_narratives is a dict {control_id: body_text} suitable for
    AIProvenanceDetector.analyze_packet().
    """
    matches = list(_CONTROL_HDR.finditer(text))
    if not matches:
        return text, {}

    narratives = {}
    bodies = []
    for i, m in enumerate(matches):
        cid = m.group(1).strip()
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        body = text[start:end].strip()
        # Deduplicate repeated IDs by suffixing.
        key = cid
        n = 1
        while key in narratives:
            n += 1
            key = f"{cid}#{n}"
        narratives[key] = body
        bodies.append(body)

    stripped = "\n\n".join(bodies)
    return stripped, narratives


def _apply_factual(rep, f_finding):
    """Fold a factual-plausibility finding into the report in-place."""
    if f_finding.score > 0:
        rep.findings.append(f_finding)
        rep.aggregate_score = max(rep.aggregate_score, f_finding.score)
        if f_finding.score >= 0.95:
            rep.confidence = Confidence.SYNTHETIC
        elif f_finding.score >= 0.5 and rep.confidence == Confidence.CLEAN:
            rep.confidence = Confidence.CONTAMINATED


def _risk_rollup_for(rep_dict, aid: str) -> dict:
    class _F:
        def __init__(self, d):
            self.heuristic = d["heuristic"]
            self.artifact_id = d["artifact_id"]
            self.score = d["score"]
            self.nist_objectives = tuple(d.get("nist_objectives", ()) or ())
    flagged = [_F(f) for f in rep_dict["findings"] if f["score"] >= 0.2]
    return risk_rollup(aid, flagged).to_dict()


def run_one(aid: str, raw_text: str, detector: AIProvenanceDetector,
            factual: FactualPlausibilityDetector) -> dict:
    """Run v0.3 in TWO modes: whole-file and per-control-packet.

    Mode A (whole-file analyze_artifact):
        Exercises SentenceStructureAnomaly, MappingDensity, PromptLeakage,
        ArtifactSpecificityIndex, FactualPlausibility on the stripped
        concatenated narrative body.
    Mode B (per-control analyze_packet):
        Additionally exercises BoilerplateCluster across control narratives,
        which is where a vendor-template sample will expose itself.
    """
    stripped, narratives = extract_narratives(raw_text)

    # --- MODE A: whole-file ---
    rep_a = detector.analyze_artifact(aid, stripped if stripped else raw_text)
    f_a = factual.detect(aid, stripped if stripped else raw_text)
    _apply_factual(rep_a, f_a)
    rep_a_dict = rep_a.to_dict()
    roll_a = _risk_rollup_for(rep_a_dict, aid)

    # --- MODE B: per-control packet ---
    mode_b_report = None
    mode_b_dict = None
    roll_b = None
    per_control_factual = {}
    if narratives:
        rep_b = detector.analyze_packet(narratives)
        # Fold factual-plausibility per narrative, then recompute aggregate.
        for cid, body in narratives.items():
            f_cid = factual.detect(cid, body)
            per_control_factual[cid] = {
                "score": f_cid.score,
                "evidence": f_cid.evidence,
            }
            if f_cid.score > 0:
                rep_b.findings.append(f_cid)
                rep_b.aggregate_score = max(rep_b.aggregate_score, f_cid.score)
                if f_cid.score >= 0.95:
                    rep_b.confidence = Confidence.SYNTHETIC
                elif f_cid.score >= 0.5 and rep_b.confidence == Confidence.CLEAN:
                    rep_b.confidence = Confidence.CONTAMINATED
        mode_b_report = rep_b
        mode_b_dict = rep_b.to_dict()
        roll_b = _risk_rollup_for(mode_b_dict, f"{aid}_PACKET")

    return {
        "artifact_id": aid,
        "narratives_count": len(narratives),
        "mode_a_whole_file": {
            "confidence": rep_a_dict["confidence"],
            "aggregate_score": rep_a_dict["aggregate_score"],
            "findings": rep_a_dict["findings"],
            "risk_headline": roll_a["headline"],
            "worst_poam_risk": roll_a["worst_poam_risk"],
            "worst_fca_exposure": roll_a["worst_fca_exposure"],
            "factual_matches": list(getattr(f_a, "factual_matches", []) or []),
        },
        "mode_b_per_control_packet": None if mode_b_dict is None else {
            "confidence": mode_b_dict["confidence"],
            "aggregate_score": mode_b_dict["aggregate_score"],
            "findings": mode_b_dict["findings"],
            "risk_headline": roll_b["headline"],
            "worst_poam_risk": roll_b["worst_poam_risk"],
            "worst_fca_exposure": roll_b["worst_fca_exposure"],
            "per_control_factual": per_control_factual,
        },
    }


SAMPLE_DESCRIPTIONS = {
    "A_generic_llm_ssp": "Generic LLM output (no prompt guidance, no impossibilities)",
    "B_human_authored_ssp": "Human-authored, NIST-style, specific tools/people/dates",
    "C_vendor_template_ssp": "Vendor/MSP template (repeated paragraph skeleton)",
}

EXPECTED_VERDICT = {
    "A_generic_llm_ssp": "CONTAMINATED or LIKELY_SYNTHETIC (recall test)",
    "B_human_authored_ssp": "CLEAN or PARTIALLY_CONTAMINATED (precision test)",
    "C_vendor_template_ssp": "CONTAMINATED via BoilerplateCluster (cross-narrative test)",
}


def _print_mode(label: str, mode: dict):
    print(f"  {label}")
    print(f"    Confidence:    {mode['confidence']}")
    print(f"    Aggregate:     {mode['aggregate_score']:.3f}")
    print(f"    Risk headline: {mode['risk_headline']}")
    print(f"    POA&M risk:    {mode['worst_poam_risk']}    FCA: {mode['worst_fca_exposure']}")
    print(f"    Findings (score >= 0.2):")
    surfaced = [f for f in mode["findings"] if f["score"] >= 0.2]
    if not surfaced:
        print("      (none)")
    for f in sorted(surfaced, key=lambda x: -x["score"]):
        mark = "FLAG" if f["score"] >= 0.5 else "....."
        print(f"      [{mark}] {f['heuristic']:28s} {f['score']:.3f}  on {f['artifact_id']}")


def main() -> int:
    samples = {}
    for f in sorted(WILD_DIR.iterdir()):
        if f.suffix != ".md":
            continue
        samples[f.stem] = f.read_text(encoding="utf-8")

    if not samples:
        print(f"No .md samples found in {WILD_DIR}", file=sys.stderr)
        return 1

    detector = AIProvenanceDetector()
    factual = FactualPlausibilityDetector()

    results = []
    for aid, text in samples.items():
        results.append(run_one(aid, text, detector, factual))

    output = {
        "engine_version": "v0.3.1 (factual + risk + rebuttal + 2-tier FCA gate)",
        "runner_version": "wild_sample_runner v2 (dual-mode: whole-file + per-control-packet)",
        "samples_run": [r["artifact_id"] for r in results],
        "sample_descriptions": SAMPLE_DESCRIPTIONS,
        "expected_verdict": EXPECTED_VERDICT,
        "results": results,
    }
    OUT_JSON.write_text(json.dumps(output, indent=2, default=str))

    # Stdout summary
    print("=" * 78)
    print("WILD SAMPLE RUN - v0.3.1 against samples Rico did not author")
    print("=" * 78)
    print()
    print(f"{'Sample':30s}  {'Mode A whole':18s}  {'Mode B packet':18s}")
    print("-" * 78)
    for r in results:
        aid = r["artifact_id"]
        a_conf = r["mode_a_whole_file"]["confidence"]
        a_score = r["mode_a_whole_file"]["aggregate_score"]
        b = r.get("mode_b_per_control_packet")
        b_conf = b["confidence"] if b else "n/a"
        b_score = b["aggregate_score"] if b else 0.0
        print(f"{aid:30s}  {a_conf:12s} {a_score:4.2f}  {b_conf:12s} {b_score:4.2f}")
    print()
    for r in results:
        aid = r["artifact_id"]
        desc = SAMPLE_DESCRIPTIONS.get(aid, "")
        print("-" * 78)
        print(f"SAMPLE: {aid}")
        print(f"  Description: {desc}")
        print(f"  Expected:    {EXPECTED_VERDICT.get(aid, 'n/a')}")
        print(f"  Narratives parsed: {r['narratives_count']}")
        _print_mode("MODE A (whole-file analyze_artifact):", r["mode_a_whole_file"])
        if r.get("mode_b_per_control_packet"):
            _print_mode("MODE B (per-control analyze_packet):", r["mode_b_per_control_packet"])
        print()

    print("=" * 78)
    print(f"JSON written to: {OUT_JSON}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
