"""
Driver v2: run mismatch_engine_ai + factual_check + risk_delta + rebuttal
on the Falcon Edge demo packet. Emits a richer JSON for the v2 PDF builder.

War-panel Round 1 (April 22, 2026) added three new layers to the engine.
This driver wires them into the same packet.

Stdlib-only.
"""
from __future__ import annotations

import json
import re
import sys
from datetime import datetime
from pathlib import Path

ENGINE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(ENGINE_DIR))

from mismatch_engine_ai import AIProvenanceDetector, Confidence  # noqa: E402
from factual_check import FactualPlausibilityDetector  # noqa: E402
from risk_delta import rollup as risk_rollup  # noqa: E402
from rebuttal_generator import build_rebuttal  # noqa: E402

PACKET_DIR = ENGINE_DIR / "samples" / "falcon_edge_demo"
OUT_JSON = ENGINE_DIR / "falcon_edge_report_v2.json"

TS_RE = re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")


def extract_timestamps(text: str) -> list:
    out = []
    for m in TS_RE.finditer(text):
        try:
            out.append(datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S"))
        except ValueError:
            pass
    return out


def main() -> int:
    narratives = {}
    timestamps = {}
    for f in sorted(PACKET_DIR.iterdir()):
        if f.suffix != ".md":
            continue
        text = f.read_text(encoding="utf-8")
        narratives[f.stem] = text
        ts = extract_timestamps(text)
        if len(ts) >= 6:
            timestamps[f.stem] = ts

    detector = AIProvenanceDetector()
    factual = FactualPlausibilityDetector()

    per_artifact = {}
    factual_findings_all = {}
    for aid, text in narratives.items():
        ts = timestamps.get(aid)
        rep = detector.analyze_artifact(aid, text, timestamps=ts)
        # v2: bolt the factual check on as an additional finding.
        f_finding = factual.detect(aid, text)
        if f_finding.score > 0:
            rep.findings.append(f_finding)
            # Recompute aggregate to include factual check.
            rep.aggregate_score = max(rep.aggregate_score, f_finding.score)
            # If factual hits, classification escalates.
            if f_finding.score >= 0.95:
                rep.confidence = Confidence.SYNTHETIC
            elif f_finding.score >= 0.5 and rep.confidence == Confidence.CLEAN:
                rep.confidence = Confidence.CONTAMINATED
        per_artifact[aid] = rep.to_dict()

        # Stash the structured factual matches for the PDF builder.
        # factual_check stores them as dicts already.
        if hasattr(f_finding, "factual_matches"):
            factual_findings_all[aid] = list(f_finding.factual_matches)

    # Packet-level (catches cross-artifact boilerplate)
    packet = detector.analyze_packet(narratives, timestamps_by_artifact=timestamps)
    packet_dict = packet.to_dict()

    # Risk-delta rollups per artifact + packet-wide
    risk_per_artifact = {}
    all_findings_for_packet = []
    for aid, rep in per_artifact.items():
        # Rebuild Finding-like objects with score >= 0.4 for risk translation.
        # We use simple namespaces because risk_delta only reads attributes.
        class _F:
            def __init__(self, d):
                self.heuristic = d["heuristic"]
                self.artifact_id = d["artifact_id"]
                self.score = d["score"]
                self.nist_objectives = tuple(d.get("nist_objectives", ()) or ())

        findings_objs = [_F(f) for f in rep["findings"] if f["score"] >= 0.2]
        roll = risk_rollup(aid, findings_objs)
        risk_per_artifact[aid] = roll.to_dict()
        all_findings_for_packet.extend(findings_objs)

    packet_risk = risk_rollup("falcon_edge_packet_v1", all_findings_for_packet).to_dict()

    # Rebuttal kit per finding (only for findings >= 0.5)
    rebuttals_per_artifact = {}
    for aid, rep in per_artifact.items():
        rb_list = []
        for f in rep["findings"]:
            if f["score"] >= 0.5:
                class _F:
                    def __init__(self, d):
                        self.heuristic = d["heuristic"]
                        self.artifact_id = d["artifact_id"]
                        self.score = d["score"]
                rb = build_rebuttal(_F(f))
                rb_list.append(rb.to_dict())
        rebuttals_per_artifact[aid] = rb_list

    output = {
        "packet": packet_dict,
        "per_artifact": per_artifact,
        "factual_matches": factual_findings_all,
        "risk_per_artifact": risk_per_artifact,
        "packet_risk": packet_risk,
        "rebuttals_per_artifact": rebuttals_per_artifact,
        "input_files": sorted(narratives.keys()),
        "timestamp_extracted_artifacts": sorted(timestamps.keys()),
        "engine_version": "v0.3.1 (factual + risk + rebuttal + 2-tier FCA gate)",
    }
    OUT_JSON.write_text(json.dumps(output, indent=2, default=str))

    # Stdout summary
    print(f"PACKET CONFIDENCE: {packet.confidence.value}")
    print(f"PACKET AGGREGATE SCORE: {packet.aggregate_score}")
    print(f"PACKET RISK HEADLINE: {packet_risk['headline']}")
    print()
    for aid, rep in per_artifact.items():
        print(f"--- {aid} ---")
        print(f"  Confidence: {rep['confidence']}  Score: {rep['aggregate_score']}")
        for f in rep["findings"]:
            mark = "FLAG" if f["score"] >= 0.5 else "    "
            print(f"  [{mark}] {f['heuristic']:30s} {f['score']:.3f}  {f['evidence'][:90]}")
    print()
    print("FACTUAL MATCHES:")
    for aid, matches in factual_findings_all.items():
        print(f"  {aid}: {len(matches)} match(es)")
        for m in matches:
            print(f"    - {m['label']}")
    print()
    print(f"JSON written to: {OUT_JSON}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
