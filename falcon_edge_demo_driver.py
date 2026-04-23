"""
Driver: run mismatch_engine_ai on the Falcon Edge demo packet,
including extracted SIEM timestamps. Emits per-artifact reports
and an aggregate packet report as JSON for the PDF builder.

Stdlib-only.
"""
from __future__ import annotations

import json
import re
import sys
from datetime import datetime
from pathlib import Path

# Allow import of the engine without packaging
ENGINE_DIR = Path("/sessions/compassionate-vibrant-hypatia/mnt/Claude/Hardseal-AI-Detection")
sys.path.insert(0, str(ENGINE_DIR))

from mismatch_engine_ai import AIProvenanceDetector, Confidence  # noqa: E402

PACKET_DIR = ENGINE_DIR / "samples" / "falcon_edge_demo"
OUT_JSON = Path("/sessions/compassionate-vibrant-hypatia/falcon_edge_report.json")

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

    # Per-artifact reports (so we can render finding-by-finding in the PDF)
    per_artifact = {}
    for aid, text in narratives.items():
        ts = timestamps.get(aid)
        rep = detector.analyze_artifact(aid, text, timestamps=ts)
        per_artifact[aid] = rep.to_dict()

    # Packet-level report (catches boilerplate clustering across artifacts)
    packet = detector.analyze_packet(narratives, timestamps_by_artifact=timestamps)
    packet_dict = packet.to_dict()

    output = {
        "packet": packet_dict,
        "per_artifact": per_artifact,
        "input_files": sorted(narratives.keys()),
        "timestamp_extracted_artifacts": sorted(timestamps.keys()),
    }
    OUT_JSON.write_text(json.dumps(output, indent=2, default=str))

    # Stdout summary
    print(f"PACKET CONFIDENCE: {packet.confidence.value}")
    print(f"PACKET AGGREGATE SCORE: {packet.aggregate_score}")
    print()
    for aid, rep in per_artifact.items():
        print(f"--- {aid} ---")
        print(f"  Confidence: {rep['confidence']}  Score: {rep['aggregate_score']}")
        for f in rep["findings"]:
            mark = "FLAG" if f["score"] >= 0.5 else "    "
            print(f"  [{mark}] {f['heuristic']:30s} {f['score']:.3f}  {f['evidence'][:90]}")
    print()
    print(f"JSON written to: {OUT_JSON}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
