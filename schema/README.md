# Schema

Machine-readable contract for the JSON output of
`mismatch_engine_ai.py --json`.

## Files

- **`score_v1.json`**: JSON Schema (draft 2020-12) describing the shape,
  types, enums, and value ranges of every field emitted by the CLI in
  `--json` mode. Consumers (C3PAOs, MSPs, CI integrations) can validate
  engine output against this schema to ensure compatibility.

## Stability guarantees

The schema is the stability contract for the engine output.

**Within v1.x (major version 1):**
- No field will be renamed.
- No field will be removed.
- No enum value will be removed.
- `aggregate_score` boundary thresholds will not change.
- `heuristic` names are locked: the 7 names in the enum are the 7 we
  ship.

**What may change within v1.x:**
- New optional fields may be added. Consumers MUST ignore unknown
  fields.
- New enum values may be added (e.g., a future `UNCERTAIN` confidence
  tier). Consumers should handle unknown enum values gracefully.
- `additionalProperties: false` is set in the schema to make breaking
  changes visible. Validators that tolerate unknown fields are
  recommended for forward compatibility.

**v2.x will be declared if:**
- A field must be renamed or removed.
- A heuristic is renamed (ANCHOR_PLAN.md documents the vocabulary lock;
  a rename here is a major version event).
- The classification logic changes in a way that moves previously CLEAN
  packets into a non-CLEAN bucket.

## How to use

### Python (stdlib only, matches the rest of the repo)

```python
import json, subprocess, sys

result = subprocess.run(
    ["python3", "mismatch_engine_ai.py", "packet/", "--json"],
    capture_output=True, text=True,
)
output = json.loads(result.stdout)

# Structural check, stdlib only.
assert set(output.keys()) >= {"artifact_id", "confidence", "aggregate_score", "findings"}
assert output["confidence"] in {"CLEAN", "PARTIALLY_CONTAMINATED", "CONTAMINATED", "LIKELY_SYNTHETIC"}
assert 0.0 <= output["aggregate_score"] <= 1.0
for finding in output["findings"]:
    assert finding["heuristic"] in {
        "SentenceStructureAnomaly", "BoilerplateCluster", "TimestampRegularity",
        "MappingDensity", "CitationGraph", "PromptLeakage", "ArtifactSpecificityIndex",
    }
```

### With a JSON Schema validator (not stdlib)

If you are already using a JSON Schema validator in your pipeline:

```python
import json, jsonschema

schema = json.load(open("schema/score_v1.json"))
output = json.load(open("run_output.json"))
jsonschema.validate(output, schema)
```

Hardseal does not bundle `jsonschema` because the engine is stdlib-only
by policy (see `README.md`).

## Commitment hash

The schema is included in the v0.2 commitment bundle. Any future change
to the schema will update the combined commitment hash and be noted in
`CHANGELOG.md`.

Current v0.2 combined bundle hash:
`32f1e682b0544b1af20077cc33f0604ec76238489182190c8d77a1cb01f42bbf`.
